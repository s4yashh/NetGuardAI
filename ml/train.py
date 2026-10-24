"""Train and compare three classifiers on CIC-IDS2017 and save the best one.

Usage (from the project root):
    python -m ml.train                      # default: 500,000-flow stratified sample
    python -m ml.train --sample-size 0      # use every flow (needs lots of RAM)
    python -m ml.train --protocol temporal  # train Mon-Wed, test on unseen days

Protocols
---------
``original``       random split over all eight capture files (the historical setup)
``random_monwed``  random split restricted to Monday-Wednesday
``temporal``       train on Monday-Wednesday, calibrate on Thursday morning,
                   test on Thursday afternoon + Friday

The deployed model uses ``original`` by default so that the dashboard keeps its
historical behaviour. The research comparison lives in ``ml.experiments``.

Outputs:
    models/netguard_model.joblib   best pipeline + feature list + reliability layer
    reports/metrics.json           evaluation results shown in the dashboard
    reports/model_report.md        the same results as a readable table
    dataset/samples/*.csv          demo files taken from the held-out test set
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml import config, reliability
from ml.preprocess import clean_column_names, to_binary_labels

DAY_COLUMN = "_day"

# Which capture files belong to which day bucket.
_MONWED = {"Monday", "Tuesday", "Wednesday"}


def day_from_filename(filename: str) -> str:
    """Map a CIC-IDS2017 CSV filename to a capture-day label."""
    name = filename.lower()
    if name.startswith("monday"):
        return "Monday"
    if name.startswith("tuesday"):
        return "Tuesday"
    if name.startswith("wednesday"):
        return "Wednesday"
    if "thursday" in name and "morning" in name:
        return "Thursday-Morning"
    if "thursday" in name:
        return "Thursday-Afternoon"
    if "friday" in name and "morning" in name:
        return "Friday-Morning"
    if "friday" in name and "portscan" in name:
        return "Friday-PortScan"
    if "friday" in name and "ddos" in name:
        return "Friday-DDoS"
    return "Unknown"


# --------------------------------------------------------------------------
# 1. Load and clean the dataset
# --------------------------------------------------------------------------
def load_dataset(data_dir: Path) -> tuple[pd.DataFrame, dict]:
    """Read every CIC-IDS2017 CSV, clean it and combine into one DataFrame."""
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise SystemExit(
            f"No CSV files found in {data_dir}.\n"
            "Download the CIC-IDS2017 MachineLearningCSV files first (see README.md)."
        )

    frames = []
    for path in files:
        print(f"  reading {path.name}")
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df = clean_column_names(df)
        df = df.dropna(subset=[config.LABEL_COLUMN])
        df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype(str).str.strip()
        df[DAY_COLUMN] = day_from_filename(path.name)

        feature_cols = [c for c in df.columns
                        if c not in (config.LABEL_COLUMN, DAY_COLUMN)]
        df[feature_cols] = (
            df[feature_cols]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .astype(np.float32)  # float32 halves memory use
        )
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)
    raw_rows = len(data)

    # Identical rows add no information and can leak between train and test.
    # Hashing each row (64-bit) is much faster than comparing all 79 columns.
    row_hashes = pd.util.hash_pandas_object(
        data.drop(columns=[DAY_COLUMN]), index=False
    )
    data = data[~row_hashes.duplicated().to_numpy()].reset_index(drop=True)

    info = {
        "source": "CIC-IDS2017 MachineLearningCSV (Canadian Institute for Cybersecurity)",
        "files": [p.name for p in files],
        "raw_rows": int(raw_rows),
        "duplicates_removed": int(raw_rows - len(data)),
        "rows_after_cleaning": int(len(data)),
        "days": {d: int((data[DAY_COLUMN] == d).sum())
                 for d in sorted(data[DAY_COLUMN].unique())},
    }
    return data, info


def stratified_sample(data: pd.DataFrame, size: int) -> pd.DataFrame:
    """Keep `size` rows while preserving the benign/malicious ratio."""
    if size <= 0 or size >= len(data):
        return data
    y = to_binary_labels(data[config.LABEL_COLUMN])
    sample, _ = train_test_split(
        data, train_size=size, stratify=y, random_state=config.RANDOM_STATE
    )
    return sample.reset_index(drop=True)


def cap_per_class(data: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    """Cap each attack label at `max_per_class` rows, keeping rare classes whole.

    Temporal test pools contain hundreds of thousands of DDoS/PortScan rows but
    only a handful of Infiltration rows. Capping the common classes keeps the
    evaluation fast without erasing the rare ones.
    """
    if max_per_class <= 0:
        return data
    parts = []
    for _, group in data.groupby(config.LABEL_COLUMN, sort=False):
        parts.append(group if len(group) <= max_per_class
                     else group.sample(n=max_per_class, random_state=config.RANDOM_STATE))
    return pd.concat(parts, ignore_index=True)


# --------------------------------------------------------------------------
# 2. Define the models
# --------------------------------------------------------------------------
def build_models() -> dict[str, Pipeline]:
    """Each model is a Pipeline so preprocessing is saved together with it."""
    return {
        "Random Forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=100, n_jobs=-1, random_state=config.RANDOM_STATE
            )),
        ]),
        "Decision Tree": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", DecisionTreeClassifier(random_state=config.RANDOM_STATE)),
        ]),
        "Logistic Regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),  # LR needs features on a similar scale
            ("model", LogisticRegression(max_iter=1000)),
        ]),
    }


def evaluate(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Standard binary metrics with Malicious (1) as the positive class."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        # [[TN, FP], [FN, TP]] - rows = actual, columns = predicted
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


# --------------------------------------------------------------------------
# 3. Protocol-aware splitting
# --------------------------------------------------------------------------
def _split_frame(frame: pd.DataFrame, seed: int) -> dict[str, pd.DataFrame]:
    """Split one pool into train / validation / calibration / test (62/8/10/20)."""
    y = to_binary_labels(frame[config.LABEL_COLUMN])
    rest, test = train_test_split(
        frame, test_size=0.20, stratify=y, random_state=seed)
    rest_y = to_binary_labels(rest[config.LABEL_COLUMN])
    train, tmp = train_test_split(
        rest, test_size=0.225, stratify=rest_y, random_state=seed)
    tmp_y = to_binary_labels(tmp[config.LABEL_COLUMN])
    val, cal = train_test_split(
        tmp, test_size=0.5556, stratify=tmp_y, random_state=seed)
    return {"train": train, "validation": val, "calibration": cal, "test": test}


def build_splits(data: pd.DataFrame, protocol: str,
                 temporal_test_cap: int = 20000) -> tuple[dict, dict]:
    """Return the four splits plus descriptive metadata for a protocol."""
    seed = config.RANDOM_STATE

    if protocol == "original":
        splits = _split_frame(data, seed)
        meta = {"protocol": "original", "description": "random split over all capture days"}

    elif protocol == "random_monwed":
        pool = data[data[DAY_COLUMN].isin(_MONWED)]
        splits = _split_frame(pool, seed)
        meta = {"protocol": "random_monwed",
                "description": "random split restricted to Monday-Wednesday"}

    elif protocol == "temporal":
        pool = data[data[DAY_COLUMN].isin(_MONWED)]
        base = _split_frame(pool, seed)
        calibration = data[data[DAY_COLUMN] == "Thursday-Morning"]
        test = data[data[DAY_COLUMN].isin(
            {"Thursday-Afternoon", "Friday-Morning", "Friday-PortScan", "Friday-DDoS"})]
        splits = {
            "train": base["train"],
            "validation": base["validation"],
            "calibration": calibration,
            "test": cap_per_class(test, temporal_test_cap),
        }
        meta = {
            "protocol": "temporal",
            "description": ("train Monday-Wednesday, calibrate Thursday morning, "
                            "test Thursday afternoon + Friday"),
            "test_cap_per_class": temporal_test_cap,
        }
    else:
        raise ValueError(f"unknown protocol: {protocol}")

    meta["sizes"] = {k: int(len(v)) for k, v in splits.items()}
    meta["days"] = {
        name: {d: int((part[DAY_COLUMN] == d).sum())
               for d in sorted(part[DAY_COLUMN].unique())}
        for name, part in splits.items()
    }
    return splits, meta


def _xy(frame: pd.DataFrame, feature_names: list[str] | None = None):
    """Split a frame into (features, binary labels, raw label strings, days)."""
    y = to_binary_labels(frame[config.LABEL_COLUMN])
    labels = frame[config.LABEL_COLUMN].astype(str).str.strip().to_numpy()
    days = frame[DAY_COLUMN].to_numpy() if DAY_COLUMN in frame.columns else None
    X = frame.drop(columns=[c for c in (config.LABEL_COLUMN, DAY_COLUMN)
                            if c in frame.columns])
    if feature_names is not None:
        X = X[feature_names]
    return X, y, labels, days


# --------------------------------------------------------------------------
# 4. Train, compare and save
# --------------------------------------------------------------------------
def select_model(results: list[dict]) -> dict:
    """Pick the model to deploy using the validation set (never the test set).

    Random Forest is the primary model. A baseline replaces it only when its
    validation F1 is higher by more than SELECTION_MARGIN, so a difference of
    one or two flows (noise) does not change the deployed model.
    """
    by_name = {r["name"]: r for r in results}
    primary = by_name[config.PRIMARY_MODEL]
    challenger = max(results, key=lambda r: r["validation_f1"])
    if challenger["validation_f1"] - primary["validation_f1"] > config.SELECTION_MARGIN:
        return challenger
    return primary


def write_markdown_report(metrics: dict, path: Path) -> None:
    lines = [
        "# Model evaluation report",
        "",
        f"Generated: {metrics['generated_at']}  ",
        f"Dataset: {metrics['dataset']['source']}  ",
        f"Protocol: {metrics.get('protocol', {}).get('protocol', 'original')}  ",
        f"Flows used: {metrics['dataset']['rows_used']:,} "
        f"(train {metrics['split']['train']:,} / validation {metrics['split']['validation']:,} "
        f"/ calibration {metrics['split'].get('calibration', 0):,} "
        f"/ test {metrics['split']['test']:,})  ",
        f"Selected model: **{metrics['best_model']}**  ",
        f"Selection rule: {metrics['selection_metric']}",
        "",
        "Test-set results (positive class = Malicious):",
        "",
        "| Model | Validation F1 | Accuracy | Precision | Recall | F1-score | Train time (s) |",
        "|---|---|---|---|---|---|---|",
    ]
    for m in metrics["models"]:
        lines.append(f"| {m['name']} | {m['validation_f1']:.4f} | {m['accuracy']:.4f} | {m['precision']:.4f} | "
                     f"{m['recall']:.4f} | {m['f1_score']:.4f} | {m['train_seconds']} |")
    lines += ["", "Confusion matrices on the test set ([[TN, FP], [FN, TP]]):", ""]
    for m in metrics["models"]:
        lines.append(f"- {m['name']}: {m['confusion_matrix']}")

    if "reliability" in metrics:
        rel = metrics["reliability"]
        lines += [
            "",
            "## Reliability layer",
            "",
            f"- Calibration: {rel['kind']} "
            f"(alpha={rel['alpha']}, review capacity={rel['review_capacity']})",
            f"- Alert threshold: {rel['t_alert']:.4f}, review band lower edge: {rel['t_benign']:.4f}",
            "",
            "| Variant | Precision | Recall | F1 | FPR | Alerts |",
            "|---|---|---|---|---|---|",
        ]
        for row in rel["variants"]:
            lines.append(
                f"| {row['name']} | {row['precision']:.4f} | {row['recall']:.4f} | "
                f"{row['f1_score']:.4f} | {row['false_positive_rate']:.5f} | {row['alerts']} |"
            )
        lines += [
            "",
            f"- Review rate: {rel['review_rate']:.2%} "
            f"({rel['review_count']:,} of {rel['test_size']:,} flows)",
        ]

    if "shift_gate" in metrics:
        gate = metrics["shift_gate"]
        lines += [
            "",
            "## Batch shift gate",
            "",
            f"- In-distribution false-alarm rate: {gate['false_alarm_rate']:.2%}",
            f"- Synthetic-shift detection rate: {gate['detection_rate']:.2%}",
            f"- Separation (AUC): {gate['auc']:.4f}",
        ]

    path.write_text("\n".join(lines) + "\n")


def save_demo_samples(X_test: pd.DataFrame, labels: pd.Series, feature_names: list[str],
                      samples_dir: Path, n_rows: int = 2000) -> None:
    """Save real flows from the held-out test set for demonstrating the app."""
    samples_dir.mkdir(parents=True, exist_ok=True)
    demo = X_test.copy()
    demo[config.LABEL_COLUMN] = labels.to_numpy()
    demo = demo.sample(n=min(n_rows, len(demo)), random_state=config.RANDOM_STATE)
    demo.to_csv(samples_dir / "demo_test_flows.csv", index=False)

    # The same flows without the Label column, as a real user would upload them.
    demo.drop(columns=[config.LABEL_COLUMN]).to_csv(
        samples_dir / "demo_unlabeled_flows.csv", index=False)

    # An intentionally broken file to demonstrate input validation.
    demo.drop(columns=feature_names[:3]).head(50).to_csv(
        samples_dir / "invalid_missing_columns.csv", index=False)

    # A deliberately shifted copy of the demo flows, to demonstrate the shift gate.
    # Every numeric feature is scaled and offset far outside its training range.
    shifted = demo.drop(columns=[config.LABEL_COLUMN]).copy()
    numeric = shifted.select_dtypes(include=[np.number]).columns
    shifted[numeric] = shifted[numeric] * 50.0 + 1e6
    shifted.to_csv(samples_dir / "demo_shifted_flows.csv", index=False)


def train(data_dir: Path, sample_size: int, models_dir: Path, reports_dir: Path,
          samples_dir: Path, protocol: str = "original",
          alpha: float = config.ALPHA,
          review_capacity: float = config.REVIEW_CAPACITY) -> dict:
    print("Loading dataset...")
    data, dataset_info = load_dataset(data_dir)
    dataset_info["protocol"] = protocol

    if protocol == "temporal":
        # Keep the Mon-Wed training pool at the requested sample size and leave
        # the calibration/test days untouched.
        pool = data[data[DAY_COLUMN].isin(_MONWED)]
        rest = data[~data[DAY_COLUMN].isin(_MONWED)]
        data = pd.concat([stratified_sample(pool, sample_size), rest],
                         ignore_index=True)
    else:
        pool = data if protocol == "original" else data[data[DAY_COLUMN].isin(_MONWED)]
        data = stratified_sample(pool, sample_size)

    dataset_info["rows_used"] = int(len(data))
    dataset_info["sampled"] = dataset_info["rows_used"] < dataset_info["rows_after_cleaning"]
    dataset_info["attack_counts"] = {
        k: int(v) for k, v in data[config.LABEL_COLUMN].value_counts().items()
    }

    splits, protocol_meta = build_splits(data, protocol)
    train_frame = splits["train"]
    dataset_info["rows_used"] = int(sum(len(v) for v in splits.values()))

    y_train = to_binary_labels(train_frame[config.LABEL_COLUMN])
    X_train = train_frame.drop(columns=[config.LABEL_COLUMN, DAY_COLUMN])

    # Drop features that never change in the training data (they carry no signal).
    constant = [c for c in X_train.columns if X_train[c].nunique(dropna=False) <= 1]
    feature_names = [c for c in X_train.columns if c not in constant]
    print(f"  {len(feature_names)} features kept, {len(constant)} constant features dropped")

    results = []
    fitted = {}
    for name, pipeline in build_models().items():
        print(f"Training {name}...")
        start = time.perf_counter()
        pipeline.fit(X_train[feature_names], y_train)
        train_seconds = time.perf_counter() - start

        X_val, y_val, _, _ = _xy(splits["validation"], feature_names)
        X_test, y_test, _, _ = _xy(splits["test"], feature_names)

        val_f1 = f1_score(y_val, pipeline.predict(X_val))
        test_metrics = evaluate(y_test, pipeline.predict(X_test))
        results.append({
            "name": name,
            "validation_f1": float(val_f1),
            "train_seconds": round(train_seconds, 2),
            **test_metrics,
        })
        fitted[name] = pipeline
        print(f"  validation F1={val_f1:.4f}  test accuracy={test_metrics['accuracy']:.4f} "
              f"F1={test_metrics['f1_score']:.4f}  ({train_seconds:.1f}s)")

    best = select_model(results)
    best_pipeline = fitted[best["name"]]
    print(f"Selected model: {best['name']}")

    importances = []
    estimator = best_pipeline.named_steps["model"]
    if hasattr(estimator, "feature_importances_"):
        pairs = sorted(zip(feature_names, estimator.feature_importances_),
                       key=lambda p: p[1], reverse=True)[:15]
        importances = [{"feature": f, "importance": float(v)} for f, v in pairs]

    # ---- reliability layer -------------------------------------------------
    print("Fitting calibration and decision thresholds...")
    X_cal, y_cal, _, _ = _xy(splits["calibration"], feature_names)
    cal_raw = best_pipeline.predict_proba(X_cal)[:, 1]
    fitted_reliability = reliability.fit_reliability(
        cal_raw, y_cal, alpha=alpha, review_capacity=review_capacity,
        seed=config.RANDOM_STATE,
    )

    X_test, y_test, label_test, day_test = _xy(splits["test"], feature_names)
    test_raw = best_pipeline.predict_proba(X_test)[:, 1]
    test_cal = reliability.apply_calibration(fitted_reliability["calibrator"], test_raw)
    test_decision = reliability.decide(
        test_cal, fitted_reliability["t_benign"], fitted_reliability["t_alert"])
    variants = reliability_variants(test_raw, test_cal, y_test, fitted_reliability)
    review_count = int(np.count_nonzero(test_decision == reliability.REVIEW))

    # ---- batch shift gate --------------------------------------------------
    print("Fitting batch shift gate...")
    # The gate models *benign* traffic: attack composition varies by capture day
    # and is the classifier's job, not a reason to distrust a whole batch.
    benign_mask = y_train == 0
    day_train = train_frame[DAY_COLUMN].to_numpy()
    shift_profile = reliability.fit_shift_profile(
        X_train[feature_names].to_numpy()[benign_mask], feature_names,
        groups=day_train[benign_mask], seed=config.RANDOM_STATE)

    rng = np.random.default_rng(config.RANDOM_STATE)
    X_val, y_val, _, _ = _xy(splits["validation"], feature_names)
    benign_val = X_val.to_numpy()[y_val == 0]
    in_batches = _sample_batches(benign_val, rng, n_batches=40, size=2000)
    shift_kinds = _synthetic_shift_batches(benign_val, rng)
    gate_metrics = reliability.evaluate_gate(
        shift_profile, in_batches, shift_kinds["scaled"])
    gate_by_kind = {
        kind: reliability.evaluate_gate(shift_profile, in_batches, batches)
        for kind, batches in shift_kinds.items()
    }

    gate_days = {}
    test_matrix = X_test.to_numpy()
    for day in sorted(set(day_test)):
        mask = day_test == day
        if mask.sum() < 50:
            continue
        # Judge the day on the flows the model did not flag, i.e. the traffic it
        # believes is benign. Flagged flows are supposed to look different.
        benign_like = mask & (test_decision != reliability.MALICIOUS)
        basis = "non_alerted"
        if np.count_nonzero(benign_like) < 100:
            benign_like, basis = mask, "all_flows"
        score, per_feature = reliability.batch_shift_score(
            test_matrix[benign_like], shift_profile)
        gate_days[day] = {
            "rows": int(mask.sum()),
            "rows_compared": int(np.count_nonzero(benign_like)),
            "basis": basis,
            **reliability.shift_verdict(score, shift_profile, per_feature=per_feature),
        }

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": best_pipeline,
        "feature_names": feature_names,
        "model_name": best["name"],
        "class_names": config.CLASS_NAMES,
        "trained_at": trained_at,
        "protocol": protocol,
        "reliability": fitted_reliability,
        "shift_profile": shift_profile,
    }, models_dir / config.MODEL_PATH.name, compress=3)

    metrics = {
        "generated_at": trained_at,
        "best_model": best["name"],
        "selection_metric": (
            f"validation F1-score ({config.PRIMARY_MODEL} is kept unless another model "
            f"beats it by more than {config.SELECTION_MARGIN})"
        ),
        "positive_class": "Malicious",
        "protocol": protocol_meta,
        "dataset": dataset_info,
        "split": {
            "train": int(len(splits["train"])),
            "validation": int(len(splits["validation"])),
            "calibration": int(len(splits["calibration"])),
            "test": int(len(splits["test"])),
            "stratified": True,
            "random_state": config.RANDOM_STATE,
        },
        "features": {
            "count": len(feature_names),
            "names": feature_names,
            "dropped_constant": constant,
        },
        "models": results,
        "feature_importances": importances,
        "reliability": {
            "kind": fitted_reliability["kind"],
            "alpha": fitted_reliability["alpha"],
            "t_alert": fitted_reliability["t_alert"],
            "t_benign": fitted_reliability["t_benign"],
            "review_capacity": fitted_reliability["review_capacity"],
            "calibration": fitted_reliability["calibration"],
            "variants": variants,
            "review_count": review_count,
            "review_rate": review_count / max(len(test_decision), 1),
            "test_size": int(len(test_decision)),
        },
        "shift_gate": {
            **gate_metrics,
            "threshold_severe": shift_profile["threshold_severe"],
            "null_calibration": shift_profile.get("null_calibration"),
            "null_days": shift_profile.get("null_days"),
            "reference_size": shift_profile.get("reference_size"),
            "by_kind": gate_by_kind,
            "per_day": gate_days,
        },
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / config.METRICS_PATH.name).write_text(json.dumps(metrics, indent=2))
    write_markdown_report(metrics, reports_dir / "model_report.md")

    X_demo = splits["test"].drop(columns=[config.LABEL_COLUMN, DAY_COLUMN])[feature_names]
    save_demo_samples(X_demo, splits["test"][config.LABEL_COLUMN], feature_names, samples_dir)
    print(f"Saved model to {models_dir} and reports to {reports_dir}")
    return metrics


def reliability_variants(raw: np.ndarray, calibrated: np.ndarray, y_true: np.ndarray,
                         fitted: dict) -> list[dict]:
    """B0-B3: the same model with progressively more of the reliability layer."""
    alert = fitted["t_alert"]
    band = fitted["t_benign"]

    binary = (calibrated >= alert).astype(int)
    three_way = reliability.decide(calibrated, band, alert)
    no_alert = (three_way == reliability.MALICIOUS).astype(int)  # review counts as not flagged
    raw_binary = (raw >= 0.5).astype(int)

    rows = []
    for name, prediction in (
        ("B0 raw RF @0.5", raw_binary),
        ("B1 calibrated @0.5", (calibrated >= 0.5).astype(int)),
        ("B2 CRC threshold", binary),
        ("B3 + review band", no_alert),
    ):
        m = reliability.binary_metrics(y_true, prediction)
        rows.append({
            "name": name,
            "precision": m["precision"],
            "recall": m["recall"],
            "f1_score": m["f1_score"],
            "accuracy": m["accuracy"],
            "false_positive_rate": m["false_positive_rate"],
            "alerts": m["tp"] + m["fp"],
            "confusion_matrix": m["confusion_matrix"],
        })

    return rows


def _sample_batches(matrix: np.ndarray, rng, n_batches: int, size: int) -> list[np.ndarray]:
    if matrix.shape[0] < size:
        size = matrix.shape[0]
    return [matrix[rng.choice(matrix.shape[0], size=size, replace=False)]
            for _ in range(n_batches)]


def _synthetic_shift_batches(matrix: np.ndarray, rng,
                             n_per_kind: int = 10, size: int = 2000) -> dict[str, list]:
    """Deliberately perturbed batches used only to characterise gate sensitivity.

    ``permuted`` is a negative control: shuffling each column independently
    preserves every marginal distribution exactly, so a marginal KS statistic
    cannot detect it. Reporting that failure is more useful than hiding it.
    """
    scale = np.nanstd(matrix, axis=0) + 1e-9
    out: dict[str, list] = {"scaled": [], "noised": [], "mean_shifted": [], "permuted": []}
    for _ in range(n_per_kind):
        take = rng.choice(matrix.shape[0], size=min(size, matrix.shape[0]), replace=False)
        base = matrix[take].astype(np.float64)
        out["scaled"].append(base * 5.0)
        out["noised"].append(base + rng.normal(0, 1.0, base.shape) * scale)
        out["mean_shifted"].append(base + 2.0 * scale)
        permuted = base.copy()
        for j in range(permuted.shape[1]):
            permuted[:, j] = rng.permutation(permuted[:, j])
        out["permuted"].append(permuted)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Train NetGuard AI models on CIC-IDS2017")
    parser.add_argument("--data-dir", type=Path, default=config.DATASET_DIR)
    parser.add_argument("--sample-size", type=int, default=500_000,
                        help="number of flows to use after cleaning (0 = all)")
    parser.add_argument("--protocol", choices=["original", "random_monwed", "temporal"],
                        default="original", help="splitting protocol")
    parser.add_argument("--alpha", type=float, default=config.ALPHA,
                        help="tolerable false-positive rate on benign flows")
    parser.add_argument("--review-capacity", type=float, default=config.REVIEW_CAPACITY,
                        help="share of traffic routed to human review")
    args = parser.parse_args()
    train(args.data_dir, args.sample_size, config.MODELS_DIR, config.REPORTS_DIR,
          config.SAMPLES_DIR, protocol=args.protocol, alpha=args.alpha,
          review_capacity=args.review_capacity)


if __name__ == "__main__":
    main()
