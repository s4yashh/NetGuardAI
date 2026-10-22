"""Train and compare three classifiers on CIC-IDS2017 and save the best one.

Usage (from the project root):
    python -m ml.train                      # default: 500,000-flow stratified sample
    python -m ml.train --sample-size 0      # use every flow (needs lots of RAM)

Outputs:
    models/netguard_model.joblib   the best pipeline + its feature list
    reports/metrics.json           real evaluation results shown in the dashboard
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

from ml import config
from ml.preprocess import clean_column_names, to_binary_labels


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

        feature_cols = [c for c in df.columns if c != config.LABEL_COLUMN]
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
    row_hashes = pd.util.hash_pandas_object(data, index=False)
    data = data[~row_hashes.duplicated().to_numpy()].reset_index(drop=True)

    info = {
        "source": "CIC-IDS2017 MachineLearningCSV (Canadian Institute for Cybersecurity)",
        "files": [p.name for p in files],
        "raw_rows": int(raw_rows),
        "duplicates_removed": int(raw_rows - len(data)),
        "rows_after_cleaning": int(len(data)),
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
# 3. Train, compare and save
# --------------------------------------------------------------------------
def train(data_dir: Path, sample_size: int, models_dir: Path, reports_dir: Path,
          samples_dir: Path) -> dict:
    print("Loading dataset...")
    data, dataset_info = load_dataset(data_dir)
    data = stratified_sample(data, sample_size)
    dataset_info["rows_used"] = int(len(data))
    dataset_info["sampled"] = dataset_info["rows_used"] < dataset_info["rows_after_cleaning"]
    dataset_info["attack_counts"] = {
        k: int(v) for k, v in data[config.LABEL_COLUMN].value_counts().items()
    }

    y = to_binary_labels(data[config.LABEL_COLUMN])
    X = data.drop(columns=[config.LABEL_COLUMN])
    dataset_info["class_counts"] = {
        "Benign": int((y == 0).sum()), "Malicious": int((y == 1).sum())
    }
    print(f"  {len(data):,} flows used ({dataset_info['class_counts']})")

    # Split: 80% train+validation / 20% test, stratified so both keep the class ratio.
    X_trval, X_test, y_trval, y_test, lab_trval, lab_test = train_test_split(
        X, y, data[config.LABEL_COLUMN], test_size=config.TEST_SIZE,
        stratify=y, random_state=config.RANDOM_STATE,
    )
    # Hold out a validation set (used only to pick the best model).
    X_train, X_val, y_train, y_val = train_test_split(
        X_trval, y_trval, test_size=config.VALIDATION_SIZE,
        stratify=y_trval, random_state=config.RANDOM_STATE,
    )

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

        val_f1 = f1_score(y_val, pipeline.predict(X_val[feature_names]))
        test_metrics = evaluate(y_test, pipeline.predict(X_test[feature_names]))
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

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": best_pipeline,
        "feature_names": feature_names,
        "model_name": best["name"],
        "class_names": config.CLASS_NAMES,
        "trained_at": trained_at,
    }, models_dir / config.MODEL_PATH.name, compress=3)

    metrics = {
        "generated_at": trained_at,
        "best_model": best["name"],
        "selection_metric": (
            f"validation F1-score ({config.PRIMARY_MODEL} is kept unless another model "
            f"beats it by more than {config.SELECTION_MARGIN})"
        ),
        "positive_class": "Malicious",
        "dataset": dataset_info,
        "split": {
            "train": int(len(X_train)),
            "validation": int(len(X_val)),
            "test": int(len(X_test)),
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
    }
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / config.METRICS_PATH.name).write_text(json.dumps(metrics, indent=2))
    write_markdown_report(metrics, reports_dir / "model_report.md")

    save_demo_samples(X_test, lab_test, feature_names, samples_dir)
    print(f"Saved model to {models_dir} and reports to {reports_dir}")
    return metrics


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
        f"Flows used: {metrics['dataset']['rows_used']:,} "
        f"(train {metrics['split']['train']:,} / validation {metrics['split']['validation']:,} "
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Train NetGuard AI models on CIC-IDS2017")
    parser.add_argument("--data-dir", type=Path, default=config.DATASET_DIR)
    parser.add_argument("--sample-size", type=int, default=500_000,
                        help="number of flows to use after cleaning (0 = all)")
    args = parser.parse_args()
    train(args.data_dir, args.sample_size, config.MODELS_DIR, config.REPORTS_DIR,
          config.SAMPLES_DIR)


if __name__ == "__main__":
    main()
