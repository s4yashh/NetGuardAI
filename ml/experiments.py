"""Protocol comparison and reliability ablations.

Runs the same model family under three splitting protocols and measures what each
part of the reliability layer contributes:

    original        random split over all capture days (the historical setup)
    random_monwed   random split restricted to Monday-Wednesday
    temporal        train Mon-Wed, calibrate Thu morning, test Thu afternoon + Fri

The comparison between ``random_monwed`` and ``temporal`` isolates the effect of
unseen capture days, because both share the same training pool.

Usage:
    python -m ml.experiments
    python -m ml.experiments --sample-size 300000 --protocols temporal
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from ml import config, reliability
from ml import train as train_module

PROTOCOLS = ("original", "random_monwed", "temporal")
EXPERIMENTS_PATH = config.REPORTS_DIR / "experiments.json"


def _prepare(data: pd.DataFrame, protocol: str, sample_size: int,
             temporal_test_cap: int):
    """Mirror ml.train's sampling so the protocols are comparable."""
    if protocol == "temporal":
        pool = data[data[train_module.DAY_COLUMN].isin(train_module._MONWED)]
        rest = data[~data[train_module.DAY_COLUMN].isin(train_module._MONWED)]
        work = pd.concat([train_module.stratified_sample(pool, sample_size), rest],
                         ignore_index=True)
    else:
        pool = (data if protocol == "original"
                else data[data[train_module.DAY_COLUMN].isin(train_module._MONWED)])
        work = train_module.stratified_sample(pool, sample_size)

    splits, meta = train_module.build_splits(work, protocol, temporal_test_cap)
    return splits, meta


def recall_at_fpr(probabilities: np.ndarray, labels: np.ndarray,
                  target_fpr: float) -> float:
    """Descriptive ROC point: highest recall whose FPR stays under the target.

    Computed on the test set for reporting only; it never selects a threshold.
    """
    curve = reliability.alert_curve(probabilities, labels)
    feasible = [row for row in curve if row["false_positive_rate"] <= target_fpr]
    if not feasible:
        return 0.0
    return float(max(row["recall"] for row in feasible))


def per_attack_metrics(label_test: np.ndarray, decisions: np.ndarray) -> list[dict]:
    """Recall for each attack family; false-positive rate for benign traffic."""
    rows = []
    flagged = decisions == reliability.MALICIOUS
    for label in sorted(set(label_test)):
        mask = label_test == label
        n = int(np.count_nonzero(mask))
        if n == 0:
            continue
        detected = int(np.count_nonzero(flagged & mask))
        entry = {
            "label": label,
            "n": n,
            "detected": detected,
            "rate": detected / n,
            "metric": "false_positive_rate" if label.upper() == config.BENIGN_LABEL else "recall",
        }
        if entry["metric"] == "false_positive_rate":
            # For benign rows the "rate" is the false-alarm rate.
            entry["false_positive_rate"] = entry.pop("rate")
        else:
            entry["recall"] = entry.pop("rate")
        rows.append(entry)
    return rows


def gate_report(splits, feature_names: list[str], train_frame: pd.DataFrame,
                y_train: np.ndarray, X_test: pd.DataFrame,
                label_test: np.ndarray, day_test: np.ndarray,
                decisions: np.ndarray, seed: int) -> dict:
    """Fit the batch gate on benign training traffic and score the test days."""
    X_train = train_frame[feature_names]
    benign_mask = y_train == 0
    days = train_frame[train_module.DAY_COLUMN].to_numpy()

    profile = reliability.fit_shift_profile(
        X_train.to_numpy()[benign_mask], feature_names,
        groups=days[benign_mask], seed=seed)

    rng = np.random.default_rng(seed)
    X_val, y_val, _, _ = train_module._xy(splits["validation"], feature_names)
    benign_val = X_val.to_numpy()[y_val == 0]

    in_batches = train_module._sample_batches(benign_val, rng, n_batches=40, size=2000)
    kinds = train_module._synthetic_shift_batches(benign_val, rng)
    by_kind = {kind: reliability.evaluate_gate(profile, in_batches, batches)
               for kind, batches in kinds.items()}
    overall = reliability.evaluate_gate(profile, in_batches, kinds["scaled"])

    matrix = X_test.to_numpy()
    per_day = {}
    for day in sorted(set(day_test)):
        mask = day_test == day
        if np.count_nonzero(mask) < 50:
            continue
        benign_like = mask & (decisions != reliability.MALICIOUS)
        basis = "non_alerted"
        if np.count_nonzero(benign_like) < 100:
            benign_like, basis = mask, "all_flows"
        score, per_feature = reliability.batch_shift_score(
            matrix[benign_like], profile)
        per_day[day] = {
            "rows": int(np.count_nonzero(mask)),
            "rows_compared": int(np.count_nonzero(benign_like)),
            "basis": basis,
            **reliability.shift_verdict(score, profile, per_feature=per_feature),
        }

    return {
        "threshold_in": profile["threshold_in"],
        "threshold_severe": profile["threshold_severe"],
        "null_calibration": profile.get("null_calibration"),
        "null_days": profile.get("null_days"),
        "in_distribution_false_alarm_rate": overall["false_alarm_rate"],
        "by_kind": by_kind,
        "per_day": per_day,
    }


def prevalence_matched_metrics(y_test: np.ndarray, test_raw: np.ndarray,
                               test_cal: np.ndarray, layer: dict,
                               label_test: np.ndarray,
                               target_rate: float, seed: int) -> dict | None:
    """Recompute the operating point on a class balance matching training.

    The temporal test set is dominated by DDoS and PortScan, so its malicious rate
    is far above the training rate. That inflates the denominator of the
    false-positive rate and makes Brier scores incomparable with the random-split
    protocol. Here the benign rows are kept whole and the attack rows are
    subsampled to restore the training prevalence.
    """
    positives = np.flatnonzero(y_test == 1)
    negatives = np.flatnonzero(y_test == 0)
    if positives.size == 0 or negatives.size == 0 or not 0 < target_rate < 1:
        return None

    wanted = int(negatives.size * target_rate / (1.0 - target_rate))
    wanted = min(wanted, positives.size)
    if wanted < 100:
        return None

    rng = np.random.default_rng(seed)
    chosen = np.concatenate([
        rng.choice(positives, size=wanted, replace=False),
        negatives,
    ])
    y_sub = y_test[chosen]
    raw_sub = test_raw[chosen]
    cal_sub = test_cal[chosen]

    decisions = reliability.decide(cal_sub, layer["t_benign"], layer["t_alert"])
    variants = []
    for name, prediction in (
        ("B0 raw RF @0.5", (raw_sub >= 0.5).astype(int)),
        ("B1 calibrated @0.5", (cal_sub >= 0.5).astype(int)),
        ("B2 CRC threshold", (cal_sub >= layer["t_alert"]).astype(int)),
        ("B3 + review band", (decisions == reliability.MALICIOUS).astype(int)),
    ):
        variants.append({"name": name, **reliability.binary_metrics(y_sub, prediction)})

    return {
        "target_positive_rate": float(target_rate),
        "achieved_positive_rate": float(np.mean(y_sub == 1)),
        "size": int(y_sub.size),
        "variants": variants,
        "per_attack": per_attack_metrics(label_test[chosen], decisions),
        "brier_raw": reliability.brier_score(y_sub, raw_sub),
        "brier_calibrated": reliability.brier_score(y_sub, cal_sub),
        "baseline_brier_constant": reliability.brier_score(
            y_sub, np.full(y_sub.shape, float(np.mean(y_sub == 1)))),
    }


def run_protocol(data: pd.DataFrame, protocol: str, sample_size: int,
                 alpha: float, review_capacity: float,
                 temporal_test_cap: int, seed: int = config.RANDOM_STATE) -> dict:
    print(f"\n=== protocol: {protocol} ===")
    splits, meta = _prepare(data, protocol, sample_size, temporal_test_cap)

    train_frame = splits["train"]
    y_train = train_module.to_binary_labels(train_frame[config.LABEL_COLUMN])
    X_train = train_frame.drop(columns=[config.LABEL_COLUMN, train_module.DAY_COLUMN])

    constant = [c for c in X_train.columns if X_train[c].nunique(dropna=False) <= 1]
    feature_names = [c for c in X_train.columns if c not in constant]

    pipeline = train_module.build_models()["Random Forest"]
    start = time.perf_counter()
    pipeline.fit(X_train[feature_names], y_train)
    train_seconds = time.perf_counter() - start
    print(f"  trained in {train_seconds:.1f}s on {len(X_train):,} flows")

    X_val, y_val, _, _ = train_module._xy(splits["validation"], feature_names)
    val_f1 = float(f1_score(y_val, pipeline.predict(X_val)))

    X_cal, y_cal, _, _ = train_module._xy(splits["calibration"], feature_names)
    cal_raw = pipeline.predict_proba(X_cal)[:, 1]
    layer = reliability.fit_reliability(
        cal_raw, y_cal, alpha=alpha, review_capacity=review_capacity, seed=seed)

    X_test, y_test, label_test, day_test = train_module._xy(splits["test"], feature_names)
    test_raw = pipeline.predict_proba(X_test)[:, 1]
    test_cal = reliability.apply_calibration(layer["calibrator"], test_raw)
    decisions = reliability.decide(test_cal, layer["t_benign"], layer["t_alert"])

    # ---- ablations -------------------------------------------------------
    variants = []
    for name, prediction in (
        ("B0 raw RF @0.5", (test_raw >= 0.5).astype(int)),
        ("B1 calibrated @0.5", (test_cal >= 0.5).astype(int)),
        ("B2 CRC threshold", (test_cal >= layer["t_alert"]).astype(int)),
        ("B3 + review band", (decisions == reliability.MALICIOUS).astype(int)),
    ):
        m = reliability.binary_metrics(y_test, prediction)
        variants.append({"name": name, **m})

    review_rate = float(np.mean(decisions == reliability.REVIEW))

    calibration = {
        "brier_raw": reliability.brier_score(y_test, test_raw),
        "brier_calibrated": reliability.brier_score(y_test, test_cal),
        "ece_raw": reliability.expected_calibration_error(y_test, test_raw),
        "ece_calibrated": reliability.expected_calibration_error(y_test, test_cal),
    }

    print("  " + " | ".join(
        f"{v['name'].split()[0]} R={v['recall']:.3f} FPR={v['false_positive_rate']:.4f}"
        for v in variants))

    gate = gate_report(splits, feature_names, train_frame, y_train, X_test,
                       label_test, day_test, decisions, seed)

    train_positive_rate = float(np.mean(y_train == 1))
    matched = prevalence_matched_metrics(
        y_test, test_raw, test_cal, layer, label_test,
        target_rate=train_positive_rate, seed=seed)

    return {
        "split": {k: int(len(v)) for k, v in splits.items()},
        "meta": meta,
        "train_seconds": round(train_seconds, 2),
        "validation_f1": val_f1,
        "train_positive_rate": train_positive_rate,
        "test_positive_rate": float(np.mean(y_test == 1)),
        "test_size": int(len(y_test)),
        "test_class_counts": {
            "malicious": int(np.count_nonzero(y_test == 1)),
            "benign": int(np.count_nonzero(y_test == 0)),
        },
        "reliability": {
            "alpha": layer["alpha"],
            "t_alert": layer["t_alert"],
            "t_benign": layer["t_benign"],
            "calibration": layer["calibration"],
            "review_rate": review_rate,
            "review_count": int(np.count_nonzero(decisions == reliability.REVIEW)),
        },
        "variants": variants,
        "probability_quality": calibration,
        "recall_at_fpr": {
            "0.001": recall_at_fpr(test_cal, y_test, 0.001),
            "0.01": recall_at_fpr(test_cal, y_test, 0.01),
            "0.05": recall_at_fpr(test_cal, y_test, 0.05),
        },
        "per_attack": per_attack_metrics(label_test, decisions),
        "prevalence_matched": matched,
        "gate": gate,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run NetGuard protocol experiments")
    parser.add_argument("--data-dir", type=Path, default=config.DATASET_DIR)
    parser.add_argument("--sample-size", type=int, default=500_000)
    parser.add_argument("--alpha", type=float, default=config.ALPHA)
    parser.add_argument("--review-capacity", type=float, default=config.REVIEW_CAPACITY)
    parser.add_argument("--temporal-test-cap", type=int, default=20000,
                        help="max rows per attack class in the temporal test set")
    parser.add_argument("--protocols", nargs="+", default=list(PROTOCOLS),
                        choices=list(PROTOCOLS))
    args = parser.parse_args()

    print("Loading dataset...")
    data, dataset_info = train_module.load_dataset(args.data_dir)

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": {
            "sample_size": args.sample_size,
            "alpha": args.alpha,
            "review_capacity": args.review_capacity,
            "temporal_test_cap": args.temporal_test_cap,
            "random_state": config.RANDOM_STATE,
        },
        "dataset": dataset_info,
        "protocols": {},
    }

    for protocol in args.protocols:
        results["protocols"][protocol] = run_protocol(
            data, protocol, args.sample_size, args.alpha,
            args.review_capacity, args.temporal_test_cap)

    EXPERIMENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXPERIMENTS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {EXPERIMENTS_PATH}")


if __name__ == "__main__":
    main()
