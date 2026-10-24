"""Unit tests for the reliability layer.

These use synthetic scores with a known relationship between the raw score and the
label, so the expected behaviour (FPR control, monotone calibration, three-way
decisions, shift detection) is unambiguous.
"""

import numpy as np
import pytest

from ml import reliability as R


def synthetic_scores(n: int = 20000, seed: int = 0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.15).astype(int)
    raw = np.where(y == 1, rng.beta(6, 2, n), rng.beta(2, 6, n))
    return raw, y


# ---------------------------------------------------------------- calibration
def test_isotonic_is_monotone_and_bounded():
    raw, y = synthetic_scores()
    calibrator = R.fit_isotonic(raw, y)
    grid = np.linspace(0, 1, 50)
    mapped = R.apply_calibration(calibrator, grid)

    assert np.all(mapped >= 0) and np.all(mapped <= 1)
    assert np.all(np.diff(mapped) >= -1e-9), "calibration map must be monotone"


def test_calibration_requires_both_classes():
    with pytest.raises(ValueError):
        R.fit_isotonic(np.array([0.1, 0.2]), np.array([0, 0]))


# ---------------------------------------------------------------- CRC threshold
@pytest.mark.parametrize("alpha", [0.005, 0.01, 0.05])
def test_crc_threshold_holds_budget_on_unseen_data(alpha):
    raw, y = synthetic_scores(20000, seed=1)
    fit = R.fit_reliability(raw, y, alpha=alpha, review_capacity=0.05)

    test_raw, test_y = synthetic_scores(60000, seed=2)
    calibrated = R.apply_calibration(fit["calibrator"], test_raw)
    decisions = R.decide(calibrated, fit["t_benign"], fit["t_alert"])
    metrics = R.binary_metrics(test_y, (decisions == R.MALICIOUS).astype(int))

    # Allow a small slack for sampling noise; the point is that the budget is
    # respected in the right order of magnitude, not that it is exact.
    assert metrics["false_positive_rate"] <= alpha * 1.5


def test_crc_reports_infeasible_budget_instead_of_pretending():
    probabilities = np.linspace(0.0, 1.0, 100)
    labels = np.array([0] * 90 + [1] * 10)
    # 90 negatives means one false alarm is 1.1%; alpha=1e-4 cannot be met.
    info = R.crc_threshold(probabilities, labels, alpha=1e-4)
    assert info["feasible"] is False
    assert info["threshold"] > 1.0  # alerts on nothing rather than violating the budget


def test_crc_handles_tied_scores():
    """Isotonic output is heavily tied; the FPR must still respect the budget."""
    negatives = np.repeat([0.1, 0.2, 0.3, 0.4], 500)
    positives = np.repeat([0.35, 0.45], 100)
    probabilities = np.concatenate([negatives, positives])
    labels = np.concatenate([np.zeros(2000, int), np.ones(200, int)])

    info = R.crc_threshold(probabilities, labels, alpha=0.10)
    realised = np.count_nonzero(negatives >= info["threshold"]) / negatives.size
    assert realised <= 0.10 + 1e-12


# ---------------------------------------------------------------- review band
def test_review_band_respects_capacity():
    raw, y = synthetic_scores(20000, seed=3)
    fit = R.fit_reliability(raw, y, alpha=0.01, review_capacity=0.05)

    test_raw, _ = synthetic_scores(40000, seed=4)
    calibrated = R.apply_calibration(fit["calibrator"], test_raw)
    decisions = R.decide(calibrated, fit["t_benign"], fit["t_alert"])

    review_rate = float(np.mean(decisions == R.REVIEW))
    assert review_rate <= 0.10, f"review rate {review_rate:.3f} exceeded capacity"
    assert fit["t_benign"] <= fit["t_alert"]


def test_zero_capacity_means_no_review_band():
    band = R.choose_review_band(np.array([0.1, 0.5, 0.9]), 0.7, capacity=0.0)
    assert band["t_benign"] == 0.7
    assert band["expected_review_rate"] == 0.0


def test_three_way_decision_boundaries():
    probabilities = np.array([0.0, 0.2, 0.5, 0.8, 1.0])
    decisions = R.decide(probabilities, t_benign=0.3, t_alert=0.7)
    assert decisions.tolist() == [R.BENIGN, R.BENIGN, R.REVIEW, R.MALICIOUS, R.MALICIOUS]


# ---------------------------------------------------------------- shift gate
def test_shift_gate_detects_shift_and_ignores_in_distribution():
    rng = np.random.default_rng(7)
    reference = rng.normal(0, 1, (4000, 6)).astype(np.float32)

    profile = R.fit_shift_profile(
        reference, [f"f{i}" for i in range(6)],
        reference_size=1000, null_pool_size=2000, null_batch_size=500,
        n_bootstrap=60, seed=7,
    )

    in_batches = [reference[rng.choice(len(reference), 500, replace=False)]
                  for _ in range(20)]
    shifted_batches = [reference[rng.choice(len(reference), 500, replace=False)] * 40 + 5000
                       for _ in range(10)]

    result = R.evaluate_gate(profile, in_batches, shifted_batches)
    assert result["detection_rate"] >= 0.9
    assert result["auc"] >= 0.9


def test_shift_verdict_orders_severity():
    profile = {"threshold_in": 1.0, "threshold_severe": 2.0, "feature_names": ["a", "b"],
               "reference": np.zeros((10, 2), dtype=np.float32)}
    assert R.shift_verdict(0.5, profile)["verdict"] == "in_distribution"
    assert R.shift_verdict(1.5, profile)["verdict"] == "moderately_shifted"
    assert R.shift_verdict(2.5, profile)["verdict"] == "severely_shifted"


def test_shift_verdict_lists_suspect_features():
    profile = {"threshold_in": 1.0, "threshold_severe": 2.0,
               "feature_names": ["a", "b", "c"], "reference": np.zeros((10, 3))}
    verdict = R.shift_verdict(3.0, profile, per_feature=np.array([0.1, 9.0, 0.2]))
    assert verdict["top_shifted_features"][0]["feature"] == "b"


# ---------------------------------------------------------------- metrics
def test_binary_metrics_counts_and_rates():
    y_true = np.array([0, 0, 1, 1, 0])
    y_pred = np.array([R.BENIGN, R.MALICIOUS, R.MALICIOUS, R.REVIEW, R.BENIGN])
    m = R.binary_metrics(y_true, y_pred)

    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 2)
    assert m["recall"] == pytest.approx(0.5)
    assert m["precision"] == pytest.approx(0.5)
    assert m["false_positive_rate"] == pytest.approx(1 / 3)


def test_alert_curve_is_monotone_in_recall():
    raw, y = synthetic_scores(10000, seed=9)
    curve = R.alert_curve(raw, y)
    recalls = [row["recall"] for row in curve]
    # thresholds descend, so recall must not decrease
    assert all(b >= a - 1e-9 for a, b in zip(recalls, recalls[1:]))
