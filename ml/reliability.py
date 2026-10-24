"""Reliability layer: probability calibration, risk-controlled alerting, review band,
and batch-level distribution-shift auditing.

This module is intentionally free of I/O so every function can be unit-tested.

Design notes
------------
Calibration and threshold selection use **disjoint** halves of the calibration data.
Fitting isotonic regression and then deriving an alert threshold from the same
examples would let the threshold overfit the calibration set and invalidate the
finite-sample false-positive bound. Splitting avoids that.

The alert threshold follows the Conformal Risk Control idea (Angelopoulos et al.,
arXiv:2208.02814): choose the most permissive threshold whose empirical
false-positive rate on held-out negatives, plus the finite-sample slack, stays
under the operator's budget ``alpha``. This is a well-established method; it is
used here, not claimed as a contribution.

The batch-shift score uses a two-sample Kolmogorov-Smirnov statistic per feature,
normalised by sqrt(n_eff) so that its null distribution is approximately
independent of batch size. The decision threshold is calibrated empirically by
bootstrapping batches from an in-distribution pool that is disjoint from the
reference sample.
"""

from __future__ import annotations

import numpy as np
from scipy.stats import ks_2samp
from sklearn.isotonic import IsotonicRegression

# Decision codes
BENIGN = 0
MALICIOUS = 1
REVIEW = 2

DECISION_CODES = (BENIGN, MALICIOUS, REVIEW)
DECISION_NAMES = ("Benign", "Malicious", "Review")

DEFAULT_ALPHA = 0.01            # tolerable false-positive rate on benign flows
DEFAULT_REVIEW_CAPACITY = 0.05  # at most 5% of flows pushed to human review
SHIFT_AGGREGATE_QUANTILE = 0.90  # let a few shifted features dominate the score


# ---------------------------------------------------------------------------
# Probability calibration
# ---------------------------------------------------------------------------
def fit_isotonic(scores: np.ndarray, labels: np.ndarray) -> IsotonicRegression:
    """Map raw ensemble vote fractions to empirical probabilities.

    Parameters
    ----------
    scores : raw ``predict_proba[:, 1]`` values
    labels : 0/1 ground truth
    """
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    if scores.size == 0:
        raise ValueError("cannot calibrate on an empty set")
    if np.unique(labels).size < 2:
        raise ValueError("calibration set must contain both classes")

    calibrator = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
    calibrator.fit(scores, labels)
    return calibrator


def apply_calibration(calibrator: IsotonicRegression | None, scores: np.ndarray) -> np.ndarray:
    """Apply a fitted calibrator; identity when no calibrator is available."""
    scores = np.asarray(scores, dtype=float)
    if calibrator is None:
        return np.clip(scores, 0.0, 1.0)
    return np.clip(np.asarray(calibrator.predict(scores), dtype=float), 0.0, 1.0)


# ---------------------------------------------------------------------------
# Risk-controlled alert threshold
# ---------------------------------------------------------------------------
def crc_threshold(probabilities: np.ndarray, labels: np.ndarray, alpha: float) -> dict:
    """Choose an alert threshold whose expected false-positive rate is <= alpha.

    Only negatives constrain the threshold. Returns the threshold plus the
    diagnostic information needed to report honestly when the budget is too tight
    for the available calibration data.

    The rule is: allow at most ``k = floor(alpha * (n0 + 1))`` false positives on
    the calibration negatives, where ``n0`` is their count. The threshold is then
    just above the ``k``-th largest negative score.
    """
    probabilities = np.asarray(probabilities, dtype=float)
    labels = np.asarray(labels, dtype=int)

    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")

    negatives = probabilities[labels == 0]
    n0 = int(negatives.size)
    if n0 == 0:
        raise ValueError("calibration set contains no benign flows")

    # CRC condition: (n0/(n0+1)) * FPR_hat + 1/(n0+1) <= alpha
    target = float(alpha - (1.0 - alpha) / n0)

    threshold = float(np.nextafter(1.0, 2.0))
    empirical_fpr = 0.0
    feasible = False

    if target > 0:
        # Ties matter: isotonic calibration maps many raw scores to the same
        # probability, so "the k-th largest score" can admit far more than k
        # false positives. Walk distinct values and take the smallest threshold
        # whose *realised* FPR still satisfies the budget.
        for candidate in np.unique(negatives):  # ascending
            fpr = float(np.count_nonzero(negatives >= candidate) / n0)
            if fpr <= target:
                threshold = float(candidate)
                empirical_fpr = fpr
                feasible = True
                break

    k = int(round(empirical_fpr * n0))
    return {
        "threshold": threshold,
        "alpha": float(alpha),
        "negatives": n0,
        "allowed_false_positives": int(k),
        "empirical_fpr": empirical_fpr,
        "feasible": bool(feasible),
        "minimum_supportable_alpha": float(2.0 / (n0 + 1)),
    }


def choose_review_band(probabilities: np.ndarray, alert_threshold: float,
                       capacity: float) -> dict:
    """Pick the lower edge of the review band from a review-capacity constraint.

    ``capacity`` is the largest fraction of traffic an analyst can review. The
    band is ``[t_benign, t_alert)``: flows below it are called benign, flows at or
    above ``t_alert`` are called malicious, everything between is sent to review.
    """
    if not 0.0 <= capacity < 1.0:
        raise ValueError("capacity must be in [0, 1)")

    probabilities = np.asarray(probabilities, dtype=float)
    if probabilities.size == 0:
        raise ValueError("cannot choose a review band from an empty set")

    if capacity == 0.0:
        return {"t_benign": float(alert_threshold), "capacity": 0.0,
                "expected_review_rate": 0.0}

    # The band [t_benign, t_alert) must hold at most `capacity` of the traffic.
    # Simply taking a quantile is wrong when scores are heavily tied (isotonic
    # output often has a large spike at zero): a quantile can select a lower edge
    # that still admits most of the batch. Walk the distinct values instead and
    # take the widest band whose *actual* mass fits the capacity.
    below = probabilities[probabilities < alert_threshold]
    t_benign = float(alert_threshold)
    review_rate = 0.0
    if below.size:
        for candidate in np.unique(below):  # ascending
            mass = float(np.mean(
                (probabilities >= candidate) & (probabilities < alert_threshold)))
            if mass <= capacity:
                t_benign = float(candidate)
                review_rate = mass
                break
    return {"t_benign": t_benign, "capacity": float(capacity),
            "expected_review_rate": review_rate}


def decide(probabilities: np.ndarray, t_benign: float, t_alert: float) -> np.ndarray:
    """Three-way decision: 0 benign, 1 malicious, 2 review."""
    probabilities = np.asarray(probabilities, dtype=float)
    out = np.full(probabilities.shape, REVIEW, dtype=np.int8)
    out[probabilities < t_benign] = BENIGN
    out[probabilities >= t_alert] = MALICIOUS
    return out


def fit_reliability(raw_scores: np.ndarray, labels: np.ndarray,
                    alpha: float = DEFAULT_ALPHA,
                    review_capacity: float = DEFAULT_REVIEW_CAPACITY,
                    seed: int = 42) -> dict:
    """Fit the calibrator and both thresholds on disjoint halves.

    Half A fits the isotonic map. Half B — untouched by the map — supplies the
    false-positive budget and the review-capacity quantile. Returns a plain dict
    that can be serialised inside the model bundle.
    """
    raw_scores = np.asarray(raw_scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    if raw_scores.shape[0] != labels.shape[0]:
        raise ValueError("scores and labels must have the same length")

    rng = np.random.default_rng(seed)
    order = rng.permutation(raw_scores.shape[0])
    half = raw_scores.shape[0] // 2
    idx_a, idx_b = order[:half], order[half:]
    if half == 0:
        raise ValueError("calibration set is too small to split")

    calibrator = fit_isotonic(raw_scores[idx_a], labels[idx_a])
    cal_b = apply_calibration(calibrator, raw_scores[idx_b])

    threshold_info = crc_threshold(cal_b, labels[idx_b], alpha)
    band_info = choose_review_band(cal_b, threshold_info["threshold"], review_capacity)

    return {
        "kind": "isotonic+crc",
        "calibrator": calibrator,
        "alpha": float(alpha),
        "t_alert": float(threshold_info["threshold"]),
        "t_benign": float(band_info["t_benign"]),
        "review_capacity": float(review_capacity),
        "calibration": {
            "size": int(raw_scores.shape[0]),
            "fit_half": int(idx_a.size),
            "threshold_half": int(idx_b.size),
            **threshold_info,
            **{k: v for k, v in band_info.items() if k != "t_benign"},
        },
    }


# ---------------------------------------------------------------------------
# Batch-level distribution-shift auditing
# ---------------------------------------------------------------------------
def _normalised_ks(batch_column: np.ndarray, reference_column: np.ndarray) -> float:
    """Two-sample KS statistic scaled so its null distribution is ~size-invariant.

    Under the null, KS ~ sqrt(-ln(a/2) / (2 * n_eff)) with
    n_eff = n*m/(n+m); multiplying by sqrt(n_eff) removes the sample-size term.
    """
    n, m = batch_column.size, reference_column.size
    if n < 2 or m < 2:
        return 0.0
    stat = float(ks_2samp(batch_column, reference_column, method="asymp").statistic)
    n_eff = (n * m) / (n + m)
    return stat * float(np.sqrt(n_eff))


def batch_shift_score(features: np.ndarray, profile: dict,
                      max_batch_size: int = 2000, seed: int = 0) -> tuple[float, np.ndarray]:
    """Aggregate per-feature KS statistics into one batch-shift score.

    Very large batches are downsampled deterministically. Without this, a batch of
    100,000 flows makes the KS test sensitive to differences far too small to
    matter operationally: at that size almost any real batch looks "significant".

    Returns ``(score, per_feature_scores)``. A high aggregate means at least one
    feature's distribution differs materially from the reference.
    """
    features = np.asarray(features, dtype=float)
    reference = np.asarray(profile["reference"], dtype=float)
    if features.ndim != 2 or features.shape[1] != reference.shape[1]:
        raise ValueError(
            f"expected {reference.shape[1]} features, got "
            f"{features.shape[1] if features.ndim == 2 else 'a non-2D array'}"
        )

    if max_batch_size and features.shape[0] > max_batch_size:
        rng = np.random.default_rng(seed)
        take = rng.choice(features.shape[0], size=max_batch_size, replace=False)
        features = features[take]

    per_feature = np.zeros(features.shape[1], dtype=float)
    for j in range(features.shape[1]):
        column = features[:, j]
        column = column[np.isfinite(column)]
        if column.size < 2:
            continue
        reference_column = reference[:, j]
        reference_column = reference_column[np.isfinite(reference_column)]
        per_feature[j] = _normalised_ks(column, reference_column)

    score = float(np.quantile(per_feature, SHIFT_AGGREGATE_QUANTILE))
    return score, per_feature


def fit_shift_profile(x_reference_pool: np.ndarray, feature_names: list[str],
                      groups: np.ndarray | None = None,
                      reference_size: int = 2000,
                      null_pool_size: int = 20000,
                      null_batch_size: int = 2000,
                      n_bootstrap: int = 200,
                      in_quantile: float = 0.99,
                      severe_quantile: float = 0.999,
                      seed: int = 42) -> dict:
    """Build the reference profile and calibrate the gate on in-distribution data.

    Pass **benign** training flows. The gate is meant to answer "does the normal
    traffic in this batch resemble the normal traffic the model learned?", not
    "does the attack mix match?" — attack composition legitimately varies between
    capture days and is the classifier's job, not a reason to distrust the batch.

    ``groups`` should hold a capture-day label per row. When supplied, the null
    distribution is bootstrapped **within single days** rather than by mixing
    days. Without that, an ordinary one-day upload looks anomalous simply because
    it is not a blend of five days, and the gate cries wolf on its own training
    data.

    The bootstrap pool is disjoint from the reference sample, so the null
    distribution is not measured against itself.
    """
    x = np.asarray(x_reference_pool, dtype=np.float64)
    if x.ndim != 2 or x.shape[0] < reference_size + 100:
        raise ValueError("reference pool is too small to split")

    rng = np.random.default_rng(seed)
    order = rng.permutation(x.shape[0])
    ref_idx = order[:reference_size]
    pool_idx = order[reference_size:reference_size + null_pool_size]

    reference = np.ascontiguousarray(x[ref_idx], dtype=np.float32)
    null_pool = x[pool_idx]
    profile = {"feature_names": list(feature_names), "reference": reference}

    batch_size = min(null_batch_size, null_pool.shape[0])

    per_day: dict[str, np.ndarray] = {}
    if groups is not None:
        groups = np.asarray(groups)
        pool_groups = groups[pool_idx]
        for label in np.unique(pool_groups):
            members = pool_idx[pool_groups == label]
            if members.size >= batch_size:
                per_day[str(label)] = members

    null_scores = np.empty(n_bootstrap, dtype=float)
    for b in range(n_bootstrap):
        if per_day:
            members = per_day[str(rng.choice(list(per_day)))]
            take = rng.choice(members, size=batch_size, replace=False)
        else:
            take = rng.choice(pool_idx, size=batch_size, replace=False)
        null_scores[b], _ = batch_shift_score(x[take], profile)

    threshold_in = float(np.quantile(null_scores, in_quantile))
    threshold_severe = float(np.quantile(null_scores, severe_quantile))
    if threshold_severe <= threshold_in:
        threshold_severe = threshold_in * 1.25

    profile.update({
        "reference_size": int(reference.shape[0]),
        "null_batch_size": int(batch_size),
        "null_scores": null_scores.astype(np.float32),
        "null_calibration": "per_day" if per_day else "pooled",
        "null_days": sorted(per_day),
        "threshold_in": float(threshold_in),
        "threshold_severe": float(threshold_severe),
        "in_quantile": float(in_quantile),
        "severe_quantile": float(severe_quantile),
    })
    return profile


def shift_verdict(score: float, profile: dict, top_k: int = 5,
                  per_feature: np.ndarray | None = None) -> dict:
    """Turn a shift score into a human-facing verdict with the guilty features."""
    threshold_in = float(profile["threshold_in"])
    threshold_severe = float(profile["threshold_severe"])

    if score >= threshold_severe:
        verdict = "severely_shifted"
    elif score >= threshold_in:
        verdict = "moderately_shifted"
    else:
        verdict = "in_distribution"

    suspects: list[dict] = []
    if per_feature is not None and verdict != "in_distribution":
        names = profile.get("feature_names") or []
        order = np.argsort(per_feature)[::-1][:top_k]
        suspects = [
            {"feature": names[j] if j < len(names) else f"feature_{j}",
             "score": float(per_feature[j])}
            for j in order
        ]

    return {
        "verdict": verdict,
        "score": float(score),
        "threshold_in": threshold_in,
        "threshold_severe": threshold_severe,
        "top_shifted_features": suspects,
    }


def evaluate_gate(profile: dict, in_distribution_batches: list[np.ndarray],
                  shifted_batches: list[np.ndarray]) -> dict:
    """Measure the gate: false-alarm rate on in-distribution, detection on shifted."""
    in_scores = [batch_shift_score(b, profile)[0] for b in in_distribution_batches]
    shifted_scores = [batch_shift_score(b, profile)[0] for b in shifted_batches]

    threshold = float(profile["threshold_in"])
    false_alarms = float(np.mean(np.asarray(in_scores) >= threshold)) if in_scores else float("nan")
    detections = float(np.mean(np.asarray(shifted_scores) >= threshold)) if shifted_scores else float("nan")

    # Rank-based separation, independent of the chosen threshold.
    if in_scores and shifted_scores:
        combined = np.concatenate([in_scores, shifted_scores])
        ranks = combined.argsort().argsort()
        n_in = len(in_scores)
        auc = float((ranks[n_in:].sum() - (len(shifted_scores) * (len(shifted_scores) - 1)) / 2)
                    / (n_in * len(shifted_scores)))
    else:
        auc = float("nan")

    return {
        "threshold": threshold,
        "in_distribution_mean": float(np.mean(in_scores)) if in_scores else None,
        "shifted_mean": float(np.mean(shifted_scores)) if shifted_scores else None,
        "false_alarm_rate": false_alarms,
        "detection_rate": detections,
        "auc": auc,
        "n_in": len(in_scores),
        "n_shifted": len(shifted_scores),
    }


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------
def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Binary metrics treating 'Malicious' as positive and 'Review' as no alert.

    Used for the base system and for ablation comparisons, where the review
    outcome is counted as "not flagged" so that the cost of abstaining is visible
    in the recall number rather than hidden.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    flagged = y_pred == MALICIOUS

    tp = int(np.count_nonzero(flagged & (y_true == 1)))
    fp = int(np.count_nonzero(flagged & (y_true == 0)))
    fn = int(np.count_nonzero(~flagged & (y_true == 1)))
    tn = int(np.count_nonzero(~flagged & (y_true == 0)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(len(y_true), 1)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": float(precision), "recall": float(recall),
        "f1_score": float(f1), "accuracy": float(accuracy),
        "false_positive_rate": float(fpr),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def brier_score(labels: np.ndarray, probabilities: np.ndarray) -> float:
    """Mean squared error of probabilistic predictions. Lower is better."""
    labels = np.asarray(labels, dtype=float)
    probabilities = np.asarray(probabilities, dtype=float)
    return float(np.mean((probabilities - labels) ** 2))


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray,
                               bins: int = 10) -> float:
    """Bin-wise gap between predicted confidence and observed frequency."""
    labels = np.asarray(labels, dtype=float)
    probabilities = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = probabilities.size
    if total == 0:
        return float("nan")

    error = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (probabilities >= low) & (probabilities < high)
        count = int(np.count_nonzero(mask))
        if count == 0:
            continue
        gap = abs(float(np.mean(labels[mask])) - float(np.mean(probabilities[mask])))
        error += (count / total) * gap
    return float(error)


def alert_curve(probabilities: np.ndarray, labels: np.ndarray,
                thresholds: np.ndarray | None = None) -> list[dict]:
    """Alert-rate / recall / FPR trade-off as the alert threshold sweeps.

    This is the curve an operator uses to see what a given false-positive budget
    costs in missed attacks.
    """
    probabilities = np.asarray(probabilities, dtype=float)
    labels = np.asarray(labels, dtype=int)
    if thresholds is None:
        thresholds = np.quantile(probabilities, np.linspace(0.999, 0.5, 25))

    rows = []
    for threshold in np.unique(thresholds)[::-1]:
        flagged = probabilities >= threshold
        tp = int(np.count_nonzero(flagged & (labels == 1)))
        fp = int(np.count_nonzero(flagged & (labels == 0)))
        fn = int(np.count_nonzero(~flagged & (labels == 1)))
        tn = int(np.count_nonzero(~flagged & (labels == 0)))
        rows.append({
            "threshold": float(threshold),
            "alert_rate": float(np.mean(flagged)),
            "recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "alerts": tp + fp,
        })
    return rows
