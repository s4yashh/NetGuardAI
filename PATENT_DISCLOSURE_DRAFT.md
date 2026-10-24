# PATENT_DISCLOSURE_DRAFT.md

**Status: NOT a patent application. NOT a legal opinion. NOT a novelty claim.**
**Date:** 2026-10-23
**Prepared for:** review by a qualified patent professional, if the applicant wishes to pursue one

---

## 0. Required reading before anything else

This document records a technical contribution in the format of an invention
disclosure so that a professional can evaluate it. It is written on the explicit
understanding that:

1. **No novelty was established.** `NOVELTY_RESEARCH.md` found that every
   algorithmic component described here is already published, several of them
   applied to the same dataset in 2026. A screening search is not a prior-art
   search.
2. **No freedom to operate is asserted.** Patents exist in adjacent territory
   (US8800036B2 adaptive IDS thresholds; US11057399B2 alert presentation flags).
   Whether any claim could be drafted around them is a legal question this
   document cannot answer.
3. **The measured results are reported as they came out**, including the ones that
   weaken the case.
4. **Filing would require a professional prior-art search** across patent
   databases and non-patent literature, and probably external review.

The honest recommendation of this project is **not to file**. The contribution is
an engineering and measurement contribution suitable for a course project or a
systems paper, not a patent.

---

## 1. Technical problem

A machine-learning flow classifier deployed behind a CSV upload interface answers
*"is this flow malicious?"* but not *"should this batch of answers be believed?"*

Three failure modes were measured on the reference implementation:

| ID | Failure | Measurement |
|---|---|---|
| P1 | A batch far outside the training distribution is labelled with full confidence | All numeric features transformed by `x ↦ 50x + 10⁶`: recall fell from 99.4% to **0%**, every calibrated probability landed in the ambiguous band, and the API returned 2,000 `Benign` labels with HTTP 200 |
| P2 | The reported score is not the deployed score | Same model: 99.83% accuracy on a random split, but recall **0.998 → 0.303** when the test set is made of unseen capture days |
| P3 | Uncertain flows are forced into a binary label | The model's own probabilities contained the information that it was out of its depth; the 0.5 threshold discarded it |

---

## 2. Proposed solution (as implemented)

A **reliability layer** interposed between the classifier and the interface,
comprising three components.

### Component A — Batch-level distribution-shift gate (pre-inference)

**Method steps:**

1. During training, store a reference sample of *benign* training flows
   (2,000 × 69 features) and a disjoint bootstrap pool (20,000 rows).
2. For each of the 69 features compute a two-sample Kolmogorov–Smirnov statistic
   between the incoming batch and the reference sample.
3. Normalise each statistic by `sqrt(n_eff)` where `n_eff = n·m/(n+m)`, rendering
   it approximately invariant to batch size.
4. Aggregate across features with the 90th percentile, so a few badly shifted
   features are not diluted by stable ones.
5. Calibrate two thresholds (99th and 99.9th percentiles) on a null distribution
   produced by bootstrapping batches **within individual capture days** from the
   disjoint pool.
6. At inference, optionally downsample the batch to 2,000 rows; compute the score
   over the rows the classifier did **not** flag; return
   `in_distribution` / `moderately_shifted` / `severely_shifted`, plus the
   most-affected features.
7. When the verdict is not `in_distribution`, surface a warning that supersedes
   the per-flow results in the interface.

**Two design choices worth noting to a reviewer:**

- *Per-day null calibration.* Bootstrapping from a mixture of days makes any
  ordinary one-day upload look anomalous, because it is not a blend of five days.
  Measured: with pooled calibration the gate flagged 8 of 8 capture days; with
  per-day calibration it flagged 1 of 8 (the day whose benign traffic genuinely
  changed).
- *Benign-conditional comparison.* The gate scores the non-flagged subset against a
  benign reference, so a batch containing novel attack types is not automatically
  declared untrustworthy. Attack composition legitimately varies by day and is the
  classifier's job.

### Component B — Calibrated, budget-driven, three-way decision

**Method steps:**

1. Split the calibration data into two disjoint halves.
2. Fit isotonic regression on half A, mapping the ensemble vote fraction to an
   empirical probability.
3. On half B, select the most permissive alert threshold whose *realised*
   false-positive rate satisfies
   `FPR_hat ≤ alpha − (1 − alpha)/n0`, walking distinct values to remain correct
   under the ties that isotonic output produces.
4. Derive the lower edge of a review band so that the interval
   `[t_benign, t_alert)` contains at most a specified share of traffic
   (analyst capacity), again walking distinct values rather than taking a naive
   quantile.
5. Emit `Benign` below the band, `Malicious` at or above the alert threshold, and
   `Review` in between.

### Component C — Evaluation protocol

Train on Monday–Wednesday, calibrate on Thursday morning, test on Thursday
afternoon and Friday; report per-attack-type recall and a prevalence-matched
operating point alongside the aggregate.

---

## 3. Experimentally supported effects

Measured on CIC-IDS2017, 500,000-flow stratified training sample, Random Forest
(100 trees), `random_state=42`. Full details in `EXPERIMENTS.md`.

| Effect | Evidence | Strength |
|---|---|---|
| The gate detects perturbed batches | AUC 1.000 for scaling, additive noise, and mean shift; 0% false alarms on 40 in-distribution batches | Strong, but only for shifts that change marginals |
| The gate does **not** detect marginal-preserving shifts | Independent per-column permutation: AUC 0.487, detection 0% | Strong negative result; a real limitation |
| The gate fires only where benign traffic genuinely changed | Friday-DDoS benign subset scores 6.39 against a threshold of 4.24; other days score 1.2–2.1 | Strong |
| A budget-derived threshold recovers recall under shift | Temporal protocol: recall 0.303 (0.5 threshold) → 0.524 (budget threshold) | Moderate |
| The false-positive guarantee breaks under day shift | Nominal α = 0.01; realised 0.0464 under the temporal split, versus 0.0067 in-distribution | Strong; consistent with conformal theory |
| Isotonic calibration alone cannot repair shift | Temporal protocol, prevalence-matched: Brier 0.0928 → 0.0881 against a constant-predictor baseline of 0.1179. Calibration helps, but the score remains ~70× worse than in-distribution (0.0013) | Strong negative result, correctly scoped |
| The review band did not change recall in these runs | B2 and B3 identical in all three protocols | Negative; hypothesis not supported |

---

## 4. Possible variations

Recorded for completeness, not as claims:

- Other two-sample statistics (Anderson–Darling, Cramér–von Mises, energy distance)
  or multivariate tests (MMD) in place of per-feature KS.
- Reference profiles per capture day, scoring a batch against the nearest day
  rather than a pooled reference.
- Density-ratio or classifier-based two-sample testing for higher power.
- Sequential/online calibration (adaptive conformal inference) instead of a static
  threshold, for streaming deployment.
- Weighted conformal prediction to correct for known covariate shift.
- Multi-class attack typing with class-conditional (Mondrian) coverage.
- Alternative calibrators (temperature scaling, beta calibration, Venn–Abers).

---

## 5. Closest known prior art

Screened, not exhaustively searched:

| Reference | Overlap |
|---|---|
| Angelopoulos et al., *Conformal Risk Control* (arXiv:2208.02814) | The thresholding method used in Component B |
| CALIBURN (arXiv:2605.24696) | Isotonic calibration + CRC alert budget on CICIDS2017 |
| FIRCE (arXiv:2605.01962) | Conformal evaluation for IDS drift detection |
| CRISP (MLISE 2026) | Conformal selective prediction for intrusion detection |
| NeutroSENSE (AIIoT 2025) | Abstention thresholds and a review queue for IDS |
| Uncertainty quantification for ML-NIDS (2024, DOI 10.1007/s40860-024-00238-8) | Frames the uncertainty/OoD problem for IDS |
| Classification of intrusion detection alerts using abstaining classifiers (2007, DOI 10.3233/IDA-2007-11306) | Abstain-and-defer-to-analyst for IDS alerts, ~19 years old |
| US8800036B2 | Adaptive threshold tuning for anomaly-based IDS |
| US11057399B2 | Alert classifier with a presentation flag suppressing or presenting alerts |

**Assessment:** Component B is directly anticipated. Component A's per-feature KS
batch test is a standard statistical tool; its combination with day-aware null
calibration and benign-conditional scoring may not be separately published, but
this was not established and the mechanism is incremental.

---

## 6. What a reviewer should be told

- The contribution is **integration and measurement**, not a new algorithm.
- The most valuable output of the project is the **measurement**: a 69.5-point
  recall drop between random and temporal splits of the same dataset and model,
  and the collapse of the conformal false-positive guarantee under day shift.
- Those findings are a **replication and evaluation** contribution. They are
  publishable as a systems/evaluation study. They are not patentable subject
  matter in any obvious way.
- The negative results (marginal-preserving shifts undetectable; calibration
  cannot repair non-exchangeability) are reported because they bound the value of
  the mechanism.

---

## 7. Declaration

The author of this document is not a patent attorney and has not conducted a
prior-art search sufficient for any filing decision. This document must not be
represented as a filed application, a granted patent, a freedom-to-operate
opinion, or a statement that the described subject matter is patentable. No public
disclosure of any potentially patentable subject matter should occur before
obtaining professional advice.
