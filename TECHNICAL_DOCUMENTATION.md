# TECHNICAL_DOCUMENTATION.md

**System:** NetGuard AI — flow-based malware detection with a reliability layer
**Version:** 1.1
**Date:** 2026-10-23

---

## 1. What the system does

Reads a CSV of network-flow records (CICFlowMeter / CIC-IDS2017 format), classifies
each flow, and — before presenting results — reports whether the batch as a whole
resembles the traffic the model was trained on.

Three things changed relative to version 1.0:

1. Each flow now receives a **three-way decision** (`Benign` / `Malicious` / `Review`)
   instead of being forced into a binary label.
2. The alert threshold is derived from an operator-specified **false-alarm budget**
   rather than a fixed 0.5.
3. Every uploaded batch is audited for **distribution shift** before its predictions
   are presented as findings.

---

## 2. Architecture

```
                        ┌──────────────────────────────────────────┐
   CIC-IDS2017 CSVs ───▶ │ ml/train.py                              │
                        │  load → clean → dedupe → split → train   │
                        │  → select → fit reliability → fit gate   │
                        └───────────────┬──────────────────────────┘
                                        │
                    ┌───────────────────▼─────────────────────────┐
                    │ models/netguard_model.joblib                │
                    │  pipeline        sklearn Pipeline           │
                    │  feature_names   69 columns, ordered        │
                    │  reliability     calibrator + thresholds    │
                    │  shift_profile   reference + gate limits    │
                    │  protocol        which split produced it    │
                    └───────────────────┬─────────────────────────┘
                                        │ joblib.load (once, cached by mtime)
   CSV upload ──▶ backend/app/main.py ──┴─▶ backend/app/model_store.py
                        │                          │
                        │  1. validate columns     │ predict_proba
                        │  2. calibrate            │
                        │  3. decide (3-way)       │
                        │  4. audit batch shift    │
                        ▼                          ▼
                 JSON response / CSV download     React dashboard
                 (+ shift warning)                (ShiftWarning, SummaryCards, ResultsTable)
```

**Invariants preserved from version 1.0**

- Training is offline; the API never retrains.
- `ml/preprocess.py` is the single source of truth for column handling and is
  imported by both training and inference.
- The imputer lives inside the persisted `Pipeline`, so imputation statistics are
  training-only.
- `/api/health`, `/api/metrics`, `/api/model/features`, `/api/predict` and
  `/api/predict/download` keep their existing response fields. New fields are
  additive, and a bundle without a `reliability` key still works.

---

## 3. `ml/reliability.py` — algorithms

### 3.1 Probability calibration

`fit_isotonic(scores, labels)` fits `sklearn.isotonic.IsotonicRegression`
(`y_min=0`, `y_max=1`, `out_of_bounds="clip"`) mapping the Random Forest vote
fraction to an empirical probability. Random Forest vote fractions are not
probabilities; they cluster near 0 and 1 and are not monotone in the true
conditional risk. Isotonic regression is a monotone step function, so it cannot
invert the ranking of the underlying scores.

### 3.2 Risk-controlled alert threshold

`crc_threshold(probabilities, labels, alpha)` returns the most permissive
threshold whose empirical false-positive rate on calibration negatives satisfies
the Conformal Risk Control condition

```
(n0 / (n0 + 1)) * FPR_hat + 1 / (n0 + 1)  <=  alpha
```

equivalently `FPR_hat <= alpha - (1 - alpha) / n0`, where `n0` is the number of
calibration negatives.

**Ties matter.** Isotonic output is a step function, so many flows share the same
probability. Selecting "the k-th largest negative score" can therefore admit far
more than `k` false positives. The implementation instead walks the distinct
negative values in ascending order and takes the smallest threshold whose
*realised* FPR still satisfies the budget.

If no threshold satisfies the budget (possible when `alpha` is smaller than
roughly `2 / (n0 + 1)`), the function returns `feasible: False` and a threshold
above 1.0 — i.e. it alerts on nothing and says so, rather than silently violating
the budget. `minimum_supportable_alpha` reports the smallest budget this
calibration set can certify.

### 3.3 Review band

`choose_review_band(probabilities, alert_threshold, capacity)` sets the lower edge
`t_benign` of the review interval `[t_benign, t_alert)`, subject to the constraint
that the interval holds at most `capacity` of the traffic.

A naive quantile is wrong here for the same tie reason: with a large spike of
probabilities at 0, `quantile(0.95)` can still sit at 0 and admit the whole batch
into review. The implementation walks the distinct values below `t_alert` and
selects the widest band whose actual mass fits the capacity.

### 3.4 Three-way decision

```
p <  t_benign          -> Benign      (0)
p >= t_alert           -> Malicious   (1)
otherwise              -> Review      (2)
```

`Review` is not a classification claim. In evaluation it is counted as "no alert",
so abstaining costs recall rather than hiding it.

### 3.5 Calibration / threshold split

`fit_reliability` divides the calibration data into two disjoint halves:

- **Half A** fits the isotonic map.
- **Half B** — never seen by the map — supplies the false-positive budget and the
  review-capacity quantile.

Fitting the map and deriving the threshold from the same examples would let the
threshold overfit the calibration set and invalidate the finite-sample bound.

### 3.6 Batch shift gate

`batch_shift_score(features, profile)`:

1. Optionally downsamples the batch to 2,000 rows (deterministic seed). Without
   this, a 100,000-row upload makes the test sensitive to differences far too
   small to matter.
2. For each of the 69 features, computes a two-sample Kolmogorov–Smirnov statistic
   against the stored reference sample.
3. Normalises it: `Z = KS * sqrt(n_eff)` with `n_eff = n*m/(n+m)`. Under the null,
   `KS ~ sqrt(-ln(a/2) / (2 n_eff))`, so `Z` is approximately independent of batch
   size and the same threshold applies to any upload size.
4. Aggregates with the **90th percentile** across features, so a handful of badly
   shifted features is not diluted by 60 stable ones.

`fit_shift_profile(...)` stores the reference and calibrates the gate:

- Reference sample: 2,000 benign training rows.
- Bootstrap pool: 20,000 further benign rows, **disjoint** from the reference.
- Null distribution: 200 bootstrap batches. When capture-day labels are supplied,
  each bootstrap batch is drawn **within a single day** rather than by mixing days.
  This is essential: without it, an ordinary one-day upload looks anomalous simply
  because it is not a blend of five days, and the gate fires on its own training
  data.
- `threshold_in` = 99th percentile of the null, `threshold_severe` = 99.9th.

**What the gate compares.** The gate models *benign* traffic. At inference it
scores the flows the model did **not** flag (`basis: "non_alerted"`), falling back
to all flows when fewer than 100 remain unflagged. Flagged flows are expected to
look different — including them would make every batch containing attacks appear
shifted. Consequently the gate answers *"does the normal traffic in this batch
resemble the normal traffic the model learned?"* — not *"does the attack mix
match?"*, which legitimately varies between capture days.

**Known limitation.** A marginal (per-feature) test cannot detect a shift that
preserves every marginal distribution, such as independent permutation of each
column. This is measured and reported (`by_kind.permuted`) rather than hidden.

---

## 4. Data flow

### 4.1 Training

```
8 CSVs
  └─ clean_column_names        strip header spaces, drop "Fwd Header Length.1"
  └─ tag capture day           from the filename (_day)
  └─ numeric coercion          "Infinity" → NaN, float32
  └─ deduplicate               hash rows, drop exact duplicates  (before any split)
  └─ stratified sample         default 500,000 flows
  └─ split by protocol         see below
  └─ drop constant features    computed on the training split only
  └─ fit pipelines             SimpleImputer (+ StandardScaler for LR) + estimator
  └─ select model              validation F1, primary model kept unless beaten by > 0.001
  └─ fit reliability           isotonic + CRC + review band
  └─ fit shift profile         reference sample + bootstrap null
  └─ write bundle, metrics.json, model_report.md, demo samples
```

### 4.2 Splitting protocols

| Protocol | Train | Validation | Calibration | Test |
|---|---|---|---|---|
| `original` | 62% random, all days | 8% random | 10% random | 20% random |
| `random_monwed` | 62% random of Mon–Wed | 8% | 10% | 20% |
| `temporal` | 62% random of Mon–Wed | 8% | **Thursday morning** | **Thursday afternoon + Friday** |

`random_monwed` and `temporal` share the same training pool, so the difference
between them isolates the effect of unseen capture days. The temporal test set is
capped at 20,000 rows per attack label so that rare classes survive intact while
DDoS/PortScan do not dominate.

### 4.3 Inference

```
upload → extension / size / emptiness checks
       → parse CSV → clean column names
       → prepare_features: required columns present, numeric values, order fixed
       → Pipeline.predict_proba[:, 1]            raw vote fraction
       → apply_calibration                        calibrated probability
       → decide(t_benign, t_alert)                three-way decision
       → batch_shift_score on non-alerted rows    shift verdict
       → JSON response (+ warning) or annotated CSV
```

Validation failures return 400 (bad file), 413 (too large), 422 (bad columns or
values, with the offending column names) or 503 (no model).

---

## 5. Model bundle format

```python
{
  "pipeline":       sklearn.pipeline.Pipeline,   # imputer + estimator
  "feature_names":  list[str],                   # 69 columns, ordered
  "model_name":     str,                         # "Random Forest"
  "class_names":    ["Benign", "Malicious"],
  "trained_at":     ISO-8601 str,
  "protocol":       "original" | "random_monwed" | "temporal",
  "reliability": {
      "kind": "isotonic+crc",
      "calibrator": IsotonicRegression,
      "alpha": float, "t_alert": float, "t_benign": float,
      "review_capacity": float,
      "calibration": { ...diagnostics including empirical_fpr and feasible... },
  },
  "shift_profile": {
      "feature_names": list[str],
      "reference": np.ndarray,      # (2000, 69) float32
      "null_scores": np.ndarray,    # bootstrap null, for diagnostics
      "threshold_in": float, "threshold_severe": float,
      "null_calibration": "per_day" | "pooled",
      "null_days": list[str],
      "reference_size": int, "null_batch_size": int,
  },
}
```

`reliability` and `shift_profile` are optional. When absent,
`ModelStore.predict` falls back to raw probabilities and a 0.5 threshold, and no
gate is applied — so bundles written by version 1.0 still load.

---

## 6. API reference

### `GET /api/health`

Adds `protocol`, `reliability_active`, `shift_gate_active`.

### `POST /api/predict`

New response fields:

| Field | Meaning |
|---|---|
| `summary.review`, `summary.review_ratio`, `summary.benign_ratio` | three-way counts |
| `reliability.active`, `.alpha`, `.t_alert`, `.t_benign`, `.counts` | operating point |
| `shift.verdict` | `in_distribution` / `moderately_shifted` / `severely_shifted` |
| `shift.score`, `.threshold_in`, `.threshold_severe` | gate diagnostics |
| `shift.top_shifted_features` | most-affected features |
| `shift.basis`, `.rows_compared` | which rows were compared |
| `warning` | human-readable warning, `null` when the batch looks normal |
| `rows[].decision` | `Benign` / `Malicious` / `Review` |
| `rows[].raw_vote_fraction` | uncalibrated ensemble vote fraction |
| `rows[].malicious_probability` | **now the calibrated probability** (was the vote fraction in 1.0) |
| `evaluation.alert_precision`, `.alert_recall`, `.review`, `.review_rate` | operating-point metrics |

### `POST /api/predict/download`

Adds `Decision`, `Calibrated_Probability` and `Raw_Vote_Fraction` columns, and
neutralises spreadsheet formula injection by prefixing text cells that begin with
`=`, `+`, `-`, `@`, tab or carriage return. Numeric columns are untouched, so
negative numbers keep their meaning.

---

## 7. Configuration

`ml/config.py`:

| Constant | Default | Meaning |
|---|---|---|
| `ALPHA` | 0.01 | tolerable false-positive rate on benign flows |
| `REVIEW_CAPACITY` | 0.05 | share of traffic routed to human review |
| `RANDOM_STATE` | 42 | every random step |
| `TEST_SIZE` / `VALIDATION_SIZE` / `CALIBRATION_SIZE` | 0.20 / 0.10 / 0.10 | split fractions |

Overridable per run: `--alpha`, `--review-capacity`, `--sample-size`, `--protocol`.

---

## 8. Reproducing

```bash
# deployed artefact (original protocol, with the reliability layer)
python -m ml.train --sample-size 500000 --protocol original

# the research comparison (writes reports/experiments.json)
python -m ml.experiments

# tests
pytest
```

Requires the 8 CIC-IDS2017 CSVs in `dataset/raw/` (see README §3). The committed
artefacts let the application run without them.

---

## 9. Testing

38 tests, all passing.

| File | Covers |
|---|---|
| `backend/tests/test_reliability.py` | monotonicity of the calibrator, FPR budget respected on unseen data, infeasible-budget reporting, tie handling, review-band capacity, decision boundaries, gate detection vs false alarms, verdict ordering, metric arithmetic |
| `backend/tests/test_api.py` | health, metrics, prediction counts, missing labels, spaced headers, `Infinity`, download columns, missing columns, non-numeric values, wrong extension, empty file, 503 without a model, feature order, reliability fields, shift warning, formula neutralisation |
| `backend/tests/test_training.py` | model selection rule |

The API tests use a small synthetic model in a temporary directory. `reliable_client`
additionally exercises the full reliability path. No test touches the real
artefacts, so a broken real model cannot fail the suite — a gap noted in the audit
and left as future work.

---

## 10. What is deliberately not here

- No retraining loop, no streaming ingestion, no drift-triggered adaptation.
- No multi-class attack typing.
- No adversarial robustness beyond the synthetic shift families measured.
- No authentication, rate limiting, or audit logging.
- The gate detects marginal distribution change only.

---

## 11. Known limitations

**The alert threshold is meaningless under severe shift.** The threshold is
calibrated on in-distribution traffic and in this dataset it lands very low
(`t_alert ≈ 0.018`) because the model is highly separable at the 1% false-alarm
budget. On a severely shifted batch, where the model's probabilities collapse into
a narrow band around 0.44, every flow sits above that threshold and is reported as
`Malicious`. The demo shifted file therefore returns 2,000 malicious verdicts
instead of the 2,000 `Benign` verdicts version 1.0 returned.

Neither output is trustworthy. The difference is that version 1.1 says so: the
gate returns `severely_shifted` with a warning, and the interface presents that
warning above the results. A more principled treatment — for example suppressing
the per-flow verdict entirely, or widening the review band when the gate fires —
is left as future work.

**The review band cannot catch over-confident errors.** The band is defined as the
interval immediately below `t_alert`. A flow whose probability exceeds `t_alert` is
called `Malicious` regardless of how modest that probability is, so the band offers
no protection above the threshold.

**The gate is a marginal test.** It cannot detect shifts that preserve every
feature's marginal distribution. Measured detection rate on independently permuted
columns: 0%.

**The temporal evaluation is single-dataset.** All conclusions about unseen-day
performance come from one dataset with five capture days. Whether the same gap
appears on other networks is untested.

**Prevalence affects the operating point.** The temporal test set is deliberately
capped per attack class, which raises its malicious rate far above the training
rate. Aggregate false-positive and Brier figures are therefore reported alongside a
prevalence-matched view (`prevalence_matched` in `reports/experiments.json`); the
per-attack table is the most robust view.
