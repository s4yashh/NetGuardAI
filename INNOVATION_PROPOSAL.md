# INNOVATION_PROPOSAL.md

**Working name:** NetGuard Reliability Gate
**Status:** proposal — not implemented, no results yet
**Date:** 2026-10-22

> **Positioning statement.** This is a *systems and measurement* contribution. It does not claim a new algorithm and it is not asserted to be patentable. `NOVELTY_RESEARCH.md` establishes that every algorithmic component used here is already published, several of them applied to CIC-IDS2017 in 2026. What is proposed is a disciplined integration plus an evaluation protocol that makes the system's limits visible and testable.

---

## 1. Problem

The audited system answers the question *"is this flow malicious?"* but never answers the question an operator must answer first: ***"should I believe this batch of answers at all?"***

Three measured facts from the audit define the problem:

1. **The system cannot tell when it is out of its depth.** Feeding it the same 2,000 flows with all numeric features transformed by `x ↦ 50x + 10⁶` produced 0 detections out of 323 real attacks (recall 99.4% → 0%). Every probability fell in the ambiguous band (0.1–0.9) — the model was signalling ignorance — yet the API returned HTTP 200 and labelled all 2,000 flows `Benign`. A dashboard user would read "no threats found".

2. **The reported score is not the score an operator gets.** The 99.83% comes from a random split that interleaves capture sessions between train and test (`ml/train.py:158-166`).

3. **The aggregate score hides where the model is blind.** 91.8% of malicious rows in the training sample are DoS Hulk, DDoS, and PortScan. The three rarest attack types contribute 14 rows in total, so no per-type claim about them is supportable — but the dashboard reports one recall number implying otherwise.

The gap is therefore not detection accuracy. It is **epistemic honesty**: the system does not distinguish "confidently benign" from "I have never seen traffic like this", and it does not distinguish "malicious" from "not sure".

---

## 2. Proposed mechanism

Three components, layered onto the existing architecture without replacing it.

### Component 1 — Batch Shift Audit (pre-inference gate)

**Mechanism.** Store a compact reference profile of the training distribution in the model bundle: per-feature robust location and scale (median, IQR) plus a fixed-size reference sample of each feature.

For an uploaded batch of size *n*, compute a per-feature two-sample Kolmogorov–Smirnov statistic against the reference sample. Aggregate to a scalar batch-shift score (e.g. the 90th percentile of per-feature statistics, so one badly shifted feature is not diluted by 68 stable ones).

Calibrate the decision threshold empirically: draw many bootstrap batches **from held-out in-distribution data**, compute the same score, and take a high quantile (e.g. 99th) as the null threshold. This makes the gate's false-alarm rate a measured property rather than a hand-picked number.

**Output.** A verdict attached to the prediction response:
`in_distribution` · `moderately_shifted` · `severely_shifted`, with the top contributing features.

**Effect on the UI.** When the batch is severely shifted, the dashboard does not present a benign/malicious breakdown as a finding. It presents the warning first, and the per-flow predictions as *unreliable*.

**Why batch-level, not per-flow.** Per-flow OOD scores already exist (energy, Mahalanobis, conformal p-values) and are published. The distinguishing operational question here is about the *unit of work* — a file upload — and a batch statistic is far more stable than a per-row score at realistic batch sizes. A single row cannot be reliably called out-of-distribution; 2,000 rows can.

### Component 2 — Calibrated, budget-driven, three-way decision

**Mechanism.**

1. **Calibration.** Fit isotonic regression on a held-out calibration split mapping the RF vote fraction to an empirical probability. Report a reliability diagram and Brier score before/after. This fixes the fact that `Malicious_Probability` is currently a vote fraction, not a probability.

2. **Alert threshold from a budget.** Given a user-specified tolerable false-positive rate α (e.g. "at most 1 false alarm per 1,000 benign flows"), derive the threshold by Conformal Risk Control on the calibration set's negatives. This replaces the arbitrary 0.5. The method is due to Angelopoulos et al. (arXiv:2208.02814) and its use for IDS alert budgets is published in CALIBURN (arXiv:2605.24696) — **it is credited, not claimed.**

3. **Review band.** Two thresholds, not one:
   - `p ≥ t_alert` → **Malicious**
   - `p < t_benign` → **Benign**
   - otherwise → **Review**

   `t_benign` is set so that the review band absorbs a target fraction of flows (a capacity constraint: analysts can review *k* flows per shift). This turns an unlimited review queue into a bounded one.

**Why three outcomes.** A binary classifier forces every uncertain flow into "benign", which is the failure mode measured in the audit. A review queue is the operationally correct sink for "I don't know", and it makes the abstention rate an explicit, reportable cost rather than a hidden error.

### Component 3 — Honest evaluation protocol

**Mechanism.** A second training/evaluation mode with a **temporal split**: train on Monday–Wednesday, calibrate on Thursday morning, test on Thursday afternoon and Friday. Plus per-attack-type metrics and a selective-risk/coverage curve.

This is the component that makes the other two meaningful: without genuine distribution shift in the test set, a shift gate has nothing real to detect.

---

## 3. Why this is stronger than the obvious alternatives

| Alternative | Why it is weaker |
|---|---|
| Add another dashboard panel | Cosmetic; changes no measured property |
| Add a fourth classifier / bigger model | The problem is not accuracy. A better classifier on the same random split produces the same undetectable failure |
| Switch to a deep model | Same issue, plus loses interpretability and laptop trainability; no evidence it helps under shift |
| Multi-class attack typing only | Improves reporting but still emits a confident label on alien input |
| Pure conformal-prediction layer only | Published for IDS (CRISP, FIRCE, CALIBURN); would be a reproduction, and would still say "benign" on the shifted batch unless the shift is detected |
| Federated / privacy-preserving | Not feasible with one party; would be simulation without evidence |

The proposal is stronger because it targets the **measured** defect (a false "all clear" on alien traffic), it is **falsifiable** (the gate either fires on the perturbed batch or it does not), and it is **ablatable** (each of the three components can be removed and the effect measured).

---

## 4. Expected benefit — stated as hypotheses, not results

These are predictions to be tested. None is a measured result yet.

| ID | Hypothesis | Measurement |
|---|---|---|
| H1 | The batch gate separates the perturbed batches from in-distribution batches with high AUC | ROC-AUC of batch-shift score, in-distribution vs synthetic-shift batches |
| H2 | On a genuinely unseen capture day, the gate raises a warning | Gate verdict on Thursday/Friday batches under a Mon–Wed-trained model |
| H3 | Calibration reduces Brier score and makes the probability meaningful | Brier score, reliability diagram, ECE before/after |
| H4 | Budget-driven thresholding hits the requested FPR more accurately than a fixed 0.5 | Realised FPR vs nominal α across α ∈ {0.001, 0.005, 0.01, 0.05} |
| H5 | A review band recovers recall at a bounded abstention cost | Recall at FPR = 1% with vs without the band; abstention rate |
| H6 | Temporal splitting lowers the headline score substantially versus random splitting | F1 under both protocols, same model, same data |
| H7 | Rare attack types are near-invisible in aggregate metrics | Per-attack-type recall table |

**If a hypothesis fails, it will be reported as failed.** H6 in particular may show a modest drop rather than a dramatic one; the direction of the result is unknown and will not be massaged.

---

## 5. Closest prior art and how this differs in scope

| Prior art | What it already covers | What this proposal does differently |
|---|---|---|
| CALIBURN (2026) | Isotonic calibration + CRC alert budget on CICIDS2017, streaming | Batch/upload gate; three-way review band with a capacity constraint |
| FIRCE (2026) | Conformal drift detection + retraining | Pre-inference batch verdict surfaced to a human, no retraining loop |
| CRISP (2026) | Conformal selective prediction for IDS | Adds the batch-level gate; evaluation under day split |
| NeutroSENSE (2025) | Indeterminacy abstention + review queue | No shift gate; different uncertainty source |
| 2007 abstaining alert classifiers | Abstain + defer to analyst | Predates; same operational idea at alert level |
| US11057399B2 | Presentation flag suppress/present | Batch-level distributional verdict, not per-alert dissimilarity |

**Honest reading:** each mechanism exists. The integration is a reasonable engineering contribution and a good course project. It is **not** a defensible patent claim.

---

## 6. Experimental plan

### 6.1 Data

CIC-IDS2017 `MachineLearningCSV` — 8 files, 2,830,743 rows, one per capture session. Downloaded for this work (public HuggingFace mirror `c01dsnap/CIC-IDS2017`, identified by SHA-free HTTP fetch; the official UNB source is the authoritative distribution).

Cleaning is unchanged from `ml/preprocess.py` (strip headers, drop duplicate column, `Infinity` → NaN, drop exact duplicate rows).

### 6.2 Two evaluation protocols, same model family

| Protocol | Train | Calibrate | Test | Purpose |
|---|---|---|---|---|
| **P1 — random** (existing) | 72% random | 8% random | 20% random | Reproduces the current result |
| **P2 — temporal** (new) | Mon–Wed | Thu morning | Thu afternoon + Fri | Measures generalisation to unseen days |

Same cleaning, same 69 features, same `random_state` where randomness is used. P1 and P2 differ **only** in split construction, so the difference is attributable to the protocol.

### 6.3 Baselines and variants

| ID | System |
|---|---|
| B0 | Current system: RF, argmax at 0.5, no gate |
| B1 | RF + isotonic calibration only |
| B2 | B1 + CRC alert threshold (no review band) |
| B3 | B2 + review band |
| B4 | B3 + batch shift gate (proposed full system) |

Plus two external reference points where feasible:
- Logistic Regression (already trained, as a weak baseline)
- Decision Tree (already trained)

### 6.4 Metrics

- Precision, recall, F1, confusion matrix — aggregate.
- **Recall at fixed FPR** (1%, 0.1%) — the operationally meaningful comparison.
- **Realised FPR vs nominal α** — calibration of the guarantee.
- Brier score, ECE, reliability diagram.
- **Selective risk vs coverage curve.**
- **Abstention rate** at fixed review capacity.
- **Per-attack-type recall** and per-type sample counts.
- Batch-shift ROC-AUC; gate verdict per capture day.
- Inference latency per 1,000 flows; model size; peak memory (the current system's practical envelope).

### 6.5 Ablations

Remove one component at a time from B4: `−gate`, `−calibration`, `−CRC`, `−review band`. Report the delta on recall@FPR=1% and on the shifted-batch false-clear rate.

### 6.6 Shift scenarios for the gate

1. **Real temporal shift** — Thursday/Friday data vs Mon–Wed training. The most credible test.
2. **Controlled synthetic shifts** — per-feature scaling, additive noise, feature permutation, and a "wrong tool" shift (values plausible but from a different feature scale). Used only to characterise sensitivity, clearly labelled as synthetic.
3. **In-distribution control** — held-out Monday batches. Must **not** trigger the gate; this measures the false-alarm rate.

### 6.7 Leakage controls

- Reference profile and calibration set are disjoint from the test set.
- Gate threshold is calibrated on in-distribution held-out batches only.
- No test data influences threshold choice.
- Duplicate removal before any splitting, unchanged.

---

## 7. Deliverables if approved

| File | Content |
|---|---|
| `ml/reliability.py` | Calibration, CRC threshold, review band, shift score (new) |
| `ml/train.py` | Extended to fit and persist calibration + reference profile; `--protocol random\|temporal` |
| `backend/app/model_store.py` | Returns calibrated probability, decision, review flag, shift verdict |
| `backend/app/main.py` | Additive response fields; gate warning; download columns |
| `frontend/` | Batch warning banner; three-way results; calibration panel |
| `tests/` | Unit tests for calibration, CRC, shift gate; API tests for new fields |
| `EXPERIMENTS.md` | Protocol, results, ablations, failures |
| `TECHNICAL_DOCUMENTATION.md` | Architecture, algorithms, data flow |
| `PATENT_DISCLOSURE_DRAFT.md` | Technical disclosure stating clearly that no novelty was established |

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Temporal split shows the model is much worse than 99.8% | That is a **finding**, not a failure. Report it — it is the most valuable result in the project |
| Shift gate fires on Friday because of attack mix, not benign drift | Report honestly; frame as "traffic changed", not "attack detected"; evaluate on benign-only batches to separate the two |
| Rare attack types too sparse for per-type claims | Report counts alongside every per-type metric; state "insufficient evidence" where n is small |
| Calibration set too small for α = 0.001 | Report the minimum supportable α given calibration size; use `n₀+1` slack explicitly |
| Retraining exceeds laptop memory | Cap training sample; document the cap and its effect |
| Dataset download unavailable | Fall back to the committed 2,000-flow sample for demonstration; state that only H3–H5 can be partially tested |

---

## 9. Explicit non-claims

This proposal does **not** claim:

- that any component is novel;
- that the system is patentable;
- that measured results will show improvement;
- that the approach generalises beyond CIC-IDS2017;
- that the review band is a substitute for an analyst.

It claims only that the three components are implementable in this codebase, that each addresses a measured weakness, and that each can be evaluated with a clear pass/fail criterion.
