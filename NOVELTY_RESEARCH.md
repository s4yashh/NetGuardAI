# NOVELTY_RESEARCH.md

**Purpose:** assess whether the directions proposed for this project contain a genuine technical contribution, and identify the closest prior art.
**Date:** 2026-10-22
**Status of this review:** literature and patent **screening**, not a professional prior-art search. Sources were identified through web search and read at abstract/landing-page level unless stated otherwise. Full texts were not obtained for most items. No conclusion here is a legal opinion, and none establishes freedom to operate.

> **Bottom line, stated first:** every direction listed in the brief is already an active, densely populated research area — several with 2026 publications that target CIC-IDS2017 specifically. **No patentable technical contribution was identified.** The honest and useful contribution available to this project is an engineering and evaluation one, not an algorithmic invention. Section 6 sets out what that is.

---

## 1. Method

1. Screened the seven directions named in the brief against recent literature.
2. Followed citations from the most recent and most specific papers found.
3. Ran patent-oriented searches for intrusion-detection thresholding, alert triage, abstention, and review-queue mechanisms.
4. Recorded only sources actually retrieved. Where a claim rests on an abstract rather than a full text, that is noted.
5. Assessed each direction for: (a) whether the mechanism is already published, (b) whether it has been applied to flow-based NIDS, (c) whether it has been applied to CIC-IDS2017.

**Known limitations of this review:** no access to IEEE/ACM full texts behind paywalls; no systematic database query (Scopus/Web of Science); no professional patent search (no CLAIMS/PatBase/Orbit); no non-English literature. Any of these could surface closer art. This is precisely why a novelty claim cannot be made from it.

---

## 2. State of the art, direction by direction

### 2.1 Detecting previously unseen malicious traffic (open-set / zero-day)

Crowded. A 2025 systematic literature review of adaptive online learning for unknown-attack detection covers 2020–2024 and finds active learning, clustering, and autoencoders dominant, with open-set methods "very promising" and explicitly lists unknown-attack discovery as an open problem. A 2025 empirical study of OpenMAX/EVM on IoT intrusion data reports unknown-attack performance roughly **30 percentage points below** known-attack performance — i.e. the gap is measured and known, not novel to discover. A 2025 survey of open-world adaptive IDS covers unknown attacks, distribution shift, and data scarcity together.

**Verdict:** no contribution available here without a new method and a much larger experimental programme.

### 2.2 Reducing false positives while keeping recall

Occupied at both ends. On the academic side, abstaining classifiers applied to IDS alert classification date to **2007** ("Classification of intrusion detection alerts using abstaining classifiers", *Intelligent Data Analysis*), which already frames the exact trade-off: abstain on uncertain alerts, defer to a human analyst, reduce misclassification cost. On the patent side, **US11057399B2** claims a classifier plus a "presentation flag" that suppresses or presents an alert to an operator based on classification result and dissimilarity — functionally an alert triage gate. **US8800036B2** claims adaptive threshold tuning for anomaly-based IDS.

**Verdict:** the concept is ~19 years old in the literature and patented. A student project cannot claim it.

### 2.3 Distribution-shift detection

Extremely crowded, including for this exact dataset. FIRCE (arXiv:2605.01962) augments supervised IDS classifiers with conformal-evaluation uncertainty and drift detection and triggers retraining; it benchmarks on CICIDS2018 and UNSW-NB15 and uses an IoT testbed. CALIBURN (arXiv:2605.24696) builds a streaming alerting pipeline with isotonic calibration and a Conformal Risk Control wrapper that converts an operator alert budget into a threshold, and evaluates on **CICIDS2017** among others. A 2026 paper (arXiv:2609.19241) specifically shows that conformal thresholds calibrated on clean traffic fail under adversarial perturbation and proposes traffic-aware calibration.

**Verdict:** this is the most occupied direction of the seven. CALIBURN in particular already does "alert budget → threshold with FPR validity" on CICIDS2017.

### 2.4 Explainable network traffic classification

Well populated (feature importance, SHAP, attention, causal-graph approaches). A 2026 example, CausalGraph-IDS (ICCE 2026), combines causal attack-chain graphs with an LLM in an assistive role and CHAIN-CRC for conformal false-positive budgets. Feature-importance reporting — what this project already does — is table stakes, not a contribution.

**Verdict:** nothing available at this scale.

### 2.5 Efficient inference on limited hardware

Occupied. Lightweight/edge IDS is a large literature. The current model (100 trees, 69 features, 3.4 MB) is already small; "make it smaller" is engineering, not novelty.

### 2.6 Privacy-preserving collaborative detection

Federated IDS is a substantial subfield with many 2023–2026 papers. It is also **not feasible** in this project: it requires multiple parties, a coordination protocol, and a threat model for the aggregator. Implementing a credible federated evaluation on one laptop would be a simulation, not evidence.

**Verdict:** out of scope, and occupied.

### 2.7 Reliable confidence estimation and selective classification

The most directly relevant, and the most occupied relative to its apparent novelty.

| Work | What it does | Relation to this project |
|---|---|---|
| **CRISP** (MLISE 2026, DOI 10.1109/MLISE70044.2026.11607513) | Conformal + selective prediction for intrusion detection | Directly the same idea |
| **FIRCE** (arXiv:2605.01962) | Conformal evaluation for drift detection + retraining trigger | Same mechanism, streaming |
| **CALIBURN** (arXiv:2605.24696) | Isotonic calibration + CRC alert budget on CICIDS2017 | Same mechanism, same dataset |
| **Uncertainty quantification for ML-NIDS** (DOI 10.1007/s40860-024-00238-8, 2024) | Compares UQ and open-set methods, BNN with OoD recalibration | Establishes the framing |
| **WisdomNet / uncertainty measures** (LCN 2024, DOI 10.1109/LCN60385.2024.10639737) | Reject/abstain on uncertain NIDS predictions, defer to administrator | Same operational concept |
| **NeutroSENSE** (AIIoT 2025, DOI 10.1109/AIIoT65859.2025.11105216) | Ensemble + indeterminacy scoring, adaptive class-specific abstention thresholds, review queue | Same concept, including the review queue |
| **Selective open-set classifiers for unknown intrusions** (ICAIET 2025, DOI 10.1109/ICAIET65052.2025.11211154) | OpenMAX/EVM evaluation | Establishes measured gap |
| **Class-conditional conformal for extreme imbalance** (Make 2026, DOI 10.3390/make8070190) | Shows marginal CP undercovers the minority class; Mondrian restores coverage | Directly the rare-class argument |
| **Class-Conditional Conformal Prediction with Many Classes** (NeurIPS 2023) | Clustered CP for many-class, low-data regimes | The methodological fix for rare classes |
| **Dual-threshold conformal abstention** (arXiv:2502.07255) | Conformal threshold + ROC-optimised abstention threshold | The two-threshold design |
| **Conformal Risk Control** (Angelopoulos et al., arXiv:2208.02814) | Converts a bounded loss target into a threshold with a guarantee | The underlying method |

**Verdict:** the confidence/abstention direction is not merely occupied — it has a 2026 paper on this dataset that does the specific thing.

---

## 3. Comparison table

| # | Existing approach | Demonstrated limitation | Proposed improvement | Technical mechanism | Evidence supporting the gap | Closest prior art | Remaining uncertainty about novelty |
|---|---|---|---|---|---|---|---|
| 1 | Binary RF at 0.5 threshold; hard labels | No indication when input is outside training distribution; measured recall drop 99.4% → 0% on shifted input, reported as "all benign" | Batch-level shift audit before trusting a prediction | Per-feature distributional distance vs a training reference; calibrated batch-level threshold | Measured on this codebase (§A3 of audit) | FIRCE (conformal drift detection); CALIBURN | Whether *batch-level pre-inference gating in an upload tool* is separately published; not established either way |
| 2 | Vote fraction exposed as "probability" | Not a calibrated probability | Isotonic / temperature calibration on a held-out split + reliability diagram | Post-hoc monotone calibration | Standard, well-documented deficiency of RF vote fractions | CALIBURN (isotonic calibration); Platt/isotonic literature | None — this is established practice, not novel |
| 3 | Fixed 0.5 cut-off | Ignores operator alert budget and cost asymmetry | Budget-driven threshold with an FPR validity guarantee | Conformal Risk Control | Operator-budget framing is standard in the cited work | CALIBURN (CRC on CICIDS2017); Angelopoulos et al. | None — directly published |
| 4 | Single aggregate recall | Hides that 91.8% of malicious rows are 3 attack types; rarest 3 types total 14 rows | Per-attack-type and per-day reporting | Stratified metrics; Mondrian/class-conditional coverage | Computed from `reports/metrics.json` (§A2) | Class-conditional conformal (Make 2026; NeurIPS 2023) | Reporting choice, not an invention |
| 5 | Random train/test split | Same-session traffic in train and test; optimistic estimate | Day-based temporal split | Split by capture day | Well-known criticism of CIC-IDS2017 evaluation | Widespread in IDS evaluation literature | Not novel; valuable as rigorous engineering |
| 6 | Abstain and route to human review | — | — | — | — | 2007 abstaining alert classifiers; US11057399B2; NeutroSENSE | **Occupied; do not claim** |
| 7 | Adaptive thresholds for IDS | — | — | — | — | US8800036B2 | **Patented; do not claim** |

Rows 1–5 are credible engineering. None is an invention. Rows 6–7 must be avoided as novelty claims entirely.

---

## 4. Patent landscape (screening only)

| Patent | Relevance |
|---|---|
| **US10372910B2** — Method for predicting and characterizing cyber attacks | Malicious score vs benign score with thresholds and alert issuance |
| **US8800036B2** — Adaptive anomaly-based intrusion detection | Adaptively tuned classification threshold for IDS — directly anticipates "tune the threshold to the operating point" |
| **US11057399B2** — Alert classification with presentation flag | Classifier suppresses or presents alerts to an operator — anticipates review-queue triage |
| **US7594270B2 / US20070169194A1** — Threat scoring and triage | Severity scoring and triage of security events |
| **US7124438B2** — Anomaly detection in monitored communications | Queue-based assessment of monitored communications |
| **US6715084B2**, **US7181768B1** — Firewall feedback; application-monitoring IDS with ML | General ML-for-IDS prior art |

This is a screening list retrieved by keyword search, not an exhaustive or classified search. It is sufficient to establish that the *triage / threshold / alert-suppression* space has long-standing patent coverage.

---

## 5. Honest assessment of the seven directions

| Direction | Occupied? | Feasible here? | Contribution available? |
|---|---|---|---|
| Unseen attack detection | Yes, heavily | Partly (open-set on held-out attack types) | No — needs a new method |
| FP reduction at high recall | Yes, since 2007 + patents | Yes | No as invention; yes as engineering |
| Distribution shift detection | Yes, incl. CICIDS2017 | Yes | No as invention; yes as engineering |
| Explainability | Yes | Yes (already done via feature importance) | No |
| Efficient inference | Yes | Yes | No |
| Privacy-preserving collaborative | Yes | **No** — needs multiple parties | No |
| Confidence / selective classification | Yes, incl. CRISP/CALIBURN 2026 | Yes | No as invention |

---

## 6. What is actually defensible

Since no algorithmic novelty is available, the defensible contribution is a **rigorous, reproducible engineering and evaluation contribution**:

> Turn a system that reports an unqualified 99.83% into one that (a) refuses to vouch for traffic outside its training distribution, (b) exposes a calibrated, budget-driven decision with an explicit `review` outcome, and (c) reports performance under a temporal split and per attack type — with every claim measured and every ablation run.

This is a **systems and measurement contribution**, which is what a course project can legitimately deliver. It is:
- concrete (each component is testable),
- honest (no novelty claim required),
- demonstrable (the OOD failure is reproducible in one upload),
- and it directly repairs the three highest-severity findings in the audit.

It is **not** patentable, and the disclosure draft should say so.

### What would be needed to make a genuine novelty claim

1. A method not already described in the cited work — most plausibly something specific about *how* batch-level shift and per-flow abstention interact (e.g. a shift-conditional coverage guarantee that adapts the review band to the batch verdict).
2. A professional prior-art search including patent databases.
3. Evaluation on at least two independent datasets and under adversarial perturbation.
4. Comparison against the specific baselines in CRISP, CALIBURN, and FIRCE — not against a 0.5 threshold.
5. External review.

None of that is achievable in this project's timeframe, and pretending otherwise would be the single fastest way to lose credibility in a viva.
