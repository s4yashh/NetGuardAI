# EXPERIMENTS.md

**System:** NetGuard AI 1.1 — reliability layer
**Date:** 2026-10-23
**Status:** all numbers below are measured. Nothing in this document is projected, estimated, or illustrative.

Raw output: `reports/experiments.json` (written by `python -m ml.experiments`).
Deployed-artefact metrics: `reports/metrics.json` (written by `python -m ml.train`).

---

## 1. Headline result

The same model family, the same training pool, the same hyper-parameters — only the
**test set** differs.

| Test set | Recall | Precision | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| Random split of Monday–Wednesday | **0.9979** | 0.9984 | 0.9981 | 0.00025 | 0.9995 |
| Unseen days (Thursday afternoon + Friday) | **0.3033** | 0.9993 | 0.4654 | 0.00045 | 0.5279 |

**Recall drops 69.5 percentage points.** The 99%+ figures reported by the original
project are a property of the random split, not of the model's ability to detect
attacks on traffic it has not seen.

Precision stays high (0.9993) because the model rarely raises a false alarm; it
simply fails to raise alarms at all. Accuracy falls to 0.528, which — on a test set
that is 67.7% malicious — is barely better than always answering "malicious".

---

## 2. Setup

| Item | Value |
|---|---|
| Dataset | CIC-IDS2017 `MachineLearningCSV`, 8 files, 2,830,743 raw rows |
| Cleaning | `ml/preprocess.py`, unchanged from version 1.0 |
| Duplicates removed before any split | 331,200 |
| Training sample | 500,000 stratified flows (`random_state=42`) |
| Model | Random Forest, 100 trees, `SimpleImputer(median)` inside a Pipeline |
| Features | 69 (8 constant features dropped on the training split) |
| Splits | 62% train / 8% validation / 10% calibration / 20% test |
| False-alarm budget α | 0.01 |
| Review capacity | 0.05 |
| Seed | 42 everywhere |

Temporal test set is capped at 20,000 rows per attack label so that rare classes
survive intact while DDoS and PortScan do not dominate. That cap is the reason the
temporal test set's malicious rate (67.7%) is far above the training rate (13.7%),
and §7 corrects for it.

---

## 3. Protocols

| Protocol | Train | Validation | Calibration | Test |
|---|---|---|---|---|
| `original` | random, all 8 days | random | random | random |
| `random_monwed` | random, Mon–Wed | random | random | random |
| `temporal` | random, Mon–Wed | random | **Thu morning** | **Thu afternoon + Fri** |

`random_monwed` and `temporal` share an identical training and validation pool, so
the difference between them isolates the effect of unseen capture days.

---

## 4. Ablations (B0–B4)

| Variant | Description |
|---|---|
| B0 | Raw Random Forest, argmax at 0.5 — the version 1.0 behaviour |
| B1 | B0 + isotonic probability calibration, still at 0.5 |
| B2 | B1 + CRC alert threshold derived from the 1% false-alarm budget |
| B3 | B2 + review band (three-way decision; `Review` counts as no alert) |
| B4 | B3 + batch shift gate (batch-level, so it does not change per-flow metrics) |

### `original` protocol — 100,000 test flows, 17.0% malicious

| Variant | Precision | Recall | F1 | FPR | Accuracy | Alerts |
|---|---|---|---|---|---|---|
| B0 raw RF @0.5 | 0.9953 | 0.9942 | 0.9948 | 0.00096 | 0.9982 | 17,020 |
| B1 calibrated @0.5 | 0.9910 | 0.9982 | 0.9946 | 0.00186 | 0.9981 | 17,161 |
| B2 CRC threshold | 0.9683 | 0.9992 | 0.9835 | 0.00673 | 0.9943 | 17,583 |
| B3 + review band | 0.9683 | 0.9992 | 0.9835 | 0.00673 | 0.9943 | 17,583 |

### `random_monwed` protocol — 100,000 test flows, 13.7% malicious

| Variant | Precision | Recall | F1 | FPR | Accuracy | Alerts |
|---|---|---|---|---|---|---|
| B0 raw RF @0.5 | 0.9984 | 0.9979 | 0.9981 | 0.00025 | 0.9995 | 13,642 |
| B1 calibrated @0.5 | 0.9978 | 0.9988 | 0.9983 | 0.00035 | 0.9995 | 13,662 |
| B2 CRC threshold | 0.9947 | 0.9996 | 0.9971 | 0.00085 | 0.9992 | 13,716 |
| B3 + review band | 0.9947 | 0.9996 | 0.9971 | 0.00085 | 0.9992 | 13,716 |

### `temporal` protocol — 61,989 test flows, 67.7% malicious

| Variant | Precision | Recall | F1 | FPR | Accuracy | Alerts |
|---|---|---|---|---|---|---|
| B0 raw RF @0.5 | 0.9993 | **0.3033** | 0.4654 | 0.00045 | 0.5279 | 12,745 |
| B1 calibrated @0.5 | 0.9970 | 0.3120 | 0.4753 | 0.00195 | 0.5333 | 13,139 |
| B2 CRC threshold | 0.9596 | **0.5241** | 0.6779 | 0.04635 | 0.6627 | 22,934 |
| B3 + review band | 0.9596 | 0.5241 | 0.6779 | 0.04635 | 0.6627 | 22,934 |

**Two findings worth stating plainly:**

1. **Lowering the threshold recovers 22 points of recall under shift** (0.303 →
   0.524) but blows the false-alarm budget by 4.6×. The fixed 0.5 threshold is
   badly wrong for unseen days; a budget-derived one is less wrong but its
   guarantee does not hold.
2. **The review band changed nothing.** B2 and B3 are identical in all three
   protocols. See §8.

---

## 5. Per-attack-type breakdown

The aggregate number hides which attacks fail. `temporal` protocol, B3 decisions:

| Attack | Rows | Recall |
|---|---|---|
| DDoS | 20,000 | 0.980 |
| Infiltration | 36 | 0.583 |
| PortScan | 20,000 | **0.117** |
| Bot | 1,953 | **0.023** |
| BENIGN | 20,000 | FPR 0.046 |

For comparison, `random_monwed` — where every attack type in the test set also
appears in training:

| Attack | Rows | Recall |
|---|---|---|
| DoS Hulk | 11,614 | 0.9996 |
| DoS GoldenEye | 680 | 1.0000 |
| FTP-Patator | 403 | 1.0000 |
| DoS slowloris | 383 | 0.9974 |
| DoS Slowhttptest | 339 | 1.0000 |
| SSH-Patator | 228 | 1.0000 |
| Heartbleed | 2 | 1.0000 |

**Interpretation.** PortScan and Bot occur only on days the model never trained on,
and they are almost entirely missed. DDoS also occurs only on unseen days, yet is
detected 98% of the time — so the failure is not "unseen attacks always fail". Some
attacks are distinctive enough in flow-feature space to transfer; others are not.
Reporting both is the point.

Note also the sample sizes. Heartbleed contributes 2 rows and Infiltration 36. No
per-type claim about them is statistically meaningful, and the table says so by
showing `n` alongside every rate.

---

## 6. Probability quality

Brier score and expected calibration error, before and after isotonic calibration:

| Protocol | Brier (raw) | Brier (calibrated) | ECE (raw) | ECE (calibrated) |
|---|---|---|---|---|
| `original` | 0.0013 | 0.0013 | 0.0010 | **0.0004** |
| `random_monwed` | 0.0004 | 0.0004 | 0.0008 | **0.0002** |
| `temporal` | 0.4608 | 0.4307 | 0.5013 | 0.4611 |

In-distribution, calibration halves the calibration error and the Random Forest is
already close to calibrated. Under day shift, calibration improves the numbers
slightly and leaves them catastrophic — an ECE of 0.46 means the stated
probabilities are essentially uninformative.

**Calibration cannot repair non-exchangeability.** This is the expected result, and
it is the strongest argument for the shift gate.

---

## 7. Prevalence-matched robustness check

The temporal test set is 67.7% malicious against a 13.7% training rate, so its
aggregate FPR and Brier figures are not directly comparable with the other
protocols. The check keeps all benign rows and subsamples the attack rows to
restore the training prevalence.

| Protocol | Pos. rate | Size | Brier raw | Brier calibrated | Brier of constant predictor |
|---|---|---|---|---|---|
| `temporal` (natural) | 0.677 | 61,989 | 0.4608 | 0.4307 | — |
| `temporal` (matched) | 0.136 | 23,161 | 0.0928 | **0.0881** | 0.1179 |

Under the matched view the model **does** beat a constant predictor (0.0881 vs
0.1179), and the operating point is unchanged:

| Variant | Recall | FPR |
|---|---|---|
| B0 raw RF @0.5 | 0.3078 | 0.0004 |
| B1 calibrated @0.5 | 0.3176 | 0.0019 |
| B2 CRC threshold | 0.5220 | 0.0464 |

This corrected an earlier reading of the data. Before the matched check the
calibrated Brier (0.4307) looked worse than a constant predictor; that was an
artefact of the attack-heavy test set, not a property of the model. Reported here
because the correction matters.

Calibration still improves the score by only 5% relative and remains ~70× worse
than in-distribution (0.0881 vs 0.0013).

---

## 8. Shift gate

Calibrated on benign training flows, null distribution bootstrapped within single
capture days. 40 in-distribution validation batches, 10 batches per shift family.

| Shift family | Detection rate | AUC | Comment |
|---|---|---|---|
| Scaled (`×5`) | 1.00 | 1.000 | |
| Additive noise (1 σ) | 1.00 | 1.000 | |
| Mean shift (2 σ) | 1.00 | 1.000 | |
| **Permuted columns** | **0.00** | **0.487** | negative control |

False-alarm rate on in-distribution batches: **0.000** in all protocols.

**The permuted-columns control is a real limitation, not a bug.** Shuffling each
column independently preserves every marginal distribution exactly, so a per-feature
KS test cannot see it. Any shift that changes only the dependence structure between
features is invisible to this gate. Reported rather than removed.

### Per-day verdicts

`original` protocol (reference built from all days):

| Day | Verdict | Score |
|---|---|---|
| Friday-DDoS | **severely_shifted** | 6.30 |
| Thursday-Afternoon | in_distribution | 3.56 |
| Tuesday | in_distribution | 3.46 |
| Friday-Morning | in_distribution | 2.02 |
| Friday-PortScan | in_distribution | 2.02 |
| Thursday-Morning | in_distribution | 1.76 |
| Wednesday | in_distribution | 1.72 |
| Monday | in_distribution | 1.39 |

Threshold: 4.24.

`temporal` protocol (reference built from Mon–Wed only):

| Day | Verdict |
|---|---|
| Friday-DDoS | severely_shifted |
| Friday-Morning | severely_shifted |
| Friday-PortScan | severely_shifted |
| Thursday-Afternoon | in_distribution |

Threshold: 3.46.

**The single flagged day was investigated rather than assumed.** For Friday-DDoS
the non-alerted subset contained 94,353 flows of which only **24 were actually
attacks** (0.03%), so the flag is not caused by misclassified attacks contaminating
the comparison. Scoring the strictly-benign subset instead gives 6.39 — essentially
identical to 6.30. The benign traffic during the DDoS episode genuinely differs in
its flow statistics, plausibly because congestion alters timing and packet-size
distributions. The gate detected an attack-induced environmental change.

This also means H2 was only partly right: the gate does **not** flag every unseen
day, only days whose normal traffic actually changed. That is the desired behaviour,
but it is not what the hypothesis predicted.

---

## 9. Hypothesis-by-hypothesis assessment

| ID | Hypothesis | Outcome | Evidence |
|---|---|---|---|
| H1 | The gate separates perturbed from in-distribution batches | **Supported, with a caveat** | AUC 1.000 on three shift families; AUC 0.487 on marginal-preserving shifts |
| H2 | The gate warns on genuinely unseen capture days | **Partially supported** | 3 of 4 unseen days under `temporal`; the flagged day is the one whose benign traffic changed |
| H3 | Calibration reduces Brier score and ECE | **Supported in-distribution; fails under shift** | ECE 0.0010 → 0.0004 (`original`); 0.5013 → 0.4611 (`temporal`) |
| H4 | Budget-driven thresholding hits the requested FPR better than 0.5 | **Supported in-distribution; violated under shift** | Realised FPR 0.0067 against α = 0.01 (`original`); 0.0464 (`temporal`) |
| H5 | The review band recovers recall at bounded abstention cost | **Not supported** | B2 ≡ B3 in all three protocols |
| H6 | Temporal splitting lowers the headline score substantially | **Strongly supported** | Recall 0.9979 → 0.3033 |
| H7 | Rare attack types are near-invisible in aggregate metrics | **Supported** | Bot recall 0.023 (n = 1,953); Heartbleed n = 2; Infiltration n = 36 |

**H5 deserves elaboration.** The band is defined as the interval immediately below
the alert threshold, and `Review` counts as "no alert" in the binary metrics. The
band can therefore only reduce alerts, never increase recall — the hypothesis was
mis-specified. What the band actually does is route ambiguous flows to a human, and
that is not captured by a binary metric. In these runs it routed 0.30% of flows
in-distribution and 16.2% under temporal shift. It did not hurt, but it did not do
what was predicted.

---

## 10. Negative and unexpected results

Stated explicitly, because they bound the value of the contribution.

1. **The gate is blind to marginal-preserving shift.** Detection 0%, AUC 0.487.
2. **The false-alarm guarantee does not survive day shift.** 1% nominal, 4.64%
   realised. This is consistent with conformal theory — the guarantee assumes
   exchangeability — but it means the budget is only trustworthy when the gate says
   the batch is in-distribution.
3. **Calibration is not a fix for distribution shift.** It improves ECE by 8%
   relative under shift and leaves the probabilities unusable.
4. **The review band produced no measurable benefit** on any metric collected.
5. **Under severe shift the threshold becomes meaningless in the other direction.**
   The deployed model's `t_alert` is 0.0182; the demo shifted file's probabilities
   all sit near 0.44, so all 2,000 flows are reported `Malicious` instead of the
   `Benign` labels version 1.0 produced. Neither verdict is trustworthy, but the
   new one at least arrives with a `severely_shifted` warning. A principled
   treatment of this case is future work.
6. **Precision stays high throughout**, which is a reminder that precision is a poor
   headline metric here: a model that never alerts has undefined-but-flattering
   precision on an attack-heavy set.

---

## 11. Limitations of this evaluation

- **One dataset.** Five capture days from one lab network in 2017. Nothing here
  shows the same gap on another network.
- **One model family.** Random Forest only. The gap may differ for other
  classifiers; that is untested.
- **The temporal split has one configuration.** Train Mon–Wed, test Thu–Fri. Other
  day partitions were not tried.
- **The synthetic shift families are synthetic.** Only the per-day verdicts in §8
  come from real shift.
- **The gate's reference is a single pooled sample.** Per-day references were not
  tried.
- **No adversarial evaluation.** The perturbation study in the prior literature
  (arXiv:2609.19241) is not replicated here.
- **Single seed for the reliability fit.** The calibration/threshold halves are one
  random draw; no variance across draws is reported.
- **Test-set caps change prevalence.** Mitigated by §7 but not eliminated.

---

## 12. Reproduction

```bash
python -m ml.train --sample-size 500000 --protocol original   # deployed artefact
python -m ml.experiments                                       # all three protocols
pytest                                                         # 38 tests
```

Runtime on a 6-core laptop: dataset load ≈ 60 s, each protocol ≈ 15 s of training
plus prediction. Total ≈ 6 minutes. Memory peak ≈ 3 GB.

---

## 13. What this means

The project's original claim — 99.83% accuracy, 99.44% recall — is reproducible and
correct **for the split it was measured on**. This evaluation shows that the split
was doing most of the work.

The reliability layer does not fix that. It cannot: no post-hoc layer repairs a
model that has never seen the traffic it is being asked about. What the layer does
is make the problem visible — a batch-level warning when the input is outside the
training distribution, a three-way decision instead of a forced binary label, and a
false-alarm budget whose violation under shift is measurable rather than silent.

The most useful output of this work is the measurement in §1 and §5, not the
mechanism. That is worth stating plainly in any presentation of it.
