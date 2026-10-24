# PROJECT_AUDIT.md

**Project:** NetGuard AI — Malware Detection Using AI-Based Network Traffic Analysis
**Audit date:** 2026-10-22
**Method:** full read of `ml/`, `backend/`, `frontend/src/`, `backend/tests/`, `reports/`, `docs/`; execution of the API against real and deliberately perturbed data; test-suite run.
**Scope rule:** no source file was modified during this audit.

---

## 1. Inventory of what exists

| Area | Files | Lines | Status |
|---|---|---|---|
| ML pipeline | `ml/config.py`, `ml/preprocess.py`, `ml/train.py` | 425 | Implemented, works |
| Backend | `backend/app/main.py`, `backend/app/model_store.py` | 241 | Implemented, works |
| Frontend | `frontend/src/App.tsx` + 9 components + `api.ts` | ~800 | Implemented, works |
| Tests | `backend/tests/conftest.py`, `test_api.py`, `test_training.py` | ~250 | 17 tests, all pass in 0.24 s |
| Artefacts | `models/netguard_model.joblib` (3.4 MB), `reports/metrics.json`, `dataset/samples/*.csv` | — | Committed and valid |
| Raw dataset | `dataset/raw/` | empty | Not committed (downloaded separately by this audit) |

Verified working end-to-end: `GET /api/health` returns `model_loaded: true`, `model_name: "Random Forest"`, `feature_count: 69`. Uploading `demo_test_flows.csv` returns 2,000 predictions, 1,998 correct (99.90%). The Vite dev proxy and the single-port built-frontend mount both work.

Nothing in the repository is a stub or placeholder. Every endpoint documented in `README.md` exists and behaves as described.

---

## 2. Architecture as actually implemented

```
CIC-IDS2017 CSVs ──► ml/train.py ──► models/netguard_model.joblib
                          │                    (sklearn Pipeline:
                          │                     SimpleImputer + RandomForest)
                          └──────► reports/metrics.json ──┐
                                                          │
CSV upload ──► backend/app/main.py ──► model_store.predict ┤
                    │                                      │
                    │  predict_proba[:, 1]                 │
                    ▼                                      ▼
              JSON / CSV download              React dashboard (reads metrics)
```

The design is sound and the separation is correct:

- Training is offline and never runs inside the API.
- `ml/preprocess.py` is imported by both training and inference, so column handling cannot drift.
- The imputer lives **inside** the persisted `Pipeline`, so imputation statistics are training-only.
- The backend never retrains and only calls `predict` / `predict_proba`.

These are the project's strongest architectural decisions and must be preserved by any change.

---

## 3. Findings

Severity reflects impact on correctness, trustworthiness, or deployability — not on the demo.

### A. Machine-learning evaluation

**A1 — Random splitting ignores capture-session structure. (High)**

`ml/train.py:158-166` splits with `train_test_split(..., random_state=42)`. CIC-IDS2017 consists of five capture days, and flows from the same day — often from the same attack campaign and the same endpoints — are dealt out into both train and test. The reported 99.83% therefore measures performance on traffic drawn from the *same sessions* as training, not on new traffic.

This is the single most important weakness in the project. It is the reason the headline number is not operationally meaningful, and it is a well-known criticism of random-split evaluation on this dataset. No temporal or day-based split exists anywhere in the code.

**A2 — Binary collapse hides failure on rare attack types. (High)**

`ml/preprocess.py:37-40` maps all 14 attack labels to `1`. From `reports/metrics.json`:

| Attack | Rows in the 500k sample | Share of malicious |
|---|---|---|
| DoS Hulk | 34,475 | 40.5% |
| DDoS | 25,587 | 30.0% |
| PortScan | 18,151 | 21.3% |
| **Subtotal (3 types)** | **78,213** | **91.8%** |
| All other 11 types | 6,975 | 8.2% |
| of which Infiltration | 9 | 0.011% |
| of which Heartbleed | 4 | 0.005% |
| of which SQL Injection | 1 | 0.001% |

The reported recall of 99.44% is therefore almost entirely a statement about three volumetric attack families. After the 80/20 split, Infiltration contributes ~2 test rows and SQL injection ~0. No conclusion about them is statistically supportable — but the dashboard presents a single aggregate recall that implies otherwise.

**A3 — No distribution-shift guard at inference. (High — measured)**

`ml/preprocess.py:43-73` validates only that required columns are present and numeric. There is no check that the **values** resemble the training distribution. `ml/model_store.py:40-47` then applies `predict` unconditionally.

Measured on this codebase (same 2,000 flows, all numeric features transformed by `x ↦ 50x + 10⁶`):

| Input | Predicted malicious | True attacks caught | Rows with p ∈ (0.1, 0.9) |
|---|---|---|---|
| `demo_test_flows.csv` | 321 | 321 / 323 | 0.5% |
| shifted file | **0** | **0 / 323** | **100%** |

Recall falls from 99.4% to **0%**. Every single probability lands in the ambiguous band — the model is, in fact, signalling that it has never seen anything like this input. The API nevertheless returns HTTP 200 with 2,000 hard `Benign` labels and the dashboard would report "no threats found".

The uncertainty signal already exists in `predict_proba`. The system discards it.

**A4 — The decision threshold is arbitrary. (Medium)**

`pipeline.predict()` applies an implicit 0.5 cut-off (`model_store.py:45`). Nothing ties that threshold to a false-alarm budget, an analyst review capacity, or a cost ratio. On `demo_test_flows.csv` the model's probabilities are strongly bimodal (83.7% below 0.1, 15.8% above 0.9, 0.5% in between), so the choice is low-impact *in-distribution* — but it is unjustified, unranged, and unexposed to the operator.

**A5 — Probabilities are not calibrated. (Medium)**

`model_store.py:46` exposes the Random Forest vote fraction directly as `Malicious_Probability`. Vote fractions from tree ensembles are not probabilities; they are typically pushed toward 0 and 1 and do not satisfy `P(y=1 | p̂ = p) ≈ p`. The field name and the UI both assert a meaning the number does not have.

**A6 — No per-attack-type or per-day reporting. (Medium)**

`ml/train.py:124-133` computes only aggregate binary metrics. There is no breakdown by attack family, by capture day, or by false-positive cause. Combined with A2 this makes the reported numbers unfalsifiable in the way that matters.

**A7 — Single split, no resampling of the estimate. (Low)**

One `random_state=42` split, no cross-validation, no confidence intervals. Reported differences of 0.0002 F1 between Random Forest and Decision Tree (see `ml/config.py:30`) are well inside split noise.

**A8 — Sampling is stratified on the binary label only. (Low)**

`ml/train.py:89-97` preserves the benign/malicious ratio but not the attack-type ratio. Rare classes are sampled with whatever variance the draw produces (Infiltration: 9 rows). A stratified-by-attack-type sample would make per-class reporting feasible.

*Positive note:* duplicate removal before splitting (`ml/train.py:74-77`) is correct and is a leakage vector that a large fraction of published work on this dataset gets wrong. This should be retained and highlighted.

### B. Security

**B1 — CSV formula injection on download. (Medium)**

`backend/app/main.py:170-185` echoes the uploaded frame back with two columns appended. Any cell beginning with `=`, `+`, `-`, or `@` is preserved verbatim. Opening the downloaded file in Excel/LibreOffice can execute the cell as a formula. In a security tool that ingests untrusted CSVs this is an avoidable own-goal.

**B2 — Unbounded per-request memory. (Low)**

`main.py:43` reads up to 100 MB + 1 byte into memory per request, then `pd.read_csv` builds a second in-memory copy. There is no concurrency limit, no authentication, and no rate limiting. A handful of parallel uploads can exhaust the host.

**B3 — Model artefact loaded with `joblib.load`. (Low)**

`model_store.py:32` deserialises a pickle. This executes arbitrary code if the file is replaced. The trust boundary is local, so the practical risk is low, but it should be documented rather than implicit.

**B4 — No audit trail. (Info)**

Predictions are not logged. For a security tool, "what did the system say about this file, and when" is normally a requirement.

### C. Code quality

- `main.py:156` calls `store.get()` a second time inside the response body purely to read `model_name`; the bundle is already in hand via `predict_or_raise`.
- `json_value` (`main.py:59-65`) handles `np.integer` and floats but not `pd.NA`, `pd.Timestamp`, or `datetime`, which would be passed through to the JSON encoder and fail. Not reachable with CIC-IDS2017 data; reachable with a real upload containing timestamp columns.
- Metric computation is duplicated between `ml/train.py:124-133` and `main.py:145-153` in two different shapes. They will drift.
- No structured logging anywhere in the backend.
- The frontend has no error boundary; a render exception blanks the page.

### D. Testing

- All 17 tests pass. They use a synthetic 4-feature model in a temp directory, which is fast and correctly isolated.
- **No test exercises the real 69-feature model or the real `metrics.json`.** A regression in the shipped artefact — wrong feature order, corrupted model — would not be caught.
- No tests for: distribution shift, calibration, threshold selection, or the download-injection case.
- `requirements.txt` pins `httpx2==2.13.1` rather than `httpx`. It works (the suite passes), but it is an unusual dependency that a reviewer will question; the conventional pin is `httpx`.

### E. Operational / reproducibility

- `reports/training_log.txt` embeds absolute paths from the machine that trained the model (`/home/titan/vit/suyash/cnproj`), which is cosmetic but signals the artefacts were produced elsewhere.
- No dataset checksum or provenance record; `dataset/raw/README.md` just points at the README section.
- No CI, no container, no pinned Python version file.
- `requirements.txt` pins exact versions, which is good for reproducibility.

---

## 4. What is *not* wrong

Worth stating explicitly, because an improvement plan should not "fix" these:

- Duplicate removal before splitting is correct.
- The imputer inside the Pipeline is correct.
- Model selection on validation and reporting on test is correct.
- Constant-feature dropping uses training data only — correct.
- `random_state=42` everywhere makes results reproducible.
- Upload validation (extension, size, emptiness, missing columns, non-numeric values, 503 without a model) is thorough and returns precise errors.
- The frontend is honest: it reads real metrics from disk rather than hardcoding numbers.

---

## 5. Summary

| ID | Weakness | Severity | Measured evidence |
|---|---|---|---|
| A1 | Random split ignores capture sessions | High | Reported 99.83% on same-session traffic |
| A2 | Binary collapse hides rare-class failure | High | 91.8% of malicious rows are 3 attack types; 14 rows total for the rarest three |
| A3 | No shift guard; hard labels on OOD input | High | Recall 99.4% → 0%; 100% of probabilities ambiguous; API still returns "Benign" |
| A4 | Arbitrary 0.5 threshold | Medium | 0.5% of rows in ambiguous band in-distribution |
| A5 | Uncalibrated "probability" | Medium | Vote fraction exposed as probability |
| A6 | No per-type / per-day reporting | Medium | Aggregate metrics only |
| B1 | CSV formula injection | Medium | Uploaded cells echoed verbatim |
| B2 | Unbounded memory per request | Low | 100 MB read per request, no limit |
| D | Real model untested | Medium | Suite is synthetic-only |

**The three findings that matter are A3, A1, and A2** — in that order of immediacy.

A3 is a live, reproducible defect: the system will confidently pronounce a completely alien batch of traffic to be entirely benign. A1 and A2 mean the reported performance is not the performance an operator would experience.

---

## 6. Constraints any improvement must respect

1. Preserve `/api/health`, `/api/metrics`, `/api/model/features`, `/api/predict`, `/api/predict/download` response shapes additively — the frontend depends on them.
2. Preserve `ml/preprocess.py` as the single source of truth for column handling.
3. Preserve the offline-train / online-serve separation.
4. Keep training runnable on a laptop; do not introduce a GPU or a deep-learning framework.
5. Do not break the 17 existing tests.
6. Keep the demo runnable with the committed artefacts even if the raw dataset is absent.

---

## 7. Remediation (added 2026-10-23)

Version 1.1 addressed the following findings. See `TECHNICAL_DOCUMENTATION.md` for
the mechanisms and `EXPERIMENTS.md` for measurements.

| ID | Finding | Status | What was done |
|---|---|---|---|
| A3 | No shift guard; hard labels on OOD input | **Fixed** | Batch shift gate; the shifted demo file now returns `severely_shifted` with a warning instead of a silent "all benign" |
| A4 | Arbitrary 0.5 threshold | **Fixed** | Threshold derived from a false-alarm budget via Conformal Risk Control |
| A5 | Uncalibrated "probability" | **Fixed** | Isotonic calibration; raw vote fraction still exported as `Raw_Vote_Fraction` |
| A6 | No per-type reporting | **Partly fixed** | Per-attack metrics now produced by `ml.experiments`; not yet surfaced in the dashboard |
| A1 | Random split ignores capture sessions | **Not fixed — quantified** | A temporal protocol was added and the gap measured: recall 0.9979 → 0.3033. The deployed artefact still uses the random split so the dashboard keeps its historical behaviour |
| A2 | Binary collapse hides rare-class failure | **Not fixed — quantified** | Per-attack table shows PortScan 0.117 and Bot 0.023 on unseen days |
| A7 | Single split, no variance | **Not fixed** | One seed throughout |
| A8 | Sampling stratified on binary label only | **Partly addressed** | Temporal test set is capped per attack class; the training sample is unchanged |
| B1 | CSV formula injection | **Fixed** | Text cells beginning with `=`, `+`, `-`, `@`, tab or CR are prefixed on download |
| B2 | Unbounded per-request memory | **Not fixed** | Still 100 MB per request, no rate limiting |
| B3 | `joblib.load` on the model file | **Documented** | Trust boundary stated in `TECHNICAL_DOCUMENTATION.md` |
| B4 | No audit trail | **Not fixed** | |
| C | Code-quality items | **Partly fixed** | Duplicate `store.get()` removed; CSV sanitisation added. Metric duplication between training and API remains |
| D | Real model untested | **Not fixed** | Suite is still synthetic-only; a `reliable_client` fixture now exercises the reliability path |

New findings that emerged during implementation are recorded in
`TECHNICAL_DOCUMENTATION.md` §11 and `EXPERIMENTS.md` §10 — notably that the
budget-derived threshold becomes meaningless in the *other* direction under severe
shift, and that the review band produced no measurable benefit on any metric
collected.
