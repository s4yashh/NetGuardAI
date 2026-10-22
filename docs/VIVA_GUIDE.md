# NetGuard AI: Viva Guide

A short guide for presenting and defending the project in about 20 minutes.

---

## 1. One-line summary

> NetGuard AI takes network-flow records (CSV), runs them through a Random Forest trained on the
> CIC-IDS2017 dataset, and labels each flow **Benign** or **Malicious**, showing the results and the model's
> real evaluation metrics in a web dashboard.

## 2. Architecture

```
 ┌──────────────┐  CSV upload   ┌──────────────────┐   joblib.load   ┌──────────────────────┐
 │ React (Vite) │ ────────────▶ │ FastAPI backend  │ ──────────────▶ │ models/              │
 │ dashboard    │ ◀──────────── │ /api/predict     │                 │ netguard_model.joblib│
 └──────────────┘  JSON / CSV   │ /api/metrics     │ ── reads ──▶ reports/metrics.json     │
                                └──────────────────┘                 └──────────────────────┘
                                         ▲  same preprocessing (ml/preprocess.py)
                                         │
                       ┌─────────────────┴──────────────────┐
                       │ ml/train.py (run once, offline)     │
                       │ CIC-IDS2017 CSVs → clean → split →  │
                       │ train RF / DT / LR → evaluate → save│
                       └─────────────────────────────────────┘
```

- **Training is offline.** `python -m ml.train` runs once and writes the model + report to disk.
- **The backend never retrains.** It loads the saved pipeline and only calls `predict` / `predict_proba`.
- **Same preprocessing everywhere.** `ml/preprocess.py` is imported by both training and the API, and the
  imputer is stored *inside* the saved scikit-learn `Pipeline`, so an uploaded CSV is treated exactly like
  the training data.
- **No hardcoded numbers.** Every metric in the dashboard comes from `reports/metrics.json`, written by training.
  Every prediction comes from the model.

## 3. Dataset: CIC-IDS2017

- Created by the Canadian Institute for Cybersecurity (UNB) in 2017. Five days of traffic from a lab network
  with realistic benign users plus scripted attacks.
- Raw packets were converted into **flows** by **CICFlowMeter**. A flow is one conversation between two
  endpoints (src IP/port → dst IP/port, protocol), summarised by 78 statistics such as duration,
  packet counts, packet-length mean/std, inter-arrival times (IAT), TCP flag counts and bytes/second.
- Attack types include DoS/DDoS (Hulk, GoldenEye, Slowloris, Slowhttptest), PortScan, FTP/SSH brute force
  (Patator), Web attacks (brute force, XSS, SQL injection), Botnet, Infiltration and Heartbleed.
- We use the `MachineLearningCSV` version: 8 files, 2,830,743 flows.

**Cleaning steps (and why):**

| Step | Why |
|---|---|
| Strip spaces from column names | Original headers look like `" Flow Duration"` |
| Drop `Fwd Header Length.1` | Exact duplicate of `Fwd Header Length` |
| `Infinity` → missing, then median imputation | `Flow Bytes/s` divides by a zero duration for some flows |
| Remove duplicate rows | Identical rows could land in both train and test and inflate the score |
| Drop constant features | A column that never changes cannot help the model |
| `BENIGN` → 0, every attack → 1 | The project's question is binary: benign or malicious |

## 4. Train / validation / test split

- **80 % train+validation, 20 % test.** Then 10 % of the training part becomes the validation set
  (≈ 72 % / 8 % / 20 % overall).
- **Stratified:** every split keeps the same benign/malicious ratio as the full data.
- **`random_state=42`:** the split is reproducible.
- **Validation set** is used only to *choose* the model to deploy.
  **Test set** is used only to *report* the final scores. The model never sees test flows during
  training or selection, so the scores show how it handles unseen traffic.
- A 500,000-flow stratified sample is used by default so training fits in a laptop's memory.

## 5. Random Forest (the primary model)

- A **decision tree** asks a sequence of yes/no questions about features
  (e.g. "Is `Bwd Packet Length Std` > 1200?") until it reaches a leaf with a class.
  A single tree tends to **overfit**: it memorises the training data.
- A **Random Forest** trains many trees (here 100). Each tree:
  1. gets a **bootstrap sample** (random rows drawn with replacement), and
  2. at each split considers only a **random subset of features** (√78 ≈ 9).
- The trees become different from each other. For a new flow, every tree votes and the **majority**
  wins. `predict_proba` is the fraction of trees voting "Malicious" (shown as *malicious probability*).
- Why it suits this problem: handles many numeric features with very different scales (no scaling needed),
  captures non-linear patterns, resists overfitting, and gives **feature importances**.

**Compared models:**

- *Decision Tree:* one tree. Fast and easy to read, but more prone to overfitting.
- *Logistic Regression:* a linear model. It needs scaled features (`StandardScaler`) and can only
  draw a straight (linear) boundary, so it misses the complex patterns that trees catch.

## 6. Evaluation metrics

Positive class = **Malicious**. From the confusion matrix:

|                     | Predicted Benign | Predicted Malicious |
|---|---|---|
| **Actual Benign**   | TN (true negative) | FP (false positive / false alarm) |
| **Actual Malicious**| FN (false negative / missed attack) | TP (true positive) |

| Metric | Formula | Meaning here |
|---|---|---|
| Accuracy | (TP + TN) / all | Share of all flows classified correctly |
| Precision | TP / (TP + FP) | When NetGuard raises an alert, how often is it a real attack? |
| Recall | TP / (TP + FN) | Of all real attacks, how many did NetGuard catch? |
| F1-score | 2·P·R / (P + R) | Balance of precision and recall |

**Why not just accuracy?** Most traffic is benign (≈ 80 %+). A model that always says "Benign"
would already score ~80 % accuracy while catching zero attacks. Recall and F1 expose that.
For intrusion detection, **false negatives (missed attacks) are the costliest error**.

## 7. Results (test set: 100,000 unseen flows)

| Model | Accuracy | Precision | Recall | F1-score | Validation F1 |
|---|---|---|---|---|---|
| **Random Forest** (deployed) | 99.83% | 99.58% | 99.44% | 99.51% | 99.55% |
| Decision Tree | 99.81% | 99.41% | 99.50% | 99.46% | 99.57% |
| Logistic Regression | 95.61% | 87.81% | 86.23% | 87.01% | 86.88% |

Random Forest confusion matrix: **82,890 TN, 72 FP, 95 FN, 16,943 TP**.
That means 72 false alarms out of 82,962 benign flows and 95 missed attacks out of 17,038 malicious flows.

How to read it:

- **Random Forest and Decision Tree are almost tied.** Random Forest has fewer false alarms (72 vs 100); Decision
  Tree misses slightly fewer attacks (85 vs 95). The forest averages 100 trees, so it is more stable.
- **Logistic Regression is clearly worse** (F1 87%): ≈ 2,000 false alarms and ≈ 2,300 missed attacks. Attack
  patterns are not linearly separable, so a straight-line boundary is not enough.
- **Top features** (Random Forest): Bwd Packet Length Std, Packet Length Variance, Packet Length Std,
  Avg Bwd Segment Size. Packet-size statistics separate scripted attacks from normal traffic best.

**Model selection rule:** Random Forest is the primary model. Another model replaces it only if its *validation* F1 is
higher by more than 0.001. Decision Tree was 0.0002 higher (≈ 1–2 flows out of 40,000), so Random Forest stayed.

Data facts: 2,830,743 raw flows → 331,200 duplicates removed → 500,000-flow stratified sample
(414,812 benign / 85,188 malicious) → 360,000 train / 40,000 validation / 100,000 test. 69 of 77 features kept
(8 were constant, e.g. `Bwd PSH Flags` and the `*Bulk*` features).

On the demo file (`demo_test_flows.csv`, 2,000 test-set flows) the deployed model gets 1,998 right (99.9%).

## 8. Live demo script (≈ 5 minutes)

1. Show the header badge: *Model ready · Random Forest*.
2. Model evaluation section: comparison table and chart, confusion matrix (switch between models), split, top features.
3. Upload `dataset/samples/demo_test_flows.csv` → **Analyze traffic**. Explain counts, the agreement with the file's
   labels, the probability column, and the *Misclassified* filter.
4. **Download CSV** → open it to show the new `Prediction` and `Malicious_Probability` columns.
5. Upload `dataset/samples/invalid_missing_columns.csv` → show the validation error listing missing columns.
6. Optional: open <http://127.0.0.1:8000/docs> to show the API.

## 9. Likely viva questions

- **Why Random Forest?** It is tied with the Decision Tree on validation F1 and best on test accuracy, precision and
  F1. An ensemble of 100 trees is more stable than one tree, needs no feature scaling, gives feature importances, and
  predicts quickly.
- **Decision Tree had slightly higher validation F1. Why not deploy it?** The gap was 0.0002, about one or two flows out
  of 40,000, which is noise. The rule keeps the primary model unless a rival is better by more than 0.001, and it
  looks only at validation data. The test set plays no part in the choice. (Be open about it: the margin was added
  after the first run showed the near-tie.)
- **How do you avoid data leakage?** Duplicates removed before splitting. The imputer is fitted only on training data
  (inside the Pipeline). Model selection uses the validation set, not the test set.
- **What if the uploaded CSV is wrong?** The API checks the extension, size, emptiness, required columns and numeric
  values, and returns a clear error (HTTP 400/422). Without a model it returns 503.
- **Why are the scores so high?** CIC-IDS2017 attacks are generated by scripted tools in one lab network, so they
  have very distinctive flow statistics. Real-world performance would be lower. That is a known limitation of this
  dataset.
- **Can it capture live traffic?** No. It works on flow CSVs produced by CICFlowMeter. Live capture is future work.
- **Future work:** multi-class attack types, live capture with CICFlowMeter, testing on newer datasets
  (e.g. CSE-CIC-IDS2018), handling class imbalance (class weights / SMOTE), hyper-parameter tuning.
