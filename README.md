# NetGuard AI — Malware Detection Using AI-Based Network Traffic Analysis

NetGuard AI is a web application that reads network-flow records from a CSV file and uses a
machine-learning model to label every flow as **Benign** or **Malicious**.

- **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity, University of New Brunswick)
- **ML:** Python, Pandas, scikit-learn. Random Forest, Decision Tree and Logistic Regression are trained and compared
- **Backend:** FastAPI (CSV upload → real predictions from the saved model)
- **Frontend:** React + Vite + TypeScript + Tailwind CSS + Recharts + Lucide icons

---

## Project structure

```
cnproj/
├── ml/                     Machine-learning pipeline
│   ├── config.py           Paths and constants (split sizes, random seed, label names)
│   ├── preprocess.py       Cleaning used by BOTH training and the API
│   └── train.py            Load → clean → split → train 3 models → evaluate → save best
├── backend/
│   ├── app/main.py         FastAPI app and endpoints
│   ├── app/model_store.py  Loads the saved model and runs predictions
│   └── tests/              pytest tests (use a tiny synthetic model, not the real one)
├── frontend/               React dashboard (NetGuard AI)
│   └── src/components/     Upload panel, summary cards, results table, charts
├── dataset/
│   ├── raw/                CIC-IDS2017 CSV files go here (not committed, ~844 MB)
│   └── samples/            Demo CSVs created by training from the held-out test set
├── models/                 netguard_model.joblib (created by training)
├── reports/                metrics.json, model_report.md, training_log.txt
└── docs/VIVA_GUIDE.md      Short explanation for the viva / presentation
```

---

## 1. Requirements

- Python 3.11+ (tested with 3.14)
- Node.js 20+ (tested with 24)
- About 6 GB of free RAM for training with the default sample size

## 2. Installation

```bash
git clone https://github.com/s4yashh/NetGuardAI.git
cd NetGuardAI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
cd ..
```

## 3. Get the dataset

NetGuard uses the **MachineLearningCSV** version of CIC-IDS2017: 8 CSV files, 2,830,743 flows,
78 features + a `Label` column.

**Option A: official source.** Fill in the form at
<https://www.unb.ca/cic/datasets/ids-2017.html>, download `MachineLearningCSV.zip`, and unzip
the 8 CSV files into `dataset/raw/`.

**Option B: Kaggle mirror of the same files** (needs a Kaggle account + `~/.kaggle/kaggle.json`):

```bash
pip install kaggle
kaggle datasets download -d chethuhn/network-intrusion-dataset -p dataset/raw --unzip
```

After either option, `dataset/raw/` should contain files like
`Monday-WorkingHours.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, …

## 4. Train the models

> The repository already contains a trained model (`models/netguard_model.joblib`) and its evaluation report, so you
> can skip straight to step 5. Retrain only if you want to reproduce the results; you will need the dataset from step 3.

```bash
source .venv/bin/activate
python -m ml.train
```

What it does:

1. Reads all 8 CSVs, strips spaces from column names, drops the duplicated `Fwd Header Length.1` column,
   turns `Infinity` values into missing values, and removes exact duplicate rows.
2. Takes a **stratified sample of 500,000 flows**. This keeps the benign/malicious ratio and lets training
   run on a laptop. Use `python -m ml.train --sample-size 0` to train on every flow (needs much more RAM and time).
3. Maps labels: `BENIGN` → Benign, every attack type (DDoS, PortScan, DoS Hulk, …) → Malicious.
4. Splits the data **80% / 20%** (train / test), then keeps 10% of the training part as a validation set.
   All splits are stratified with `random_state=42`.
5. Drops features that are constant in the training data.
6. Trains Random Forest, Decision Tree and Logistic Regression. Each is a scikit-learn `Pipeline` with a median
   `SimpleImputer` (plus `StandardScaler` for Logistic Regression).
7. Chooses the model to deploy using the **validation** set: Random Forest (the primary model) is kept unless
   another model beats its validation F1 by more than 0.001. It then reports accuracy, precision, recall, F1 and the
   confusion matrix of every model on the **test** set.
8. Saves:
   - `models/netguard_model.joblib`: best pipeline + required feature list
   - `reports/metrics.json` and `reports/model_report.md`: evaluation results
   - `dataset/samples/`: demo files built from real test-set flows

Training takes about 11 minutes on a 6-core laptop (peak memory ≈ 2.8 GB). Most of that time is reading the CSVs.

## 5. Start the backend

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --port 8000
```

API documentation: <http://127.0.0.1:8000/docs>

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Is a model loaded? Which one? |
| GET | `/api/metrics` | Evaluation results saved by training |
| GET | `/api/model/features` | Feature columns an uploaded CSV must contain |
| POST | `/api/predict` | Upload a CSV → counts + per-row predictions (JSON) |
| POST | `/api/predict/download` | Upload a CSV → same CSV with `Prediction` and `Malicious_Probability` columns |

Input validation: only `.csv` files up to 100 MB; empty files, files with no rows, missing feature columns
and non-numeric feature values are rejected with a clear message. Extra columns are ignored. If no model has
been trained, prediction endpoints return HTTP 503.

## 6. Start the frontend

In a second terminal:

```bash
cd frontend
npm run dev
```

Open <http://localhost:5173>. Vite forwards `/api` requests to the backend on port 8000.

**Single-port alternative:** run `npm run build` inside `frontend/`, then start the backend. FastAPI serves the
built dashboard at <http://127.0.0.1:8000>.

## 7. Demonstration

1. Open the dashboard. The header should show **Model ready · Random Forest**.
2. Scroll to **Model evaluation** to see the comparison table, bar chart, confusion matrix, dataset split and
   feature importances (all loaded from `reports/metrics.json`).
3. Upload `dataset/samples/demo_test_flows.csv` (2,000 real flows from the held-out test set, with labels).
   Click **Analyze traffic**. You'll see benign/malicious counts, the agreement with the file's own labels, and
   the results table (filter by Benign / Malicious / Misclassified).
4. Click **Download CSV** to get the file with predictions added.
5. Upload `dataset/samples/demo_unlabeled_flows.csv` to see predictions for a file without labels.
6. Upload `dataset/samples/invalid_missing_columns.csv` to show input validation (missing columns are listed).

Command-line check without the UI:

```bash
curl -F "file=@dataset/samples/demo_test_flows.csv" http://127.0.0.1:8000/api/predict | head -c 600
```

## 8. Tests

```bash
source .venv/bin/activate
pytest
```

The tests train a tiny model on **synthetic** data in a temporary folder. They check the API behaviour
(valid upload, missing columns, wrong file type, empty file, no model, CSV download) and never touch the real model
or the real evaluation report.

## Results

From the training run in this repository (`reports/model_report.md`). The data is a 500,000-flow stratified sample
of the 2,499,543 unique CIC-IDS2017 flows; the test set is 100,000 flows never used for training or selection:

| Model | Accuracy | Precision | Recall | F1-score | Validation F1 |
|---|---|---|---|---|---|
| **Random Forest** (deployed) | 99.83% | 99.58% | 99.44% | 99.51% | 99.55% |
| Decision Tree | 99.81% | 99.41% | 99.50% | 99.46% | 99.57% |
| Logistic Regression | 95.61% | 87.81% | 86.23% | 87.01% | 86.88% |

Random Forest confusion matrix on the test set: 82,890 TN · 72 FP · 95 FN · 16,943 TP.

Decision Tree scored 0.0002 higher validation F1 than Random Forest (about one or two flows out of 40,000). That gap
is noise, so the selection rule keeps Random Forest, which also scores higher on the test set.
Re-running `python -m ml.train` reproduces these numbers, because every random step uses `random_state=42`.

## Limitations

- The model works on **flow features produced by CICFlowMeter** (as in CIC-IDS2017). It does not capture live
  packets or read `.pcap` files.
- CIC-IDS2017 was recorded in one lab network in 2017; accuracy on other networks will be lower.
- Training uses a 500,000-flow stratified sample by default for speed and memory.
