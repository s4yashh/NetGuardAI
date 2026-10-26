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
NetGuardAI/
├── ml/                     Machine-learning pipeline
│   ├── config.py           Paths and constants (split sizes, random seed, label names)
│   ├── preprocess.py       Cleaning used by BOTH training and the API
│   ├── reliability.py      Calibration, risk-controlled thresholds, review band,
│   │                       and the batch distribution-shift gate
│   ├── train.py            Load → clean → split → train 3 models → evaluate → save best
│   ├── experiments.py      Protocol comparison (random vs temporal) and ablations
│   └── analyze_dataset.py  Dataset analysis: quality, duplicates, distributions, per-attack results
├── backend/
│   ├── app/main.py         FastAPI app and endpoints
│   ├── app/model_store.py  Loads the saved model and runs predictions
│   └── tests/              pytest tests (use a tiny synthetic model, not the real one)
├── frontend/               React dashboard (NetGuard AI)
│   └── src/components/     Upload panel, shift warning, summary cards, results table, charts
├── dataset/
│   ├── raw/                CIC-IDS2017 CSV files go here (not committed, ~844 MB)
│   └── samples/            Demo CSVs created by training from the held-out test set
├── models/                 netguard_model.joblib (created by training)
├── reports/                metrics.json, experiments.json, dataset_analysis.json, figures/
├── report/                 Scripts that generate the project report (VIT BCSE308P template)
└── docs/                   screenshots/, demo/, report/ (project report .docx + .pdf)
```

Research and audit documents live in the repository root:

| Document | Contents |
|---|---|
| `PROJECT_AUDIT.md` | audit of the original implementation, with measured evidence |
| `NOVELTY_RESEARCH.md` | related work, prior-art comparison, honest novelty assessment |
| `INNOVATION_PROPOSAL.md` | the reliability layer: problem, mechanism, validation plan |
| `EXPERIMENTS.md` | protocols, ablations, measured results, failures |
| `TECHNICAL_DOCUMENTATION.md` | architecture, algorithms, data flow, API |
| `PATENT_DISCLOSURE_DRAFT.md` | technical disclosure (states plainly that no novelty was established) |

---

## 1. Requirements

- Python 3.11+ (tested with 3.14)
- Node.js 20+ (tested with 24)
- About 6 GB of free RAM for training with the default sample size

## Quick start (one command)

If you just want to run the website, use the launcher:

```bash
./start.sh
```

It creates `.venv` and installs dependencies if they are missing, starts the backend on port 8000
and the frontend on port 5173, waits until both respond, and opens <http://localhost:5173>.
Logs and PID files are written to `.run/` (ignored by git).

On macOS you can also double-click **`Start NetGuard.command`** in Finder, and
**`Stop NetGuard.command`** to shut everything down.

| Command | Meaning |
|---|---|
| `./start.sh` | Start both servers and open the dashboard |
| `./start.sh status` | Show whether both servers are running |
| `./start.sh stop` or `./stop.sh` | Stop both servers |
| `./start.sh restart` | Restart both servers |
| `NO_OPEN=1 ./start.sh` | Start without opening the browser |

The dataset is not needed for this; the trained model is included. Use the manual steps below only
if you want to run the two servers yourself or set the project up from scratch.

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

Useful options:

| Option | Meaning |
|---|---|
| `--protocol original` | random split over all capture days (default, matches the deployed artefact) |
| `--protocol temporal` | train Mon–Wed, calibrate Thursday morning, test Thursday afternoon + Friday |
| `--alpha 0.01` | tolerable false-positive rate on benign flows (default 0.01) |
| `--review-capacity 0.05` | share of traffic routed to human review (default 0.05) |
| `--sample-size 0` | train on every flow (needs much more RAM and time) |

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
8. Fits the **reliability layer**: isotonic probability calibration on half of the
   calibration split, then a false-alarm-budgeted alert threshold and a
   review-capacity-bounded abstention band on the other half.
9. Fits the **batch shift gate**: a reference sample of benign training flows plus a
   bootstrap null distribution drawn within single capture days.
10. Saves:
   - `models/netguard_model.joblib`: best pipeline + required feature list +
     reliability layer + shift profile
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
| GET | `/api/health` | Is a model loaded? Which one? Are the reliability layer and shift gate active? |
| GET | `/api/metrics` | Evaluation results saved by training |
| GET | `/api/model/features` | Feature columns an uploaded CSV must contain |
| POST | `/api/predict` | Upload a CSV → counts, per-row predictions, three-way decisions, batch shift verdict (JSON) |
| POST | `/api/predict/download` | Upload a CSV → same CSV with `Prediction`, `Decision`, `Malicious_Probability`, `Raw_Vote_Fraction` columns |

Input validation: only `.csv` files up to 100 MB; empty files, files with no rows, missing feature columns
and non-numeric feature values are rejected with a clear message. Extra columns are ignored. If no model has
been trained, prediction endpoints return HTTP 503.

The reliability layer adds three things to the response:

- `rows[].decision` is `Benign`, `Malicious` or `Review`. `Review` means the model
  is not confident enough to call it either way; it is not a classification claim.
- `reliability` reports the operating point (`alpha`, `t_alert`, `t_benign`) and the
  three-way counts.
- `shift` reports whether the batch as a whole resembles the training traffic, with
  a `warning` string when it does not. The gate compares the flows the model did
  **not** flag against a reference sample of benign training traffic.

Downloaded CSVs have text cells beginning with `=`, `+`, `-` or `@` prefixed with an
apostrophe, so opening the file in a spreadsheet cannot execute a formula from an
untrusted upload.

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
   Click **Analyze traffic**. You'll see a green *distribution matches training traffic* line, benign /
   malicious / **review** counts, the agreement with the file's own labels, and the results table
   (filter by Benign / Malicious / Review / Misclassified). Each row shows a three-way **Decision**;
   `Review` means the model declined to call it either way.
4. Click **Download CSV** to get the file with `Prediction`, `Decision`, `Malicious_Probability` and
   `Raw_Vote_Fraction` columns added.
5. Upload `dataset/samples/demo_unlabeled_flows.csv` to see predictions for a file without labels.
6. Upload `dataset/samples/demo_shifted_flows.csv`. This is the same 2,000 flows with every numeric
   feature scaled far outside its training range. The dashboard shows a red **distribution warning**
   above the results and names the most-affected features. Before the reliability layer existed, this
   file produced 2,000 confident `Benign` labels and no warning at all.
7. Upload `dataset/samples/invalid_missing_columns.csv` to show input validation (missing columns are listed).

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

## 9. Dataset analysis

```bash
python -m ml.analyze_dataset
```

Reads the raw CSV files and writes `reports/dataset_analysis.json` and the figures in `reports/figures/`
(about 4 minutes). It also rebuilds the exact training sample and test split and checks that the saved model
reproduces the stored confusion matrices, then breaks detection down per attack type. Main findings:

- 331,200 of 2,830,743 rows (11.7%) are exact duplicates: 45% of SSH-Patator and 43% of PortScan rows, 9% of benign.
- `Flow Bytes/s` and `Flow Packets/s` contain ∞ and NaN because some flows have zero duration;
  `-1` in `Init_Win_bytes_*` is a sentinel for flows without a TCP window (e.g. all DNS and NTP flows).
- 8 features are constant (all bulk features, `Bwd PSH Flags`, `Bwd URG Flags`); 44 pairs have |r| ≥ 0.95 and
  `Fwd PSH Flags` equals `SYN Flag Count` in every row.
- At the default 0.5 vote, Random Forest detects ≥ 99.1% of every attack label with at least 100 test flows but
  only 68.9% of Bot, 1 of 5 Infiltration and 0 of 3 Heartbleed flows (4 and 0 training examples). The deployed
  risk-controlled threshold raises Bot to 97.3% and Infiltration to 5 of 5, and sends the Heartbleed flows to review.
- With the temporal protocol (train Mon–Wed, test Thu–Fri, from `reports/experiments.json`), recall falls to 30.3%:
  attack types absent from training (PortScan, Bot) are missed. Random-split scores do not predict performance on
  new traffic.

## 10. Project report

The report follows the VIT BCSE308P template (Times New Roman 12, 1.5 spacing, roman/arabic page numbers,
86 pages from Chapter 1 to the References) and is printed in black and white. It is generated from the real
results in `reports/` (metrics, experiments, dataset analysis):

```bash
python -m report.build_report          # writes docs/report/NetGuard_AI_Project_Report.docx
```

Open the .docx in Word and press Ctrl+A, F9 to fill the page numbers in the Contents and lists, or run
`report/update_word.ps1` on Windows, which also exports the PDF. Fill in the highlighted placeholders
(student names, register numbers, guide, dates) before submitting.

## Results

From the training run in this repository (`reports/model_report.md`). The data is a 500,000-flow stratified sample
of the 2,499,543 unique CIC-IDS2017 flows; the test set is 100,000 flows never used for training or selection:

| Model | Accuracy | Precision | Recall | F1-score | Validation F1 |
|---|---|---|---|---|---|
| **Random Forest** (deployed) | 99.83% | 99.58% | 99.44% | 99.51% | 99.55% |
| Decision Tree | 99.81% | 99.41% | 99.50% | 99.46% | 99.57% |
| Logistic Regression | 95.61% | 87.81% | 86.23% | 87.01% | 86.88% |

Random Forest confusion matrix on the test set: 82,890 TN · 72 FP · 95 FN · 16,943 TP.

> **Important caveat — read this before quoting the table above.**
> These numbers come from a **random** train/test split, which deals flows from the
> same capture sessions into both sides. Re-running the same model with a **temporal**
> split (train Mon–Wed, test Thu afternoon + Fri) drops recall from **0.998 to
> 0.303**. Per attack type on those unseen days: DDoS 0.980, PortScan 0.117, Bot
> 0.023. The table below is reproducible and correct *for the split it was measured
> on*; it is not an estimate of how the model would perform on a new network. See
> `EXPERIMENTS.md` for the full comparison.

Decision Tree scored 0.0002 higher validation F1 than Random Forest (about one or two flows out of 40,000). That gap
is noise, so the selection rule keeps Random Forest, which also scores higher on the test set.
Re-running `python -m ml.train` reproduces these numbers, because every random step uses `random_state=42`.

## Limitations

- The model works on **flow features produced by CICFlowMeter** (as in CIC-IDS2017). It does not capture live
  packets or read `.pcap` files.
- CIC-IDS2017 was recorded in one lab network in 2017; accuracy on other networks will be lower.
- Training uses a 500,000-flow stratified sample by default for speed and memory.
