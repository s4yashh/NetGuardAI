"""Chapters 5-9 and Appendix A of the NetGuard AI project report."""

import ast
from pathlib import Path

from report.content_part1 import fmt, pct
from report.docx_helpers import Report

ROOT = Path(__file__).resolve().parent.parent

SCHEDULE = [
    ("Literature survey and dataset selection", 1, 2),
    ("Dataset download and verification", 2, 1),
    ("Exploratory data analysis", 3, 2),
    ("Preprocessing and deduplication", 4, 2),
    ("Sampling, splitting, model training", 5, 2),
    ("Evaluation and model selection", 7, 1),
    ("FastAPI backend and validation", 7, 2),
    ("React dashboard", 8, 2),
    ("Reliability layer and shift gate", 9, 2),
    ("Temporal protocol experiments", 10, 1),
    ("Tests, integration, test files", 10, 2),
    ("Dataset analysis and report", 11, 2),
]


def source_of(path: str, *names: str) -> str:
    """Exact source of the named top-level functions/classes from a project file."""
    text = (ROOT / path).read_text()
    tree = ast.parse(text)
    parts = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
            lines = text.splitlines()[start - 1:node.end_lineno]
            parts.append("\n".join(lines))
    return "\n\n".join(parts)


def lines_of(path: str, start_marker: str, end_marker: str) -> str:
    """Lines from the first line containing start_marker up to (not incl.) end_marker."""
    lines = (ROOT / path).read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if start_marker in line)
    end = next(i for i in range(start + 1, len(lines)) if end_marker in lines[i])
    return "\n".join(lines[start:end]).rstrip()


# =========================================================================== CHAPTER 5
def chapter5(R: Report, A: dict, M: dict, D) -> None:
    R.chapter("Schedule, Tasks and Milestones")
    R.para(
        "The project was planned as a twelve-week course project. Work was organised so that each stage "
        "produced a concrete artefact that the next stage depended on: the verified dataset, the analysis "
        "results, the trained model and report, the API, the dashboard and finally this document."
    )
    R.heading("5.1", "Tasks")
    R.table("Project Tasks and Planned Weeks", ["No.", "Task", "Weeks", "Output"], [
        ["1", "Literature survey and dataset selection", "W1–W2", "Comparison of IDS datasets (Table 1.3)"],
        ["2", "Dataset download and verification", "W2", "8 CSV files, row count verified"],
        ["3", "Exploratory data analysis", "W3–W4", "Distributions, quality issues, duplicates"],
        ["4", "Preprocessing and deduplication", "W4–W5", "ml/preprocess.py, cleaning functions"],
        ["5", "Sampling, splitting and model training", "W5–W6", "ml/train.py, three trained models"],
        ["6", "Evaluation and model selection", "W7", "metrics.json, model_report.md"],
        ["7", "FastAPI backend and input validation", "W7–W8", "backend/app/"],
        ["8", "React dashboard", "W8–W9", "frontend/src/"],
        ["9", "Reliability layer and shift gate", "W9–W10", "ml/reliability.py"],
        ["10", "Temporal protocol experiments", "W10", "ml/experiments.py, experiments.json"],
        ["11", "Tests, integration and test files", "W10–W11", "38 passing tests, dataset/faculty_tests/"],
        ["12", "Dataset analysis and report", "W11–W12", "dataset_analysis.json, this report"],
    ], widths=[0.45, 2.4, 0.8, 2.35])
    R.heading("5.2", "Gantt chart")
    R.para(f"{R.next_fig} shows the same plan as a Gantt chart. Several tasks overlap where they were independent.")
    R.figure(D / "diag_gantt.png", "Project Gantt Chart")
    R.heading("5.3", "Milestones")
    R.table("Project Milestones", ["Milestone", "Week", "Completion criterion"], [
        ["M1 Dataset ready", "W2", f"{fmt(A['raw_rows'])} flows loaded, matching the official count"],
        ["M2 Data understood", "W4", "Quality issues, duplicates and distributions documented"],
        ["M3 Models trained", "W7", "Three models evaluated on the test set; Random Forest F1 > 99%"],
        ["M4 API working", "W8", "Real predictions returned; invalid files rejected with clear errors"],
        ["M5 Dashboard working", "W9", "Upload, results, download and evaluation views working end to end"],
        ["M6 Reliable", "W10", "Alert threshold meets α = 1% on the test set; shift gate flags synthetic shift"],
        ["M7 Verified", "W11", "38 backend tests pass; frontend production build succeeds; browser test passes"],
        ["M8 Submitted", "W12", "Report and demonstration complete"],
    ], widths=[1.5, 0.7, 3.8])
    R.heading("5.4", "Risks and mitigation")
    R.table("Project Risks and Mitigation", ["Risk", "Impact", "Mitigation"], [
        ["Official dataset download requires a form", "Delay in obtaining data", "Byte-identical Kaggle mirror; row count verified"],
        ["Training exceeds available memory", "Pipeline cannot run", "float32 storage, 500k stratified sample; peak 2.8 GB measured"],
        ["Slow deduplication", "Long iteration cycle", "Replaced column-wise comparison with 64-bit row hashing"],
        ["Data leakage between train and test", "Over-optimistic results", "Deduplicate first; fit preprocessing on training data only"],
        ["Training/inference mismatch", "Wrong predictions in the app", "Shared preprocess.py and a saved Pipeline with feature list"],
        ["Results not reproducible", "Report cannot be verified", "Fixed seeds; analysis script re-checks the saved confusion matrices"],
    ], widths=[2.0, 1.5, 2.5])


# =========================================================================== CHAPTER 6
def chapter6(R: Report, A: dict, M: dict, S: Path) -> None:
    """S is the folder of (grayscale) screenshots."""
    R.chapter("Project Demonstration")
    R.para(
        "This chapter shows the most important parts of the implementation and the working application. The "
        "code excerpts are taken verbatim from the project repository; the screenshots were captured from the "
        "running application analysing real CIC-IDS2017 flows from the held-out test set."
    )
    R.heading("6.1", "Sample Codes")

    R.heading("6.1.1", "Shared preprocessing (ml/preprocess.py)", level=3)
    R.para(
        "prepare_features() is called both by the training pipeline's callers and by the API. It strips the "
        "column names, rejects files with missing or non-numeric feature columns and returns the features in "
        "the exact order used in training, with infinities converted to missing values."
    )
    R.code(source_of("ml/preprocess.py", "clean_column_names", "to_binary_labels", "prepare_features"))

    R.heading("6.1.2", "Splitting protocols (ml/train.py)", level=3)
    R.para("_split_frame() makes the stratified 62/8/10/20 split; build_splits() applies it under the random or temporal protocol.")
    R.code(source_of("ml/train.py", "_split_frame", "build_splits"))

    R.heading("6.1.3", "Model definitions and selection (ml/train.py)", level=3)
    R.para("Each model is a Pipeline, so the imputer (and scaler) is saved with it. select_model() applies the validation-set rule.")
    R.code(source_of("ml/train.py", "build_models", "evaluate", "select_model"))

    R.heading("6.1.4", "Risk-controlled threshold and three-way decision (ml/reliability.py)", level=3)
    R.para("crc_threshold() picks the alert threshold for the false-positive budget α; decide() maps calibrated scores to Benign, Review or Malicious.")
    R.code(source_of("ml/reliability.py", "crc_threshold", "decide"))

    R.heading("6.1.5", "Batch shift score (ml/reliability.py)", level=3)
    R.code(source_of("ml/reliability.py", "_normalised_ks", "batch_shift_score"))

    R.heading("6.1.6", "Loading the model and predicting (backend/app/model_store.py)", level=3)
    R.code(source_of("backend/app/model_store.py", "ModelStore"))

    R.heading("6.1.7", "Upload validation and the prediction endpoint (backend/app/main.py)", level=3)
    R.code(source_of("backend/app/main.py", "read_csv_upload"))
    R.code(lines_of("backend/app/main.py", '@app.post("/api/predict")', '@app.post("/api/predict/download")'))

    R.heading("6.1.8", "Frontend API client (frontend/src/api.ts)", level=3)
    R.para("The client turns HTTP errors into readable messages and keeps the list of offending columns for the error box.")
    R.code(lines_of("frontend/src/api.ts", "async function request(", "export async function getHealth"))

    R.heading("6.1.9", "Automated tests (backend/tests/)", level=3)
    R.para("The tests use synthetic data, so they check the API and the reliability layer without needing the real dataset.")
    R.code(source_of("backend/tests/test_api.py", "test_missing_columns_are_rejected",
                     "test_shifted_batch_raises_a_warning", "test_download_neutralises_spreadsheet_formulas"))
    R.code(source_of("backend/tests/test_reliability.py", "test_crc_threshold_holds_budget_on_unseen_data"))

    R.heading("6.1.10", "Per-attack evaluation (ml/analyze_dataset.py)", level=3)
    R.para("The dataset analysis rebuilds the split, verifies it against the saved results and computes the detection rate per attack label.")
    R.code(lines_of("ml/analyze_dataset.py", "# Sanity check: the rebuilt split", 'result["rf_errors_by_label"]'))

    R.heading("6.1.11", "Running the project", level=3)
    R.para("The complete project is run with the commands below, from the project folder.")
    R.code(
        "# 1. Install dependencies\n"
        "python3 -m venv .venv && source .venv/bin/activate\n"
        "pip install -r requirements.txt\n"
        "cd frontend && npm install && cd ..\n\n"
        "# 2. Train the models (dataset in dataset/raw/), run the protocol\n"
        "#    experiments and analyse the dataset\n"
        "python -m ml.train\n"
        "python -m ml.experiments\n"
        "python -m ml.analyze_dataset\n\n"
        "# 3. Start everything with ./start.sh, or the backend (port 8000)\n"
        "#    and the frontend (port 5173) separately\n"
        "uvicorn backend.app.main:app --port 8000\n"
        "cd frontend && npm run dev\n\n"
        "# 4. Run the tests\n"
        "pytest", size=9)

    R.heading("6.2", "Sample Screen Shots")
    shots = [
        ("shot_home.png", "Dashboard on Start-Up: Navigation, Model Status and Upload Panel",
         "When the dashboard opens it calls /api/health and shows that the Random Forest with 69 features is "
         "loaded, that its probabilities are calibrated and that the shift gate is active. The upload panel "
         "lists the input requirements and accepts a CSV file by clicking or by drag and drop."),
        ("shot_summary.png", "Analysis Summary for the 2,000-Flow Demonstration File",
         "After demo_test_flows.csv is analysed, the summary cards show the benign, malicious and review counts "
         "and, because the file contains labels, how many predictions agree with them."),
        ("shot_shift_ok.png", "Shift Verdict for an In-Distribution Batch", ""),
        ("shot_results_table.png", "Prediction Results Table With Decisions and Probabilities",
         "The results table shows readable flow features, the decision, the calibrated probability and the actual "
         "label. The Download CSV button returns the full file with the new columns."),
        ("shot_misclassified.png", "Results Filtered to the Misclassified Flows", ""),
        ("shot_shift_warning.png", "Warning for a Batch Outside the Training Distribution",
         "Uploading demo_shifted_flows.csv, a copy of the demo flows with every feature scaled far outside its "
         "training range, produces a warning that the per-flow predictions should not be trusted, with the "
         "features that moved most."),
        ("shot_validation_error.png", "Validation Error for a File With Missing Feature Columns",
         "A file from which three required features were removed is rejected with a list of the missing columns."),
        ("shot_model_comparison.png", "Model Comparison Table and Chart in the Dashboard",
         "The evaluation section reads reports/metrics.json and shows the test-set metrics of the three models."),
        ("shot_confusion.png", "Confusion Matrix in the Dashboard", ""),
        ("shot_training_data.png", "Training Data Summary in the Dashboard", ""),
        ("shot_features.png", "Most Important Features in the Dashboard", ""),
        ("shot_api_docs.png", "Interactive API Documentation Generated by FastAPI",
         "FastAPI generates OpenAPI 3.1 documentation at /docs, where every endpoint can be tried from the browser."),
    ]
    for name, caption, text in shots:
        if text:
            R.para(text)
        R.figure(S / name, caption, 6.0)
    R.para(f"The layout adapts to small screens, as shown for a 390-pixel-wide phone in {R.next_fig}.")
    R.figure(S / "shot_mobile.png", "Dashboard on a 390-Pixel-Wide Mobile Screen", 2.6)


# =========================================================================== CHAPTER 7
def chapter7(R: Report, A: dict, M: dict, F: Path, E: dict, D: Path, API: dict) -> None:
    models = {m["name"]: m for m in M["models"]}
    rf, dt, lr = models["Random Forest"], models["Decision Tree"], models["Logistic Regression"]
    curves = A["curves"]
    rel = M["reliability"]
    R.chapter("Result & Discussion")
    R.para(
        "This chapter presents the evaluation of the three models on the held-out test set of "
        f"{fmt(M['split']['test'])} flows, breaks the results down by attack type, measures the effect of the "
        "reliability layer, tests generalisation to unseen capture days, evaluates the shift gate and discusses "
        "the limitations that come from the dataset. All numbers are produced by ml/train.py, ml/experiments.py "
        "and ml/analyze_dataset.py, or measured through the running application."
    )

    # ---------------------------------------------------------------- 7.1
    R.heading("7.1", "Overall model comparison")
    R.table("Test-Set Performance of the Three Models (Positive Class = Malicious)",
            ["Model", "Accuracy", "Precision", "Recall", "F1-score", "Validation F1", "Train time"],
            [[m["name"], pct(m["accuracy"]), pct(m["precision"]), pct(m["recall"]), pct(m["f1_score"]),
              pct(m["validation_f1"]), f"{m['train_seconds']:.1f} s"] for m in M["models"]],
            widths=[1.35, 0.75, 0.75, 0.7, 0.75, 0.9, 0.8], align=["left"] + ["right"] * 6)
    R.figure(F / "fig_model_comparison.png", "Accuracy, Precision, Recall and F1-Score of the Three Models")
    better_p = "Random Forest" if rf["precision"] >= dt["precision"] else "Decision Tree"
    better_r = "Decision Tree" if dt["recall"] > rf["recall"] else "Random Forest"
    R.para(
        f"Random Forest and Decision Tree are almost tied, with F1-scores of {pct(rf['f1_score'])} and "
        f"{pct(dt['f1_score'])}. {better_p} has the higher precision, meaning fewer false alarms, and "
        f"{better_r} the higher recall. Logistic Regression is clearly weaker, with an F1-score of "
        f"{pct(lr['f1_score'])}: its single linear boundary cannot capture the threshold-like, non-linear "
        "patterns revealed by the exploratory analysis, such as a flow being suspicious when it is very short "
        "and targets an unusual port, or very long and almost silent."
    )
    if dt["validation_f1"] > rf["validation_f1"]:
        sel = (f"On the validation set Decision Tree scored {pct(dt['validation_f1'])} and Random Forest "
               f"{pct(rf['validation_f1'])}; the gap is below the 0.001 selection margin, so the primary model, "
               "Random Forest, was kept.")
    else:
        sel = (f"Random Forest also had the highest validation F1 ({pct(rf['validation_f1'])} against "
               f"{pct(dt['validation_f1'])} for Decision Tree), so the selection rule chose it without needing "
               "the margin.")
    R.para(sel + " Accuracy is high for all models partly because 83% of the test flows are benign, which is "
           "why the following sections rely on per-class measures.")

    # ---------------------------------------------------------------- 7.2
    R.heading("7.2", "Confusion matrices")
    R.figure(F / "fig_confusion_matrices.png", "Test-Set Confusion Matrices With Row Percentages")
    rows = []
    for m in M["models"]:
        (tn, fp), (fn, tp) = m["confusion_matrix"]
        rows.append([m["name"], fmt(tn), fmt(fp), fmt(fn), fmt(tp), pct(fp / (fp + tn), 3), pct(fn / (fn + tp), 3)])
    R.table("Confusion Matrix Counts and Error Rates", ["Model", "TN", "FP", "FN", "TP", "FPR", "Miss rate"], rows,
            widths=[1.4, 0.8, 0.6, 0.6, 0.8, 0.8, 0.9], align=["left"] + ["right"] * 6)
    (tn, fp), (fn, tp) = rf["confusion_matrix"]
    R.para(
        f"Out of {fmt(tn + fp)} benign test flows, the Random Forest at its default 0.5 vote raised {fp} false "
        f"alarms, a false positive rate of {pct(fp / (fp + tn), 3)}. Out of {fmt(fn + tp)} malicious flows it "
        f"missed {fn}. Roughly one alert in {round((tp + fp) / fp)} is a false alarm and one attack flow in "
        f"{round((tp + fn) / fn)} is missed. Logistic Regression would produce {fmt(lr['confusion_matrix'][0][1])} "
        f"false alarms and miss {fmt(lr['confusion_matrix'][1][0])} attack flows on the same traffic."
    )

    # ---------------------------------------------------------------- 7.3
    R.heading("7.3", "Threshold-independent evaluation")
    R.para(
        f"{R.next_fig} shows the ROC and precision–recall curves, which summarise performance over all decision "
        "thresholds [27], [28]; the false positive rate is plotted on a logarithmic axis because the interesting "
        "region is below 1%."
    )
    R.figure(F / "fig_roc_pr.png", "ROC and Precision–Recall Curves on the Test Set")
    R.table("Area Under the ROC Curve and Average Precision", ["Model", "ROC AUC", "Average precision"],
            [[name, f"{c['roc_auc']:.5f}", f"{c['average_precision']:.5f}"] for name, c in curves.items()],
            widths=[2.0, 1.4, 1.6], align=["left", "right", "right"])
    R.para(
        f"Random Forest reaches a ROC AUC of {curves['Random Forest']['roc_auc']:.4f} and an average precision of "
        f"{curves['Random Forest']['average_precision']:.4f}, and its curve lies above the others at every false "
        "positive rate. The Decision Tree's curve has few points because an unpruned tree outputs almost only "
        f"probabilities of 0 or 1. {R.next_fig} shows that the Random Forest's raw vote fractions are well "
        "separated: most benign flows receive a vote close to 0 and most malicious flows a vote close to 1."
    )
    R.figure(F / "fig_probability_hist.png", "Distribution of the Random Forest Vote Fraction by Actual Class")

    # ---------------------------------------------------------------- 7.4
    det, support = A["per_label_detection"], A["test_support"]
    raw_err, dep_err = A["rf_errors_by_label"], A["rf_deployed_errors_by_label"]
    review = A["deployed_review_by_label"]
    R.heading("7.4", "Detection rate per attack type")
    R.para(
        "Because the test set keeps the original attack names, recall can be computed for each label "
        f"separately. {R.next_fig} compares the three models at their default threshold, and {R.next_table} adds "
        "the deployed decision of the Random Forest (calibrated score at the risk-controlled threshold). For "
        "BENIGN the value is the share correctly passed."
    )
    R.figure(F / "fig_per_attack_recall.png", "Detection Rate per Attack Label on the Test Set (Default Threshold)")
    rows = []
    for label in sorted(support, key=lambda k: -support[k]):
        rows.append([label, fmt(support[label]), pct(det["Random Forest"][label], 1),
                     pct(det["RF deployed alert"][label], 1), pct(det["Decision Tree"][label], 1),
                     pct(det["Logistic Regression"][label], 1), fmt(review.get(label, 0))])
    R.table("Detection Rate per Label on the Test Set",
            ["Label", "Flows", "RF 0.5", "RF deployed", "DT", "LR", "To review"], rows,
            widths=[1.75, 0.7, 0.7, 0.85, 0.65, 0.65, 0.7], font_size=9, align=["left"] + ["right"] * 6)
    rfd, dep = det["Random Forest"], det["RF deployed alert"]
    big = [k for k in support if support[k] >= 100 and k != "BENIGN"]
    tr = A["split_label_counts"]["train"]
    R.para(
        f"At the default threshold, every attack label with at least 100 test flows is detected at "
        f"{pct(min(rfd[k] for k in big), 1)} or more by Random Forest. The weak points are the rare labels: "
        f"Bot ({pct(rfd['Bot'], 1)} of {support['Bot']} flows), Infiltration "
        f"({round(rfd['Infiltration'] * support['Infiltration'])} of {support['Infiltration']}) and Heartbleed "
        f"({round(rfd['Heartbleed'] * support['Heartbleed'])} of {support['Heartbleed']}). The dataset analysis "
        f"explains why. The training set held only {tr.get('Infiltration', 0)} Infiltration and "
        f"{tr.get('Heartbleed', 0)} Heartbleed flows ({R.refs['rare']}), and Bot traffic consists of short, "
        f"low-volume HTTP exchanges (median three packets each way, {R.refs['profiles']}) that resemble ordinary "
        "web requests, so the forest's averaged votes for many of these flows stay below 0.5."
    )
    R.para(
        f"The deployed decision changes this picture. Its lower, calibrated threshold detects "
        f"{pct(dep['Bot'], 1)} of the Bot flows and {round(dep['Infiltration'] * support['Infiltration'])} of "
        f"{support['Infiltration']} Infiltration flows, and reduces the missed attack flows from "
        f"{sum(v for k, v in raw_err.items() if k != 'BENIGN')} to {sum(v for k, v in dep_err.items() if k != 'BENIGN')}. "
        f"The Heartbleed flows, which the model never saw in training, are not passed as benign but sent to "
        f"review ({review.get('Heartbleed', 0)} of {support['Heartbleed']}), which is the intended behaviour for "
        "flows the model cannot judge. The cost is more false alarms, analysed in the next section. Decision Tree "
        "isolates rare training examples in their own leaves and therefore detects more Bot flows than the raw "
        "forest; Logistic Regression fails completely on SSH-Patator and the web attacks."
    )

    # ---------------------------------------------------------------- 7.5
    R.heading("7.5", "Effect of the reliability layer")
    R.para(
        f"{R.next_table} applies the reliability layer step by step to the same Random Forest on the same test "
        "set: B0 is the raw vote at 0.5, B1 the calibrated score at 0.5, B2 the calibrated score at the "
        f"risk-controlled threshold for α = {rel['alpha']}, and B3 adds the review band (reviewed flows count as "
        "not alerted)."
    )
    R.table("Random Forest With Progressively More of the Reliability Layer (Test Set)",
            ["Variant", "Precision", "Recall", "F1-score", "FPR", "Alerts"],
            [[v["name"], pct(v["precision"]), pct(v["recall"]), pct(v["f1_score"]), pct(v["false_positive_rate"], 3),
              fmt(v["alerts"])] for v in rel["variants"]],
            widths=[1.7, 0.85, 0.85, 0.85, 0.85, 0.8], align=["left"] + ["right"] * 5)
    b0, b2 = rel["variants"][0], rel["variants"][2]
    pq = E["protocols"]["original"]["probability_quality"]
    R.para(
        f"The risk-controlled threshold trades precision for recall: recall rises from {pct(b0['recall'])} to "
        f"{pct(b2['recall'])} while the false positive rate rises from {pct(b0['false_positive_rate'], 3)} to "
        f"{pct(b2['false_positive_rate'], 3)}, which is still within the budget α = {pct(rel['alpha'], 0)}. In other "
        "words the operator gives up some precision to miss far fewer attacks, and the rule guarantees how much "
        f"false-alarm cost that can create. The review band holds {fmt(rel['review_count'])} test flows "
        f"({pct(rel['review_rate'])}), far below the {pct(rel['review_capacity'], 0)} capacity. Calibration also "
        f"improves the probabilities themselves: the expected calibration error falls from {pq['ece_raw']:.5f} to "
        f"{pq['ece_calibrated']:.5f} and the Brier score from {pq['brier_raw']:.5f} to {pq['brier_calibrated']:.5f}."
    )

    # ---------------------------------------------------------------- 7.6
    P = E["protocols"]
    R.heading("7.6", "Generalisation to unseen days")
    R.para(
        f"{R.next_fig} and {R.next_table} compare the three evaluation protocols of Section 4.1.8. This is the "
        "most important dataset result of the project."
    )
    R.figure(D / "exp_protocols.png", "Random Forest Performance Under the Three Evaluation Protocols (Raw Vote at 0.5)")
    rows = []
    for key, name in (("original", "Random (all days)"), ("random_monwed", "Random (Mon–Wed)"), ("temporal", "Temporal")):
        v0, v2 = P[key]["variants"][0], P[key]["variants"][2]
        rows.append([name, pct(v0["precision"], 1), pct(v0["recall"], 1), pct(v0["f1_score"], 1),
                     pct(v2["recall"], 1), pct(v2["false_positive_rate"], 2), pct(P[key]["reliability"]["review_rate"], 1)])
    R.table("Results Under the Three Protocols", ["Protocol", "Precision", "Recall", "F1", "Recall (deployed)",
                                                  "FPR (deployed)", "Review"], rows,
            widths=[1.35, 0.75, 0.7, 0.65, 0.95, 0.9, 0.7], font_size=9, align=["left"] + ["right"] * 6)
    t = P["temporal"]
    t0, t2 = t["variants"][0], t["variants"][2]
    R.para(
        f"With a random split the model looks almost perfect, with an F1-score of {pct(P['original']['variants'][0]['f1_score'], 1)}. "
        f"When it is trained on Monday to Wednesday and tested on Thursday afternoon and Friday, recall collapses "
        f"to {pct(t0['recall'], 1)} and the F1-score to {pct(t0['f1_score'], 1)}, although precision stays at "
        f"{pct(t0['precision'], 1)}: almost everything the model flags is an attack, but it misses most attacks. "
        f"{R.next_fig} shows why, label by label."
    )
    R.figure(D / "exp_temporal_per_attack.png", "Detection of Each Later-Day Attack: Random Split Versus Unseen Days")
    tp_ = {a["label"]: a for a in t["per_attack"]}
    from ml.analyze_dataset import display_label
    rows = [[display_label(k), fmt(v["n"]), pct(v.get("recall", v.get("false_positive_rate")), 1),
             "false positive rate" if k == "BENIGN" else "detection rate"] for k, v in tp_.items()]
    R.table("Temporal Protocol: Results per Label on Thursday Afternoon and Friday",
            ["Label", "Test flows", "Value", "Measure"], rows, widths=[1.8, 1.0, 1.0, 1.8],
            align=["left", "right", "right", "left"])
    R.para(
        "DDoS is still detected because its HTTP flooding resembles the DoS attacks of Wednesday that the model "
        "did see. PortScan and Bot, which never occurred on Monday to Wednesday, are almost entirely missed "
        f"({pct(tp_['PortScan']['recall'], 1)} and {pct(tp_['Bot']['recall'], 1)}). A supervised model recognises "
        "attacks that resemble its training examples; it does not detect attack types it has never seen. A "
        "random split hides this because every attack type is present in training, which is why the very "
        "high scores commonly reported on CIC-IDS2017 do not predict performance on new traffic [14], [15]."
    )
    R.para(
        f"The temporal protocol also tests the reliability layer's assumptions. The threshold was calibrated on "
        f"Thursday morning for α = {pct(rel['alpha'], 0)}, yet the false positive rate on the later days is "
        f"{pct(t2['false_positive_rate'], 2)}, and the review band grows to "
        f"{pct(t['reliability']['review_rate'], 1)} of the traffic. Risk control is only guaranteed when the "
        "calibration and test traffic come from the same distribution; across days they do not. The calibration "
        f"error rises from {P['original']['probability_quality']['ece_calibrated']:.4f} on the random split to "
        f"{t['probability_quality']['ece_calibrated']:.3f}. This is precisely the situation the batch shift gate "
        "is designed to warn about."
    )

    # ---------------------------------------------------------------- 7.7
    gate = M["shift_gate"]
    R.heading("7.7", "Batch shift gate")
    kinds = {"scaled": "Every feature × 5", "noised": "Gaussian noise (1 s.d.)", "mean_shifted": "Mean + 2 s.d.",
             "permuted": "Columns shuffled independently"}
    R.para(
        f"The gate was evaluated on {gate['n_in']} in-distribution batches of benign validation flows and on "
        f"synthetic shifted batches ({R.next_table})."
    )
    R.table("Shift Gate on In-Distribution and Synthetic Shifted Batches",
            ["Shift type", "Mean score", "Detection rate", "AUC"],
            [[kinds[k], f"{v['shifted_mean']:.2f}", pct(v["detection_rate"], 0), f"{v['auc']:.3f}"]
             for k, v in gate["by_kind"].items()],
            widths=[2.4, 1.1, 1.2, 0.8], align=["left", "right", "right", "right"])
    R.para(
        f"No in-distribution batch was flagged (mean score {gate['in_distribution_mean']:.2f}, threshold "
        f"{gate['threshold']:.2f}), and scaled, noisy and mean-shifted batches were all detected. Shuffling each "
        "column independently is a deliberate negative control: it destroys the relationships between features "
        "but leaves every single-feature distribution unchanged, so a per-feature Kolmogorov–Smirnov test cannot "
        f"see it, and the gate's detection rate is {pct(gate['by_kind']['permuted']['detection_rate'], 0)}. "
        f"{R.next_fig} shows the gate applied to each capture day of the test set."
    )
    R.figure(D / "exp_shift_per_day.png", "Batch Shift Score of Each Capture Day in the Test Set")
    flagged = [d for d, v in gate["per_day"].items() if v["verdict"] != "in_distribution"]
    R.para(
        f"Only {', '.join(flagged)} exceeds the limit; the features whose distribution moved most on that day are "
        + ", ".join(f["feature"] for f in gate["per_day"][flagged[0]]["top_shifted_features"][:3])
        + ". The other days, including those with attacks, stay below it because the gate judges only the "
        "traffic the model did not flag. The gate also "
        "flagged the deliberately shifted demonstration file (score "
        f"{API['shifted']['shift']['score']:.1f}) and, instructively, a contiguous slice of the first 5,000 rows of "
        f"the raw Wednesday file (score {API['raw_wed']['shift']['score']:.1f}), although that slice is benign "
        "traffic from the training period. A few minutes of traffic from one part of one day does not look like "
        "a whole day's mixture, so the verdict should be read as \"this batch is unlike the reference\", not as "
        "\"this batch is malicious\"."
    )

    # ---------------------------------------------------------------- 7.8
    R.heading("7.8", "Feature importance")
    R.figure(F / "fig_feature_importance.png", "Fifteen Most Important Features of the Random Forest")
    imp = M["feature_importances"]
    length_share = sum(i["importance"] for i in imp if "Length" in i["feature"] or "Size" in i["feature"]
                       or "Bytes" in i["feature"])
    port_rank = next((i for i, f in enumerate(imp, 1) if f["feature"] == "Destination Port"), None)
    R.para(
        f"{R.prev_fig} shows the features with the largest mean decrease in impurity. Packet-size features "
        f"dominate: {imp[0]['feature']} ({pct(imp[0]['importance'], 1)}), {imp[1]['feature']}, {imp[2]['feature']} "
        f"and {imp[3]['feature']} lead the ranking, and size-related features account for {pct(length_share, 0)} "
        "of the importance among the top fifteen. Attacked web servers return a mixture of large pages and small "
        "error responses, so the size variation of backward packets is high for DoS and DDoS flows and low for "
        "typical benign flows."
    )
    R.para(
        f"Because many features are almost perfectly correlated ({R.refs['corr']}), the importance of a property "
        "is spread over its copies; Packet Length Variance and Packet Length Std, for example, carry the same "
        "information. The ranking should therefore be read at the level of properties: packet sizes and byte "
        "totals first"
        + (f", the destination port next (rank {port_rank})" if port_rank else "")
        + ", and timing, flag and TCP window features further down."
    )

    # ---------------------------------------------------------------- 7.9
    R.heading("7.9", "Results on the demonstration files")
    d = API["demo"]
    ev = d["evaluation"]
    R.para(
        f"The demonstration file demo_test_flows.csv contains {fmt(d['summary']['total'])} labelled flows from the "
        f"test set. Through the running application {fmt(d['summary']['benign'])} were decided benign, "
        f"{fmt(d['summary']['malicious'])} malicious and {fmt(d['summary']['review'])} were sent to review. The "
        f"binary prediction agreed with the label for {fmt(ev['correct'])} flows ({pct(ev['accuracy'])}); the "
        f"alerts had a precision of {pct(ev['alert_precision'], 1)} and caught {pct(ev['alert_recall'], 1)} of the "
        f"{ev['actual_malicious']} malicious flows. The batch was judged in distribution (shift score "
        f"{d['shift']['score']:.2f}). The deliberately shifted copy demo_shifted_flows.csv was flagged as severely "
        "shifted with a warning not to trust its per-flow predictions, and the invalid file was rejected with the "
        "list of missing columns."
    )

    # ---------------------------------------------------------------- 7.10
    R.heading("7.10", "Limitations and threats to validity")
    R.bullets([
        "**Unseen attack types.** The temporal experiment shows that the model detects attacks similar to those in "
        "its training data but misses new attack types. The random-split scores overstate real-world performance.",
        "**Single laboratory network.** All traffic comes from one testbed recorded in 2017 [14], [15].",
        "**Dataset errors.** Engelen et al. [20] and Lanvin et al. [21] found labelling mistakes and flow-meter "
        "artefacts in CIC-IDS2017. This analysis found further artefacts: negative durations, Fwd PSH Flags "
        "identical to SYN Flag Count, and bulk features that are always zero. Class imbalance was also noted by "
        "Panigrahi and Borah [42].",
        "**Rare labels.** Heartbleed, Infiltration and SQL injection have too few flows for reliable learning or "
        "evaluation.",
        "**Risk-control assumption.** The false-positive guarantee holds only for traffic that resembles the "
        "calibration data; under the temporal protocol it was exceeded.",
        "**Shift gate scope.** The gate compares single-feature distributions, so it cannot detect changes in the "
        "relationships between features, and short contiguous slices of normal traffic can be flagged.",
        "**Binary output.** The system says whether a flow is malicious, not which attack it belongs to.",
    ])

    # ---------------------------------------------------------------- 7.11
    R.heading("7.11", "Cost analysis")
    R.para(
        "The project uses only open-source software and a public dataset, and it runs on an ordinary laptop. "
        f"{R.next_table} lists the cost items."
    )
    R.table("Project Cost", ["Item", "Choice", "Cost"], [
        ["Dataset", "CIC-IDS2017 (public)", "Free"],
        ["Programming languages and libraries", "Python, scikit-learn, SciPy, FastAPI, React, Vite, Tailwind, Recharts", "Free (open source)"],
        ["Hardware", "Existing laptop (Intel Core i5, 8 GB RAM)", "No additional cost"],
        ["Hosting for the demonstration", "Local machine (single process on one port)", "Free"],
        ["Computation", "A few minutes of training and analysis", "Negligible electricity"],
    ], widths=[2.0, 2.8, 1.2])


# =========================================================================== CHAPTER 8
def chapter8(R: Report, A: dict, M: dict, E: dict) -> None:
    rf = next(m for m in M["models"] if m["name"] == "Random Forest")
    rel = M["reliability"]
    t = E["protocols"]["temporal"]
    dep = rel["variants"][2]
    R.chapter("Summary")
    R.para(
        "NetGuard AI is a complete, working system for malware and intrusion detection based on AI-driven "
        "analysis of network flows. Its machine learning pipeline turns the eight CIC-IDS2017 files into a "
        "clean, deduplicated and correctly split dataset; three classifiers are trained and compared; and the "
        "selected Random Forest, wrapped in a reliability layer, is served through a validated FastAPI backend "
        "and a React dashboard that shows real predictions and real evaluation results."
    )
    R.para(
        "The dataset received particular attention. The analysis of all "
        f"{fmt(A['raw_rows'])} flows showed that {pct((A['raw_rows'] - A['dedup_rows']) / A['raw_rows'], 1)} of the "
        "rows are exact duplicates, concentrated in the attack labels PortScan and SSH-Patator; that rate "
        "features contain infinite and missing values because of zero-duration flows; that the -1 values in the "
        "window features are protocol sentinels for UDP rather than errors; that eight features are constant and "
        "several others are exact copies; and that the attack labels are distributed extremely unevenly, from "
        "231,073 DoS Hulk flows to 11 Heartbleed flows. Each finding led to a specific design decision."
    )
    R.para(
        f"On {fmt(M['split']['test'])} unseen test flows from a random split, the Random Forest achieved an accuracy "
        f"of {pct(rf['accuracy'])}, precision of {pct(rf['precision'])}, recall of {pct(rf['recall'])} and an "
        f"F1-score of {pct(rf['f1_score'])}, with a ROC AUC of {A['curves']['Random Forest']['roc_auc']:.4f}. The "
        f"reliability layer raised recall to {pct(dep['recall'])} while keeping the false positive rate at "
        f"{pct(dep['false_positive_rate'], 2)}, within the chosen budget of {pct(rel['alpha'], 0)}, and sent the "
        "flows it could not judge, including the unseen Heartbleed flows, to review."
    )
    R.para(
        "The most important finding concerns generalisation. When the model is trained on Monday to Wednesday "
        f"and tested on later days, recall falls to {pct(t['variants'][0]['recall'], 1)}: attacks similar to "
        "those in training (DDoS) are still detected, but attack types that never occurred in training "
        "(PortScan, Bot) are almost entirely missed, and the false-positive guarantee no longer holds. The very "
        "high scores of the random split therefore describe recognition of known attacks, not detection of new "
        "ones, and this is a property of how the dataset is split rather than of the model."
    )
    R.para("Based on these findings, the following recommendations are made:")
    R.bullets([
        "**Evaluate on unseen days or networks.** Report a temporal or cross-dataset result alongside any random "
        "split; it is the honest estimate of real-world performance.",
        "**Stratify on the attack label.** Stratifying the sample and split on the original attack label instead "
        "of the binary class would guarantee that every attack type appears in training, validation and test.",
        "**Keep every flow of rare labels.** Including all Heartbleed, Infiltration, SQL injection and Bot flows "
        "in the training data, or oversampling them (for example with SMOTE [43]), would give the model enough "
        "examples to learn from.",
        "**Recalibrate when the shift gate fires.** A shift warning means the alert threshold may no longer meet "
        "its budget; the calibration set should then be refreshed with recent traffic.",
        "**Use a corrected version of the dataset.** The relabelled CIC-IDS2017 released by Engelen et al. [20] "
        "fixes known labelling and flow-meter errors and should be used for further work.",
        "**Extend the system.** Multi-class output (naming the attack), live flow capture with CICFlowMeter and an "
        "anomaly detector for attack types absent from training are natural next steps.",
    ])
    R.para(
        "The project demonstrates that a small, explainable system built from standard tools can detect most "
        "known network attacks in a realistic dataset very accurately, that it can be made to state how far its "
        "decisions can be trusted, and that understanding the dataset is as important as choosing the model."
    )


# =========================================================================== CHAPTER 9
REFERENCES = [
    "J. F. Kurose and K. W. Ross, *Computer Networking: A Top-Down Approach*, 8th ed. Hoboken, NJ, USA: Pearson, 2021.",
    "A. S. Tanenbaum, N. Feamster and D. J. Wetherall, *Computer Networks*, 6th ed. Pearson, 2021.",
    "W. Eddy, Ed., \"Transmission Control Protocol (TCP),\" IETF, RFC 9293, Aug. 2022.",
    "J. Postel, \"User Datagram Protocol,\" IETF, RFC 768, Aug. 1980.",
    "K. Ramakrishnan, S. Floyd and D. Black, \"The Addition of Explicit Congestion Notification (ECN) to IP,\" IETF, RFC 3168, Sep. 2001.",
    "B. Claise, Ed., \"Cisco Systems NetFlow Services Export Version 9,\" IETF, RFC 3954, Oct. 2004.",
    "B. Claise, B. Trammell and P. Aitken, Eds., \"Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information,\" IETF, RFC 7011, Sep. 2013.",
    "G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun and A. A. Ghorbani, \"Characterization of encrypted and VPN traffic using time-related features,\" in *Proc. 2nd Int. Conf. Information Systems Security and Privacy (ICISSP)*, 2016, pp. 407–414.",
    "A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun and A. A. Ghorbani, \"Characterization of Tor traffic using time based features,\" in *Proc. 3rd Int. Conf. Information Systems Security and Privacy (ICISSP)*, 2017, pp. 253–262.",
    "D. E. Denning, \"An intrusion-detection model,\" *IEEE Transactions on Software Engineering*, vol. SE-13, no. 2, pp. 222–232, Feb. 1987.",
    "A. L. Buczak and E. Guven, \"A survey of data mining and machine learning methods for cyber security intrusion detection,\" *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153–1176, 2016.",
    "L. Breiman, \"Random forests,\" *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.",
    "L. Breiman, J. H. Friedman, R. A. Olshen and C. J. Stone, *Classification and Regression Trees*. Belmont, CA, USA: Wadsworth, 1984.",
    "R. Sommer and V. Paxson, \"Outside the closed world: On using machine learning for network intrusion detection,\" in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305–316.",
    "D. Arp et al., \"Dos and don'ts of machine learning in computer security,\" in *Proc. 31st USENIX Security Symposium*, 2022, pp. 3971–3988.",
    "M. Ring, S. Wunderlich, D. Scheuring, D. Landes and A. Hotho, \"A survey of network-based intrusion detection data sets,\" *Computers & Security*, vol. 86, pp. 147–167, 2019.",
    "M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, \"A detailed analysis of the KDD CUP 99 data set,\" in *Proc. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*, 2009, pp. 1–6.",
    "N. Moustafa and J. Slay, \"UNSW-NB15: A comprehensive data set for network intrusion detection systems,\" in *Proc. Military Communications and Information Systems Conference (MilCIS)*, 2015, pp. 1–6.",
    "I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, \"Toward generating a new intrusion detection dataset and intrusion traffic characterization,\" in *Proc. 4th Int. Conf. Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108–116. Dataset: https://www.unb.ca/cic/datasets/ids-2017.html",
    "G. Engelen, V. Rimmer and W. Joosen, \"Troubleshooting an intrusion detection dataset: The CICIDS2017 case study,\" in *Proc. IEEE Security and Privacy Workshops (SPW)*, 2021, pp. 7–12.",
    "M. Lanvin, P.-F. Gimenez, Y. Han, F. Majorczyk, L. Mé and É. Totel, \"Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes,\" in *Risks and Security of Internet and Systems (CRiSIS 2022)*, LNCS, vol. 13857. Springer, 2023, pp. 18–33.",
    "Z. Durumeric et al., \"The matter of Heartbleed,\" in *Proc. ACM Internet Measurement Conference (IMC)*, 2014, pp. 475–488.",
    "H. He and E. A. Garcia, \"Learning from imbalanced data,\" *IEEE Transactions on Knowledge and Data Engineering*, vol. 21, no. 9, pp. 1263–1284, 2009.",
    "F. Pedregosa et al., \"Scikit-learn: Machine learning in Python,\" *Journal of Machine Learning Research*, vol. 12, pp. 2825–2830, 2011.",
    "J. R. Quinlan, \"Induction of decision trees,\" *Machine Learning*, vol. 1, no. 1, pp. 81–106, 1986.",
    "D. R. Cox, \"The regression analysis of binary sequences,\" *Journal of the Royal Statistical Society: Series B*, vol. 20, no. 2, pp. 215–242, 1958.",
    "T. Fawcett, \"An introduction to ROC analysis,\" *Pattern Recognition Letters*, vol. 27, no. 8, pp. 861–874, 2006.",
    "T. Saito and M. Rehmsmeier, \"The precision-recall plot is more informative than the ROC plot when evaluating binary classifiers on imbalanced datasets,\" *PLoS ONE*, vol. 10, no. 3, e0118432, 2015.",
    "J. Postel, \"Internet Protocol,\" IETF, RFC 791, Sep. 1981.",
    "R. Fielding, M. Nottingham and J. Reschke, Eds., \"HTTP Semantics,\" IETF, RFC 9110, Jun. 2022.",
    "L. Masinter, \"Returning Values from Forms: multipart/form-data,\" IETF, RFC 7578, Jul. 2015.",
    "Y. Shafranovich, \"Common Format and MIME Type for Comma-Separated Values (CSV) Files,\" IETF, RFC 4180, Oct. 2005.",
    "T. Bray, Ed., \"The JavaScript Object Notation (JSON) Data Interchange Format,\" IETF, RFC 8259, Dec. 2017.",
    "OpenAPI Initiative, \"OpenAPI Specification v3.1.0,\" Feb. 2021. [Online]. Available: https://spec.openapis.org/oas/v3.1.0",
    "G. van Rossum, B. Warsaw and N. Coghlan, \"PEP 8 – Style Guide for Python Code,\" Python Software Foundation, 2001. [Online]. Available: https://peps.python.org/pep-0008/",
    "W3C, \"Web Content Accessibility Guidelines (WCAG) 2.2,\" W3C Recommendation, Oct. 2023.",
    "B. Zadrozny and C. Elkan, \"Transforming classifier scores into accurate multiclass probability estimates,\" in *Proc. 8th ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining*, 2002, pp. 694–699.",
    "A. N. Angelopoulos, S. Bates, A. Fisch, L. Lei and T. Schuster, \"Conformal risk control,\" in *Proc. Int. Conf. Learning Representations (ICLR)*, 2024. arXiv:2208.02814.",
    "F. J. Massey, \"The Kolmogorov-Smirnov test for goodness of fit,\" *Journal of the American Statistical Association*, vol. 46, no. 253, pp. 68–78, 1951.",
    "S. Ramírez, \"FastAPI documentation.\" [Online]. Available: https://fastapi.tiangolo.com",
    "Meta Open Source, \"React documentation.\" [Online]. Available: https://react.dev",
    "R. Panigrahi and S. Borah, \"A detailed analysis of CICIDS2017 dataset for designing intrusion detection systems,\" *International Journal of Engineering & Technology*, vol. 7, no. 3.24, pp. 479–482, 2018.",
    "N. V. Chawla, K. W. Bowyer, L. O. Hall and W. P. Kegelmeyer, \"SMOTE: Synthetic minority over-sampling technique,\" *Journal of Artificial Intelligence Research*, vol. 16, pp. 321–357, 2002.",
]


def renumber_citations(R: Report) -> list[str]:
    """Number references in order of first citation (IEEE style).

    Scans every prose run written so far (code listings excluded), maps old
    numbers to new ones in order of appearance, rewrites the runs and returns
    the reference list in the new order. Uncited references are appended."""
    import re
    from report.docx_helpers import MONO

    pattern = re.compile(r"\[(\d+)\]")
    runs = []
    for p in R.doc.paragraphs:
        runs.extend(p.runs)
    for table in R.doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    runs.extend(p.runs)
    # document order: paragraphs and tables interleave, so sort runs by XML position
    body = list(R.doc.element.body.iter())
    position = {id(el): i for i, el in enumerate(body)}
    runs.sort(key=lambda r: position.get(id(r._r), 0))
    order: list[int] = []
    for run in runs:
        if run.font.name == MONO:
            continue
        for m in pattern.finditer(run.text):
            n = int(m.group(1))
            if 1 <= n <= len(REFERENCES) and n not in order:
                order.append(n)
    order += [n for n in range(1, len(REFERENCES) + 1) if n not in order]
    new_number = {old: new for new, old in enumerate(order, 1)}
    for run in runs:
        if run.font.name != MONO and pattern.search(run.text):
            run.text = pattern.sub(lambda m: f"[{new_number.get(int(m.group(1)), int(m.group(1)))}]", run.text)
    return [REFERENCES[n - 1] for n in order]


def chapter9(R: Report, references: list[str]) -> None:
    R.chapter("References")
    for i, ref in enumerate(references, 1):
        p = R.doc.add_paragraph()
        p.paragraph_format.left_indent = __import__("docx.shared", fromlist=["Inches"]).Inches(0.45)
        p.paragraph_format.first_line_indent = __import__("docx.shared", fromlist=["Inches"]).Inches(-0.45)
        p.paragraph_format.space_after = __import__("docx.shared", fromlist=["Pt"]).Pt(4)
        R._add_inline(p, f"[{i}]\t{ref}", size=11)


# =========================================================================== APPENDIX
def appendix(R: Report, A: dict, M: dict, API: dict) -> None:
    R.centered("APPENDIX A", size=14, bold=True, space_after=6)
    p = R.centered("PROJECT FILES, API EXAMPLE AND MODEL FEATURES", size=14, bold=True, space_after=18)
    R._mark(p, "C", 1, "", "APPENDIX A")
    R.first_paragraph = True
    R.chapter_no = "A"
    R.fig_no = R.table_no = 0

    R.heading("A.1", "Repository structure")
    R.code(
        "NetGuardAI/\n"
        "├── ml/                      config.py, preprocess.py, train.py, reliability.py,\n"
        "│                            experiments.py, analyze_dataset.py\n"
        "├── backend/app/             main.py (FastAPI), model_store.py\n"
        "├── backend/tests/           conftest.py, test_api.py, test_reliability.py, test_training.py\n"
        "├── frontend/src/            App.tsx, api.ts, format.ts, index.css, components/\n"
        "├── dataset/raw/             CIC-IDS2017 CSV files (not in git, ≈844 MB)\n"
        "├── dataset/samples/         demo_test_flows.csv, demo_unlabeled_flows.csv,\n"
        "│                            invalid_missing_columns.csv, demo_shifted_flows.csv\n"
        "├── dataset/faculty_tests/   14 test files for evaluators\n"
        "├── models/                  netguard_model.joblib\n"
        "├── reports/                 metrics.json, experiments.json, dataset_analysis.json, figures/\n"
        "├── report/                  scripts that generate this document\n"
        "├── docs/                    screenshots/, demo/, report/ (this document)\n"
        "├── start.sh, stop.sh        start and stop the whole application\n"
        "├── requirements.txt\n"
        "└── README.md", size=9)

    R.heading("A.2", "Example API response")
    R.para("Response of POST /api/predict for demo_test_flows.csv, recorded from the running application "
           "(only the first row of the table is shown):")
    import json as _json
    example = dict(API["demo"])
    example["rows"] = example["rows"][:1]
    R.code(_json.dumps(example, indent=2), size=8)

    R.heading("A.3", "Features required by the model")
    R.para(f"An uploaded CSV must contain the following {M['features']['count']} columns (names are matched after stripping spaces):")
    names = M["features"]["names"]
    cols = 3
    per = -(-len(names) // cols)
    rows = []
    for i in range(per):
        rows.append([f"{i + 1 + c * per}. {names[i + c * per]}" if i + c * per < len(names) else "" for c in range(cols)])
    t_no = R.table_no
    R.table_no = t_no
    R.chapter_no = "A"
    R.table("Model Input Features", ["Features 1–23", "Features 24–46", "Features 47–69"], rows,
            widths=[2.0, 2.0, 2.0], font_size=9)

    R.heading("A.4", "Demonstration and test files")
    R.table("Demonstration and Test Files", ["File", "Content", "Purpose"], [
        ["demo_test_flows.csv", "2,000 real flows from the held-out test set, with Label", "Shows predictions and agreement with labels"],
        ["demo_unlabeled_flows.csv", "The same 2,000 flows without the Label column", "Shows prediction on unlabelled traffic"],
        ["invalid_missing_columns.csv", "50 flows with three required columns removed", "Shows input validation"],
        ["demo_shifted_flows.csv", "The demo flows with every feature scaled far out of range", "Shows the shift warning"],
        ["faculty_tests/ (14 files)", "Small and large mixed, benign-only, attack-only, extra columns, missing values, non-numeric values, missing columns, empty, wrong extension, mildly and severely shifted, one flow per attack, unlabelled", "Lets an evaluator test every behaviour"],
    ], widths=[1.8, 2.4, 1.8])
