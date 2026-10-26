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
    ("Backend tests and integration", 10, 1),
    ("Dataset analysis for the report", 10, 2),
    ("Report, viva guide, demo", 11, 2),
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
        ["9", "Backend tests and integration", "W10", "17 passing tests, production build"],
        ["10", "Dataset analysis for the report", "W10–W11", "dataset_analysis.json, figures"],
        ["11", "Report, viva guide and demonstration", "W11–W12", "This report, docs/VIVA_GUIDE.md"],
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
        ["M6 Verified", "W10", "17 backend tests pass; frontend production build succeeds; browser test passes"],
        ["M7 Submitted", "W12", "Report, viva guide and demonstration complete"],
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

    R.heading("6.1.2", "Cleaning, deduplication and splitting (ml/train.py)", level=3)
    R.para("clean_frame() applies the cleaning steps to one raw file; remove_duplicates() hashes rows; split_data() makes the stratified 72/8/20 split.")
    R.code(source_of("ml/train.py", "clean_frame", "remove_duplicates", "split_data"))

    R.heading("6.1.3", "Model definitions and selection (ml/train.py)", level=3)
    R.para("Each model is a Pipeline, so the imputer (and scaler) is saved with it. select_model() applies the validation-set rule.")
    R.code(source_of("ml/train.py", "build_models", "evaluate", "select_model"))

    R.heading("6.1.4", "Loading the model and predicting (backend/app/model_store.py)", level=3)
    R.code(source_of("backend/app/model_store.py", "ModelStore"))

    R.heading("6.1.5", "Upload validation and the prediction endpoint (backend/app/main.py)", level=3)
    R.code(source_of("backend/app/main.py", "read_csv_upload"))
    R.code(lines_of("backend/app/main.py", '@app.post("/api/predict")', '@app.post("/api/predict/download")'))

    R.heading("6.1.6", "Frontend API client (frontend/src/api.ts)", level=3)
    R.para("The client turns HTTP errors into readable messages and keeps the list of offending columns for the error box.")
    R.code(lines_of("frontend/src/api.ts", "async function request(", "export async function getHealth"))

    R.heading("6.1.7", "Automated tests (backend/tests/test_api.py)", level=3)
    R.para("The tests use a synthetic model, so they check the API behaviour without needing the real dataset.")
    R.code(source_of("backend/tests/test_api.py", "test_predict_returns_counts_for_every_row",
                     "test_missing_columns_are_rejected", "test_predict_without_model_returns_503"))

    R.heading("6.1.8", "Per-attack evaluation (ml/analyze_dataset.py)", level=3)
    R.para("The dataset analysis rebuilds the split, verifies it against the saved results and computes the detection rate per attack label.")
    R.code(lines_of("ml/analyze_dataset.py", "# Sanity check: the rebuilt split", 'result["rf_errors_by_label"]'))

    R.heading("6.1.9", "Running the project", level=3)
    R.para("The complete project is run with the commands below, from the project folder.")
    R.code(
        "# 1. Install dependencies\n"
        "python3 -m venv .venv && source .venv/bin/activate\n"
        "pip install -r requirements.txt\n"
        "cd frontend && npm install && cd ..\n\n"
        "# 2. Train the models (dataset in dataset/raw/) and analyse the dataset\n"
        "python -m ml.train\n"
        "python -m ml.analyze_dataset\n\n"
        "# 3. Start the backend (port 8000) and the frontend (port 5173)\n"
        "uvicorn backend.app.main:app --port 8000\n"
        "cd frontend && npm run dev\n\n"
        "# 4. Run the tests\n"
        "pytest", size=9)
    R.para("The training script prints its progress and results; the log of the run used in this report is:")
    log = (ROOT / "reports" / "training_log.txt").read_text().strip()
    R.code(log, size=8.5)

    R.heading("6.2", "Sample Screen Shots")
    shots = [
        ("shot_home.png", "Dashboard on Start-Up With the Model Status and Upload Panel",
         "When the dashboard opens it calls /api/health and shows that the Random Forest model with 69 features "
         "is loaded. The upload panel accepts a CSV file by clicking or by drag and drop."),
        ("shot_summary.png", "Analysis Summary for 2,000 Held-Out Test Flows",
         "After demo_test_flows.csv (2,000 real flows from the test set) is analysed, the summary cards show "
         "1,679 benign and 321 malicious predictions. Because the file contains the original labels, the "
         "dashboard also reports that 1,998 of the 2,000 predictions (99.90%) agree with them."),
        ("shot_results_table.png", "Prediction Results Table With Probabilities and Actual Labels",
         "The results table shows readable flow features, the Random Forest's malicious probability, the "
         "prediction and the actual label. The Download CSV button returns the full file with two added columns."),
        ("shot_misclassified.png", "Results Filtered to the Misclassified Flows",
         "The Misclassified filter isolates the two flows on which the model disagrees with the dataset label, "
         "which is useful for error analysis during a demonstration."),
        ("shot_validation_error.png", "Validation Error for a File With Missing Feature Columns",
         "Uploading invalid_missing_columns.csv, from which three required features were removed, produces a "
         "clear error listing the missing columns instead of a wrong prediction."),
        ("shot_model_comparison.png", "Model Comparison Table and Chart in the Dashboard",
         "The evaluation section reads reports/metrics.json and shows the test-set metrics of all three models, "
         "the validation F1 used for selection and the training time."),
        ("shot_confusion_training.png", "Confusion Matrix and Training Data Summary",
         "The confusion matrix can be switched between models. The training data card shows the raw and used "
         "flow counts and the stratified train / validation / test split."),
        ("shot_features.png", "Most Important Features of the Random Forest Model", ""),
        ("shot_api_docs.png", "Interactive API Documentation Generated by FastAPI",
         "FastAPI generates OpenAPI 3.1 documentation at /docs, where every endpoint can be tried from the browser."),
    ]
    for name, caption, text in shots:
        if text:
            R.para(text)
        R.figure(S / name, caption, 6.0)
    R.para(
        "The layout adapts to small screens. On a 390-pixel-wide phone the cards stack vertically and the "
        f"results table scrolls horizontally inside its own frame, as shown in {R.next_fig}."
    )
    R.figure(S / "shot_mobile.png", "Dashboard on a 390-Pixel-Wide Mobile Screen", 2.6)


# =========================================================================== CHAPTER 7
def chapter7(R: Report, A: dict, M: dict, F: Path) -> None:
    models = {m["name"]: m for m in M["models"]}
    rf, dt, lr = models["Random Forest"], models["Decision Tree"], models["Logistic Regression"]
    curves = A["curves"]
    R.chapter("Result & Discussion")
    R.para(
        "This chapter presents the evaluation of the three models on the held-out test set of "
        f"{fmt(M['split']['test'])} flows, breaks the results down by attack type, explains which features drive "
        "the decisions and discusses the limitations that come from the dataset. All numbers are produced by "
        "ml/train.py and ml/analyze_dataset.py."
    )

    R.heading("7.1", "Overall model comparison")
    R.table("Test-Set Performance of the Three Models (Positive Class = Malicious)",
            ["Model", "Accuracy", "Precision", "Recall", "F1-score", "Validation F1", "Train time"],
            [[m["name"], pct(m["accuracy"]), pct(m["precision"]), pct(m["recall"]), pct(m["f1_score"]),
              pct(m["validation_f1"]), f"{m['train_seconds']:.1f} s"] for m in M["models"]],
            widths=[1.35, 0.75, 0.75, 0.7, 0.75, 0.9, 0.8], align=["left"] + ["right"] * 6)
    R.figure(F / "fig_model_comparison.png", "Accuracy, Precision, Recall and F1-Score of the Three Models")
    R.para(
        f"Random Forest and Decision Tree are almost tied, with F1-scores of {pct(rf['f1_score'])} and "
        f"{pct(dt['f1_score'])}. Random Forest has the higher precision ({pct(rf['precision'])} against "
        f"{pct(dt['precision'])}), meaning fewer false alarms, whereas Decision Tree has a slightly higher recall "
        f"({pct(dt['recall'])} against {pct(rf['recall'])}). Logistic Regression is clearly weaker, with an "
        f"F1-score of {pct(lr['f1_score'])}: its single linear boundary cannot capture the threshold-like, "
        "non-linear patterns revealed by the exploratory analysis, such as a flow being suspicious when it is "
        "very short and targets an unusual port, or very long and almost silent."
    )
    R.para(
        f"On the validation set Decision Tree scored {pct(dt['validation_f1'])} and Random Forest "
        f"{pct(rf['validation_f1'])}. The difference of {100 * (dt['validation_f1'] - rf['validation_f1']):.2f} "
        "percentage points, about one or two flows, is below the 0.001 selection margin, so the primary model, "
        "Random Forest, was kept. The test results support the choice, since Random Forest leads on accuracy, "
        "precision and F1. Accuracy is high for all models partly because 83% of the test flows are benign, "
        "which is why the following sections rely on per-class measures."
    )

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
        f"Out of {fmt(tn + fp)} benign test flows, Random Forest raised {fp} false alarms, a false positive rate "
        f"of {pct(fp / (fp + tn), 3)}. Out of {fmt(fn + tp)} malicious flows it missed {fn}. For an operator this "
        f"means that roughly one alert in {round((tp + fp) / fp)} is a false alarm and roughly one attack flow in "
        f"{round((tp + fn) / fn)} is missed. Logistic Regression would produce "
        f"{fmt(lr['confusion_matrix'][0][1])} false alarms and miss {fmt(lr['confusion_matrix'][1][0])} attack flows "
        "on the same traffic, a workload that would quickly make the alerts useless."
    )

    R.heading("7.3", "Threshold-independent evaluation")
    R.para(
        f"The metrics above use a fixed threshold of 0.5 on the malicious probability. {R.next_fig} shows the ROC "
        "and precision–recall curves, which summarise performance over all thresholds [27], [28]; the false "
        "positive rate is plotted on a logarithmic axis because the interesting region is below 1%."
    )
    R.figure(F / "fig_roc_pr.png", "ROC and Precision–Recall Curves on the Test Set")
    R.table("Area Under the ROC Curve and Average Precision", ["Model", "ROC AUC", "Average precision"],
            [[name, f"{c['roc_auc']:.5f}", f"{c['average_precision']:.5f}"] for name, c in curves.items()],
            widths=[2.0, 1.4, 1.6], align=["left", "right", "right"])
    R.para(
        f"Random Forest reaches a ROC AUC of {curves['Random Forest']['roc_auc']:.4f} and an average precision of "
        f"{curves['Random Forest']['average_precision']:.4f}. Its curve dominates the others at every false "
        "positive rate, so its advantage is not an artefact of the chosen threshold. The Decision Tree's curve has "
        "few points because an unpruned tree outputs almost only probabilities of 0 or 1. "
        f"{R.next_fig} shows that the Random Forest's probabilities are also well separated: most benign test "
        "flows receive a probability close to 0 and most malicious flows a probability close to 1, with few "
        "flows near the threshold."
    )
    R.figure(F / "fig_probability_hist.png", "Distribution of the Random Forest Malicious Probability by Actual Class")

    R.heading("7.4", "Detection rate per attack type")
    R.para(
        "Because the test set keeps the original attack names, the recall can be computed for each attack "
        f"label separately. This is the most informative result about the dataset. {R.next_fig} and "
        f"{R.next_table} show the detection rate per label; for BENIGN the value is the share correctly passed."
    )
    R.figure(F / "fig_per_attack_recall.png", "Detection Rate per Attack Label on the Test Set")
    det, support, errors = A["per_label_detection"], A["test_support"], A["rf_errors_by_label"]
    rows = []
    for label in sorted(support, key=lambda k: -support[k]):
        rows.append([label, fmt(support[label]), pct(det["Random Forest"][label], 1),
                     pct(det["Decision Tree"][label], 1), pct(det["Logistic Regression"][label], 1),
                     fmt(errors[label])])
    R.table("Detection Rate per Label on the Test Set", ["Label", "Test flows", "RF", "DT", "LR", "RF errors"],
            rows, widths=[1.9, 0.85, 0.75, 0.75, 0.75, 0.8], align=["left"] + ["right"] * 5)
    rfd = det["Random Forest"]
    big = [k for k in support if support[k] >= 100 and k != "BENIGN"]
    R.para(
        f"Every attack label with at least 100 test flows is detected at a rate of {pct(min(rfd[k] for k in big), 1)} "
        "or higher by Random Forest, and FTP-Patator, SSH-Patator and DoS slowloris are detected completely. "
        "These are the labels with distinctive profiles in Table 4.6: fixed target ports, characteristic packet "
        "counts and durations that benign traffic rarely shows."
    )
    R.para(
        f"The weak points are Bot, Infiltration and Heartbleed. Random Forest detects {pct(rfd['Bot'], 1)} of the "
        f"{support['Bot']} Bot flows, {round(rfd['Infiltration'] * support['Infiltration'])} of "
        f"{support['Infiltration']} Infiltration flows and none of the {support['Heartbleed']} Heartbleed flows. "
        "The cause is visible in the dataset analysis. Bot traffic consists of short, low-volume HTTP exchanges "
        "with a command-and-control server (median three packets each way, Table 4.6), which look very similar to "
        "ordinary web requests. Infiltration and Heartbleed are so rare that the training set contained only "
        f"{A['split_label_counts']['train'].get('Infiltration', 0)} and "
        f"{A['split_label_counts']['train'].get('Heartbleed', 0)} examples (Table 4.9). A Random Forest averages "
        "the votes of trees that each saw a bootstrap sample in which these examples may be absent, so it "
        "tends to assign such isolated patterns to the majority class."
    )
    R.para(
        f"Decision Tree detects more Bot flows ({pct(det['Decision Tree']['Bot'], 1)}) because a single unpruned "
        "tree isolates even one or two training examples in their own leaves, the same property that makes it "
        "overfit elsewhere. Logistic Regression catches all three Heartbleed flows, whose thousands of packets "
        "and bytes lie far out on the linear scale, but fails completely on SSH-Patator and the web attacks. The "
        "per-attack view therefore shows that the excellent overall F1 hides weaknesses on rare labels that "
        "together make up less than 0.1% of the test set. Since attack types that are rare in a dataset can be "
        "the most dangerous ones in practice, this result is the strongest argument for the dataset "
        "recommendations in Chapter 8."
    )

    R.heading("7.5", "Feature importance")
    R.figure(F / "fig_feature_importance.png", "Fifteen Most Important Features of the Random Forest")
    imp = M["feature_importances"]
    length_share = sum(i["importance"] for i in imp if "Length" in i["feature"] or "Size" in i["feature"]
                       or "Bytes" in i["feature"])
    R.para(
        f"{R.prev_fig} shows the features with the largest mean decrease in impurity. Packet-size features "
        f"dominate: {imp[0]['feature']} ({pct(imp[0]['importance'], 1)}), {imp[1]['feature']}, {imp[2]['feature']} "
        f"and {imp[3]['feature']} lead the ranking, and size-related features account for {pct(length_share, 0)} "
        "of the importance among the top fifteen. This agrees with the exploratory analysis: attacked web "
        "servers return a mixture of large pages and small error responses, so the size variation of backward "
        "packets is high for DoS and DDoS flows and low for typical benign flows."
    )
    R.para(
        "Because many features are almost perfectly correlated (Table 4.7), the importance of a property is "
        "spread over its copies; for example Packet Length Variance and Packet Length Std carry the same "
        "information. The ranking should therefore be read at the level of properties: packet sizes and byte "
        "totals first, the destination port next (rank 11), and timing, flag and TCP window features further "
        "down, rather than as a strict order of individual columns. The destination port matters but is not "
        "decisive, so the model is not merely memorising that port 80 was attacked in this testbed."
    )

    R.heading("7.6", "Results on the demonstration files")
    R.para(
        "The demonstration file demo_test_flows.csv contains 2,000 flows drawn from the test set with their "
        "labels. Through the running application the Random Forest classified 1,998 of them correctly (99.90%), "
        "predicting 321 as malicious against 323 actually malicious flows, which is consistent with the test-set "
        "results. A raw, unmodified file from the original dataset (5,000 Wednesday flows with leading spaces in "
        "the headers and Infinity values) was also accepted and classified, confirming that the API handles the "
        "published format directly."
    )

    R.heading("7.7", "Limitations and threats to validity")
    R.bullets([
        "**Single laboratory network.** All traffic comes from one testbed recorded in 2017. Attack tools, "
        "benign applications and network size differ in real networks, so performance elsewhere will be lower "
        "[14], [15].",
        "**Dataset errors.** Engelen et al. [20] and Lanvin et al. [21] found labelling mistakes and flow-meter "
        "artefacts in CIC-IDS2017, such as flows of failed attack attempts labelled as attacks and incorrectly "
        "terminated TCP flows. This analysis found further artefacts: negative durations, Fwd PSH Flags "
        "identical to SYN Flag Count, and bulk features that are always zero.",
        "**Rare labels.** Heartbleed, Infiltration and SQL injection have too few flows for reliable learning or "
        "evaluation; their test results are based on three to five flows, or none.",
        "**Sampling.** The model uses a 500,000-flow sample of the 2.5 million unique flows. The sample is "
        "stratified on the binary class, so rare labels are represented only by chance.",
        "**Site-specific features.** Destination ports and window sizes partly reflect the testbed's "
        "configuration, and a model may learn them as shortcuts.",
        "**Binary output.** The system says whether a flow is malicious, not which attack it belongs to.",
    ])

    R.heading("7.8", "Cost analysis")
    R.para(
        "The project uses only open-source software and a public dataset, and it runs on an ordinary laptop. "
        f"{R.next_table} lists the cost items."
    )
    R.table("Project Cost", ["Item", "Choice", "Cost"], [
        ["Dataset", "CIC-IDS2017 (public)", "Free"],
        ["Programming languages and libraries", "Python, scikit-learn, FastAPI, React, Vite, Tailwind, Recharts", "Free (open source)"],
        ["Hardware", "Existing laptop (Intel Core i5, 8 GB RAM)", "No additional cost"],
        ["Hosting for the demonstration", "Local machine (single process on one port)", "Free"],
        ["Computation", "About 11 minutes of training, 4 minutes of analysis", "Negligible electricity"],
    ], widths=[2.0, 2.8, 1.2])


# =========================================================================== CHAPTER 8
def chapter8(R: Report, A: dict, M: dict) -> None:
    rf = next(m for m in M["models"] if m["name"] == "Random Forest")
    R.chapter("Summary")
    R.para(
        "NetGuard AI is a complete, working system for malware and intrusion detection based on AI-driven "
        "analysis of network flows. Its machine learning pipeline turns the eight CIC-IDS2017 files into a "
        "clean, deduplicated and correctly split dataset; three classifiers are trained and compared; and the "
        "selected Random Forest is served through a validated FastAPI backend and a React dashboard that shows "
        "real predictions and real evaluation results."
    )
    R.para(
        "The dataset received particular attention. The analysis of all "
        f"{fmt(A['raw_rows'])} flows showed that {pct((A['raw_rows'] - A['dedup_rows']) / A['raw_rows'], 1)} of the "
        "rows are exact duplicates, concentrated in the attack labels PortScan and SSH-Patator; that rate "
        "features contain infinite and missing values because of zero-duration flows; that the -1 values in the "
        "window features are protocol sentinels for UDP rather than errors; that eight features are constant and "
        "several others are exact copies; and that the attack labels are distributed extremely unevenly, from "
        "231,073 DoS Hulk flows to 11 Heartbleed flows. Each finding led to a specific design decision in the "
        "preprocessing pipeline."
    )
    R.para(
        f"On {fmt(M['split']['test'])} unseen test flows the Random Forest achieved an accuracy of "
        f"{pct(rf['accuracy'])}, precision of {pct(rf['precision'])}, recall of {pct(rf['recall'])} and an F1-score "
        f"of {pct(rf['f1_score'])}, with a ROC AUC of {A['curves']['Random Forest']['roc_auc']:.4f}. The Decision "
        "Tree performed almost identically, and Logistic Regression was clearly weaker, which confirms the "
        "non-linear structure of the data. The per-attack analysis showed that the high overall score hides weak "
        "detection of the rarest labels, which is a property of the dataset rather than a defect of the model."
    )
    R.para("Based on these findings, the following recommendations are made:")
    R.bullets([
        "**Stratify on the attack label.** Stratifying the sample and split on the original attack label instead "
        "of the binary class would guarantee that every attack type appears in training, validation and test.",
        "**Keep every flow of rare labels.** Including all Heartbleed, Infiltration, SQL injection and Bot flows "
        "in the training data, or oversampling them (for example with SMOTE [38]), would give the model enough "
        "examples to learn from.",
        "**Use a corrected version of the dataset.** The relabelled CIC-IDS2017 released by Engelen et al. [20] "
        "fixes known labelling and flow-meter errors and should be used for further work.",
        "**Test across datasets.** Training on CIC-IDS2017 and testing on CSE-CIC-IDS2018 or traffic from another "
        "network would measure how well the model generalises beyond one testbed.",
        "**Extend the system.** Multi-class output (naming the attack), live flow capture with CICFlowMeter, and "
        "threshold tuning for a target false-alarm rate are natural next steps.",
    ])
    R.para(
        "The project demonstrates that a small, explainable system built from standard tools can detect most "
        "network attacks in a realistic dataset very accurately, and that understanding the dataset is as "
        "important as choosing the model."
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
    "R. Panigrahi and S. Borah, \"A detailed analysis of CICIDS2017 dataset for designing intrusion detection systems,\" *International Journal of Engineering & Technology*, vol. 7, no. 3.24, pp. 479–482, 2018.",
    "N. V. Chawla, K. W. Bowyer, L. O. Hall and W. P. Kegelmeyer, \"SMOTE: Synthetic minority over-sampling technique,\" *Journal of Artificial Intelligence Research*, vol. 16, pp. 321–357, 2002.",
    "S. Ramírez, \"FastAPI documentation.\" [Online]. Available: https://fastapi.tiangolo.com",
    "Meta Open Source, \"React documentation.\" [Online]. Available: https://react.dev",
]


def chapter9(R: Report) -> None:
    R.chapter("References")
    for i, ref in enumerate(REFERENCES, 1):
        p = R.doc.add_paragraph()
        p.paragraph_format.left_indent = __import__("docx.shared", fromlist=["Inches"]).Inches(0.45)
        p.paragraph_format.first_line_indent = __import__("docx.shared", fromlist=["Inches"]).Inches(-0.45)
        p.paragraph_format.space_after = __import__("docx.shared", fromlist=["Pt"]).Pt(4)
        R._add_inline(p, f"[{i}]\t{ref}", size=11)


# =========================================================================== APPENDIX
def appendix(R: Report, A: dict, M: dict) -> None:
    R.centered("APPENDIX A", size=14, bold=True, space_after=6)
    p = R.centered("PROJECT FILES, API EXAMPLE AND MODEL FEATURES", size=14, bold=True, space_after=18)
    R._mark(p, "C", 1, "", "APPENDIX A")
    R.first_paragraph = True
    R.chapter_no = "A"
    R.fig_no = R.table_no = 0

    R.heading("A.1", "Repository structure")
    R.code(
        "NetGuardAI/\n"
        "├── ml/                      config.py, preprocess.py, train.py, analyze_dataset.py\n"
        "├── backend/app/             main.py (FastAPI), model_store.py\n"
        "├── backend/tests/           conftest.py, test_api.py, test_training.py\n"
        "├── frontend/src/            App.tsx, api.ts, format.ts, index.css, components/\n"
        "├── dataset/raw/             CIC-IDS2017 CSV files (not in git, ≈844 MB)\n"
        "├── dataset/samples/         demo_test_flows.csv, demo_unlabeled_flows.csv,\n"
        "│                            invalid_missing_columns.csv\n"
        "├── models/                  netguard_model.joblib\n"
        "├── reports/                 metrics.json, model_report.md, dataset_analysis.json,\n"
        "│                            training_log.txt, figures/\n"
        "├── report/                  scripts that generate this document\n"
        "├── docs/                    VIVA_GUIDE.md, screenshots/, project report\n"
        "├── requirements.txt\n"
        "└── README.md", size=9)

    R.heading("A.2", "Example API response")
    R.para("Abbreviated response of POST /api/predict for demo_test_flows.csv (first row only):")
    R.code(
        '{\n'
        '  "filename": "demo_test_flows.csv",\n'
        '  "model_name": "Random Forest",\n'
        '  "summary": {"total": 2000, "benign": 1679, "malicious": 321, "malicious_ratio": 0.1605},\n'
        '  "evaluation": {"accuracy": 0.999, "correct": 1998,\n'
        '                 "actual_malicious": 323, "actual_benign": 1677},\n'
        '  "display_columns": ["Destination Port", "Flow Duration", "Total Fwd Packets",\n'
        '                      "Total Backward Packets", "Flow Bytes/s"],\n'
        '  "rows": [{"row": 1,\n'
        '            "values": {"Destination Port": 80.0, "Flow Duration": 10175832.0,\n'
        '                       "Total Fwd Packets": 4.0, "Total Backward Packets": 4.0,\n'
        '                       "Flow Bytes/s": 79.20728},\n'
        '            "prediction": "Benign", "malicious_probability": 0.0, "actual": "Benign"}],\n'
        '  "rows_truncated": false\n'
        '}', size=9)

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

    R.heading("A.4", "Demonstration files")
    R.table("Demonstration Files in dataset/samples", ["File", "Content", "Purpose"], [
        ["demo_test_flows.csv", "2,000 real flows from the held-out test set, with Label", "Shows predictions and agreement with labels"],
        ["demo_unlabeled_flows.csv", "The same 2,000 flows without the Label column", "Shows prediction on unlabelled traffic"],
        ["invalid_missing_columns.csv", "50 flows with three required columns removed", "Shows input validation"],
    ], widths=[1.8, 2.4, 1.8])
