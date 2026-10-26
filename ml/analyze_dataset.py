"""Exploratory analysis of the CIC-IDS2017 dataset used by NetGuard AI.

Usage (from the project root, after downloading the dataset):
    python -m ml.analyze_dataset

It reads the raw CSV files, measures data quality, class/attack distributions,
duplicates, feature statistics, correlations and destination ports, then
rebuilds the *same* sample and train/validation/test split as ml/train.py to
break the detection results down per attack type.

Outputs:
    reports/dataset_analysis.json   every number used in the project report
    reports/figures/*.png           figures for the project report
"""

import json
import time
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from ml import config  # noqa: E402
from ml.preprocess import clean_column_names, to_binary_labels  # noqa: E402
from ml.train import (  # noqa: E402
    build_models,
    clean_frame,
    dataset_files,
    read_raw_csv,
    remove_duplicates,
    split_data,
    stratified_sample,
)

FIGURES_DIR = config.REPORTS_DIR / "figures"
OUTPUT_PATH = config.REPORTS_DIR / "dataset_analysis.json"
SAMPLE_SIZE = 500_000  # must match the default in ml/train.py

# Colours validated for colour-vision deficiency on a white page.
BLUE, ORANGE, AQUA, RED = "#2a78d6", "#eb6834", "#1baf7a", "#e34948"
INK, INK_2, MUTED, GRID = "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
MODEL_COLORS = {"Random Forest": BLUE, "Decision Tree": ORANGE, "Logistic Regression": AQUA}

DAYS = {"Monday": "Mon 3 Jul", "Tuesday": "Tue 4 Jul", "Wednesday": "Wed 5 Jul",
        "Thursday": "Thu 6 Jul", "Friday": "Fri 7 Jul"}

# CICFlowMeter feature groups (77 features after removing the duplicate column).
FEATURE_GROUPS = {
    "Basic flow": ["Destination Port", "Flow Duration", "Total Fwd Packets",
                   "Total Backward Packets", "Total Length of Fwd Packets",
                   "Total Length of Bwd Packets"],
    "Packet length": ["Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
                      "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
                      "Bwd Packet Length Mean", "Bwd Packet Length Std", "Min Packet Length",
                      "Max Packet Length", "Packet Length Mean", "Packet Length Std",
                      "Packet Length Variance", "Average Packet Size", "Avg Fwd Segment Size",
                      "Avg Bwd Segment Size"],
    "Flow rate": ["Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"],
    "Inter-arrival time": ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
                           "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
                           "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
                           "Bwd IAT Max", "Bwd IAT Min"],
    "TCP flags": ["Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
                  "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
                  "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count"],
    "Header & window": ["Fwd Header Length", "Bwd Header Length", "Init_Win_bytes_forward",
                        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
                        "Down/Up Ratio"],
    "Bulk transfer": ["Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
                      "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"],
    "Subflow": ["Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
                "Subflow Bwd Bytes"],
    "Active / idle": ["Active Mean", "Active Std", "Active Max", "Active Min",
                      "Idle Mean", "Idle Std", "Idle Max", "Idle Min"],
}

KEY_FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                "Bwd Packet Length Std", "Packet Length Variance", "Average Packet Size",
                "Flow Bytes/s", "Flow Packets/s", "Init_Win_bytes_forward", "Destination Port"]


def display_label(label: str) -> str:
    """'Web Attack \\x96 XSS' -> 'Web Attack – XSS' (the files use a cp1252 dash)."""
    return label.replace("\x96", "–").replace("ï¿½", "–").strip()


def setup_matplotlib() -> None:
    """Times New Roman to match the report, quiet axes and hairline grid."""
    for path in ["/mnt/c/Windows/Fonts/times.ttf", "/mnt/c/Windows/Fonts/timesbd.ttf"]:
        if Path(path).exists():
            font_manager.fontManager.addfont(path)
    plt.rcParams.update({
        "font.family": ["Times New Roman", "DejaVu Serif"],
        "font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10,
        "axes.edgecolor": "#c3c2b7", "axes.labelcolor": INK_2, "axes.titlecolor": INK,
        "xtick.color": INK_2, "ytick.color": INK_2, "axes.grid": True,
        "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "figure.dpi": 100, "savefig.dpi": 220,
        "savefig.bbox": "tight",
    })


def save(fig, name: str) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES_DIR / f"{name}.png", facecolor="white")
    plt.close(fig)


def day_of(file_name: str) -> str:
    return next(d for d in DAYS if file_name.lower().startswith(d.lower()))


# --------------------------------------------------------------------------
# Raw-file analysis (before any cleaning)
# --------------------------------------------------------------------------
def analyse_raw_files(files: list[Path]) -> tuple[pd.DataFrame, dict]:
    per_file, nan_counts, inf_counts, neg_counts = [], {}, {}, {}
    frames = []
    for path in files:
        print(f"  {path.name}")
        raw = read_raw_csv(path)
        named = clean_column_names(raw)
        labels = named[config.LABEL_COLUMN].astype(str).map(display_label)
        numeric = named.drop(columns=[config.LABEL_COLUMN]).apply(pd.to_numeric, errors="coerce")

        for col in numeric.columns:
            values = numeric[col].to_numpy(dtype=np.float64)
            nan_counts[col] = nan_counts.get(col, 0) + int(np.isnan(values).sum())
            inf_counts[col] = inf_counts.get(col, 0) + int(np.isinf(values).sum())
            neg_counts[col] = neg_counts.get(col, 0) + int((values < 0).sum())

        counts = labels.value_counts()
        per_file.append({
            "file": path.name,
            "day": day_of(path.name),
            "rows": int(len(raw)),
            "columns": int(raw.shape[1]),
            "benign": int(counts.get("BENIGN", 0)),
            "malicious": int(len(raw) - counts.get("BENIGN", 0)),
            "labels": {k: int(v) for k, v in counts.items()},
        })
        frames.append(clean_frame(raw))
        del raw, named, numeric

    data = pd.concat(frames, ignore_index=True)
    data[config.LABEL_COLUMN] = data[config.LABEL_COLUMN].map(display_label)
    quality = {
        "raw_columns": per_file[0]["columns"],
        "nan_by_column": {k: v for k, v in nan_counts.items() if v},
        "inf_by_column": {k: v for k, v in inf_counts.items() if v},
        "negative_by_column": dict(sorted(((k, v) for k, v in neg_counts.items() if v),
                                          key=lambda kv: -kv[1])),
    }
    return data, {"per_file": per_file, "quality": quality}


def class_stats(df: pd.DataFrame, features: list[str]) -> dict:
    y = to_binary_labels(df[config.LABEL_COLUMN])
    out = {}
    for f in features:
        col = df[f].astype(np.float64)
        out[f] = {}
        for cls, name in ((0, "Benign"), (1, "Malicious")):
            v = col[y == cls].dropna()
            out[f][name] = {
                "mean": float(v.mean()), "median": float(v.median()),
                "p25": float(v.quantile(0.25)), "p75": float(v.quantile(0.75)),
                "std": float(v.std()), "max": float(v.max()),
            }
    return out


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------
def fig_flows_per_file(per_file: list[dict]) -> None:
    rows = sorted(per_file, key=lambda r: list(DAYS).index(r["day"]))
    names = [r["file"].replace(".pcap_ISCX.csv", "").replace("WorkingHours", "")
             .replace("workingHours", "").replace("--", "-").strip("-") for r in rows]
    names = [n.replace("-", " ").replace("  ", " ") for n in names]
    benign = np.array([r["benign"] for r in rows]) / 1000
    malicious = np.array([r["malicious"] for r in rows]) / 1000
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    y = np.arange(len(rows))
    ax.barh(y, benign, height=0.55, color=BLUE, label="Benign")
    ax.barh(y, malicious, left=benign + benign.max() * 0.004, height=0.55, color=RED,
            label="Malicious")
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xlabel("Flows (thousands)")
    ax.grid(axis="y", visible=False)
    for i, (b, m) in enumerate(zip(benign, malicious)):
        ax.text(b + m + benign.max() * 0.015, i, f"{(b + m):,.0f}K", va="center",
                fontsize=9, color=INK_2)
    ax.set_xlim(0, (benign + malicious).max() * 1.15)
    ax.legend(loc="lower right", ncol=2)
    save(fig, "fig_flows_per_file")


def fig_label_distribution(raw_counts: dict, dedup_counts: dict) -> None:
    labels = sorted(raw_counts, key=lambda k: -raw_counts[k])
    fig, ax = plt.subplots(figsize=(6.2, 4.4))
    y = np.arange(len(labels))
    ax.barh(y, [raw_counts[k] for k in labels], height=0.6, color=BLUE)
    ax.set_xscale("log")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Number of flows (log scale)")
    ax.grid(axis="y", visible=False)
    for i, k in enumerate(labels):
        ax.text(raw_counts[k] * 1.15, i, f"{raw_counts[k]:,}", va="center", fontsize=8.5,
                color=INK_2)
    ax.set_xlim(5, max(raw_counts.values()) * 12)
    save(fig, "fig_label_distribution")


def fig_duplicates(raw_counts: dict, dedup_counts: dict) -> None:
    labels = sorted(raw_counts, key=lambda k: -(1 - dedup_counts.get(k, 0) / raw_counts[k]))
    share = [100 * (1 - dedup_counts.get(k, 0) / raw_counts[k]) for k in labels]
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    y = np.arange(len(labels))
    ax.barh(y, share, height=0.6, color=ORANGE)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Rows removed as exact duplicates (%)")
    ax.grid(axis="y", visible=False)
    for i, s in enumerate(share):
        ax.text(s + 0.8, i, f"{s:.1f}%", va="center", fontsize=8.5, color=INK_2)
    ax.set_xlim(0, max(share) * 1.15 + 2)
    save(fig, "fig_duplicates_by_label")


def fig_data_quality(quality: dict) -> None:
    neg = dict(list(quality["negative_by_column"].items())[:8])
    issues = {**{f"{k} (∞)": v for k, v in quality["inf_by_column"].items()},
              **{f"{k} (NaN)": v for k, v in quality["nan_by_column"].items()},
              **{f"{k} (< 0)": v for k, v in neg.items()}}
    names = sorted(issues, key=lambda k: -issues[k])
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    y = np.arange(len(names))
    ax.barh(y, [issues[k] for k in names], height=0.6, color=BLUE)
    ax.set_xscale("log")
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xlabel("Affected rows in the raw files (log scale)")
    ax.grid(axis="y", visible=False)
    for i, k in enumerate(names):
        ax.text(issues[k] * 1.15, i, f"{issues[k]:,}", va="center", fontsize=8.5, color=INK_2)
    ax.set_xlim(1, max(issues.values()) * 15)
    save(fig, "fig_data_quality")


def fig_feature_groups(constant: list[str]) -> None:
    names = list(FEATURE_GROUPS)
    kept = [len([f for f in FEATURE_GROUPS[g] if f not in constant]) for g in names]
    dropped = [len([f for f in FEATURE_GROUPS[g] if f in constant]) for g in names]
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    y = np.arange(len(names))
    ax.barh(y, kept, height=0.55, color=BLUE, label="Used by the model")
    ax.barh(y, dropped, left=np.array(kept) + 0.08, height=0.55, color=MUTED,
            label="Dropped (constant)")
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xlabel("Number of features")
    ax.grid(axis="y", visible=False)
    for i, (k, d) in enumerate(zip(kept, dropped)):
        ax.text(k + d + 0.3, i, str(k + d), va="center", fontsize=9, color=INK_2)
    ax.legend(loc="lower right")
    save(fig, "fig_feature_groups")


def fig_feature_boxplots(df: pd.DataFrame) -> None:
    feats = ["Flow Duration", "Total Fwd Packets", "Bwd Packet Length Std",
             "Packet Length Variance", "Average Packet Size", "Flow Bytes/s"]
    y = to_binary_labels(df[config.LABEL_COLUMN])
    fig, axes = plt.subplots(2, 3, figsize=(6.4, 4.6))
    for ax, f in zip(axes.flat, feats):
        col = df[f].astype(np.float64).clip(lower=0)
        data = [np.log10(col[y == c].dropna() + 1) for c in (0, 1)]
        parts = ax.boxplot(data, widths=0.5, showfliers=False, patch_artist=True,
                           medianprops={"color": INK, "linewidth": 1.2})
        for patch, color in zip(parts["boxes"], (BLUE, RED)):
            patch.set_facecolor(color)
            patch.set_alpha(0.85)
            patch.set_edgecolor(color)
        for key in ("whiskers", "caps"):
            for line in parts[key]:
                line.set_color(INK_2)
        ax.set_xticks([1, 2], ["Benign", "Malicious"])
        ax.set_title(f, fontsize=10)
        ax.grid(axis="x", visible=False)
    fig.supylabel("log10(value + 1)", fontsize=10, color=INK_2)
    fig.tight_layout()
    save(fig, "fig_feature_boxplots")


def fig_flow_duration_ecdf(df: pd.DataFrame) -> None:
    y = to_binary_labels(df[config.LABEL_COLUMN])
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    for cls, name, color in ((0, "Benign", BLUE), (1, "Malicious", RED)):
        v = np.sort(df.loc[y == cls, "Flow Duration"].astype(np.float64).clip(lower=1).dropna())
        ax.plot(v / 1e6, np.arange(1, len(v) + 1) / len(v), color=color, linewidth=2,
                label=name)
    ax.set_xscale("log")
    ax.set_xlabel("Flow duration (seconds, log scale)")
    ax.set_ylabel("Share of flows ≤ duration")
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right")
    save(fig, "fig_flow_duration_ecdf")


def fig_correlation(corr: pd.DataFrame, features: list[str]) -> None:
    sub = corr.loc[features, features]
    fig, ax = plt.subplots(figsize=(6.4, 5.6))
    im = ax.imshow(sub.to_numpy(), cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(features)), features, rotation=90, fontsize=8)
    ax.set_yticks(range(len(features)), features, fontsize=8)
    ax.grid(False)
    cbar = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cbar.set_label("Pearson correlation (r)", color=INK_2)
    cbar.outline.set_visible(False)
    save(fig, "fig_correlation_heatmap")


def fig_top_ports(ports: dict) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(6.4, 3.4))
    for ax, (name, color) in zip(axes, (("Benign", BLUE), ("Malicious", RED))):
        items = list(ports[name].items())[:10]
        labels = [str(p) for p, _ in items]
        values = [v / 1000 for _, v in items]
        y = np.arange(len(items))
        ax.barh(y, values, height=0.6, color=color)
        ax.set_yticks(y, labels)
        ax.invert_yaxis()
        ax.set_title(f"{name} flows", fontsize=10)
        ax.set_xlabel("Flows (thousands)")
        ax.grid(axis="y", visible=False)
    axes[0].set_ylabel("Destination port")
    fig.tight_layout()
    save(fig, "fig_top_ports")


def fig_sample_vs_population(pop: dict, sample: dict) -> None:
    labels = sorted(pop, key=lambda k: -pop[k])
    p_tot, s_tot = sum(pop.values()), sum(sample.values())
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    y = np.arange(len(labels))
    ax.scatter([100 * pop[k] / p_tot for k in labels], y, s=60, color=BLUE,
               label="Cleaned dataset", zorder=3, edgecolors="white", linewidths=1.5)
    ax.scatter([100 * sample.get(k, 0) / s_tot for k in labels], y, s=22, color=ORANGE,
               label="500,000-flow sample", zorder=4)
    ax.set_xscale("log")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Share of flows (%, log scale)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower left")
    save(fig, "fig_sample_vs_population")


def fig_model_comparison(models: list[dict]) -> None:
    metrics = [("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall"),
               ("f1_score", "F1-score")]
    fig, ax = plt.subplots(figsize=(6.2, 3.3))
    x = np.arange(len(metrics))
    width = 0.24
    for i, m in enumerate(models):
        values = [100 * m[k] for k, _ in metrics]
        ax.bar(x + (i - 1) * (width + 0.01), values, width, color=MODEL_COLORS[m["name"]],
               label=m["name"])
    ax.set_xticks(x, [label for _, label in metrics])
    ax.set_ylim(0, 100)
    ax.set_ylabel("Score on test set (%)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="lower center", ncol=3, bbox_to_anchor=(0.5, 1.0))
    save(fig, "fig_model_comparison")


def fig_confusion_matrices(models: list[dict]) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(6.6, 2.6))
    for ax, m in zip(axes, models):
        cm = np.array(m["confusion_matrix"])
        share = cm / cm.sum(axis=1, keepdims=True)
        ax.imshow(share, cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]:,}\n{100 * share[i, j]:.2f}%", ha="center",
                        va="center", fontsize=8.5,
                        color="white" if share[i, j] > 0.5 else INK)
        ax.set_xticks([0, 1], ["Benign", "Malicious"], fontsize=8.5)
        ax.set_yticks([0, 1], ["Benign", "Malicious"], fontsize=8.5)
        ax.set_title(m["name"], fontsize=10)
        ax.grid(False)
        ax.set_xlabel("Predicted", fontsize=9)
    axes[0].set_ylabel("Actual", fontsize=9)
    fig.tight_layout()
    save(fig, "fig_confusion_matrices")


def fig_per_attack(per_label: dict, support: dict) -> None:
    labels = [k for k in sorted(support, key=lambda k: -support[k]) if k != "BENIGN"]
    fig, ax = plt.subplots(figsize=(6.4, 5.0))
    y = np.arange(len(labels))
    h = 0.26
    for i, name in enumerate(MODEL_COLORS):
        ax.barh(y + (i - 1) * (h + 0.01), [100 * per_label[name][k] for k in labels], h,
                color=MODEL_COLORS[name], label=name)
    ax.set_yticks(y, [f"{k} (n={support[k]:,})" for k in labels], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel("Detection rate on test set (recall, %)")
    ax.set_xlim(0, 105)
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", ncol=3, bbox_to_anchor=(0.4, 1.0))
    save(fig, "fig_per_attack_recall")


def fig_feature_importance(importances: list[dict]) -> None:
    items = importances[:15]
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    y = np.arange(len(items))
    ax.barh(y, [100 * i["importance"] for i in items], height=0.6, color=BLUE)
    ax.set_yticks(y, [i["feature"] for i in items])
    ax.invert_yaxis()
    ax.set_xlabel("Mean decrease in Gini impurity (%)")
    ax.grid(axis="y", visible=False)
    save(fig, "fig_feature_importance")


def fig_probability_hist(proba: np.ndarray, y_test: np.ndarray) -> None:
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    bins = np.linspace(0, 1, 21)
    for cls, name, color in ((0, "Actual benign", BLUE), (1, "Actual malicious", RED)):
        ax.hist(proba[y_test == cls], bins=bins, color=color, alpha=0.85, label=name,
                rwidth=0.9)
    ax.set_yscale("log")
    ax.axvline(0.5, color=INK_2, linewidth=1)
    ax.text(0.51, ax.get_ylim()[1] * 0.4, "decision threshold 0.5", fontsize=8.5, color=INK_2)
    ax.set_xlabel("Random Forest malicious probability")
    ax.set_ylabel("Test flows (log scale)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper center")
    save(fig, "fig_probability_hist")


def fig_roc_pr(y_test: np.ndarray, scores: dict) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(6.4, 3.1))
    for name, s in scores.items():
        fpr, tpr, _ = roc_curve(y_test, s)
        prec, rec, _ = precision_recall_curve(y_test, s)
        axes[0].plot(fpr, tpr, color=MODEL_COLORS[name], linewidth=2, label=name)
        axes[1].plot(rec, prec, color=MODEL_COLORS[name], linewidth=2, label=name)
    axes[0].set_xscale("log")
    axes[0].set_xlim(1e-4, 1)
    axes[0].set_xlabel("False positive rate (log)")
    axes[0].set_ylabel("True positive rate")
    axes[0].set_title("ROC curve", fontsize=10)
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision–recall curve", fontsize=10)
    axes[1].set_ylim(0.5, 1.01)
    axes[0].legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    save(fig, "fig_roc_pr")


# --------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    setup_matplotlib()
    files = dataset_files(config.DATASET_DIR)

    print("Reading raw files...")
    data, result = analyse_raw_files(files)
    raw_counts = {k: int(v) for k, v in data[config.LABEL_COLUMN].value_counts().items()}
    result["raw_rows"] = int(len(data))
    result["raw_label_counts"] = raw_counts

    print("Removing duplicates...")
    dedup = remove_duplicates(data)
    del data
    dedup_counts = {k: int(v) for k, v in dedup[config.LABEL_COLUMN].value_counts().items()}
    result["dedup_rows"] = int(len(dedup))
    result["dedup_label_counts"] = dedup_counts
    y_all = to_binary_labels(dedup[config.LABEL_COLUMN])
    result["dedup_class_counts"] = {"Benign": int((y_all == 0).sum()),
                                    "Malicious": int((y_all == 1).sum())}
    raw_benign = raw_counts.get("BENIGN", 0)
    result["raw_class_counts"] = {"Benign": raw_benign,
                                  "Malicious": result["raw_rows"] - raw_benign}

    features = [c for c in dedup.columns if c != config.LABEL_COLUMN]
    constant = [c for c in features if dedup[c].nunique(dropna=False) <= 1]
    result["features"] = {"count": len(features), "constant_in_full_dataset": constant,
                          "groups": FEATURE_GROUPS}
    result["key_feature_stats"] = class_stats(dedup, KEY_FEATURES)

    print("Per-attack characteristics, ports, correlation...")
    per_attack = {}
    for label, group in dedup.groupby(config.LABEL_COLUMN):
        per_attack[label] = {f: float(group[f].astype(np.float64).median())
                             for f in ["Flow Duration", "Total Fwd Packets",
                                       "Total Backward Packets", "Flow Bytes/s",
                                       "Bwd Packet Length Std", "Destination Port"]}
        top_port = group["Destination Port"].value_counts()
        per_attack[label]["top_port"] = int(top_port.index[0])
        per_attack[label]["top_port_share"] = float(top_port.iloc[0] / len(group))
    result["per_attack_medians"] = per_attack

    ports = {}
    for cls, name in ((0, "Benign"), (1, "Malicious")):
        counts = dedup.loc[y_all == cls, "Destination Port"].astype(int).value_counts().head(10)
        ports[name] = {int(k): int(v) for k, v in counts.items()}
    result["top_ports"] = ports
    result["distinct_ports"] = int(dedup["Destination Port"].nunique())

    corr_sample = dedup[features].sample(n=200_000, random_state=config.RANDOM_STATE)
    corr_sample = corr_sample.drop(columns=constant)
    corr = corr_sample.fillna(corr_sample.median()).astype(np.float64).corr()
    pairs = []
    cols = list(corr.columns)
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            r = corr.iat[i, j]
            if abs(r) >= 0.95:
                pairs.append({"a": cols[i], "b": cols[j], "r": float(r)})
    pairs.sort(key=lambda p: -abs(p["r"]))
    result["correlation"] = {"sample_rows": 200_000, "threshold": 0.95,
                             "pairs_above_threshold": len(pairs), "top_pairs": pairs[:20],
                             "perfect_pairs": sum(1 for p in pairs if abs(p["r"]) > 0.9999)}

    print("Rebuilding the training sample and split...")
    sample = stratified_sample(dedup, SAMPLE_SIZE)
    sample_counts = {k: int(v) for k, v in sample[config.LABEL_COLUMN].value_counts().items()}
    result["sample_label_counts"] = sample_counts
    split = split_data(sample)
    result["split_label_counts"] = {
        part: {k: int(v) for k, v in split[f"labels_{part}"].value_counts().items()}
        for part in ("train", "val", "test")
    }

    metrics = json.loads(config.METRICS_PATH.read_text())
    bundle = joblib.load(config.MODEL_PATH)
    feature_names = bundle["feature_names"]
    X_train, y_train = split["X_train"][feature_names], split["y_train"]
    X_test, y_test = split["X_test"][feature_names], split["y_test"]
    labels_test = split["labels_test"].to_numpy()

    predictions, scores = {}, {}
    rf = bundle["pipeline"]
    predictions["Random Forest"] = rf.predict(X_test)
    scores["Random Forest"] = rf.predict_proba(X_test)[:, 1]
    for name, pipeline in build_models().items():
        if name == "Random Forest":
            continue
        print(f"  refitting {name} for per-attack results")
        pipeline.fit(X_train, y_train)
        predictions[name] = pipeline.predict(X_test)
        scores[name] = pipeline.predict_proba(X_test)[:, 1]

    # Sanity check: the rebuilt split must reproduce the saved evaluation exactly.
    reproduced = {}
    for m in metrics["models"]:
        cm = confusion_matrix(y_test, predictions[m["name"]], labels=[0, 1]).tolist()
        reproduced[m["name"]] = cm == m["confusion_matrix"]
    result["reproduces_saved_metrics"] = reproduced
    print(f"  reproduces saved confusion matrices: {reproduced}")

    support = {k: int(v) for k, v in pd.Series(labels_test).value_counts().items()}
    per_label = {}
    for name, pred in predictions.items():
        per_label[name] = {}
        for label in support:
            mask = labels_test == label
            expected = 0 if label == "BENIGN" else 1
            per_label[name][label] = float((pred[mask] == expected).mean())
    result["test_support"] = support
    result["per_label_detection"] = per_label
    result["rf_errors_by_label"] = {
        label: int(((predictions["Random Forest"] != (0 if label == "BENIGN" else 1))
                    & (labels_test == label)).sum())
        for label in support
    }
    result["curves"] = {name: {"roc_auc": float(roc_auc_score(y_test, s)),
                               "average_precision": float(average_precision_score(y_test, s))}
                        for name, s in scores.items()}

    print("Drawing figures...")
    fig_flows_per_file(result["per_file"])
    fig_label_distribution(raw_counts, dedup_counts)
    fig_duplicates(raw_counts, dedup_counts)
    fig_data_quality(result["quality"])
    fig_feature_groups(metrics["features"]["dropped_constant"])
    fig_feature_boxplots(dedup)
    fig_flow_duration_ecdf(dedup)
    top_features = [f["feature"] for f in metrics["feature_importances"][:15]]
    fig_correlation(corr, top_features)
    fig_top_ports(ports)
    fig_sample_vs_population(dedup_counts, sample_counts)
    fig_model_comparison(metrics["models"])
    fig_confusion_matrices(metrics["models"])
    fig_per_attack(per_label, support)
    fig_feature_importance(metrics["feature_importances"])
    fig_probability_hist(scores["Random Forest"], y_test)
    fig_roc_pr(y_test, scores)

    result["generated_in_seconds"] = round(time.perf_counter() - start, 1)
    OUTPUT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Saved {OUTPUT_PATH} and figures in {FIGURES_DIR}")


if __name__ == "__main__":
    main()
