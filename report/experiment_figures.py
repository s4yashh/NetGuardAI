"""Black-and-white figures drawn from reports/experiments.json and reports/metrics.json."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from ml.analyze_dataset import INK_2, display_label, setup_matplotlib  # noqa: E402

PROTOCOL_NAMES = {
    "original": "Random split\n(all days)",
    "random_monwed": "Random split\n(Mon–Wed)",
    "temporal": "Temporal\n(train Mon–Wed,\ntest Thu–Fri)",
}
SERIES = [("precision", "Precision", "#2b2b2b", ""), ("recall", "Recall", "#8c8c8c", ""),
          ("f1_score", "F1-score", "white", "////")]


def protocol_comparison(path: Path, experiments: dict) -> None:
    protocols = list(PROTOCOL_NAMES)
    raw = {p: experiments["protocols"][p]["variants"][0] for p in protocols}  # B0 raw RF @0.5
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    x = np.arange(len(protocols))
    w = 0.25
    for i, (key, label, color, hatch) in enumerate(SERIES):
        values = [100 * raw[p][key] for p in protocols]
        bars = ax.bar(x + (i - 1) * (w + 0.01), values, w, color=color, hatch=hatch, label=label)
        for bar, v in zip(bars, values):
            if v < 90:
                ax.text(bar.get_x() + bar.get_width() / 2, v + 1.5, f"{v:.1f}", ha="center",
                        fontsize=8, color=INK_2)
    ax.set_xticks(x, [PROTOCOL_NAMES[p] for p in protocols], fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Random Forest score on test set (%)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="lower center", ncol=3, bbox_to_anchor=(0.5, 1.0))
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def temporal_per_attack(path: Path, experiments: dict) -> None:
    original = {display_label(a["label"]): a for a in experiments["protocols"]["original"]["per_attack"]}
    temporal = {display_label(a["label"]): a for a in experiments["protocols"]["temporal"]["per_attack"]}
    labels = [k for k in temporal if k != "BENIGN"]
    fig, ax = plt.subplots(figsize=(6.2, 2.8))
    y = np.arange(len(labels))
    h = 0.36
    ax.barh(y - h / 2 - 0.01, [100 * original[k]["recall"] for k in labels], h, color="#8c8c8c",
            label="Random split (all days)")
    ax.barh(y + h / 2 + 0.01, [100 * temporal[k]["recall"] for k in labels], h, color="white",
            hatch="////", label="Temporal (unseen days)")
    ax.set_yticks(y, [f"{k} (n={temporal[k]['n']:,})" for k in labels])
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    ax.set_xlabel("Detection rate at the deployed alert threshold (%)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", ncol=2, bbox_to_anchor=(0.4, 1.0))
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def shift_per_day(path: Path, metrics: dict) -> None:
    gate = metrics["shift_gate"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday-Morning", "Thursday-Afternoon",
            "Friday-Morning", "Friday-PortScan", "Friday-DDoS"]
    days = [d for d in days if d in gate["per_day"]]
    scores = [gate["per_day"][d]["score"] for d in days]
    fig, ax = plt.subplots(figsize=(6.2, 3.0))
    x = np.arange(len(days))
    flagged = [gate["per_day"][d]["verdict"] != "in_distribution" for d in days]
    ax.bar(x, scores, 0.55, color=["white" if f else "#8c8c8c" for f in flagged],
           hatch=None)
    for i, f in enumerate(flagged):
        if f:
            ax.patches[i].set_hatch("////")
    ax.axhline(gate["threshold"], color="black", linestyle="--", linewidth=1)
    ax.text(-0.4, gate["threshold"] + 0.15, f"in-distribution limit {gate['threshold']:.2f}",
            ha="left", fontsize=8, color=INK_2)
    ax.set_xticks(x, [d.replace("-", "\n") for d in days], fontsize=8)
    ax.set_ylabel("Batch shift score")
    ax.grid(axis="x", visible=False)
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def draw_all(out_dir: Path, experiments: dict, metrics: dict) -> None:
    setup_matplotlib()
    out_dir.mkdir(parents=True, exist_ok=True)
    protocol_comparison(out_dir / "exp_protocols.png", experiments)
    temporal_per_attack(out_dir / "exp_temporal_per_attack.png", experiments)
    shift_per_day(out_dir / "exp_shift_per_day.png", metrics)
