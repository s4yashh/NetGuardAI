"""Explanatory diagrams for the project report (drawn with matplotlib)."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from ml.analyze_dataset import BLUE, INK, INK_2, MUTED, ORANGE, RED, setup_matplotlib  # noqa: E402

LIGHT_BLUE, LIGHT_GRAY, LIGHT_RED = "#e8f0fb", "#f3f4f6", "#fdecec"


def _box(ax, x, y, w, h, title, body="", fill=LIGHT_BLUE, edge=BLUE, size=9.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                facecolor=fill, edgecolor=edge, linewidth=1.2))
    if body:
        ax.text(x + w / 2, y + h - 0.16, title, ha="center", va="top", fontsize=size,
                fontweight="bold", color=INK)
        ax.text(x + w / 2, y + h - 0.45, body, ha="center", va="top", fontsize=size - 1.5,
                color=INK_2, linespacing=1.35)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=size,
                fontweight="bold", color=INK)


def _arrow(ax, start, end, text="", color=INK_2, offset=(0, 0.12), style="-|>", rad=0.0):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=12, color=color,
                                 linewidth=1.2, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((start[0] + end[0]) / 2 + offset[0], (start[1] + end[1]) / 2 + offset[1], text,
                ha="center", va="bottom", fontsize=8, color=INK_2)


def _canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


def architecture(path: Path) -> None:
    fig, ax = _canvas(6.4, 4.6)
    ax.text(0.15, 4.45, "Online (every upload)", fontsize=9, color=MUTED, va="top")
    _box(ax, 0.15, 2.55, 1.85, 1.6, "Web browser",
         "React + Vite + TypeScript\nTailwind CSS, Recharts\nupload, results table,\ncharts, CSV download")
    _box(ax, 2.35, 2.55, 1.95, 1.6, "FastAPI backend",
         "/api/health\n/api/metrics\n/api/predict\n/api/predict/download")
    _box(ax, 4.65, 3.4, 1.6, 0.75, "ModelStore", "loads joblib bundle", fill=LIGHT_GRAY, edge=MUTED)
    _box(ax, 4.65, 2.55, 1.6, 0.7, "preprocess.py", "same cleaning as training",
         fill=LIGHT_GRAY, edge=MUTED)
    _arrow(ax, (2.0, 3.55), (2.35, 3.55), "CSV")
    _arrow(ax, (2.35, 3.05), (2.0, 3.05), "JSON / CSV", offset=(0, -0.3))
    _arrow(ax, (4.3, 3.75), (4.65, 3.75))
    _arrow(ax, (4.3, 2.9), (4.65, 2.9))

    ax.plot([0.1, 6.3], [2.25, 2.25], color="#c3c2b7", linewidth=0.8)
    ax.text(0.15, 2.1, "Offline (run once)", fontsize=9, color=MUTED, va="top")
    _box(ax, 0.15, 0.35, 1.85, 1.45, "CIC-IDS2017",
         "8 CSV files\n2,830,743 flows\n78 features + Label", fill=LIGHT_RED, edge=RED)
    _box(ax, 2.35, 0.35, 1.95, 1.45, "ml/train.py",
         "clean → deduplicate →\nsample → split →\ntrain RF / DT / LR →\nevaluate → select")
    _box(ax, 4.65, 1.05, 1.6, 0.75, "models/", "netguard_model.joblib", fill=LIGHT_GRAY, edge=MUTED)
    _box(ax, 4.65, 0.35, 1.6, 0.6, "reports/", "metrics.json", fill=LIGHT_GRAY, edge=MUTED)
    _arrow(ax, (2.0, 1.05), (2.35, 1.05))
    _arrow(ax, (4.3, 1.4), (4.65, 1.4))
    _arrow(ax, (4.3, 0.65), (4.65, 0.65))
    _arrow(ax, (5.45, 1.8), (5.45, 3.4), "loaded by API", offset=(0.45, -0.05), color=BLUE)
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def data_generation(path: Path) -> None:
    fig, ax = _canvas(6.4, 2.6)
    _box(ax, 0.05, 0.9, 1.35, 1.35, "Victim network",
         "Windows, Ubuntu,\nmacOS hosts and\nservers; benign\nusers (B-Profile)")
    _box(ax, 0.05, 0.05, 1.35, 0.7, "Attack network", "Kali Linux attackers",
         fill=LIGHT_RED, edge=RED)
    _box(ax, 1.75, 0.55, 1.2, 1.2, "Packet capture", "full traffic\nmirrored to\n.pcap files")
    _box(ax, 3.3, 0.55, 1.3, 1.2, "CICFlowMeter", "groups packets\ninto bidirectional\nflows, computes\n80+ statistics")
    _box(ax, 4.95, 0.55, 1.4, 1.2, "Labelled CSV", "one row per flow\n78 features\n+ Label column",
         fill=LIGHT_GRAY, edge=MUTED)
    _arrow(ax, (1.4, 1.55), (1.75, 1.3))
    _arrow(ax, (1.4, 0.4), (1.75, 0.85))
    _arrow(ax, (2.95, 1.15), (3.3, 1.15))
    _arrow(ax, (4.6, 1.15), (4.95, 1.15))
    ax.text(3.95, 2.0, "label = attack name if the flow matches the attack schedule, else BENIGN",
            ha="center", fontsize=8, color=INK_2)
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def flow_concept(path: Path) -> None:
    """Timeline of one TCP flow: forward packets above the axis, backward below."""
    fig, ax = plt.subplots(figsize=(6.4, 2.9))
    fwd = [(0.0, 0.6, "SYN"), (0.9, 0.6, "ACK"), (1.3, 1.6, "PSH,ACK"), (3.6, 0.6, "ACK"),
           (5.6, 0.6, "FIN")]
    bwd = [(0.45, 0.6, "SYN,ACK"), (2.2, 2.4, "PSH,ACK"), (2.9, 2.4, "PSH,ACK"), (5.9, 0.6, "FIN")]
    for t, size, flag in fwd:
        ax.bar(t, size, width=0.16, bottom=0.15, color=BLUE)
        ax.text(t, 0.15 + size + 0.08, flag, ha="center", fontsize=7.5, color=INK_2)
    for t, size, flag in bwd:
        ax.bar(t, -size, width=0.16, bottom=-0.15, color=ORANGE)
        ax.text(t, -0.15 - size - 0.12, flag, ha="center", va="top", fontsize=7.5, color=INK_2)
    ax.axhline(0, color=INK_2, linewidth=1)
    ax.annotate("", xy=(5.9, 2.25), xytext=(0.0, 2.25),
                arrowprops={"arrowstyle": "<->", "color": INK, "linewidth": 1})
    ax.text(2.95, 2.33, "Flow Duration (first to last packet, µs)", ha="center", fontsize=8.5,
            color=INK)
    ax.annotate("", xy=(1.3, 1.95), xytext=(0.9, 1.95),
                arrowprops={"arrowstyle": "<->", "color": INK_2, "linewidth": 0.8})
    ax.text(1.1, 2.0, "Fwd IAT", ha="center", fontsize=7.5, color=INK_2)
    ax.text(-0.55, 1.1, "Forward\n(client → server)", ha="center", va="center", fontsize=8,
            color=BLUE)
    ax.text(-0.55, -1.3, "Backward\n(server → client)", ha="center", va="center", fontsize=8,
            color=ORANGE)
    ax.text(3.2, -2.85, "bar height = packet length", ha="center", fontsize=7.5, color=MUTED)
    ax.set_xlim(-1.2, 6.4)
    ax.set_ylim(-3.0, 2.6)
    ax.axis("off")
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def preprocessing(path: Path, a: dict, m: dict) -> None:
    raw, dedup = a["raw_rows"], a["dedup_rows"]
    split = m["split"]
    steps = [
        ("Read 8 raw CSV files", f"{raw:,} flows × {a['quality']['raw_columns']} columns"),
        ("Clean headers, drop duplicate column", "strip spaces; remove 'Fwd Header Length.1'"),
        ("Make numeric, ∞ → missing", "Flow Bytes/s and Flow Packets/s contain ∞"),
        ("Remove exact duplicate rows", f"{raw - dedup:,} removed → {dedup:,} unique flows"),
        ("Stratified sample", f"{m['dataset']['rows_used']:,} flows, class ratio kept"),
        ("Stratified split (seed 42)",
         f"train {split['train']:,} · validation {split['validation']:,} · test {split['test']:,}"),
        ("Drop constant features", f"{m['features']['count']} of 77 features kept"),
        ("Pipeline: median imputer → [scaler] → model", "fitted on the training set only"),
    ]
    fig, ax = _canvas(6.2, 5.6)
    h, gap, top = 0.52, 0.16, 5.5
    for i, (title, body) in enumerate(steps):
        y = top - (i + 1) * h - i * gap
        ax.add_patch(FancyBboxPatch((0.4, y), 5.4, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                    facecolor=LIGHT_BLUE if i < 6 else LIGHT_GRAY,
                                    edgecolor=BLUE if i < 6 else MUTED, linewidth=1.1))
        ax.text(0.6, y + h / 2, f"{i + 1}", ha="center", va="center", fontsize=10,
                fontweight="bold", color=BLUE)
        ax.text(0.85, y + h * 0.66, title, va="center", fontsize=9.5, fontweight="bold", color=INK)
        ax.text(0.85, y + h * 0.28, body, va="center", fontsize=8.5, color=INK_2)
        if i < len(steps) - 1:
            _arrow(ax, (3.1, y), (3.1, y - gap))
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def gantt(path: Path, tasks: list[tuple[str, int, int]]) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for i, (name, start, length) in enumerate(tasks):
        ax.barh(i, length, left=start - 1, height=0.55, color=BLUE)
    ax.set_yticks(range(len(tasks)), [t[0] for t in tasks], fontsize=8.5)
    ax.invert_yaxis()
    weeks = max(s + l - 1 for _, s, l in tasks)
    ax.set_xticks(range(weeks), [f"W{w + 1}" for w in range(weeks)], fontsize=8)
    ax.set_xlim(0, weeks)
    ax.set_xlabel("Project week")
    ax.grid(axis="y", visible=False)
    fig.savefig(path, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def draw_all(out_dir: Path, analysis: dict, metrics: dict, tasks) -> None:
    setup_matplotlib()
    out_dir.mkdir(parents=True, exist_ok=True)
    architecture(out_dir / "diag_architecture.png")
    data_generation(out_dir / "diag_data_generation.png")
    flow_concept(out_dir / "diag_flow_concept.png")
    preprocessing(out_dir / "diag_preprocessing.png", analysis, metrics)
    gantt(out_dir / "diag_gantt.png", tasks)
