"""Chapter 4 (design approach, dataset analysis, methods) of the NetGuard AI report."""

from report.docx_helpers import (
    Report, m_acc_hat, m_bar, m_frac, m_paren, m_run, m_sqrt, m_sub, m_subsup, m_sum, m_sup, m_text,
)
from report.content_part1 import fmt, pct

FEATURE_DESCRIPTIONS = {
    "Destination Port": "Destination TCP/UDP port of the first packet; identifies the targeted service",
    "Flow Duration": "Time between the first and the last packet of the flow, in microseconds",
    "Total Fwd Packets": "Number of packets sent in the forward direction (initiator to responder)",
    "Total Backward Packets": "Number of packets sent in the backward direction (responder to initiator)",
    "Total Length of Fwd Packets": "Total size of the forward packets in bytes",
    "Total Length of Bwd Packets": "Total size of the backward packets in bytes",
    "Fwd Packet Length Max": "Largest forward packet (bytes)",
    "Fwd Packet Length Min": "Smallest forward packet (bytes)",
    "Fwd Packet Length Mean": "Mean forward packet size (bytes)",
    "Fwd Packet Length Std": "Standard deviation of forward packet sizes",
    "Bwd Packet Length Max": "Largest backward packet (bytes)",
    "Bwd Packet Length Min": "Smallest backward packet (bytes)",
    "Bwd Packet Length Mean": "Mean backward packet size (bytes)",
    "Bwd Packet Length Std": "Standard deviation of backward packet sizes",
    "Flow Bytes/s": "Bytes per second over the whole flow (Eqn. 4.1)",
    "Flow Packets/s": "Packets per second over the whole flow (Eqn. 4.2)",
    "Flow IAT Mean": "Mean time between two consecutive packets of the flow (either direction)",
    "Flow IAT Std": "Standard deviation of the flow inter-arrival time",
    "Flow IAT Max": "Largest gap between consecutive packets",
    "Flow IAT Min": "Smallest gap between consecutive packets",
    "Fwd IAT Total": "Sum of gaps between consecutive forward packets",
    "Fwd IAT Mean": "Mean gap between consecutive forward packets",
    "Fwd IAT Std": "Standard deviation of forward inter-arrival times",
    "Fwd IAT Max": "Largest gap between forward packets",
    "Fwd IAT Min": "Smallest gap between forward packets",
    "Bwd IAT Total": "Sum of gaps between consecutive backward packets",
    "Bwd IAT Mean": "Mean gap between consecutive backward packets",
    "Bwd IAT Std": "Standard deviation of backward inter-arrival times",
    "Bwd IAT Max": "Largest gap between backward packets",
    "Bwd IAT Min": "Smallest gap between backward packets",
    "Fwd PSH Flags": "Forward packets with PSH set (identical to SYN Flag Count in the files)",
    "Bwd PSH Flags": "Backward packets with PSH set (always 0 in the files)",
    "Fwd URG Flags": "Forward packets with URG set",
    "Bwd URG Flags": "Backward packets with URG set (always 0 in the files)",
    "Fwd Header Length": "Total bytes of headers in forward packets",
    "Bwd Header Length": "Total bytes of headers in backward packets",
    "Fwd Packets/s": "Forward packets per second",
    "Bwd Packets/s": "Backward packets per second",
    "Min Packet Length": "Smallest packet in either direction",
    "Max Packet Length": "Largest packet in either direction",
    "Packet Length Mean": "Mean packet size in either direction",
    "Packet Length Std": "Standard deviation of packet sizes",
    "Packet Length Variance": "Variance of packet sizes (square of the standard deviation)",
    "FIN Flag Count": "Packets with the FIN flag",
    "SYN Flag Count": "Packets with the SYN flag",
    "RST Flag Count": "Packets with the RST flag",
    "PSH Flag Count": "Packets with the PSH flag",
    "ACK Flag Count": "Packets with the ACK flag",
    "URG Flag Count": "Packets with the URG flag",
    "CWE Flag Count": "Packets with the CWR (congestion window reduced) flag",
    "ECE Flag Count": "Packets with the ECE (ECN-echo) flag",
    "Down/Up Ratio": "Ratio of download (backward) to upload (forward) traffic",
    "Average Packet Size": "Mean size of all packets in the flow",
    "Avg Fwd Segment Size": "Mean forward segment size (equals Fwd Packet Length Mean)",
    "Avg Bwd Segment Size": "Mean backward segment size (equals Bwd Packet Length Mean)",
    "Fwd Avg Bytes/Bulk": "Mean bytes per bulk transfer, forward (always 0)",
    "Fwd Avg Packets/Bulk": "Mean packets per bulk transfer, forward (always 0)",
    "Fwd Avg Bulk Rate": "Mean bulk transfer rate, forward (always 0)",
    "Bwd Avg Bytes/Bulk": "Mean bytes per bulk transfer, backward (always 0)",
    "Bwd Avg Packets/Bulk": "Mean packets per bulk transfer, backward (always 0)",
    "Bwd Avg Bulk Rate": "Mean bulk transfer rate, backward (always 0)",
    "Subflow Fwd Packets": "Mean forward packets per sub-flow (equals Total Fwd Packets)",
    "Subflow Fwd Bytes": "Mean forward bytes per sub-flow (equals Total Length of Fwd Packets)",
    "Subflow Bwd Packets": "Mean backward packets per sub-flow (equals Total Backward Packets)",
    "Subflow Bwd Bytes": "Mean backward bytes per sub-flow",
    "Init_Win_bytes_forward": "TCP initial window size in the first forward packet (-1 if not TCP / not seen)",
    "Init_Win_bytes_backward": "TCP initial window size in the first backward packet (-1 if not seen)",
    "act_data_pkt_fwd": "Forward packets carrying at least one byte of TCP payload",
    "min_seg_size_forward": "Minimum segment (header) size observed in the forward direction",
    "Active Mean": "Mean time the flow was active before becoming idle",
    "Active Std": "Standard deviation of active periods",
    "Active Max": "Longest active period",
    "Active Min": "Shortest active period",
    "Idle Mean": "Mean time the flow was idle before becoming active again",
    "Idle Std": "Standard deviation of idle periods",
    "Idle Max": "Longest idle period",
    "Idle Min": "Shortest idle period",
}


def chapter4(R: Report, A: dict, M: dict, D, F, E: dict) -> None:
    raw, dedup = A["raw_rows"], A["dedup_rows"]
    rc, dc = A["raw_label_counts"], A["dedup_label_counts"]
    sample_counts = A["sample_label_counts"]
    split = M["split"]
    q = A["quality"]
    dropped = M["features"]["dropped_constant"]

    R.chapter("Design Approach and Details")
    R.para(
        "This chapter explains how NetGuard AI was designed. It begins with the overall methodology and "
        "system architecture, then studies the CIC-IDS2017 dataset in depth: how it was generated, what its "
        "features measure, how its classes are distributed and what quality problems it has. The findings of "
        "that analysis drive the preprocessing, sampling and splitting design that follows. The chapter then "
        "describes the three models, the evaluation metrics, the backend and frontend, the standards followed "
        "and the constraints and trade-offs."
    )

    R.heading("4.1", "Design Approach / Materials & Methods")
    R.heading("4.1.1", "Methodology", level=3)
    R.para("The project follows a data-centred methodology in which every stage produces files that the next stage reads:")
    R.bullets([
        "**Data acquisition:** download the eight MachineLearningCSV files of CIC-IDS2017 and verify the row "
        f"count ({fmt(raw)} flows) against the official figure.",
        "**Exploratory data analysis:** measure class and attack distributions, missing, infinite and negative "
        "values, duplicates, constant and correlated features, and per-attack traffic profiles "
        "(ml/analyze_dataset.py).",
        "**Preprocessing:** clean headers and values, remove duplicates, map labels to two classes.",
        "**Sampling and splitting:** stratified sample, then a stratified train / validation / calibration / "
        "test split, plus a temporal (day-based) protocol for comparison.",
        "**Modelling:** train Random Forest, Decision Tree and Logistic Regression inside scikit-learn "
        "Pipelines.",
        "**Evaluation and selection:** choose the model on the validation set and report all metrics on the "
        "test set, overall and per attack type.",
        "**Reliability layer:** calibrate the probabilities, set the alert threshold and review band on the "
        "calibration set, and fit a batch distribution-shift gate on benign training traffic.",
        "**Deployment:** serve the selected Pipeline through FastAPI and visualise it in the React dashboard.",
    ], numbered=True)

    R.heading("4.1.2", "System architecture", level=3)
    R.para(
        f"{R.next_fig} shows the architecture. The lower half runs once, offline: the training script reads the "
        "dataset and writes two artefacts, the model bundle (models/netguard_model.joblib, which also holds the "
        "calibrator, the decision thresholds and the shift-gate reference profile) and the evaluation report "
        "(reports/metrics.json). The upper half runs for every user request: the browser uploads a CSV "
        "file to the FastAPI backend, which validates it, prepares the features with the same preprocessing "
        "module used in training, runs the saved Pipeline, applies the reliability layer and the shift gate, and "
        "returns JSON (or a CSV file) to the browser. The "
        "backend never retrains the model, and the dashboard never computes metrics itself; it only displays "
        "what the backend returns."
    )
    R.figure(D / "diag_architecture.png", "System Architecture of NetGuard AI", 5.9)
    R.para(
        "Separating the offline and online parts keeps each part simple. Training can take minutes and several "
        "gigabytes of memory, whereas prediction must be fast and light. Because the saved bundle contains the "
        "fitted imputer, the optional scaler, the classifier and the exact list of feature names, the online "
        "part cannot drift from the offline part."
    )

    # ------------------------------------------------------------------ dataset
    R.heading("4.1.3", "The CIC-IDS2017 dataset", level=3)
    R.para(
        "CIC-IDS2017 was created by Sharafaldin, Habibi Lashkari and Ghorbani at the Canadian Institute for "
        "Cybersecurity [19]. The authors built a testbed with a victim network of Windows, Linux and macOS "
        "machines and servers protected by a firewall, and a separate attack network running Kali Linux. To "
        "produce realistic benign traffic they profiled the behaviour of 25 users over protocols such as HTTP, "
        "HTTPS, FTP, SSH and e-mail and replayed that behaviour with agents (the B-Profile system). Traffic was "
        "captured for five working days, from Monday 3 July to Friday 7 July 2017, while attacks were launched "
        f"according to a schedule. {R.next_fig} summarises how the published CSV files were produced."
    )
    R.figure(D / "diag_data_generation.png", "Generation of the CIC-IDS2017 Flow Records", 5.9)
    R.para(
        "The full packet captures were processed with CICFlowMeter, which grouped packets into bidirectional "
        "flows and computed the flow statistics. Each flow was then labelled BENIGN or with the name of the "
        "attack running at that time between the attacker and victim addresses. The MachineLearningCSV "
        "version used here removes the identifying columns (flow ID, IP addresses, source port, protocol and "
        "timestamp) and keeps the destination port, 77 statistical features and the label. One feature, Fwd "
        "Header Length, appears twice, so the files have 79 columns in total. "
        f"{R.next_table} lists the eight files, measured directly from the data."
    )
    rows = []
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    for f in sorted(A["per_file"], key=lambda r: (day_order.index(r["day"]), r["file"])):
        attacks = ", ".join(f"{k} ({fmt(v)})" for k, v in f["labels"].items() if k != "BENIGN") or "none"
        rows.append([f["file"].replace(".pcap_ISCX.csv", ""), fmt(f["rows"]), fmt(f["benign"]), attacks])
    rows.append(["Total", fmt(raw), fmt(A["raw_class_counts"]["Benign"]),
                 f"{fmt(A['raw_class_counts']['Malicious'])} attack flows"])
    R.table("CIC-IDS2017 Files, Flow Counts and Attacks", ["File (day and period)", "Flows", "Benign", "Attack labels (flows)"],
            rows, widths=[2.0, 0.8, 0.8, 2.4], font_size=9, align=["left", "right", "right", "left"])
    R.para(
        "Monday contains only benign traffic and serves as a clean baseline. Attacks start on Tuesday with FTP "
        "and SSH brute force, continue on Wednesday with the denial-of-service tools and Heartbleed, on Thursday "
        "with web attacks in the morning and infiltration in the afternoon, and end on Friday with the botnet, "
        f"the port scan and the DDoS attack. {R.next_fig} shows the volume of each file. Wednesday is the largest "
        "file because DoS Hulk alone generated 231,073 flows, whereas the Friday afternoon DDoS and PortScan "
        "files are more than half malicious."
    )
    R.figure(F / "fig_flows_per_file.png", "Benign and Malicious Flows in Each CIC-IDS2017 File")

    R.heading("4.1.4", "Flow features", level=3)
    R.para(
        "The 77 distinct features can be grouped by what they measure. "
        f"{R.next_fig} shows the size of each group and how many features of each group were dropped because "
        "they never change in the training data (Section 4.1.5). The groups are:"
    )
    R.bullets([
        "**Basic flow:** destination port, duration and the number and total size of packets in each direction.",
        "**Packet length:** minimum, maximum, mean and spread of packet sizes, per direction and overall.",
        "**Flow rate:** bytes and packets per second.",
        "**Inter-arrival time (IAT):** timing between consecutive packets, overall and per direction.",
        "**TCP flags:** how many packets carried each TCP flag.",
        "**Header and window:** header bytes, TCP initial window sizes, data-carrying packets and the "
        "download/upload ratio.",
        "**Bulk transfer and sub-flow:** statistics of bulk data transfers and of sub-flows within a flow.",
        "**Active / idle:** how long the flow alternated between activity and silence.",
    ])
    R.figure(F / "fig_feature_groups.png", "Feature Groups of the CICFlowMeter Feature Set")
    R.para(
        "Two of the features are derived quantities whose definitions matter for the data-quality analysis. "
        "The flow byte rate and packet rate are computed from the totals and the duration, which is measured "
        f"in microseconds, as shown in {R.next_eq} and Eqn. 4.2:"
    )
    R.equation(m_text("Flow Bytes/s") + m_run(" = ")
               + m_frac(m_text("Total Length of Fwd Packets") + m_run(" + ") + m_text("Total Length of Bwd Packets"),
                        m_text("Flow Duration")) + m_run(" × ") + m_sup(m_run("10"), m_run("6")))
    R.equation(m_text("Flow Packets/s") + m_run(" = ")
               + m_frac(m_text("Total Fwd Packets") + m_run(" + ") + m_text("Total Backward Packets"),
                        m_text("Flow Duration")) + m_run(" × ") + m_sup(m_run("10"), m_run("6")))
    R.para(
        "These definitions were checked against the files: on all 529,466 Monday flows with a positive "
        "duration, the published Flow Bytes/s and Flow Packets/s agree with Eqn. 4.1 and Eqn. 4.2 to within "
        "0.1%. When the duration is zero, the division in these equations is undefined, which explains the "
        f"infinite and missing values described below. {R.next_table} gives the meaning of every feature; "
        "features marked as constant or identical to another feature were confirmed by measurement."
    )
    rows = []
    groups = A["features"]["groups"]
    for group, names in groups.items():
        for name in names:
            status = "dropped (constant)" if name in dropped else "used"
            rows.append([name, group, FEATURE_DESCRIPTIONS[name], status])
    R.table("Feature Dictionary of the 77 CIC-IDS2017 Flow Features", ["Feature", "Group", "Description", "Model"],
            rows, widths=[1.55, 0.95, 2.75, 0.75], font_size=8.5)

    # ------------------------------------------------------------------ EDA
    R.heading("4.1.5", "Exploratory data analysis", level=3)
    R.para(
        "Before designing the preprocessing, the raw files were analysed with ml/analyze_dataset.py. The "
        "script reads all eight files, measures them before and after cleaning, and saves every number to "
        "reports/dataset_analysis.json, from which the tables and figures in this section are generated."
    )

    R.para("**Class and attack distribution.** " +
           f"{R.next_fig} shows the number of flows per label on a logarithmic scale. The distribution is "
           f"extremely skewed: BENIGN accounts for {pct(rc['BENIGN'] / raw)} of all flows, the three largest "
           f"attack labels (DoS Hulk, PortScan and DDoS) for {pct((rc['DoS Hulk'] + rc['PortScan'] + rc['DDoS']) / raw)}, "
           f"and the four smallest labels together contain only "
           f"{fmt(rc['Infiltration'] + rc['Web Attack – Sql Injection'] + rc['Heartbleed'] + rc['Web Attack – XSS'])} flows. "
           f"Heartbleed has just {rc['Heartbleed']} flows and SQL injection {rc['Web Attack – Sql Injection']}.")
    R.figure(F / "fig_label_distribution.png", "Number of Flows per Label in the Raw Dataset (Log Scale)")
    R.para(
        f"For the binary problem the imbalance ratio, defined in {R.next_eq}, is moderate: after "
        f"deduplication there are {fmt(A['dedup_class_counts']['Benign'])} benign and "
        f"{fmt(A['dedup_class_counts']['Malicious'])} malicious flows, a ratio of "
        f"{A['dedup_class_counts']['Benign'] / A['dedup_class_counts']['Malicious']:.2f} to 1. Within the "
        "malicious class, however, the ratio between the largest and smallest attack label exceeds 15,000 to 1, "
        "which is the root of the per-attack differences reported in Chapter 7 [23]."
    )
    R.equation(m_text("IR") + m_run(" = ") + m_frac(m_sub(m_run("N"), m_text("benign")), m_sub(m_run("N"), m_text("malicious"))))

    label_rows = []
    for label in sorted(rc, key=lambda k: -rc[k]):
        removed = rc[label] - dc.get(label, 0)
        label_rows.append([label, fmt(rc[label]), fmt(dc.get(label, 0)), f"{100 * removed / rc[label]:.1f}%",
                           fmt(sample_counts.get(label, 0))])
    label_rows.append(["Total", fmt(raw), fmt(dedup), f"{100 * (raw - dedup) / raw:.1f}%",
                       fmt(sum(sample_counts.values()))])
    R.table("Flows per Label Before and After Deduplication and in the Training Sample",
            ["Label", "Raw flows", "Unique flows", "Duplicates", "In 500k sample"], label_rows,
            widths=[1.9, 1.05, 1.05, 0.9, 1.1], align=["left", "right", "right", "right", "right"])

    R.para("**Duplicate records.** " +
           f"{fmt(raw - dedup)} rows ({pct((raw - dedup) / raw)}) are exact copies of another row, with identical "
           f"values in all 78 features and the same label. {R.next_fig} shows that duplication is very uneven. "
           f"SSH-Patator ({100 * (1 - dc['SSH-Patator'] / rc['SSH-Patator']):.1f}%) and PortScan "
           f"({100 * (1 - dc['PortScan'] / rc['PortScan']):.1f}%) are the most duplicated, because these tools "
           "repeat the same short exchange thousands of times: a scan probe or a failed login produces a flow "
           "with the same packet counts, sizes and flags every time. Benign traffic is far more varied, and only "
           f"{100 * (1 - dc['BENIGN'] / rc['BENIGN']):.1f}% of it is duplicated.")
    R.figure(F / "fig_duplicates_by_label.png", "Share of Each Label Removed as Exact Duplicates")
    R.para(
        "Duplicates matter for evaluation. If one copy of a record falls in the training set and another in the "
        "test set, the model is tested on a flow it has already memorised, and the test score overstates how "
        "well it generalises. Because the most duplicated labels are attacks, keeping duplicates would also "
        "inflate the apparent detection rate of exactly those attacks. NetGuard therefore removes duplicates "
        "before any sampling or splitting."
    )

    R.para("**Missing, infinite and negative values.** " +
           f"{R.next_fig} and {R.next_table} summarise the invalid values found in the raw files. Flow Bytes/s is "
           f"missing (NaN) in {fmt(q['nan_by_column'].get('Flow Bytes/s', 0))} rows and infinite in "
           f"{fmt(q['inf_by_column'].get('Flow Bytes/s', 0))} rows, and Flow Packets/s is infinite in "
           f"{fmt(q['inf_by_column'].get('Flow Packets/s', 0))} rows. All of them come from flows whose measured "
           "duration is zero: when both totals are also zero, Eqn. 4.1 evaluates 0/0 (NaN); otherwise it divides "
           "a positive number by zero (infinity).")
    R.figure(F / "fig_data_quality.png", "Infinite, Missing and Negative Values in the Raw Files (Log Scale)")
    neg = q["negative_by_column"]
    R.table("Invalid and Sentinel Values in the Raw Dataset", ["Feature", "Issue", "Rows", "Explanation and handling"], [
        ["Flow Bytes/s", "NaN", fmt(q["nan_by_column"].get("Flow Bytes/s", 0)), "0/0 for zero-duration flows → median imputation"],
        ["Flow Bytes/s", "+∞", fmt(q["inf_by_column"].get("Flow Bytes/s", 0)), "Division by zero duration → treated as missing"],
        ["Flow Packets/s", "+∞", fmt(q["inf_by_column"].get("Flow Packets/s", 0)), "Division by zero duration → treated as missing"],
        ["Init_Win_bytes_backward", "-1", fmt(neg.get("Init_Win_bytes_backward", 0)), "Sentinel: no TCP window seen (UDP or no reply) → kept as a value"],
        ["Init_Win_bytes_forward", "-1", fmt(neg.get("Init_Win_bytes_forward", 0)), "Sentinel: no TCP window seen → kept as a value"],
        ["Flow IAT Min", "< 0", fmt(neg.get("Flow IAT Min", 0)), "Timestamp ordering artefact of the flow meter → kept"],
        ["Flow Duration", "< 0", fmt(neg.get("Flow Duration", 0)), "Clock artefact, physically impossible → kept (rare)"],
    ], widths=[1.6, 0.6, 0.85, 2.95], align=["left", "center", "right", "left"])
    R.para(
        "The value -1 in the initial window features is not an error but a sentinel. In the Monday file, every "
        "flow to port 53 (DNS) and port 123 (NTP), both UDP services, has Init_Win_bytes_forward equal to -1, "
        "whereas only 0.6% of flows to port 443 do. UDP has no window field [4], so the flow meter records -1. "
        "Because the sentinel carries protocol information that tree-based models can use, it is kept as an "
        "ordinary value rather than treated as missing. The small number of negative durations and "
        "inter-arrival times are physically impossible and point to timestamp problems in the flow meter, "
        "which Engelen et al. [20] also reported; they affect fewer than 0.01% of rows and are left unchanged."
    )

    R.para("**Constant features.** " +
           f"Eight features have the same value in every one of the {fmt(dedup)} unique flows: "
           f"{', '.join(A['features']['constant_in_full_dataset'])}. All six bulk-transfer statistics are always "
           "zero, which suggests that the bulk-detection logic of the flow-meter version used did not trigger, "
           "and the backward PSH and URG counters are never set. A feature that never changes cannot separate "
           "classes, so these features are removed. The training script detects constant features on the "
           f"training split only and finds the same eight, leaving {M['features']['count']} features for the model.")

    R.para("**Feature distributions.** " +
           f"{R.next_fig} compares benign and malicious flows on six features. Values span many orders of "
           "magnitude, so they are plotted as log10(value + 1). Malicious flows last longer at the median, "
           "because slow DoS attacks and brute-force sessions keep connections open, and they have much larger "
           "variation in backward packet size, because attacked web servers return a mix of large pages and "
           "small error responses. The boxes overlap substantially, which shows that no single feature separates "
           "the classes; the model has to combine many features.")
    R.figure(F / "fig_feature_boxplots.png", "Distribution of Six Flow Features for Benign and Malicious Flows")
    ks = A["key_feature_stats"]
    stat_rows = []
    for f in ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Bwd Packet Length Std",
              "Average Packet Size", "Flow Bytes/s", "Flow Packets/s", "Init_Win_bytes_forward"]:
        b, mal = ks[f]["Benign"], ks[f]["Malicious"]
        stat_rows.append([f, f"{b['median']:,.1f}", f"{b['mean']:,.1f}", f"{mal['median']:,.1f}", f"{mal['mean']:,.1f}"])
    R.table("Median and Mean of Key Features by Class (Unique Flows)",
            ["Feature", "Benign median", "Benign mean", "Malicious median", "Malicious mean"], stat_rows,
            widths=[1.7, 1.05, 1.1, 1.05, 1.1], font_size=9, align=["left", "right", "right", "right", "right"])
    stats_table = R.prev_table
    fd = ks["Flow Duration"]
    R.para(
        f"The large gap between median and mean in {stats_table} shows heavily "
        f"skewed distributions. For benign flows the median duration is {fd['Benign']['median'] / 1e3:.1f} ms but "
        f"the mean is {fd['Benign']['mean'] / 1e6:.1f} s, because most flows are short DNS lookups while a few "
        f"long sessions dominate the mean. {R.next_fig} shows the same effect as a cumulative distribution: "
        "more than half of the benign flows finish within 50 ms, whereas more than half of the malicious flows last "
        "longer than five seconds. Skewed, heavy-tailed features favour tree-based models, which split on "
        "thresholds and are unaffected by scale, over linear models that assume roughly linear effects."
    )
    R.figure(F / "fig_flow_duration_ecdf.png", "Cumulative Distribution of Flow Duration by Class")

    R.para("**Per-attack traffic profiles.** " +
           f"Each attack leaves a distinctive network signature. {R.next_table} lists median values per label, "
           "computed on unique flows.")
    pa = A["per_attack_medians"]
    pa_rows = []
    for label in sorted(pa, key=lambda k: -dc[k]):
        p = pa[label]
        port = "many" if p["top_port_share"] < 0.05 else f"{p['top_port']} ({100 * p['top_port_share']:.0f}%)"
        pa_rows.append([label, f"{p['Flow Duration'] / 1e6:,.3f}", f"{p['Total Fwd Packets']:,.0f}",
                        f"{p['Total Backward Packets']:,.0f}", f"{p['Flow Bytes/s']:,.1f}", port])
    R.refs["profiles"] = R.next_table
    R.table("Median Traffic Profile of Each Label", ["Label", "Duration (s)", "Fwd pkts", "Bwd pkts", "Bytes/s", "Top port (share)"],
            pa_rows, widths=[1.75, 0.85, 0.65, 0.65, 0.95, 1.15], font_size=9,
            align=["left", "right", "right", "right", "right", "right"])
    R.para(
        "The profiles match how the tools work. PortScan flows last 50 µs and contain one packet in each "
        "direction (a probe and a reset), spread over thousands of ports, so no port holds even 5% of them. "
        "DoS slowloris holds connections open for about 100 seconds at 0.16 bytes per second, and DoS "
        "Slowhttptest flows typically receive no backward packet at all, which is the essence of a slow "
        "attack: occupying server resources while sending almost nothing. Brute-force sessions exchange tens of "
        "packets with the FTP or SSH server, and Heartbleed flows are long TLS sessions with thousands of "
        "packets in both directions. These distinct signatures explain why most attacks are easy to detect, "
        "and the labels whose profiles resemble benign traffic, such as Bot, are where errors concentrate."
    )

    R.para("**Destination ports.** " +
           f"The unique flows use {fmt(A['distinct_ports'])} distinct destination ports. {R.next_fig} shows the ten "
           "most frequent ports for each class.")
    R.figure(F / "fig_top_ports.png", "Ten Most Frequent Destination Ports for Benign and Malicious Flows")
    tp = A["top_ports"]
    R.para(
        f"Benign traffic is dominated by DNS (port 53, {fmt(tp['Benign']['53'])} flows), HTTPS (443) and HTTP "
        "(80), followed by NTP (123), SSH (22), LDAP (389) and Kerberos (88), which is typical of a Windows "
        f"domain network. Malicious traffic is concentrated on port 80 ({fmt(tp['Malicious']['80'])} flows) "
        "because the DoS, DDoS and web attacks all target the web server, followed by FTP (21), SSH (22) and the "
        "botnet port 8080. Destination port is therefore informative, but it is not sufficient: benign HTTP "
        "traffic also uses port 80, so the model must look at how the connection behaves, not only where it goes."
    )

    corr = A["correlation"]
    R.para("**Correlation and redundancy.** " +
           f"Linear dependence between features was measured with the Pearson correlation coefficient "
           f"({R.next_eq}) on a random sample of {fmt(corr['sample_rows'])} unique flows, after removing constant "
           "features and filling missing values with medians.")
    R.equation(m_sub(m_run("r"), m_run("ab")) + m_run(" = ")
               + m_frac(m_sum(m_run("i=1"), m_run("n"), m_paren(m_sub(m_run("a"), m_run("i")) + m_run(" − ") + m_bar(m_run("a")))
                              + m_paren(m_sub(m_run("b"), m_run("i")) + m_run(" − ") + m_bar(m_run("b")))),
                        m_sqrt(m_sum(m_run("i=1"), m_run("n"), m_sup(m_paren(m_sub(m_run("a"), m_run("i")) + m_run(" − ") + m_bar(m_run("a"))), m_run("2"))))
                        + m_sqrt(m_sum(m_run("i=1"), m_run("n"), m_sup(m_paren(m_sub(m_run("b"), m_run("i")) + m_run(" − ") + m_bar(m_run("b"))), m_run("2"))))))
    R.para(
        f"{corr['pairs_above_threshold']} feature pairs have |r| ≥ {corr['threshold']}, and {corr['perfect_pairs']} "
        f"pairs are perfectly correlated (|r| = 1). {R.next_table} lists the strongest pairs and "
        f"{R.next_fig} shows the correlation among the fifteen features the model finds "
        "most important."
    )
    R.refs["corr"] = R.next_table
    R.table("Most Strongly Correlated Feature Pairs", ["Feature A", "Feature B", "r"],
            [[p["a"], p["b"], f"{p['r']:.4f}"] for p in corr["top_pairs"][:12]],
            widths=[2.4, 2.4, 0.8], align=["left", "left", "right"])
    R.figure(F / "fig_correlation_heatmap.png", "Pearson Correlation Among the Fifteen Most Important Features", 5.6)
    R.para(
        "The perfect correlations reveal redundancy built into the feature set. The sub-flow features equal the "
        "corresponding totals because CICFlowMeter found one sub-flow per flow; the average segment sizes equal "
        "the mean packet lengths; and, surprisingly, Fwd PSH Flags equals SYN Flag Count in every row, which "
        "indicates that the flow meter stored the wrong counter in one of these columns. Redundant features do "
        "not harm a Random Forest's predictions, but they split the importance score between copies, so the "
        "importance ranking in Chapter 7 is read at the level of feature groups. They were kept to preserve "
        "compatibility with standard CIC-IDS2017 files."
    )

    # ------------------------------------------------------------------ preprocessing
    R.heading("4.1.6", "Data preprocessing pipeline", level=3)
    R.para(
        f"The findings above define the preprocessing steps shown in {R.next_fig}. Steps 1 to 4 run once on the "
        "full dataset in ml/train.py; steps 5 to 7 build the training data; step 8 lives inside the saved "
        "scikit-learn Pipeline and is therefore applied automatically to every uploaded file."
    )
    R.figure(D / "diag_preprocessing.png", "Preprocessing Pipeline With Row Counts at Each Step", 5.4)
    R.bullets([
        "**Header cleaning.** Column names in the files start with a space (\" Flow Duration\"), so names are "
        "stripped. The duplicated Fwd Header Length column, which pandas renames to Fwd Header Length.1, is dropped.",
        "**Type conversion.** Every feature is converted to a number; text that cannot be converted becomes "
        "missing, and +∞ and -∞ become missing. Features are stored as 32-bit floats, halving memory use.",
        f"**Label mapping.** Labels are stripped and mapped to two classes with {R.next_eq}.",
        "**Deduplication.** Each row (all features and the label) is hashed to a 64-bit value with "
        "pandas.util.hash_pandas_object and only the first row of each hash is kept. Hashing 2.8 million rows "
        "takes seconds, whereas pandas' column-by-column drop_duplicates had not finished after nine minutes in "
        "an early version of the pipeline. With 2.8 million rows, the probability of two different rows sharing a "
        "64-bit hash is about 2 × 10⁻⁷, which is negligible.",
    ])
    R.equation(m_sub(m_run("y"), m_run("i")) + m_run(" = ") +
               m_paren(m_text("0 if ") + m_sub(m_text("label"), m_run("i")) + m_text(" = BENIGN;  1 otherwise"), "{", ""))
    R.para(
        f"Missing values that remain after cleaning are replaced by the median of the training data "
        f"({R.next_eq}). The median is used instead of the mean because the features are heavily skewed "
        f"({stats_table}), so the mean would be pulled towards rare extreme values. For Logistic Regression the "
        f"features are additionally standardised ({R.eq_after(1)}), because that model is sensitive to the very "
        "different scales of, for example, Destination Port and Flow Duration."
    )
    R.equation(m_sub(m_sup(m_run("x"), m_run("′")), m_run("ij")) + m_run(" = ")
               + m_paren(m_text("median") + m_paren(m_sub(m_run("x"), m_run("j")) + m_run(" ∣ ") + m_text("train")) + m_text("  if ")
                         + m_sub(m_run("x"), m_run("ij")) + m_text(" is missing;  ") + m_sub(m_run("x"), m_run("ij")) + m_text(" otherwise"), "{", ""))
    R.equation(m_sub(m_run("z"), m_run("ij")) + m_run(" = ")
               + m_frac(m_sub(m_run("x"), m_run("ij")) + m_run(" − ") + m_sub(m_run("μ"), m_run("j")), m_sub(m_run("σ"), m_run("j"))))
    R.para(
        "The median, mean and standard deviation in these equations are learned with fit() on the training "
        "split only and then applied with transform() to the validation set, the test set and every uploaded "
        "file. Fitting them on all data would leak information about the test set into the model."
    )

    # ------------------------------------------------------------------ sampling / split
    R.heading("4.1.7", "Sampling and data splitting", level=3)
    R.para(
        f"Training on all {fmt(dedup)} unique flows would need far more than the 7 GB of memory available, so "
        f"the pipeline draws a stratified random sample of {fmt(M['dataset']['rows_used'])} flows. Stratification "
        "keeps the benign/malicious ratio of the sample equal to that of the full data, as expressed in "
        f"{R.next_eq}, where N~c~ is the number of flows of class c."
    )
    R.equation(m_frac(m_subsup(m_run("N"), m_run("c"), m_text("sample")), m_sup(m_run("N"), m_text("sample")))
               + m_run(" ≈ ") + m_frac(m_sub(m_run("N"), m_run("c")), m_run("N")) + m_run(",   c ∈ {benign, malicious}"))
    R.para(
        f"{R.next_fig} compares the share of every label in the sample with its share in the cleaned dataset. "
        "For the large labels the two agree closely, but the sample is stratified on the binary class, not on "
        "the attack label, so very rare labels are kept only by chance: the sample contains "
        f"{sample_counts.get('Heartbleed', 0)} of the {dc['Heartbleed']} Heartbleed flows, "
        f"{sample_counts.get('Infiltration', 0)} of the {dc['Infiltration']} Infiltration flows and "
        f"{sample_counts.get('Web Attack – Sql Injection', 0)} of the {dc['Web Attack – Sql Injection']} SQL "
        "injection flows."
    )
    R.figure(F / "fig_sample_vs_population.png", "Share of Each Label in the Cleaned Dataset and in the Training Sample")
    R.para(
        "The sample is then split in three stratified stages with random_state = 42: 20% is set aside as the "
        "test set; 22.5% of the remainder is set aside and divided almost equally into a validation set and a "
        f"calibration set. The result is {fmt(split['train'])} training, {fmt(split['validation'])} validation, "
        f"{fmt(split['calibration'])} calibration and {fmt(split['test'])} test flows (62% / 8% / 10% / 20%). "
        f"{R.next_table} shows the class balance of each part."
    )
    slc = A["split_label_counts"]
    rows = []
    for part, name in (("train", "Training"), ("validation", "Validation"), ("calibration", "Calibration"), ("test", "Test")):
        b = slc[part].get("BENIGN", 0)
        mal = sum(slc[part].values()) - b
        rows.append([name, fmt(b + mal), fmt(b), fmt(mal), pct(mal / (b + mal))])
    R.table("Composition of the Training, Validation, Calibration and Test Sets",
            ["Set", "Flows", "Benign", "Malicious", "Malicious share"],
            rows, widths=[1.2, 1.1, 1.1, 1.1, 1.2], align=["left", "right", "right", "right", "right"])
    repro = A["reproduces_saved_metrics"]
    R.para(
        "All four sets have the same malicious share to three decimal places, which confirms the "
        "stratification. Their roles are strictly separated. The training set fits the models. The validation "
        "set is used for one decision, choosing which model to deploy. The calibration set fits the reliability "
        "layer (Section 4.1.11). The test set is used only to report the final scores, so it estimates the "
        "performance on unseen traffic. As a reproducibility check, the dataset analysis script rebuilds the "
        "sample and split independently and runs the saved model on the rebuilt test set. "
        + ("It reproduces the stored confusion matrix of the deployed Random Forest exactly. "
           if repro.get("Random Forest") else "")
        + ("The Decision Tree and Logistic Regression refitted on the rebuilt training set differ from the "
           "stored results by at most six flows, which is attributable to a different library build; the "
           "per-attack figures for those two models in Chapter 7 therefore come from the refitted models."
           if not (repro.get("Decision Tree") and repro.get("Logistic Regression")) else "")
    )
    rare = ["Bot", "Web Attack – Brute Force", "Web Attack – XSS", "Infiltration", "Heartbleed", "Web Attack – Sql Injection"]
    R.para(f"{R.next_table} shows how the rare attack labels were distributed over the four sets.")
    R.table("Rare Attack Labels in Each Set", ["Label", "Train", "Validation", "Calibration", "Test"],
            [[label] + [fmt(slc[part].get(label, 0)) for part in ("train", "validation", "calibration", "test")]
             for label in rare],
            widths=[2.2, 0.9, 0.9, 0.9, 0.9], align=["left", "right", "right", "right", "right"])
    R.refs["rare"] = R.prev_table
    tr = slc["train"]
    R.para(
        "The table exposes an important property of the data. The training set contains "
        f"{tr.get('Heartbleed', 0)} Heartbleed, {tr.get('Infiltration', 0)} Infiltration and "
        f"{tr.get('Web Attack – Sql Injection', 0)} SQL injection flows, and SQL injection does not appear in "
        "the test set at all. No classifier can learn a reliable pattern from a handful of examples, or from "
        "none, so detection of these labels in Chapter 7 must be interpreted with this in mind. Stratifying on "
        "the attack label, or keeping every flow of the rarest labels, would reduce the problem; this is "
        "discussed as a recommendation in Chapter 8."
    )

    # ------------------------------------------------------------------ protocols
    R.heading("4.1.8", "Evaluation protocols: random versus temporal", level=3)
    R.para(
        "A random split mixes flows from all five days, so training and test flows come from the same hours of "
        "the same attacks. That answers the question \"can the model recognise more flows of attacks it has "
        "seen?\" but not \"will it work tomorrow?\". To answer the second question, ml/experiments.py repeats "
        f"the training under three protocols, defined in {R.next_table}."
    )
    em = {k: v["meta"] for k, v in E["protocols"].items()}
    R.table("Evaluation Protocols", ["Protocol", "Training data", "Calibration data", "Test data", "Test flows"], [
        ["Random (all days)", "Random 62% of the sample, all days", "Random 10%", "Random 20%", fmt(em["original"]["sizes"]["test"])],
        ["Random (Mon–Wed)", "Random 62% of Mon–Wed flows", "Random 10%", "Random 20% of Mon–Wed", fmt(em["random_monwed"]["sizes"]["test"])],
        ["Temporal", "Monday–Wednesday", "Thursday morning", "Thursday afternoon and Friday", fmt(em["temporal"]["sizes"]["test"])],
    ], widths=[1.15, 1.6, 1.15, 1.4, 0.7], font_size=9)
    R.para(
        "The temporal protocol is the realistic one: the model is trained on the first three days and then "
        "faces later days, which contain attack types that never occurred during training (PortScan, Bot, "
        "Infiltration, DDoS). Its test set is capped at "
        f"{fmt(em['temporal']['test_cap_per_class'])} flows per label to keep the large DDoS and PortScan "
        "classes from dominating, while every flow of the rare labels is kept. The deployed model uses the "
        "random protocol so that the dashboard reflects the standard benchmark; the temporal results are "
        "reported in Section 7.6."
    )

    # ------------------------------------------------------------------ models
    R.heading("4.1.9", "Machine learning models", level=3)
    R.para(
        "Three classifiers of increasing complexity were compared, all implemented with scikit-learn [24]. "
        "Each is wrapped in a Pipeline together with its preprocessing, so the whole chain is saved and reused "
        "as one object."
    )
    R.para(
        "**Decision Tree.** A decision tree [13], [25] splits the data recursively. At each node it chooses the "
        "feature and threshold that make the two resulting groups as pure as possible. Purity is measured with "
        f"the Gini impurity ({R.next_eq}), where p~k~ is the share of class k among the N samples at a node; "
        "a node with only one class has G = 0. The chosen split maximises the impurity decrease "
        f"({R.eq_after(1)}), where L and R are the left and right children. The tree grows until its leaves are "
        "pure, which makes it accurate on training data but prone to overfitting."
    )
    R.equation(m_run("G") + m_run(" = 1 − ") + m_sum(m_run("k=1"), m_run("K"), m_sup(m_sub(m_run("p"), m_run("k")), m_run("2"))))
    R.equation(m_run("ΔG = ") + m_sub(m_run("G"), m_text("parent")) + m_run(" − ")
               + m_frac(m_sub(m_run("N"), m_run("L")), m_run("N")) + m_sub(m_run("G"), m_run("L")) + m_run(" − ")
               + m_frac(m_sub(m_run("N"), m_run("R")), m_run("N")) + m_sub(m_run("G"), m_run("R")))
    R.para(
        "**Random Forest.** A Random Forest [12] trains T decision trees, each on a bootstrap sample of the "
        "training data (rows drawn with replacement), and at every split considers only a random subset of m "
        f"features ({R.eq_after(1)}). The randomness makes the trees different from each other, so their errors "
        f"partly cancel. The forest's malicious probability is the average of the trees' votes ({R.next_eq}), and "
        "a flow is classified as malicious when this probability is at least 0.5."
    )
    R.equation(m_run("P") + m_paren(m_run("malicious ∣ x")) + m_run(" = ") + m_frac(m_run("1"), m_run("T"))
               + m_sum(m_run("t=1"), m_run("T"), m_sub(m_run("h"), m_run("t")) + m_paren(m_run("x"))))
    R.equation(m_run("m = ") + m_paren(m_sqrt(m_run("p")), "⌊", "⌋") + m_run(" = ") + m_paren(m_sqrt(m_run(str(M["features"]["count"]))), "⌊", "⌋")
               + m_run(f" = {int(M['features']['count'] ** 0.5)}"))
    R.para(
        "Here h~t~(x) is the prediction of tree t (strictly, scikit-learn averages each tree's class probability), "
        f"and p = {M['features']['count']} is the number of features. The forest also measures feature importance as "
        f"the mean decrease in impurity ({R.next_eq}): the total Gini decrease contributed by splits on a feature, "
        "averaged over all trees and normalised to sum to one."
    )
    R.equation(m_sub(m_text("Imp"), m_run("j")) + m_run(" = ") + m_frac(m_run("1"), m_run("T"))
               + m_sum(m_run("t=1"), m_run("T"), m_sum(m_run("s ∈ t : feature(s) = j"), None,
                                                       m_frac(m_sub(m_run("N"), m_run("s")), m_run("N")) + m_run("Δ") + m_sub(m_run("G"), m_run("s")))))
    R.para(
        "**Logistic Regression.** Logistic Regression [26] is a linear model. It computes a weighted sum of the "
        "standardised features and passes it through the sigmoid function to obtain a probability "
        f"({R.next_eq}). The weights are learned by minimising the log-loss ({R.eq_after(1)}). Because its "
        "decision boundary is a hyperplane, it serves as a baseline that shows how much the non-linear tree "
        "models gain."
    )
    R.equation(m_run("P") + m_paren(m_run("y = 1 ∣ x")) + m_run(" = σ") + m_paren(m_sup(m_run("w"), m_run("T")) + m_run("x + b"))
               + m_run(" = ") + m_frac(m_run("1"), m_run("1 + ") + m_sup(m_run("e"), m_run("−") + m_paren(m_sup(m_run("w"), m_run("T")) + m_run("x + b")))))
    R.equation(m_run("L") + m_paren(m_run("w, b")) + m_run(" = −") + m_frac(m_run("1"), m_run("n"))
               + m_sum(m_run("i=1"), m_run("n"), m_paren(m_sub(m_run("y"), m_run("i")) + m_run(" log ") + m_sub(m_run("p"), m_run("i"))
                                                         + m_run(" + ") + m_paren(m_run("1 − ") + m_sub(m_run("y"), m_run("i")))
                                                         + m_run(" log") + m_paren(m_run("1 − ") + m_sub(m_run("p"), m_run("i"))), "[", "]")))
    R.table("Model Configurations", ["Model", "Pipeline steps", "Main hyper-parameters"], [
        ["Random Forest", "SimpleImputer(median) → RandomForestClassifier", "100 trees, max_features = √p, unlimited depth, n_jobs = −1, random_state = 42"],
        ["Decision Tree", "SimpleImputer(median) → DecisionTreeClassifier", "Gini criterion, unlimited depth, random_state = 42"],
        ["Logistic Regression", "SimpleImputer(median) → StandardScaler → LogisticRegression", "L2 penalty, C = 1.0, lbfgs solver, max_iter = 1000"],
    ], widths=[1.3, 2.3, 2.4])
    R.para(
        "Default hyper-parameters were used deliberately. The aim is a fair, explainable comparison rather than "
        "a tuned competition; tuning would also require additional validation data, and the models already "
        "reach very high scores. Class weights were not used because the binary imbalance (4.9 to 1) is "
        "moderate."
    )

    # ------------------------------------------------------------------ evaluation
    R.heading("4.1.10", "Evaluation metrics and model selection", level=3)
    R.para(
        "Malicious is treated as the positive class. From the test-set confusion matrix, with TP (attacks "
        "correctly flagged), TN (benign flows correctly passed), FP (false alarms) and FN (missed attacks), the "
        "following metrics are computed:"
    )
    tp, tn, fp, fn = (m_run(s) for s in ("TP", "TN", "FP", "FN"))
    R.equation(m_text("Accuracy") + m_run(" = ") + m_frac(tp + m_run(" + ") + tn, tp + m_run(" + ") + tn + m_run(" + ") + fp + m_run(" + ") + fn))
    R.equation(m_text("Precision") + m_run(" = ") + m_frac(tp, tp + m_run(" + ") + fp))
    R.equation(m_text("Recall") + m_run(" = ") + m_frac(tp, tp + m_run(" + ") + fn))
    R.equation(m_sub(m_run("F"), m_run("1")) + m_run(" = 2 × ") + m_frac(m_text("Precision") + m_run(" × ") + m_text("Recall"),
                                                                      m_text("Precision") + m_run(" + ") + m_text("Recall")))
    R.equation(m_text("FPR") + m_run(" = ") + m_frac(fp, fp + m_run(" + ") + tn))
    R.para(
        "Accuracy alone is misleading for imbalanced data: a model that labels every flow benign would reach "
        f"{pct(A['dedup_class_counts']['Benign'] / dedup)} accuracy on this dataset while detecting nothing. Precision "
        "tells an analyst how many alerts are real, recall (the detection rate) how many attacks are caught, and "
        "F1 balances the two. The false positive rate matters operationally because even a small FPR produces "
        "many false alarms on a large benign volume. The ROC curve [27] and the precision–recall curve [28] summarise "
        "performance over all decision thresholds."
    )
    R.para(
        "The model to deploy is chosen on the validation set using F1-score. Random Forest is the primary model "
        "of the project, so it is kept unless another model's validation F1 is higher by more than 0.001. "
        "This margin prevents a difference of one or two flows, which is statistical noise, from changing the "
        "deployed model. The rule was added after the first training run showed a near-tie between Random "
        "Forest and Decision Tree, and it uses validation data only, so the test set plays no part in the choice."
    )

    # ------------------------------------------------------------------ backend
    # ------------------------------------------------------------------ reliability
    rel = M["reliability"]
    cal = rel["calibration"]
    gate = M["shift_gate"]
    severe = gate.get("threshold_severe") or next(iter(gate["per_day"].values()))["threshold_severe"]
    R.heading("4.1.11", "Reliability layer", level=3)
    R.para(
        "A classifier that outputs \"malicious\" whenever its vote fraction reaches 0.5 gives the operator no "
        "control over how many false alarms to expect, treats a 0.51 vote like a 0.99 vote, and has no way of "
        "saying that a whole batch looks unlike anything it was trained on. The reliability layer "
        "(ml/reliability.py) adds these controls on top of the selected Random Forest. All of it is fitted on the "
        f"calibration set of {fmt(cal['size'])} flows, which the model never trained on, and it is split into two "
        f"disjoint halves of {fmt(cal['fit_half'])} flows so that the calibration map and the thresholds are not "
        "fitted on the same examples."
    )
    R.para(
        "**Calibration.** The raw output of a Random Forest is a vote fraction, not a probability. Isotonic "
        "regression [37] learns a non-decreasing function g that maps the vote fraction s to the observed frequency "
        f"of malicious flows on the first half of the calibration set ({R.next_eq}). Because g is monotone it never "
        "changes the ranking of flows, only the scale of the scores."
    )
    R.equation(m_run("g = ") + m_sub(m_text("arg min"), m_text("g non-decreasing"))
               + m_sum(m_run("i"), None, m_sup(m_paren(m_sub(m_run("y"), m_run("i")) + m_run(" − g") + m_paren(m_sub(m_run("s"), m_run("i")))), m_run("2"))))
    R.para(
        "**Risk-controlled alert threshold.** The operator chooses a false-positive budget α, the largest "
        f"acceptable share of benign flows that may raise an alert; NetGuard uses α = {rel['alpha']}. Following "
        "the Conformal Risk Control idea [38], the threshold t~alert~ is the lowest score at which the false "
        f"positive rate on the n~0~ benign flows of the second calibration half, corrected for finite samples, "
        f"stays within α ({R.next_eq})."
    )
    R.equation(m_frac(m_sub(m_run("n"), m_run("0")), m_sub(m_run("n"), m_run("0")) + m_run(" + 1"))
               + m_sub(m_acc_hat("FPR"), m_run("")) + m_paren(m_sub(m_run("t"), m_text("alert")))
               + m_run(" + ") + m_frac(m_run("1"), m_sub(m_run("n"), m_run("0")) + m_run(" + 1")) + m_run(" ≤ α"))
    R.para(
        f"With n~0~ = {fmt(cal['negatives'])} benign calibration flows, the chosen threshold is "
        f"t~alert~ = {rel['t_alert']:.4f} on the calibrated scale, with an empirical false positive rate of "
        f"{pct(cal['empirical_fpr'], 3)} on that half. The guarantee holds only if future traffic resembles the "
        "calibration traffic, which is exactly what the temporal experiment in Section 7.6 tests."
    )
    R.para(
        "**Review band.** Flows just below the alert threshold are the ones the model is least sure about. "
        "Instead of silently calling them benign, NetGuard sends flows with a calibrated score in "
        f"[t~benign~, t~alert~) to a human review queue ({R.next_eq}). The lower edge t~benign~ is the widest band "
        f"whose share of traffic stays within the analyst's review capacity of {pct(rel['review_capacity'], 0)}; "
        f"the fitted value is t~benign~ = {rel['t_benign']:.4f}."
    )
    R.equation(m_text("decision") + m_paren(m_run("x")) + m_run(" = ")
               + m_paren(m_text("Malicious if g(s) ≥ ") + m_sub(m_run("t"), m_text("alert"))
                         + m_text(";  Review if ") + m_sub(m_run("t"), m_text("benign")) + m_text(" ≤ g(s) < ")
                         + m_sub(m_run("t"), m_text("alert")) + m_text(";  Benign otherwise"), "{", ""))
    R.para(
        "**Batch distribution-shift gate.** Calibration and thresholds assume that new traffic comes from the "
        "same distribution as the training traffic. The shift gate checks this assumption for every uploaded "
        "batch. For each feature j it computes the two-sample Kolmogorov–Smirnov statistic [39] D~j~, the largest "
        "gap between the cumulative distribution of the batch (n flows) and that of a reference sample of "
        f"benign training flows (m flows), scaled so that its typical value does not depend on batch size "
        f"({R.next_eq}). The batch score is the 90th percentile of the scaled statistics over all features, so "
        "a few strongly shifted features are enough to raise it."
    )
    R.equation(m_sub(m_run("S"), m_run("j")) + m_run(" = ") + m_sub(m_text("sup"), m_run("v"))
               + m_paren(m_sub(m_acc_hat("F"), m_text("batch")) + m_paren(m_run("v")) + m_run(" − ")
                         + m_sub(m_acc_hat("F"), m_text("ref")) + m_paren(m_run("v")), "|", "|")
               + m_run(" × ") + m_sqrt(m_frac(m_run("n m"), m_run("n + m"))))
    R.para(
        "The gate compares only the flows the model did not flag as malicious, because attacks are supposed to "
        "look different; it asks whether the *normal* traffic in the batch resembles the normal traffic the "
        "model learned. Its thresholds are set by bootstrapping 200 batches of 2,000 benign flows from single "
        f"capture days: the 99th percentile ({gate['threshold']:.2f}) separates in-distribution from shifted "
        f"batches and the 99.9th percentile ({severe:.2f}) marks severe shift. When a batch is "
        "shifted the dashboard shows a warning and names the most affected features."
    )

    R.heading("4.1.12", "Backend design", level=3)
    R.para(
        "The backend is a FastAPI [40] application (backend/app/main.py) created by a factory function, create_app(), "
        "which receives the model and metrics paths. The factory makes the application easy to test: the tests "
        "create an app that points at a small synthetic model in a temporary folder. A ModelStore object "
        "(backend/app/model_store.py) loads the joblib bundle on first use, checks that it contains a pipeline, a "
        "feature list and a model name, and reloads it automatically if the file changes after retraining."
    )
    R.para(
        "Every prediction request follows the same path. The upload is checked for a .csv extension, a size "
        "limit of 100 MB and non-empty content; it is parsed with pandas; column names are stripped; the "
        "prepare_features() function from ml/preprocess.py checks that all 69 model features are present and "
        "numeric and orders them as in training; the Pipeline returns raw vote fractions, which the reliability "
        "layer calibrates and turns into decisions; and the shift gate scores the batch. "
        f"{R.next_table} lists the validation rules."
    )
    R.table("Input Validation Rules", ["Check", "Rule", "Response"], [
        ["File type", "Name must end in .csv", "400"],
        ["Size", "At most 100 MB (the server stops reading after the limit)", "413"],
        ["Content", "Not empty, parseable as CSV, at least one data row", "400"],
        ["Columns", "All 69 required features present (extra columns ignored)", "422 + list of missing columns"],
        ["Values", "Feature values numeric; blank, NaN and Infinity accepted as missing", "422 + list of bad columns"],
        ["Model", "Saved model file present and loadable", "503"],
    ], widths=[1.1, 3.4, 1.5])
    R.para(
        "The JSON response contains benign, review and malicious counts computed over every row, the shift "
        "verdict with the most affected features and a warning text when the batch is shifted, the first 5,000 "
        "rows for the dashboard table (five readable columns, the decision, the calibrated probability, the raw "
        "vote fraction and the actual label when present) and, if the file has a Label column, the agreement "
        "between predictions and labels together with the precision and recall of the alerts. The download "
        "endpoint returns the whole file with the prediction, decision and probability columns added, and "
        "neutralises text cells beginning with =, +, - or @ so that a spreadsheet cannot execute them as "
        "formulas (CSV injection). No row is lost however large the upload. Cross-origin requests from the Vite development server are allowed, and when the frontend "
        "has been built the backend also serves it, so the complete application can run on one port."
    )

    # ------------------------------------------------------------------ frontend
    R.heading("4.1.13", "Frontend design", level=3)
    R.para(
        "The dashboard is a single-page React [41] application written in TypeScript and styled with Tailwind CSS. "
        "It is laid out as a console with a navigation sidebar, a dark theme and Lucide icons. "
        f"{R.next_table} lists its components."
    )
    R.table("Frontend Components", ["Component", "Responsibility"], [
        ["ConsoleSidebar", "Navigation between traffic analysis, results and model evaluation"],
        ["Header", "Live model status, reliability and shift-gate state from /api/health, link to the API reference"],
        ["UploadPanel", "File picker with drag and drop, input requirements, Analyze and Clear buttons, validation errors"],
        ["ShiftWarning", "Banner with the batch shift verdict, score, limits and most affected features"],
        ["SummaryCards", "Flows analysed, benign, malicious and review counts, agreement with labels, composition bar"],
        ["ResultsTable", "Filter (all / benign / malicious / review / misclassified), pagination, probabilities, CSV download"],
        ["ModelComparison", "Test-set metrics table and grouped bar chart for the three models"],
        ["ConfusionMatrix", "2 × 2 matrix with counts and row percentages, model selector"],
        ["DatasetInfo", "Raw and used flow counts, duplicates removed, train / validation / test split"],
        ["FeatureImportance", "Top ten Random Forest features as a horizontal bar chart"],
        ["api.ts", "Typed API client with readable error messages for network and validation failures"],
    ], widths=[1.6, 4.4])
    R.para(
        "Each decision (benign, review, malicious) has its own colour in the dashboard, but every coloured "
        "mark is accompanied by a text label or an icon, so the meaning never depends on colour alone. Each "
        "model keeps the same colour in every chart, bar charts start at zero so that bar lengths are honest, "
        "and exact values are always available in an adjacent table."
    )

    # ------------------------------------------------------------------ 4.2 / 4.3
    R.heading("4.2", "Codes and Standards")
    R.para(f"The project follows the protocol, data-format and software standards in {R.next_table}.")
    R.table("Standards Followed in the Project", ["Standard", "Title", "Where it applies"], [
        ["RFC 791", "Internet Protocol [29]", "Addressing and packet structure behind every flow record"],
        ["RFC 9293", "Transmission Control Protocol [3]", "Handshake, flags and window fields used as features"],
        ["RFC 768", "User Datagram Protocol [4]", "Explains the −1 window sentinel for UDP flows"],
        ["RFC 3168", "Explicit Congestion Notification [5]", "ECE and CWR flag features"],
        ["RFC 3954 / RFC 7011", "NetFlow v9 / IPFIX [6], [7]", "Flow-record concept used by CICFlowMeter"],
        ["RFC 9110", "HTTP Semantics [30]", "REST API methods and status codes (400, 413, 422, 503)"],
        ["RFC 7578", "multipart/form-data [31]", "CSV file upload"],
        ["RFC 4180", "CSV format [32]", "Input files and downloaded results"],
        ["RFC 8259", "JSON [33]", "API responses and saved reports"],
        ["OpenAPI 3.1", "OpenAPI Specification [34]", "Interactive API documentation generated at /docs"],
        ["PEP 8", "Style Guide for Python Code [35]", "Python code layout and naming"],
        ["WCAG 2.2", "Web Content Accessibility Guidelines [36]", "Contrast, non-colour cues, keyboard focus"],
    ], widths=[1.3, 2.2, 2.5])

    R.heading("4.3", "Constraints, Alternatives and Tradeoffs")
    R.para("The design had to respect the following constraints:")
    R.bullets([
        "**Memory:** about 7 GB of RAM, which rules out loading and training on all 2.5 million unique flows at "
        "once; hence float32 storage and the 500,000-flow stratified sample.",
        "**Explainability:** the system must be explainable in a 20-minute viva, which favours classical models "
        "and a small, readable code base over deep learning.",
        "**Data access:** the official download requires a form, so a byte-identical Kaggle mirror was used and "
        "the row count was verified.",
        "**Scope:** no database, authentication or live capture, as required by the project brief.",
    ])
    R.table("Design Alternatives and the Chosen Trade-Offs", ["Decision", "Chosen", "Alternative", "Reason"], [
        ["Problem type", "Binary (benign / malicious)", "Multi-class attack type", "Matches the project goal; rare classes make multi-class unreliable"],
        ["Training data size", "500k stratified sample", "All 2.5M unique flows", "Fits in memory and trains in minutes; results stable"],
        ["Duplicates", "Removed before splitting", "Kept", "Prevents train/test leakage and inflated attack scores"],
        ["Missing values", "Median imputation inside the Pipeline", "Drop rows", "Keeps every uploaded row predictable; robust to skew"],
        ["Primary model", "Random Forest", "Gradient boosting, neural networks", "Strong, fast, needs no scaling, gives feature importance"],
        ["Model choice", "Validation F1 with 0.001 margin", "Best test score", "Test set must not influence decisions"],
        ["Alert threshold", "Risk-controlled at α = 1%", "Fixed 0.5 vote", "Operator controls the false-alarm budget"],
        ["Uncertain flows", "Review band (≤ 5% of traffic)", "Forced benign / malicious", "Doubtful flows reach an analyst"],
        ["Shift detection", "Per-feature KS gate on benign traffic", "None", "Warns when the model is used outside its data"],
        ["Deduplication method", "64-bit row hashing", "pandas drop_duplicates", "Seconds instead of more than nine minutes"],
        ["Serving", "FastAPI + saved joblib Pipeline", "Retrain per request / notebook", "Fast, consistent, automatically documented"],
        ["Frontend", "React + Vite SPA", "Server-rendered templates", "Interactive table and charts, clean API boundary"],
    ], widths=[1.15, 1.45, 1.4, 2.0], font_size=9)
    R.para(
        "The main trade-off is between completeness and practicality. Training on a sample loses some of the "
        "rare attack flows, and binary labels hide which attack was detected. In return the system is fast, "
        "fits on a laptop and is simple enough to explain completely, while the dataset analysis makes the cost "
        "of these choices visible instead of hiding it."
    )
