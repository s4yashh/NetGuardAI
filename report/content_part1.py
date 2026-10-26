"""Chapters 1-3 of the NetGuard AI project report."""

from report.docx_helpers import Report


def fmt(n: float) -> str:
    return f"{n:,.0f}"


def pct(x: float, d: int = 2) -> str:
    return f"{100 * x:.{d}f}%"


# =========================================================================== CHAPTER 1
def chapter1(R: Report, A: dict, M: dict, D) -> None:
    raw = A["raw_rows"]
    R.chapter("Introduction")
    R.para(
        "Computer networks carry almost every activity of a modern organisation, from e-mail and file "
        "sharing to banking, cloud services and remote administration. The same connectivity that makes "
        "these services possible also exposes them to attack. Malicious software rarely acts in isolation: "
        "a worm spreads by scanning for vulnerable hosts, a botnet client contacts its command-and-control "
        "server, ransomware downloads keys and exfiltrates data, and denial-of-service tools flood a "
        "victim with requests. Every one of these activities leaves a trace in the network traffic, so "
        "analysing that traffic is one of the most effective ways of detecting malware and intrusions."
    )
    R.para(
        "Traditional intrusion detection systems (IDS) compare traffic with a database of known attack "
        "signatures. They are precise for attacks they already know but cannot recognise new variants, "
        "and maintaining the signature database requires constant expert effort. Machine learning (ML) "
        "offers a complementary approach: instead of writing rules by hand, a model learns the statistical "
        "difference between normal and malicious traffic from labelled examples. Because ML works on "
        "summary statistics of network flows, such as how long a connection lasted, how many packets "
        "were exchanged and how large they were, it can also analyse encrypted traffic whose payload is "
        "unreadable."
    )
    R.para(
        "This project, **NetGuard AI**, builds a complete and working malware detection system based on "
        "AI-driven analysis of network traffic. It uses the public CIC-IDS2017 dataset published by the "
        f"Canadian Institute for Cybersecurity, which contains {fmt(raw)} labelled network flows recorded "
        "over five working days in a realistic testbed. The dataset is analysed in depth, cleaned and "
        "prepared; three classifiers (Random Forest, Decision Tree and Logistic Regression) are trained "
        "and compared on held-out data; and the best model is served through a FastAPI backend and a "
        "React dashboard where a user can upload a CSV file of flows and receive a benign or malicious "
        "verdict for every flow. A reliability layer calibrates the model's probabilities, sets the alert "
        "threshold for a chosen false-positive budget, routes uncertain flows to human review and warns "
        "when an uploaded batch does not resemble the training traffic. Particular attention is given to "
        "the dataset itself, because the quality, balance and structure of the data determine what any "
        "model can learn, and a temporal experiment tests how the model performs on days it has never seen."
    )

    R.heading("1.1", "Objective")
    R.para(
        "The primary objective of this project is to develop a web-based system that uses machine learning "
        "and data analysis techniques to classify network flows as benign or malicious, and to understand "
        "and document the dataset on which such a system depends. The specific objectives are:"
    )
    R.bullets([
        "To study the CIC-IDS2017 dataset in detail: how it was generated, what each of its 78 flow "
        "features means in networking terms, how its classes are distributed and what data-quality "
        "problems it contains.",
        "To design a cleaning and preprocessing pipeline that handles missing and infinite values, "
        "duplicate records and uninformative features, and that is applied identically during training "
        "and prediction.",
        "To split the data correctly into training, validation and test sets so that the reported "
        "performance reflects traffic the model has never seen.",
        "To train Random Forest, Decision Tree and Logistic Regression classifiers and compare their "
        "accuracy, precision, recall and F1-score using genuine evaluation results.",
        "To analyse detection performance separately for each attack type, linking strengths and "
        "weaknesses of the model back to properties of the dataset.",
        "To test whether the model generalises to traffic recorded on days it was not trained on, by "
        "comparing a random split with a temporal (day-based) split.",
        "To add a reliability layer: calibrated probabilities, an alert threshold that keeps the false "
        "positive rate within a chosen budget, a review band for uncertain flows and a batch-level "
        "distribution-shift warning.",
        "To deploy the selected model behind a validated REST API and a responsive dashboard named "
        "NetGuard AI that shows predictions, evaluation metrics, a confusion matrix and a model "
        "comparison chart, and lets the user download the results.",
    ])

    R.heading("1.2", "Motivation")
    R.para(
        "Network traffic grows faster than the number of analysts who can inspect it. A single office "
        "network in the CIC-IDS2017 testbed produced more than half a million flows on an ordinary Monday "
        "with no attacks at all. Manually separating the few malicious flows from this background is "
        "impossible, and signature-based tools only flag what they have been told to look for. A model that "
        "learns from flow statistics can screen every flow automatically and draw the analyst's attention to "
        "the suspicious ones."
    )
    R.para(
        "A second motivation is the gap between research results and working systems. Many published "
        "studies report very high accuracy on CIC-IDS2017, but few explain how the data were cleaned, "
        "whether duplicate records leaked between training and testing, or how well rare attack types "
        "are detected. This project therefore treats the dataset as a first-class subject of study. Every "
        "number in this report is produced by scripts in the project repository, and every chart in the "
        "dashboard is read from files written by the training pipeline, so the results can be reproduced "
        "and questioned."
    )
    R.para(
        "Finally, the project connects the theory of the Computer Networks course with a practical "
        "security problem. The features used by the model, such as TCP flag counts, initial window sizes, "
        "packet-length statistics, inter-arrival times and destination ports, are direct measurements of "
        "the protocols studied in the course. Understanding why a SYN-heavy, single-packet flow to a random "
        "port looks like a port scan, or why a connection that stays open for 100 seconds while sending "
        "almost no data looks like a slow denial-of-service attack, is exactly the kind of reasoning the "
        "course aims to develop."
    )

    R.heading("1.3", "Background")
    R.para(
        "This section introduces the networking and machine-learning concepts on which the project is built: "
        "the TCP/IP protocol suite, the notion of a network flow, the main families of intrusion detection "
        "systems, the use of machine learning for intrusion detection, the public datasets available for "
        "this task and the attack types contained in CIC-IDS2017."
    )

    R.heading("1.3.1", "Network traffic and the TCP/IP model", level=3)
    R.para(
        "Communication on the Internet follows the layered TCP/IP model. The application layer (HTTP, DNS, "
        "FTP, SSH, SMTP) produces messages; the transport layer (TCP or UDP) splits them into segments "
        "and identifies the communicating programs with 16-bit port numbers; the network layer (IP) "
        "addresses and routes packets between hosts; and the link layer delivers frames on each physical "
        "network [1], [2]. Every packet therefore carries a header for each layer, and an observer on the "
        "network can measure its size, its timing, its addresses and ports and, for TCP, its control flags."
    )
    R.para(
        "TCP is connection-oriented. A connection starts with a three-way handshake (SYN, SYN-ACK, ACK), "
        "transfers data in acknowledged segments and ends with FIN or RST segments [3]. The flags carried in "
        "the TCP header describe what each segment is doing, and attacks often misuse them: a port scan "
        "sends SYN segments without completing the handshake, and a SYN flood leaves thousands of "
        "half-open connections. UDP, used by DNS and NTP, has no handshake and no flags [4]. "
        f"{R.next_table} lists the TCP flags that CIC-IDS2017 counts for every flow."
    )
    R.table("TCP Header Flags Counted in CIC-IDS2017 Flow Features", ["Flag", "Name", "Meaning", "Dataset feature"], [
        ["SYN", "Synchronise", "Opens a connection and synchronises sequence numbers", "SYN Flag Count"],
        ["ACK", "Acknowledge", "Acknowledges received data; set on almost every segment after the handshake", "ACK Flag Count"],
        ["FIN", "Finish", "Sender has no more data; graceful connection close", "FIN Flag Count"],
        ["RST", "Reset", "Aborts the connection immediately", "RST Flag Count"],
        ["PSH", "Push", "Asks the receiver to pass data to the application without waiting", "PSH Flag Count, Fwd/Bwd PSH Flags"],
        ["URG", "Urgent", "Urgent pointer field is significant", "URG Flag Count, Fwd/Bwd URG Flags"],
        ["ECE", "ECN-Echo", "Explicit Congestion Notification echo [5]", "ECE Flag Count"],
        ["CWR", "Congestion Window Reduced", "Sender reduced its congestion window [5]; called CWE in the dataset", "CWE Flag Count"],
    ], widths=[0.6, 1.2, 2.6, 1.6])

    R.heading("1.3.2", "Network flows", level=3)
    R.para(
        "Inspecting every packet of a busy network is expensive and, for encrypted traffic, reveals little. "
        "Network monitoring therefore usually works with flows. A flow is a sequence of packets that share "
        "the same five-tuple (source IP address, destination IP address, source port, destination port and "
        "transport protocol) within a limited time window. Router-based standards such as NetFlow version 9 "
        "[6] and IPFIX [7] export one record per flow with counters such as packets and bytes."
    )
    R.para(
        "CIC-IDS2017 uses bidirectional flows produced by CICFlowMeter [8], [9]. The host that sends the first "
        "packet defines the forward direction and the reply traffic forms the backward direction, so a "
        "single record describes both sides of a conversation. A TCP flow ends when the connection is "
        "closed with FIN; any flow also ends when it exceeds the flow timeout. In the published files no flow "
        "lasts longer than 120,000,000 µs, i.e. 120 seconds, which is the flow timeout used by the "
        f"dataset authors. {R.next_fig} shows how the main timing and size features are measured on one TCP "
        "connection."
    )
    R.figure(D / "diag_flow_concept.png", "Forward and Backward Packets, Flow Duration and Inter-Arrival Time in One TCP Flow", 5.8)
    R.para(
        "For each flow CICFlowMeter computes more than 80 statistics: counts and sizes of packets in each "
        "direction, rates in bytes and packets per second, inter-arrival times (IAT) between consecutive "
        "packets, counts of each TCP flag, header lengths, initial TCP window sizes, bulk-transfer and "
        "sub-flow statistics, and the durations of active and idle periods. These features are the input of "
        "the NetGuard model and are described one by one in Chapter 4."
    )

    R.heading("1.3.3", "Intrusion detection systems", level=3)
    R.para(
        "An intrusion detection system monitors a host or network and raises alerts when it observes "
        "behaviour that indicates an attack. Denning's intrusion-detection model [10] introduced the idea "
        "that attacks can be recognised as deviations from normal behaviour. Today IDS are classified by "
        f"where they collect data and how they decide, as summarised in {R.next_table}."
    )
    R.table("Classification of Intrusion Detection Systems", ["Criterion", "Type", "Description", "Example"], [
        ["Data source", "Network-based (NIDS)", "Analyses packets or flows observed on a network link", "Snort, Zeek, NetGuard AI"],
        ["Data source", "Host-based (HIDS)", "Analyses logs, system calls and files on one host", "OSSEC, Wazuh"],
        ["Detection method", "Signature (misuse)", "Matches traffic against patterns of known attacks", "Snort rules"],
        ["Detection method", "Anomaly", "Learns normal behaviour and flags deviations", "Statistical profiles"],
        ["Detection method", "Supervised ML", "Learns from labelled benign and attack examples", "Random Forest on flows"],
    ], widths=[1.1, 1.4, 2.3, 1.2])
    R.para(
        "NetGuard AI is a network-based system that uses supervised machine learning on flow records. It does "
        "not capture packets itself; it analyses flow files produced by a flow meter, which keeps the system "
        "simple and lets it be evaluated on a standard dataset."
    )

    R.heading("1.3.4", "Machine learning for intrusion detection", level=3)
    R.para(
        "In supervised classification a model is trained on examples (x, y), where x is a vector of features "
        "describing a flow and y is its label, and then predicts the label of new flows. Surveys of the field "
        "[11] show that tree-based models, support vector machines, k-nearest neighbours and neural networks "
        "have all been applied to intrusion detection, with decision-tree ensembles such as Random Forest "
        "performing strongly on tabular flow features while remaining fast and interpretable [12], [13]."
    )
    R.para(
        "Applying ML to security also has well-documented pitfalls. Sommer and Paxson [14] warned that "
        "intrusion detection differs from other ML problems because errors are costly, traffic is diverse "
        "and attacks are rare. Arp et al. [15] listed common mistakes in security ML research, including "
        "sampling bias, data snooping (using test data for decisions) and inappropriate baselines. "
        "This project addresses these points explicitly: duplicates are removed before splitting, all "
        "decisions use a separate validation set, simple baselines are compared and results are broken "
        "down by attack type."
    )

    R.heading("1.3.5", "Intrusion detection datasets", level=3)
    R.para(
        "Supervised models need labelled traffic, and collecting real labelled attack traffic is difficult "
        f"because of privacy and the rarity of attacks. Researchers therefore rely on public datasets [16]. "
        f"{R.next_table} compares the most widely used ones."
    )
    R.table("Public Network Intrusion Detection Datasets", ["Dataset", "Year", "Records / features", "Remarks"], [
        ["KDD Cup 99", "1999", "≈4.9 million connections, 41 features", "Derived from DARPA 1998; many duplicates and dated attacks [17]"],
        ["NSL-KDD", "2009", "125,973 train / 22,544 test, 41 features", "Cleaned KDD 99 without duplicates [17]"],
        ["UNSW-NB15", "2015", "2,540,044 records, 49 features", "Nine attack families, modern traffic generator [18]"],
        ["CIC-IDS2017", "2017", f"{fmt(raw)} flows, 78 features", "Realistic benign profiles, 14 attack labels, CICFlowMeter features [19]"],
        ["CSE-CIC-IDS2018", "2018", "Larger capture on AWS, same feature set", "Successor of CIC-IDS2017 [16]"],
    ], widths=[1.15, 0.55, 2.0, 2.3])
    R.para(
        "CIC-IDS2017 was chosen because it is recent compared with KDD-based data, it contains a broad set of "
        "attacks that are still relevant (denial of service, brute force, web attacks, botnets, port scans), "
        "it provides flow features computed by a documented open-source tool, and it is freely available. Its "
        "known weaknesses, such as labelling errors and flow-meter artefacts reported by Engelen et al. [20] "
        "and Lanvin et al. [21], are examined in Chapters 4 and 7."
    )

    R.heading("1.3.6", "Attack types in CIC-IDS2017", level=3)
    R.para(
        f"The dataset labels each flow either BENIGN or with one of 14 attack names. {R.next_table} explains "
        "how each attack works at the network level and which service it targets in the dataset; the target "
        "ports were measured from the data."
    )
    pa = A["per_attack_medians"]

    def port(label):
        p = pa[label]
        return "many ports" if p["top_port_share"] < 0.05 else str(p["top_port"])

    R.table("Attack Types in CIC-IDS2017 and Their Network Behaviour", ["Label", "Category", "Network-level behaviour", "Main port"], [
        ["DoS Hulk", "Denial of service", "HTTP GET flood with randomised URLs and headers to exhaust the web server", port("DoS Hulk")],
        ["DoS GoldenEye", "Denial of service", "HTTP flood that keeps connections alive to occupy server workers", port("DoS GoldenEye")],
        ["DoS slowloris", "Denial of service", "Opens many connections and sends partial HTTP headers very slowly", port("DoS slowloris")],
        ["DoS Slowhttptest", "Denial of service", "Slow HTTP attacks that hold connections open with minimal traffic", port("DoS Slowhttptest")],
        ["DDoS", "Distributed DoS", "Several machines flood the web server at the same time (LOIC tool)", port("DDoS")],
        ["Heartbleed", "Vulnerability exploit", "Malformed TLS heartbeat requests leak server memory (CVE-2014-0160) [22]", port("Heartbleed")],
        ["PortScan", "Reconnaissance", "Probes thousands of ports with short connection attempts (Nmap)", port("PortScan")],
        ["FTP-Patator", "Brute force", "Repeated FTP login attempts with a password list", port("FTP-Patator")],
        ["SSH-Patator", "Brute force", "Repeated SSH login attempts with a password list", port("SSH-Patator")],
        ["Web Attack – Brute Force", "Web application", "Automated login attempts against a vulnerable web application", port("Web Attack – Brute Force")],
        ["Web Attack – XSS", "Web application", "Injects scripts into web pages (cross-site scripting)", port("Web Attack – XSS")],
        ["Web Attack – Sql Injection", "Web application", "Injects SQL statements through web form parameters", port("Web Attack – Sql Injection")],
        ["Bot", "Botnet", "Infected hosts contact a command-and-control server (Ares botnet)", port("Bot")],
        ["Infiltration", "Internal compromise", "A victim host is compromised and then used to attack the internal network", port("Infiltration")],
    ], widths=[1.45, 1.1, 2.75, 0.7])
    R.para(
        "Apart from PortScan, whose flows are spread over thousands of destination ports, each attack targets "
        "one service. Port 80 (HTTP) dominates because the denial-of-service, DDoS and web attacks all aim "
        "at the testbed's web server, the brute-force tools target FTP (21) and SSH (22), the botnet uses "
        "port 8080 for its command channel, and the Heartbleed and Infiltration flows use port 444."
    )


# =========================================================================== CHAPTER 2
def chapter2(R: Report, A: dict, M: dict, D) -> None:
    rf = next(m for m in M["models"] if m["name"] == "Random Forest")
    R.chapter("Project Description and Goals")
    R.para(
        "This chapter defines the problem addressed by NetGuard AI, describes what the system does from the "
        "user's point of view, states its goals in measurable terms and sets the boundaries of the project."
    )

    R.heading("2.1", "Problem statement")
    R.para(
        "Given a file of network flow records in CICFlowMeter format, decide for every flow whether it is "
        "benign or malicious, and present the decision together with an honest account of how reliable the "
        "deciding model is. Formally this is a binary classification problem: each flow is described by a "
        "feature vector x containing numeric flow statistics, and the system must predict a label y ∈ {0, 1}, "
        "where 0 means benign and 1 means malicious (any of the 14 attack types)."
    )
    R.para(
        "Three difficulties make the problem harder than it first appears. The classes are imbalanced, since "
        "most traffic is benign. The dataset contains duplicate, missing, infinite and constant values that "
        "must be handled without leaking information from the test set. And some attack types are extremely "
        "rare, so a model can achieve a high overall score while still missing them. A good solution must "
        "handle all three, and its evaluation must expose them."
    )

    R.heading("2.2", "Project description")
    R.para(
        "NetGuard AI consists of three parts that work together. The **machine learning pipeline** reads the "
        "eight CIC-IDS2017 CSV files, cleans and deduplicates them, builds a stratified sample, splits it into "
        "training, validation and test sets, trains three classifiers, evaluates them and saves the selected "
        "model together with an evaluation report. A separate **dataset analysis** script measures the "
        "properties of the data and produces the figures used in this report."
    )
    R.para(
        "The **FastAPI backend** loads the saved model and exposes endpoints that accept a CSV upload, validate "
        "it, apply the same preprocessing as training, and return a prediction and a malicious probability "
        "for every flow, or the uploaded file with the predictions appended as new columns. Every flow "
        "receives one of three decisions (Benign, Review or Malicious) and every batch receives a "
        "distribution-shift verdict. The **React "
        "dashboard** lets the user upload a file, start the analysis, read the benign and malicious counts, "
        "inspect and filter a results table, download the results and view the evaluation of all three "
        "models, including a confusion matrix and a comparison chart."
    )
    R.para(
        "A typical session proceeds as follows. The user opens the dashboard, which reports that the Random "
        "Forest model is loaded. The user selects a CSV file of flows and presses *Analyze traffic*. Within "
        "a few seconds the dashboard shows how many flows were analysed and how many were classified as "
        "benign, malicious or sent for review, and a banner states whether the batch resembles the "
        "training traffic; if the file contains a Label column, the agreement between the predictions and "
        "the labels is also shown. The user can filter the table to see only malicious flows or only "
        "misclassified ones, and can download the full result as a CSV file."
    )

    R.heading("2.3", "Goals")
    R.para("The project goals, with the criterion used to verify each one, are:")
    R.bullets([
        "**Dataset understanding:** document the origin, features, class distribution and data-quality "
        "issues of CIC-IDS2017 using measurements on the real files (verified in Chapter 4).",
        "**Correct methodology:** remove duplicates before splitting, use a stratified split with a fixed "
        "random seed, and never use the test set for any decision (verified by the reproducibility check "
        "in Section 4.1.7).",
        f"**Detection quality:** reach an F1-score above 99% on the test set with the primary model; "
        f"achieved {pct(rf['f1_score'])} (Chapter 7).",
        "**Honest comparison:** report accuracy, precision, recall and F1-score for Random Forest, Decision "
        "Tree and Logistic Regression from the same test set, plus per-attack detection rates.",
        "**Generalisation:** measure performance on unseen capture days with a temporal protocol and report "
        "the result even when it is poor (Section 7.6).",
        "**Controlled alerting:** keep the false positive rate of the deployed alert threshold below "
        "α = 1% on held-out data and flag batches that differ from the training distribution.",
        "**Working application:** serve real predictions from the saved model through a validated API and a "
        "responsive dashboard, with automated backend tests and a successful production build.",
        "**Reproducibility:** every number in the dashboard and in this report is generated by scripts in "
        "the repository from the public dataset.",
    ], numbered=True)

    R.heading("2.4", "Scope")
    R.para(
        f"{R.next_table} lists what is included in the project and what is deliberately left out to keep the "
        "system focused and explainable."
    )
    R.table("Project Scope", ["In scope", "Out of scope"], [
        ["Binary classification of CICFlowMeter flow records (benign / malicious)", "Classifying the exact attack type (multi-class)"],
        ["Offline training on CIC-IDS2017 with a documented pipeline", "Live packet capture or reading .pcap files"],
        ["CSV upload, validation, prediction and CSV download", "User accounts, authentication and a database"],
        ["Random Forest, Decision Tree, Logistic Regression", "Deep learning models"],
        ["Evaluation dashboard with real metrics", "Automatic blocking of traffic (intrusion prevention)"],
        ["Calibration, review band and batch shift warning", "Automatic retraining when shift is detected"],
        ["Random and temporal (day-based) evaluation protocols", "Online learning from analyst feedback"],
        ["Detailed dataset analysis and reporting", "Testing on other datasets or production networks"],
    ], widths=[3.0, 3.0])

    R.heading("2.5", "Deliverables")
    R.table("Project Deliverables and Their Location in the Repository", ["Deliverable", "Location"], [
        ["Shared preprocessing used by training and API", "ml/preprocess.py"],
        ["Training and model comparison pipeline", "ml/train.py"],
        ["Reliability layer and shift gate", "ml/reliability.py"],
        ["Protocol comparison experiments", "ml/experiments.py, reports/experiments.json"],
        ["Dataset analysis and report figures", "ml/analyze_dataset.py, reports/figures/"],
        ["Trained model bundle", "models/netguard_model.joblib"],
        ["Evaluation report", "reports/metrics.json, reports/model_report.md"],
        ["Dataset analysis results", "reports/dataset_analysis.json"],
        ["FastAPI backend and tests", "backend/app/, backend/tests/"],
        ["React dashboard", "frontend/src/"],
        ["Demo CSV files from the held-out test set", "dataset/samples/"],
        ["Test files for evaluators (valid, invalid and shifted inputs)", "dataset/faculty_tests/"],
        ["One-command start and stop scripts", "start.sh, stop.sh"],
        ["README and this report", "README.md, docs/report/"],
    ], widths=[3.4, 2.6])

    R.heading("2.6", "Users and use cases")
    R.para(
        "The primary users are students and security analysts who want to screen a set of flow records. The "
        "main use cases are: checking whether a captured set of flows contains suspicious traffic; "
        "demonstrating how a machine learning IDS works, including its evaluation; and studying how the "
        "properties of a dataset affect what a model learns. Because the dashboard shows the probability "
        "behind every prediction and the per-model evaluation, users can judge how much to trust a result "
        "rather than receiving an unexplained verdict."
    )


# =========================================================================== CHAPTER 3
def chapter3(R: Report, A: dict, M: dict, D) -> None:
    R.chapter("Technical Specification")
    R.para(
        "This chapter specifies the hardware and software used, the dataset, the functional and "
        "non-functional requirements, and the interface of the backend API."
    )

    R.heading("3.1", "Hardware specification")
    R.table("Hardware Used for Development and Training", ["Component", "Specification"], [
        ["Processor", "Intel Core i5-1135G7 (11th Gen) @ 2.40 GHz, 6 logical CPUs available to Linux"],
        ["Memory", "7 GB available to the Linux environment (WSL 2)"],
        ["Storage", "1 TB virtual disk; the dataset needs about 844 MB, the project about 100 MB plus dependencies"],
        ["Peak memory during training", "About 3 GB (2.8 GB measured with /usr/bin/time)"],
        ["Training time", "About 4 minutes to read and clean the CSV files; under 30 s to fit the three models"],
    ], widths=[1.8, 4.2])

    R.heading("3.2", "Software specification")
    R.table("Software Stack and Versions", ["Layer", "Software", "Version", "Purpose"], [
        ["Operating system", "Linux on WSL 2", "kernel 6.18", "Development and execution environment"],
        ["Language", "Python", "3.14.7", "ML pipeline, analysis and backend"],
        ["Data processing", "pandas / NumPy", "3.0.6 / 2.5.4", "Loading and cleaning CSV data"],
        ["Machine learning", "scikit-learn", "1.9.1", "Models, pipelines, calibration, metrics"],
        ["Statistics", "SciPy", "1.18.1", "Kolmogorov–Smirnov test in the shift gate"],
        ["Model storage", "joblib", "1.6.0", "Saving and loading the trained pipeline"],
        ["Web API", "FastAPI / Uvicorn", "0.157.0 / 0.54.0", "REST endpoints and ASGI server"],
        ["File upload", "python-multipart", "0.0.32", "Parsing multipart/form-data uploads"],
        ["Testing", "pytest / httpx2", "9.1.1 / 2.13.1", "Automated backend tests"],
        ["Figures and report", "matplotlib / python-docx", "3.11.2 / 1.2.0", "Dataset figures and this document"],
        ["Runtime", "Node.js / npm", "24.21.0 / 11.19.0", "Frontend tooling"],
        ["UI library", "React", "19.3.0", "Dashboard components"],
        ["Build tool", "Vite", "8.1.6", "Development server and production build"],
        ["Language", "TypeScript", "5.9.3", "Type-checked frontend code"],
        ["Styling", "Tailwind CSS", "4.3.3", "Utility-first CSS, dark navy theme"],
        ["Charts / icons", "Recharts / lucide-react", "3.10.1 / 1.52.0", "Comparison chart, feature importance, icons"],
    ], widths=[1.2, 1.5, 1.2, 2.1])

    R.heading("3.3", "Dataset specification")
    R.table("Dataset Specification", ["Property", "Value"], [
        ["Name", "CIC-IDS2017 (MachineLearningCSV / MachineLearningCVE version)"],
        ["Publisher", "Canadian Institute for Cybersecurity, University of New Brunswick [19]"],
        ["Capture period", "Monday 3 July to Friday 7 July 2017 (five working days)"],
        ["Files", "8 CSV files, one or more per day, about 844 MB in total"],
        ["Records", f"{fmt(A['raw_rows'])} flows ({fmt(A['raw_class_counts']['Benign'])} benign, "
                    f"{fmt(A['raw_class_counts']['Malicious'])} attack)"],
        ["Columns", "78 numeric flow features + 1 Label column (79 in total)"],
        ["Labels", "BENIGN and 14 attack labels"],
        ["Encoding", "Latin-1 / Windows-1252 (web attack labels contain the dash byte 0x96)"],
        ["Feature extractor", "CICFlowMeter, bidirectional flows, ≈120 s flow timeout"],
        ["Licence / access", "Free for research; official download after a short form, mirrored on Kaggle"],
    ], widths=[1.6, 4.4])

    R.heading("3.4", "Functional requirements")
    R.table("Functional Requirements", ["ID", "Requirement"], [
        ["FR1", "The system shall clean the dataset and convert its labels to Benign (BENIGN) and Malicious (all attacks)."],
        ["FR2", "The system shall split the data into training, validation and test sets using stratified sampling."],
        ["FR3", "The system shall train Random Forest, Decision Tree and Logistic Regression and report accuracy, precision, recall and F1-score on the test set."],
        ["FR4", "The system shall save the selected model with its feature list and reuse it for every prediction."],
        ["FR5", "The API shall accept a CSV upload and return a prediction and malicious probability for every row."],
        ["FR6", "The API shall reject files that are not CSV, are empty, exceed 100 MB, miss required features or contain non-numeric feature values."],
        ["FR7", "The API shall return HTTP 503 with an explanation when no trained model is available."],
        ["FR8", "The dashboard shall show total, benign and malicious counts and, when labels are present, the agreement with them."],
        ["FR9", "The dashboard shall show a filterable, paginated results table and allow the results to be downloaded as CSV."],
        ["FR10", "The dashboard shall show the model comparison table and chart, the confusion matrix, the dataset split and feature importances from the saved evaluation report."],
    ], widths=[0.6, 5.4])

    R.heading("3.5", "Non-functional requirements")
    R.table("Non-Functional Requirements", ["Quality", "Requirement and how it is met"], [
        ["Correctness", "No hard-coded predictions or statistics; all values come from the model or from files written by training."],
        ["Consistency", "Training and inference share ml/preprocess.py, and imputation is stored inside the saved scikit-learn Pipeline."],
        ["Reproducibility", "Fixed random seed (42); re-running training reproduces identical metrics and the analysis script verifies this."],
        ["Performance", "A 2,000-flow file is uploaded, classified, checked for shift and returned in about 1–3 s."],
        ["Security", "Text cells that a spreadsheet would run as formulas are neutralised in downloaded CSV files."],
        ["Usability", "Responsive layout from 390 px phones to desktops, clear error messages, colour-blind-safe chart colours."],
        ["Maintainability", "Small modules with one responsibility each; code is commented for explanation in a viva."],
        ["Testability", "38 automated tests (API, preprocessing, reliability layer) run in about four seconds on synthetic data."],
    ], widths=[1.4, 4.6])

    R.heading("3.6", "API specification")
    R.table("REST API Endpoints", ["Method", "Endpoint", "Input", "Output"], [
        ["GET", "/api/health", "–", "Model status, feature count, and whether the reliability layer and shift gate are active"],
        ["GET", "/api/model/features", "–", "List of the 69 feature columns an upload must contain"],
        ["GET", "/api/metrics", "–", "The evaluation report written by training (metrics.json)"],
        ["POST", "/api/predict", "multipart file (CSV)", "Benign / review / malicious counts, shift verdict and warning, agreement with labels, first 5,000 rows"],
        ["POST", "/api/predict/download", "multipart file (CSV)", "The uploaded CSV with prediction, decision and probability columns added"],
    ], widths=[0.6, 1.6, 1.3, 2.5])
    R.table("API Error Responses", ["HTTP status", "Condition", "Example message"], [
        ["400 Bad Request", "Wrong extension, empty file, header only, unparseable CSV", "Please upload a file with a .csv extension."],
        ["413 Payload Too Large", "File larger than 100 MB", "File is larger than 100 MB."],
        ["422 Unprocessable Entity", "Required feature columns missing or non-numeric", "CSV is missing 3 required feature column(s)."],
        ["503 Service Unavailable", "No trained model found or model file unreadable", "No trained model found. Run python -m ml.train first."],
    ], widths=[1.4, 2.4, 2.2])
    R.para(
        "Uploaded files may contain extra columns (for example source and destination IP addresses or the "
        "original Label); these are ignored for prediction. If a Label column is present, the API compares it "
        "with the predictions and reports the agreement, which is how the demonstration in Chapter 6 shows "
        "that the predictions are genuine."
    )
