"""Central paths and constants shared by training and the backend."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_DIR = PROJECT_ROOT / "dataset" / "raw"
SAMPLES_DIR = PROJECT_ROOT / "dataset" / "samples"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

MODEL_PATH = MODELS_DIR / "netguard_model.joblib"
METRICS_PATH = REPORTS_DIR / "metrics.json"

# Name of the label column in CIC-IDS2017 (after stripping whitespace).
LABEL_COLUMN = "Label"

# In CIC-IDS2017 every flow is labelled either "BENIGN" or with an attack name
# (DDoS, PortScan, DoS Hulk, ...). We turn this into a binary problem.
BENIGN_LABEL = "BENIGN"
CLASS_NAMES = ["Benign", "Malicious"]  # index 0 = Benign, index 1 = Malicious

RANDOM_STATE = 42
TEST_SIZE = 0.20        # 20% of the data is kept aside for final testing
VALIDATION_SIZE = 0.10  # 10% of the training part is used to choose the best model
CALIBRATION_SIZE = 0.10 # 10% is used to fit probability calibration + thresholds

# Random Forest is the project's primary model. Another model replaces it only if
# it is clearly better: validation F1 higher by more than this margin.
PRIMARY_MODEL = "Random Forest"
SELECTION_MARGIN = 0.001

# Reliability layer defaults.
ALPHA = 0.01             # tolerable false-positive rate on benign flows
REVIEW_CAPACITY = 0.05   # share of traffic an analyst can review
REVIEW_LABEL = "Review"

