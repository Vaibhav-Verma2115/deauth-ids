"""
config.py
=========
Single source of truth for the whole project: file paths and the exact list of
features the model is trained on.

WHY THIS FILE EXISTS
--------------------
A machine-learning IDS has three programs that must agree on one thing: the set
of features and the order they appear in. If `train_model.py` trains on
[frame_length, rssi, ...] but `realtime_detector.py` builds its feature vector
in a different order, the model silently produces garbage predictions -- no
error, just wrong answers. Defining the schema ONCE here and importing it
everywhere makes that class of bug impossible.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Project paths (all relative to the project root, so the code runs from
# anywhere without hard-coded absolute paths).
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent   # ".../drdo project"
DATA_DIR = ROOT_DIR / "data"
MODEL_DIR = ROOT_DIR / "models"
OUTPUT_DIR = ROOT_DIR / "outputs"

# Raw synthetic dataset (produced by generate_dataset.py)
RAW_DATASET = DATA_DIR / "wifi_deauth_dataset.csv"

# Artefacts produced by the pipeline
MODEL_PATH = MODEL_DIR / "model.pkl"          # trained Random Forest
SCALER_PATH = MODEL_DIR / "scaler.pkl"        # fitted StandardScaler
METADATA_PATH = MODEL_DIR / "model_meta.json" # feature order + metrics

# ---------------------------------------------------------------------------
# Feature schema — the canonical per-window features the model consumes.
# ---------------------------------------------------------------------------
# The ORDER of this list is the contract between training and detection.
# Never reorder it without retraining the model.
FEATURE_COLUMNS = [
    "frame_length",     # size in bytes of the 802.11 frame
    "rssi",             # received signal strength (dBm, negative; -30 strong, -90 weak)
    "packet_rate",      # frames per second seen in the current time window
    "duration",         # 802.11 duration/ID field (microseconds)
    "src_mac_freq",     # how often this source MAC appeared in the window
    "dst_mac_freq",     # how often this destination MAC appeared in the window
    "deauth_count",     # number of deauthentication frames in the window
]

LABEL_COLUMN = "label"      # 0 = Normal, 1 = Attack

# Human-readable names for the two classes (used in reports and alerts)
CLASS_NAMES = {0: "Normal", 1: "Attack"}


def ensure_dirs():
    """Create the data/models/outputs folders if they don't exist yet."""
    for d in (DATA_DIR, MODEL_DIR, OUTPUT_DIR):
        d.mkdir(parents=True, exist_ok=True)
