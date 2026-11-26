import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Storage paths
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
SANDBOX_DIR = BASE_DIR / "sandbox"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_URL = f"sqlite:///{DATA_DIR / 'agentguard.db'}"

# Model file paths
CLASSIFIER_MODEL_PATH = MODELS_DIR / "action_risk_model.joblib"
ANOMALY_MODEL_PATH = MODELS_DIR / "anomaly_model.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"
DATASET_PATH = DATA_DIR / "synthetic_action_data.csv"

# Decision Engine Thresholds
ALLOW_THRESHOLD = 39     # 0-39 ALLOW
ASK_THRESHOLD = 79       # 40-79 ASK USER
                         # 80-100 BLOCK

# Default Risk Calculation Weights
DEFAULT_RISK_WEIGHTS = {
    "ml_risk": 0.35,
    "behavior_anomaly": 0.20,
    "permission_violation": 0.20,
    "task_misalignment": 0.10,
    "data_sensitivity": 0.10,
    "destination_risk": 0.05
}
