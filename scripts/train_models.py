import sys
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import DATASET_PATH
from ml.dataset_generator import generate_synthetic_dataset
from ml.train_classifier import train_risk_classifier
from ml.anomaly_detector import train_anomaly_detector
from ml.evaluate import evaluate_models

if __name__ == "__main__":
    print("=== AgentGuard ML Pipeline Training ===")
    if not DATASET_PATH.exists():
        print("Generating dataset...")
        df = generate_synthetic_dataset()
    else:
        df = pd.read_csv(DATASET_PATH)

    print("\n1. Training Action Risk Classifier...")
    train_risk_classifier(df)

    print("\n2. Training Behavioral Anomaly Detector (IsolationForest)...")
    train_anomaly_detector(df)

    print("\n3. Evaluating Models & Exporting Performance Metrics...")
    metrics = evaluate_models()

    print("\n[SUCCESS] Training and Evaluation completed successfully!")
