import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline

from ml.feature_engineering import get_preprocessor, ALL_FEATURE_COLUMNS
from backend.config import ANOMALY_MODEL_PATH, DATASET_PATH


def train_anomaly_detector(df: pd.DataFrame, model_path: Path = ANOMALY_MODEL_PATH):
    # Train anomaly detector on SAFE actions (label == 0) to represent normal agent behavior
    normal_df = df[df["label"] == 0]
    if len(normal_df) < 100:
        normal_df = df # Fallback

    X_normal = normal_df[ALL_FEATURE_COLUMNS]

    preprocessor = get_preprocessor()
    preprocessor.fit(df[ALL_FEATURE_COLUMNS]) # Fit preprocessor on full dataset vocabulary

    # Transform features for IsolationForest
    X_transformed = preprocessor.transform(X_normal)

    isolation_forest = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42
    )

    print("Training IsolationForest Behavioral Anomaly Detector on normal agent actions...")
    isolation_forest.fit(X_transformed)

    model_package = {
        "preprocessor": preprocessor,
        "isolation_forest": isolation_forest
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_package, model_path)
    print(f"Anomaly Detector saved to {model_path}")
    return model_package


def predict_anomaly(feature_dict: dict, model_package: dict = None) -> tuple:
    if model_package is None:
        if not ANOMALY_MODEL_PATH.exists():
            return 0.0, "NORMAL"
        model_package = joblib.load(ANOMALY_MODEL_PATH)

    preprocessor = model_package["preprocessor"]
    isolation_forest = model_package["isolation_forest"]

    df_sample = pd.DataFrame([feature_dict])
    X_trans = preprocessor.transform(df_sample[ALL_FEATURE_COLUMNS])

    # decision_function returns raw anomaly score (higher = normal, lower = anomaly)
    raw_score = isolation_forest.decision_function(X_trans)[0]
    prediction = isolation_forest.predict(X_trans)[0] # 1 for inlier, -1 for outlier

    # Normalize raw score to 0.0 - 1.0 (where 1.0 is highest anomaly risk)
    # raw_score ranges roughly from -0.3 to 0.3
    anomaly_risk = max(0.0, min(1.0, (0.25 - raw_score) / 0.5))
    anomaly_status = "ANOMALOUS" if prediction == -1 or anomaly_risk > 0.65 else "NORMAL"

    return round(anomaly_risk, 3), anomaly_status


if __name__ == "__main__":
    if not DATASET_PATH.exists():
        from ml.dataset_generator import generate_synthetic_dataset
        generate_synthetic_dataset()
    df = pd.read_csv(DATASET_PATH)
    train_anomaly_detector(df)
