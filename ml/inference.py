import joblib
import pandas as pd
import numpy as np
from pathlib import Path

from backend.config import CLASSIFIER_MODEL_PATH, ANOMALY_MODEL_PATH, METRICS_PATH, DATASET_PATH
from ml.feature_engineering import ALL_FEATURE_COLUMNS

# Global cached models
_classifier_pipeline = None
_anomaly_model_package = None


def load_models():
    global _classifier_pipeline, _anomaly_model_package

    if not CLASSIFIER_MODEL_PATH.exists() or not ANOMALY_MODEL_PATH.exists():
        print("Model files not found. Auto-generating dataset and training ML models...")
        from ml.dataset_generator import generate_synthetic_dataset
        from ml.train_classifier import train_risk_classifier
        from ml.anomaly_detector import train_anomaly_detector
        from ml.evaluate import evaluate_models

        df = generate_synthetic_dataset()
        _classifier_pipeline = train_risk_classifier(df)
        _anomaly_model_package = train_anomaly_detector(df)
        evaluate_models()
    else:
        if _classifier_pipeline is None:
            _classifier_pipeline = joblib.load(CLASSIFIER_MODEL_PATH)
        if _anomaly_model_package is None:
            _anomaly_model_package = joblib.load(ANOMALY_MODEL_PATH)

    return _classifier_pipeline, _anomaly_model_package


def predict_action_risk(features: dict) -> dict:
    classifier, anomaly_pkg = load_models()

    # Build DataFrame matching feature columns
    df_sample = pd.DataFrame([features])
    
    # Ensure missing feature keys get sensible defaults
    for col in ALL_FEATURE_COLUMNS:
        if col not in df_sample.columns:
            if col in ["agent_role", "tool", "operation", "external_destination", "resource_type"]:
                df_sample[col] = "none"
            else:
                df_sample[col] = 0.0

    # 1. Action Risk Classifier prediction
    pred_label = classifier.predict(df_sample[ALL_FEATURE_COLUMNS])[0]
    probas = classifier.predict_proba(df_sample[ALL_FEATURE_COLUMNS])[0]

    label_map = {0: "SAFE", 1: "SUSPICIOUS", 2: "MALICIOUS"}
    ml_class = label_map.get(int(pred_label), "SAFE")

    class_probs = {
        "SAFE": round(float(probas[0]), 3) if len(probas) > 0 else 1.0,
        "SUSPICIOUS": round(float(probas[1]), 3) if len(probas) > 1 else 0.0,
        "MALICIOUS": round(float(probas[2]), 3) if len(probas) > 2 else 0.0,
    }

    # Combined ML risk probability (weighted suspicious + malicious)
    ml_risk_prob = class_probs["SUSPICIOUS"] * 0.5 + class_probs["MALICIOUS"] * 1.0

    # 2. IsolationForest Behavioral Anomaly prediction
    from ml.anomaly_detector import predict_anomaly
    anomaly_score, anomaly_status = predict_anomaly(df_sample.iloc[0].to_dict(), anomaly_pkg)

    return {
        "ml_class": ml_class,
        "ml_risk_probability": round(ml_risk_prob, 3),
        "class_probabilities": class_probs,
        "anomaly_score": anomaly_score,
        "anomaly_status": anomaly_status
    }
