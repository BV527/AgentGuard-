import joblib
import pandas as pd
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

from ml.feature_engineering import get_preprocessor, ALL_FEATURE_COLUMNS
from backend.config import CLASSIFIER_MODEL_PATH, DATASET_PATH


def train_risk_classifier(df: pd.DataFrame, model_path: Path = CLASSIFIER_MODEL_PATH):
    X = df[ALL_FEATURE_COLUMNS]
    y = df["label"]

    preprocessor = get_preprocessor()

    if HAS_XGBOOST:
        print("Using XGBoost Classifier for Action Risk Model...")
        classifier = XGBClassifier(
            n_estimators=150,
            learning_rate=0.08,
            max_depth=6,
            random_state=42,
            eval_metric="mlogloss"
        )
    else:
        print("Using RandomForestClassifier for Action Risk Model...")
        classifier = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            random_state=42
        )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", classifier)
    ])

    print("Training Action Risk Classification model...")
    pipeline.fit(X, y)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    print(f"Action Risk Classifier saved to {model_path}")
    return pipeline


if __name__ == "__main__":
    if not DATASET_PATH.exists():
        from ml.dataset_generator import generate_synthetic_dataset
        generate_synthetic_dataset()
    df = pd.read_csv(DATASET_PATH)
    train_risk_classifier(df)
