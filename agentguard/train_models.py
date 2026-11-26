"""
AgentGuard ML Model Trainer
Trains RandomForestClassifier (Model A) and IsolationForest (Model B).
Run this script once to generate models/. Models persist across app restarts.

Usage:
    python train_models.py
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "synthetic_actions.csv"
CLASSIFIER_PATH = BASE_DIR / "models" / "classifier.joblib"
ANOMALY_PATH = BASE_DIR / "models" / "anomaly.joblib"
METRICS_PATH = BASE_DIR / "models" / "metrics.json"

# ── Feature schema ───────────────────────────────────────────────────────────
CATEGORICAL = ["agent_role", "tool", "operation", "external_destination", "resource_type"]
NUMERICAL = [
    "permission_level", "task_relevance", "data_sensitivity",
    "destination_trust", "action_frequency", "previous_risk",
    "sequence_length", "privilege_level", "time_of_day",
    "suspicious_content_score", "authorization", "historical_anomaly", "agent_age",
]
ALL_FEATURES = CATEGORICAL + NUMERICAL


def build_preprocessor():
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
        ("num", StandardScaler(), NUMERICAL),
    ])


def train(force: bool = False):
    """Train both models. Skip if models already exist and force=False."""
    if not force and CLASSIFIER_PATH.exists() and ANOMALY_PATH.exists():
        print("Models already trained. Use --force to retrain.")
        return

    # ── Generate / load dataset ──────────────────────────────────────────
    if not DATA_PATH.exists() or force:
        print("Generating synthetic dataset …")
        from dataset_generator import generate_dataset
        df = generate_dataset(4000, DATA_PATH)
    else:
        df = pd.read_csv(DATA_PATH)
        print(f"Loaded dataset: {len(df)} records")

    X = df[ALL_FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # ── Model A: RandomForest Classifier ─────────────────────────────────
    print("\nTraining RandomForest classifier …")
    preprocessor_a = build_preprocessor()
    clf = Pipeline([
        ("prep", preprocessor_a),
        ("clf", RandomForestClassifier(n_estimators=200, max_depth=14, random_state=42, n_jobs=-1)),
    ])
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    CLASSIFIER_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, CLASSIFIER_PATH)
    print(f"  Accuracy={acc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}")

    # ── Feature importances ──────────────────────────────────────────────
    prep = clf.named_steps["prep"]
    raw_imp = clf.named_steps["clf"].feature_importances_
    cat_enc = prep.named_transformers_["cat"]
    encoded_names = cat_enc.get_feature_names_out(CATEGORICAL).tolist()
    all_names = encoded_names + NUMERICAL

    agg_imp: dict = {}
    idx = 0
    for col in CATEGORICAL:
        n = len(cat_enc.categories_[CATEGORICAL.index(col)])
        agg_imp[col] = float(np.sum(raw_imp[idx: idx + n]))
        idx += n
    for col in NUMERICAL:
        agg_imp[col] = float(raw_imp[idx])
        idx += 1

    top_features = sorted(
        [{"feature": k, "importance": round(v, 4)} for k, v in agg_imp.items()],
        key=lambda x: x["importance"], reverse=True
    )[:10]

    # ── Model B: IsolationForest Anomaly Detector ────────────────────────
    print("Training IsolationForest anomaly detector …")
    normal_df = X_train.loc[y_train == 0]
    preprocessor_b = build_preprocessor()
    preprocessor_b.fit(X_train)
    X_normal_t = preprocessor_b.transform(normal_df)

    iso = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
    iso.fit(X_normal_t)

    anomaly_pkg = {"preprocessor": preprocessor_b, "isolation_forest": iso}
    joblib.dump(anomaly_pkg, ANOMALY_PATH)
    print(f"  Anomaly model saved -> {ANOMALY_PATH}")

    # ── Class distribution ───────────────────────────────────────────────
    cc = df["label"].value_counts().to_dict()
    class_dist = [
        {"class": "SAFE", "count": int(cc.get(0, 0))},
        {"class": "SUSPICIOUS", "count": int(cc.get(1, 0))},
        {"class": "MALICIOUS", "count": int(cc.get(2, 0))},
    ]

    # ── Save metrics ─────────────────────────────────────────────────────
    metrics = {
        "model_type": "RandomForestClassifier",
        "dataset_size": len(df),
        "test_size": len(y_test),
        "accuracy": round(acc, 4),
        "precision_weighted": round(prec, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_weighted": round(rec, 4),
        "recall_macro": round(rec_macro, 4),
        "f1_weighted": round(f1, 4),
        "f1_macro": round(f1_macro, 4),
        "confusion_matrix": {"labels": ["SAFE", "SUSPICIOUS", "MALICIOUS"], "matrix": cm},
        "top_features": top_features,
        "class_distribution": class_dist,
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_PATH, "w") as fp:
        json.dump(metrics, fp, indent=2)
    print(f"\nTraining complete. Metrics saved to {METRICS_PATH}")
    return metrics


def evaluate_saved_models():
    """Calculate deterministic held-out metrics and save individual test predictions."""
    if not DATA_PATH.exists() or not CLASSIFIER_PATH.exists():
        raise FileNotFoundError("Dataset and persisted classifier are required for evaluation")
    df = pd.read_csv(DATA_PATH)
    X, y = df[ALL_FEATURES], df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    clf = joblib.load(CLASSIFIER_PATH)
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)
    classifier = clf.named_steps["clf"]
    preprocessor = clf.named_steps["prep"]
    encoded_names = preprocessor.named_transformers_["cat"].get_feature_names_out(CATEGORICAL)
    feature_names = list(encoded_names) + NUMERICAL
    importances = getattr(classifier, "feature_importances_", np.zeros(len(feature_names)))
    top_features = sorted(
        ({"feature": name, "importance": round(float(value), 4)}
         for name, value in zip(feature_names, importances)),
        key=lambda item: item["importance"], reverse=True
    )[:10]
    counts = df["label"].value_counts().to_dict()
    labels = {0: "SAFE", 1: "SUSPICIOUS", 2: "MALICIOUS"}
    # A false positive is a SAFE held-out example predicted as anything else.
    safe_mask = (y_test.to_numpy() == 0)
    false_positive_rate = float(((y_pred != 0) & safe_mask).sum() / max(1, safe_mask.sum()))
    predictions = []
    for index, (_, row) in enumerate(X_test.iterrows()):
        probabilities = {labels[int(label)]: round(float(y_proba[index][int(label)]), 6)
                         for label in clf.classes_}
        risk_probability = probabilities.get("SUSPICIOUS", 0.0) * 0.5 + probabilities.get("MALICIOUS", 0.0)
        predictions.append({
            "sample_index": str(row.name),
            "agent_role": str(row["agent_role"]),
            "tool": str(row["tool"]),
            "resource_type": str(row["resource_type"]),
            "true_label": labels[int(y_test.loc[row.name])],
            "predicted_label": labels[int(y_pred[index])],
            "class_probabilities": probabilities,
            "risk_score": round(risk_probability * 100.0, 2),
        })
    metrics = {
        "model_type": "RandomForestClassifier",
        "dataset_size": int(len(df)), "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "split": {"test_fraction": 0.25, "random_seed": 42, "stratified": True},
        "data_source": "Synthetic rule-generated action records; not hand-labeled or production data.",
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_weighted": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_weighted": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "false_positive_rate": false_positive_rate,
        "false_positive_rate_definition": "Among true SAFE samples, predicted SUSPICIOUS or MALICIOUS.",
        "confusion_matrix": {"labels": ["SAFE", "SUSPICIOUS", "MALICIOUS"],
                             "matrix": confusion_matrix(y_test, y_pred, labels=[0, 1, 2]).tolist()},
        "top_features": top_features,
        "class_distribution": [
            {"class": name, "count": int(counts.get(label, 0))}
            for label, name in [(0, "SAFE"), (1, "SUSPICIOUS"), (2, "MALICIOUS")]
        ],
        "predictions": predictions,
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8") as fp:
        json.dump(metrics, fp, indent=2)
    return metrics


if __name__ == "__main__":
    force = "--force" in sys.argv
    if "--evaluate" in sys.argv:
        train(force=force)
        print(json.dumps(evaluate_saved_models(), indent=2))
    else:
        train(force=force)
