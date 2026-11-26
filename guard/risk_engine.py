"""
Risk Engine for AgentGuard.
Combines ML predictions, anomaly scores, permissions, policy violations, and intent alignment into a unified risk score (0-100).
"""

from backend.config import DEFAULT_RISK_WEIGHTS


def calculate_risk_score(
    ml_risk_prob: float,
    ml_class: str,
    anomaly_score: float,
    authorized: bool,
    permission_reason: str,
    policy_risk: float,
    policy_violations: list,
    task_relevance: float,
    data_sensitivity: float,
    destination_trust: float,
    weights: dict = None
) -> tuple:
    if weights is None:
        weights = DEFAULT_RISK_WEIGHTS

    ml_score = ml_risk_prob * 100.0
    behavior_score = anomaly_score * 100.0
    perm_score = 0.0 if authorized else 100.0
    misalignment_score = max(0.0, 100.0 - task_relevance)
    dest_risk_score = max(0.0, 100.0 - destination_trust)

    raw_weighted_risk = (
        ml_score * weights.get("ml_risk", 0.35) +
        behavior_score * weights.get("behavior_anomaly", 0.20) +
        perm_score * (weights.get("permission_violation", 0.20) * 0.5) +
        policy_risk * (weights.get("permission_violation", 0.20) * 0.5) +
        misalignment_score * weights.get("task_misalignment", 0.10) +
        data_sensitivity * weights.get("data_sensitivity", 0.10) +
        dest_risk_score * weights.get("destination_risk", 0.05)
    )

    reasons = []

    # Reason gathering and floor risk adjustments
    if not authorized:
        reasons.append(f"Permission Violation: {permission_reason}")

    for violation in policy_violations:
        reasons.append(violation)

    if ml_class == "MALICIOUS":
        reasons.append("ML Risk Classifier flagged action as MALICIOUS")
        raw_weighted_risk = max(raw_weighted_risk, 82.0)
    elif ml_class == "SUSPICIOUS":
        reasons.append("ML Risk Classifier flagged action as SUSPICIOUS")
        raw_weighted_risk = max(raw_weighted_risk, 48.0)

    if anomaly_score > 0.60:
        reasons.append(f"Behavioral Anomaly Detector flagged action sequence (anomaly score: {anomaly_score:.2f})")
        raw_weighted_risk = max(raw_weighted_risk, 60.0)

    if task_relevance < 40.0:
        reasons.append(f"Task Misalignment: Action relevance to task is low ({task_relevance:.1f}%)")

    if data_sensitivity > 60.0:
        reasons.append(f"High Data Sensitivity ({data_sensitivity:.1f}/100)")

    if destination_trust < 50.0 and destination_trust > 0:
        reasons.append(f"Low Destination Trust ({destination_trust:.1f}/100)")

    final_risk = round(max(0.0, min(100.0, raw_weighted_risk)), 1)
    return final_risk, reasons
