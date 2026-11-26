"""
Decision Engine for AgentGuard.
Applies configurable risk score thresholds to dictate action lifecycle (ALLOW, ASK, BLOCK).
"""

from backend.config import ALLOW_THRESHOLD, ASK_THRESHOLD


def make_decision(
    risk_score: float,
    reasons: list,
    allow_threshold: float = ALLOW_THRESHOLD,
    ask_threshold: float = ASK_THRESHOLD
) -> dict:
    if risk_score <= allow_threshold:
        decision = "ALLOW"
        rec_action = "Execute action safely"
        if not reasons:
            reasons = ["Action passed all security policies and ML risk checks"]
    elif risk_score <= ask_threshold:
        decision = "ASK"
        rec_action = "Pause execution and request explicit user confirmation"
        if not reasons:
            reasons = ["Action risk exceeds automated allow threshold, requires human review"]
    else:
        decision = "BLOCK"
        rec_action = "Prevent tool execution and trigger security incident alert"
        if not reasons:
            reasons = ["High risk threshold exceeded, potential security threat"]

    return {
        "decision": decision,
        "risk_score": risk_score,
        "reasons": reasons,
        "recommended_action": rec_action
    }
