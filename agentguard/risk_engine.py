"""
AgentGuard Risk Engine
Combines ML predictions, anomaly scores, permissions, and policy violations
into a single risk score (0–100) and a ALLOW / ASK / BLOCK decision.
"""

import joblib
from collections import Counter
import numpy as np
import pandas as pd
import uuid
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

BASE_DIR = Path(__file__).resolve().parent
CLASSIFIER_PATH = BASE_DIR / "models" / "classifier.joblib"
ANOMALY_PATH = BASE_DIR / "models" / "anomaly.joblib"

CATEGORICAL = ["agent_role", "tool", "operation", "external_destination", "resource_type"]
NUMERICAL = [
    "permission_level", "task_relevance", "data_sensitivity",
    "destination_trust", "action_frequency", "previous_risk",
    "sequence_length", "privilege_level", "time_of_day",
    "suspicious_content_score", "authorization", "historical_anomaly", "agent_age",
]
ALL_FEATURES = CATEGORICAL + NUMERICAL

# ── Model cache ───────────────────────────────────────────────────────────────
_clf = None
_anomaly_pkg = None
MODEL_STATUS = {"classifier": "NOT_LOADED", "anomaly": "NOT_LOADED", "error": None}
EXECUTION_COUNTER = Counter()
SECURITY_INCIDENTS = []
PENDING_APPROVALS = {}
EVENT_HISTORY = []


def _load_models():
    global _clf, _anomaly_pkg
    errors = []
    if _clf is None:
        try:
            if CLASSIFIER_PATH.exists():
                _clf = joblib.load(CLASSIFIER_PATH)
                MODEL_STATUS["classifier"] = "LOADED"
            else:
                MODEL_STATUS["classifier"] = "MISSING"
        except Exception as exc:
            MODEL_STATUS["classifier"] = "FAILED"
            errors.append(f"Classifier: {exc}")
    if _anomaly_pkg is None:
        try:
            if ANOMALY_PATH.exists():
                _anomaly_pkg = joblib.load(ANOMALY_PATH)
                MODEL_STATUS["anomaly"] = "LOADED"
            else:
                MODEL_STATUS["anomaly"] = "MISSING"
        except Exception as exc:
            MODEL_STATUS["anomaly"] = "FAILED"
            errors.append(f"Anomaly detector: {exc}")
    MODEL_STATUS["error"] = "; ".join(errors) or None
    return _clf, _anomaly_pkg


# ── Task relevance (TF-IDF cosine similarity) ─────────────────────────────────
ACTION_EXPANSIONS = {
    "search_data": "research find information battery EV technology analysis",
    "read_article": "read article paper report documentation battery EV",
    "extract_information": "extract gather information research text data findings dataset battery summary report",
    "generate_report": "write document report summary findings markdown",
    "analyze_data": "analyze analyse process compare summarize findings research summary statistics battery technology dataset evidence",
    "process_findings": "process findings analyse research output results",
    "calculate_summary": "calculate summary aggregate metrics statistics",
    "compile_report": "compile assemble report document markdown output",
    "format_markdown": "format markdown document text report output",
    "export_report": "export save file report output write",
    "read_file": "read open file content data",
    "write_file": "write save create file output data generate final report compiled document",
}


def compute_task_relevance(task: str, tool: str, resource: str) -> float:
    if not task:
        return 75.0
    action_doc = f"{tool} {resource}".replace("_", " ").lower()
    action_doc += " " + ACTION_EXPANSIONS.get(tool, "")
    task_doc = task.lower()
    try:
        vect = TfidfVectorizer().fit([task_doc, action_doc])
        vecs = vect.transform([task_doc, action_doc])
        sim = float(cosine_similarity(vecs[0:1], vecs[1:2])[0][0]) * 100.0
        kw_bonus = sum(1 for w in task_doc.split() if len(w) > 3 and w in action_doc) * 12.0
        return round(max(5.0, min(100.0, sim + kw_bonus)), 1)
    except Exception:
        return 60.0


# ── ML inference ──────────────────────────────────────────────────────────────
def _predict_risk(feature_dict: dict) -> dict:
    clf, anomaly_pkg = _load_models()
    label_map = {0: "SAFE", 1: "SUSPICIOUS", 2: "MALICIOUS"}

    if clf is None:
        # Policy-only fallback: missing ML is explicitly represented and never
        # masquerades as a SAFE classifier prediction.
        return {"ml_class": "UNAVAILABLE", "ml_risk_prob": 0.0,
                "anomaly_score": 0.0, "anomaly_status": "UNAVAILABLE",
                "class_probs": None}

    df = pd.DataFrame([feature_dict])
    for col in ALL_FEATURES:
        if col not in df.columns:
            df[col] = "none" if col in CATEGORICAL else 0.0

    try:
        pred = int(clf.predict(df[ALL_FEATURES])[0])
        proba = clf.predict_proba(df[ALL_FEATURES])[0]
    except Exception as exc:
        MODEL_STATUS["classifier"] = "FAILED"
        MODEL_STATUS["error"] = f"Classifier inference failed: {exc}"
        return {"ml_class": "UNAVAILABLE", "ml_risk_prob": 0.0,
                "anomaly_score": 0.0, "anomaly_status": "UNAVAILABLE",
                "class_probs": None}
    ml_class = label_map.get(pred, "SAFE")
    p_safe = float(proba[0]) if len(proba) > 0 else 1.0
    p_susp = float(proba[1]) if len(proba) > 1 else 0.0
    p_mali = float(proba[2]) if len(proba) > 2 else 0.0
    ml_risk_prob = p_susp * 0.5 + p_mali * 1.0

    # Anomaly detection
    anomaly_score, anomaly_status = 0.0, "UNAVAILABLE"
    if anomaly_pkg:
        prep = anomaly_pkg["preprocessor"]
        iso = anomaly_pkg["isolation_forest"]
        try:
            Xt = prep.transform(df[ALL_FEATURES])
            raw = iso.decision_function(Xt)[0]
            pred_a = iso.predict(Xt)[0]
            anomaly_score = float(max(0.0, min(1.0, (0.25 - raw) / 0.5)))
            anomaly_status = "ANOMALOUS" if pred_a == -1 or anomaly_score > 0.65 else "NORMAL"
        except Exception as exc:
            MODEL_STATUS["anomaly"] = "FAILED"
            MODEL_STATUS["error"] = f"Anomaly detector inference failed: {exc}"

    return {
        "ml_class": ml_class,
        "ml_risk_prob": round(ml_risk_prob, 3),
        "anomaly_score": round(anomaly_score, 3),
        "anomaly_status": anomaly_status,
        "class_probs": {"SAFE": round(p_safe, 3), "SUSPICIOUS": round(p_susp, 3), "MALICIOUS": round(p_mali, 3)},
    }


# ── Risk score combiner ───────────────────────────────────────────────────────
WEIGHTS = {
    "ml_risk": 0.30,
    "anomaly": 0.20,
    "permission": 0.20,
    "policy": 0.15,
    "task_alignment": 0.05,
    "data_sensitivity": 0.05,
    "destination_risk": 0.05,
}


def _combine_risk(ml_risk_prob: float, ml_class: str, anomaly_score: float,
                  authorized: bool, perm_reason: str,
                  policy_risk: float, policy_violations: list,
                  task_relevance: float, data_sensitivity: float,
                  destination_trust: float) -> tuple:
    ml_score = ml_risk_prob * 100.0
    anom_score = anomaly_score * 100.0
    perm_score = 0.0 if authorized else 100.0
    align_score = max(0.0, 100.0 - task_relevance)
    sens_score = data_sensitivity
    destination_score = max(0.0, 100.0 - destination_trust)

    raw = (
        ml_score * WEIGHTS["ml_risk"]
        + anom_score * WEIGHTS["anomaly"]
        + perm_score * WEIGHTS["permission"]
        + policy_risk * WEIGHTS["policy"]
        + align_score * WEIGHTS["task_alignment"]
        + sens_score * WEIGHTS["data_sensitivity"]
        + destination_score * WEIGHTS["destination_risk"]
    )

    reasons = []
    if not authorized:
        reasons.append(f"Permission denied: {perm_reason}")
    for v in policy_violations:
        reasons.append(v)
    if ml_class == "MALICIOUS":
        reasons.append("ML classifier: action flagged as MALICIOUS")
        raw = max(raw, 82.0)
    elif ml_class == "SUSPICIOUS":
        reasons.append("ML classifier: action flagged as SUSPICIOUS")
        raw = max(raw, 48.0)
    if anomaly_score > 0.60:
        reasons.append(f"Anomaly detector: unusual behavior pattern (score={anomaly_score:.2f})")
        raw = max(raw, 60.0)
    if task_relevance < 40.0:
        reasons.append(f"Task misalignment: relevance={task_relevance:.1f}%")
    if data_sensitivity > 60.0:
        reasons.append(f"High data sensitivity: {data_sensitivity:.1f}/100")

    return round(min(100.0, max(0.0, raw)), 1), reasons


# ── Decision thresholds ───────────────────────────────────────────────────────
ALLOW_THRESHOLD = 39
ASK_THRESHOLD = 79


def _make_decision(risk_score: float, reasons: list) -> str:
    if risk_score <= ALLOW_THRESHOLD:
        if not reasons:
            reasons.append("All security checks passed")
        return "ALLOW"
    elif risk_score <= ASK_THRESHOLD:
        if not reasons:
            reasons.append("Risk elevated — human review recommended")
        return "ASK"
    else:
        if not reasons:
            reasons.append("High risk — action blocked")
        return "BLOCK"


# ── Central public API ────────────────────────────────────────────────────────
def evaluate_action(
    agent: str,
    task: str,
    tool: str,
    resource: str,
    destination: str = "none",
    data_sensitivity: float = 0.0,
    agent_history: dict = None,
    task_context: dict = None,
    payload: dict = None,
) -> dict:
    """
    The single entry point every protected tool MUST call.

    Returns:
        decision        : "ALLOW" | "ASK" | "BLOCK"
        risk_score      : 0–100
        ml_class        : "SAFE" | "SUSPICIOUS" | "MALICIOUS"
        anomaly_status  : "NORMAL" | "ANOMALOUS"
        anomaly_score   : float 0–1
        reasons         : list[str]
        ml_class_probs  : dict
    """
    try:
        from .policies import check_permission, evaluate_policies
    except ImportError:  # Streamlit's script-directory import mode
        from policies import check_permission, evaluate_policies

    hist = agent_history or {}

    # 1. Permission check
    perm = check_permission(agent, tool, resource, destination, task_context)

    # 2. Policy check
    pol = evaluate_policies(agent, tool, resource, task, destination, data_sensitivity, payload)

    # 3. Task relevance
    relevance = compute_task_relevance(task, tool, resource)

    # 4. Build feature dict for ML
    dest_trust = 100.0
    d = (destination or "none").lower()
    if any(u in d for u in ["unknown_ip", "darknet", "temp_file_host"]):
        dest_trust = 15.0
    elif d not in ["none", "internal", "output"]:
        dest_trust = 70.0

    feature_dict = {
        "agent_role": agent,
        "tool": tool,
        "operation": tool.split("_")[0] if "_" in tool else "read",
        "external_destination": destination or "none",
        "resource_type": (
            "credentials" if "cred" in resource.lower()
            else "config_file" if "config" in resource.lower()
            else "report_file" if "report" in resource.lower()
            else "analysis_output" if "analysis" in resource.lower()
            else "research_notes" if "research" in resource.lower() or "battery" in resource.lower()
            else "public_doc"
        ),
        "permission_level": perm["permission_level"],
        "task_relevance": relevance,
        "destination_trust": dest_trust,
        "data_sensitivity": data_sensitivity,
        "destination_trust": dest_trust,
        "action_frequency": hist.get("action_frequency", 5),
        "previous_risk": hist.get("avg_risk", 10.0),
        "sequence_length": hist.get("actions_count", 1),
        "privilege_level": 4 if not perm["authorized"] else 2,
        "time_of_day": __import__("datetime").datetime.now().hour,
        "suspicious_content_score": 0.85 if (
            "cred" in resource.lower() or "ignore" in task.lower()
        ) else 0.05,
        "authorization": 1 if perm["authorized"] else 0,
        "historical_anomaly": 1 if hist.get("avg_risk", 0) > 60 else 0,
        "agent_age": 30,
    }

    ml = _predict_risk(feature_dict)

    # 5. Combine risk
    risk_score, reasons = _combine_risk(
        ml["ml_risk_prob"], ml["ml_class"], ml["anomaly_score"],
        perm["authorized"], perm["reason"],
        pol["policy_risk"], pol["violations"],
        relevance, data_sensitivity, dest_trust,
    )

    # Mandatory override: restricted resources ALWAYS block regardless of ML score
    if not perm["authorized"] and "restricted" in perm["reason"].lower():
        risk_score = max(risk_score, 95.0)

    # Hard authorization and policy rules cannot be overridden by ML or a low score.
    if not perm["authorized"] or pol["violations"]:
        risk_score = max(80.0, risk_score)
        decision = "BLOCK"
    else:
        decision = _make_decision(risk_score, reasons)

    explanation = "; ".join(reasons) if reasons else "No policy or risk signals were raised."
    # The final risk thresholds are the same thresholds used to choose the decision.
    threshold_used = ALLOW_THRESHOLD if risk_score <= ALLOW_THRESHOLD else ASK_THRESHOLD
    return {
        "decision": decision,
        "risk_score": risk_score,
        "ml_class": ml["ml_class"],
        "ml_risk_prob": ml["ml_risk_prob"],
        "ml_risk_score": round(ml["ml_risk_prob"] * 100.0, 1),
        "ml_prediction": {"class": ml["ml_class"], "class_probabilities": ml["class_probs"]},
        "ml_class_probs": ml["class_probs"],
        "anomaly_score": ml["anomaly_score"],
        "anomaly_status": ml["anomaly_status"],
        "anomaly_result": {"status": ml["anomaly_status"], "score": ml["anomaly_score"]},
        "task_relevance": relevance,
        "data_sensitivity": float(data_sensitivity),
        "threshold_used": threshold_used,
        "authorized": perm["authorized"],
        "permission_result": perm,
        "policy_violations": pol["violations"],
        "reasons": reasons,
        "explanation": explanation,
        "incident_severity": ("CRITICAL" if risk_score >= 90 else "HIGH") if decision == "BLOCK" else None,
        "agent": agent,
        "tool": tool,
        "resource": resource,
        "execution_status": "NOT_EXECUTED",
        "task_scope": dict(task_context or {}),
    }


def _record_event(result, task_id):
    """Keep an in-memory view and persist the actual interceptor result."""
    try:
        from .sequence_engine import record_event
    except ImportError:
        from sequence_engine import record_event
    event = record_event(result, task_id=task_id)
    result["task_id"] = task_id
    result["timestamp"] = event.get("timestamp")
    EVENT_HISTORY.append(event)
    for finding in event.get("sequence_incidents", []):
        SECURITY_INCIDENTS.append({**finding, "decision": "BLOCK", "execution_status": "NOT_EXECUTED"})
    return event


def intercept_and_execute(agent, task, tool, resource, executor, destination="none",
                          data_sensitivity=0.0, agent_history=None, task_id=None,
                          task_context=None, payload=None):
    """The protected execution boundary: evaluate first, then invoke the tool only on ALLOW."""
    result = evaluate_action(agent, task, tool, resource, destination,
                             data_sensitivity, agent_history, task_context, payload)
    result["event_id"] = str(uuid.uuid4())
    result["destination"] = destination
    result["task"] = task
    result["input_trace"] = payload
    task_id = task_id or task.split(":", 1)[-1].strip()[:120] or "default"
    if result["decision"] == "ALLOW":
        try:
            result["tool_result"] = executor()
            result["execution_status"] = "EXECUTED"
            EXECUTION_COUNTER[tool] += 1
        except Exception as exc:
            result["execution_status"] = "FAILED"
            result["tool_error"] = str(exc)
    elif result["decision"] == "ASK":
        approval_id = str(uuid.uuid4())
        result["approval_id"] = approval_id
        result["approval_status"] = "PENDING"
        PENDING_APPROVALS[approval_id] = {
            "agent": agent, "task": task, "tool": tool, "resource": resource,
            "executor": executor, "destination": destination,
            "data_sensitivity": data_sensitivity, "agent_history": agent_history,
            "task_id": task_id, "task_context": dict(task_context or {}), "payload": payload,
        }
    else:
        result["tool_result"] = None
        if result["decision"] == "BLOCK":
            result["execution_status"] = "NOT_EXECUTED"
            SECURITY_INCIDENTS.append({**result, "explanation": result["explanation"]})
    _record_event(result, task_id)
    return result


def resolve_approval(approval_id: str, approve: bool) -> dict:
    """Resolve a risk-based ASK. Mandatory denials are rechecked before execution."""
    pending = PENDING_APPROVALS.pop(approval_id, None)
    if pending is None:
        raise KeyError("Approval request is missing or already resolved")
    current = evaluate_action(pending["agent"], pending["task"], pending["tool"],
                              pending["resource"], pending["destination"],
                              pending["data_sensitivity"], pending["agent_history"],
                              pending.get("task_context"), pending.get("payload"))
    result = {**current, "event_id": str(uuid.uuid4()), "destination": pending["destination"],
              "approval_id": approval_id, "original_decision": current["decision"]}
    if current["decision"] == "BLOCK":
        result["approval_status"] = "DENIED_BY_POLICY"
        result["execution_status"] = "NOT_EXECUTED"
    elif not approve:
        result["approval_status"] = "REJECTED"
        result["execution_status"] = "NOT_EXECUTED"
    else:
        try:
            result["tool_result"] = pending["executor"]()
            result["execution_status"] = "EXECUTED"
            result["approval_status"] = "APPROVED"
            result["decision"] = "ALLOW"
            result["reasons"] = list(result.get("reasons", [])) + ["Human reviewer approved this risk-based ASK"]
            result["explanation"] = "; ".join(result["reasons"])
            EXECUTION_COUNTER[result["tool"]] += 1
        except Exception as exc:
            result["execution_status"] = "FAILED"
            result["approval_status"] = "APPROVED_BUT_FAILED"
            result["tool_error"] = str(exc)
    if result["decision"] == "BLOCK":
        SECURITY_INCIDENTS.append(result)
    _record_event(result, pending["task_id"])
    return result
