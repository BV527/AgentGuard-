"""
API Endpoints for AgentGuard Backend.
"""

import json
from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db, AgentModel, ActionLog, SecurityEvent, ApprovalRequest
from models.schemas import ActionRequest, ApprovalDecisionPayload, ScenarioPayload
from guard.interceptor import intercept_action
from agents.simulator import simulator_instance
from agents.workflow_engine import workflow_engine
from backend.config import METRICS_PATH
from sandbox.sandbox_tools import execute_sandboxed_tool
from api.websocket import ws_manager

router = APIRouter(prefix="/api")


class TaskStartRequest(BaseModel):
    user_task: str
    inject_attack: Optional[str] = None # None, "unauthorized_file", "exfiltration"


@router.get("/agents")
def get_agents(db: Session = Depends(get_db)):
    agents = db.query(AgentModel).all()
    if not agents:
        # Seed default 3 demo agents
        default_agents = [
            AgentModel(
                agent_id="research_01",
                name="Research Agent",
                role="ResearchAgent",
                permissions=json.dumps(["search_web", "read_article", "extract_information", "generate_report", "read_file"]),
                current_task="Research EV battery technology and generate a report",
                status="ACTIVE"
            ),
            AgentModel(
                agent_id="analysis_01",
                name="Analysis Agent",
                role="AnalysisAgent",
                permissions=json.dumps(["analyze_data", "compare_metrics", "process_findings", "read_file", "write_file"]),
                current_task="Analyze findings and compare battery metrics",
                status="ACTIVE"
            ),
            AgentModel(
                agent_id="report_01",
                name="Report Agent",
                role="ReportAgent",
                permissions=json.dumps(["compile_report", "format_markdown", "generate_pdf", "write_file", "export_report"]),
                current_task="Compile analysis into final markdown report",
                status="ACTIVE"
            )
        ]
        db.add_all(default_agents)
        db.commit()
        agents = db.query(AgentModel).all()
    return [a.to_dict() for a in agents]


@router.get("/actions")
def get_actions(limit: int = 50, db: Session = Depends(get_db)):
    actions = db.query(ActionLog).order_by(ActionLog.timestamp.desc()).limit(limit).all()
    return [a.to_dict() for a in actions]


@router.get("/incidents")
def get_incidents(limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return [e.to_dict() for e in events]


@router.get("/approvals")
def get_pending_approvals(db: Session = Depends(get_db)):
    pending = db.query(ApprovalRequest).filter(ApprovalRequest.status == "PENDING").order_by(ApprovalRequest.timestamp.desc()).all()
    return [p.to_dict() for p in pending]


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total_actions = db.query(ActionLog).count()
    blocked_actions = db.query(ActionLog).filter(ActionLog.decision == "BLOCK").count()
    review_actions = db.query(ActionLog).filter(ActionLog.decision == "ASK").count()
    allowed_actions = db.query(ActionLog).filter(ActionLog.decision == "ALLOW").count()
    incidents_count = db.query(SecurityEvent).count()
    
    avg_risk = db.query(func.avg(ActionLog.risk_score)).scalar() or 0.0
    active_agents = db.query(AgentModel).count()

    return {
        "active_agents": active_agents,
        "total_actions": total_actions,
        "blocked_actions": blocked_actions,
        "review_actions": review_actions,
        "allowed_actions": allowed_actions,
        "security_incidents": incidents_count,
        "average_risk": round(float(avg_risk), 1)
    }


# User-Initiated Multi-Agent Task Workflow Endpoints
@router.post("/task/start")
def start_user_task(payload: TaskStartRequest):
    if not payload.user_task or payload.user_task.strip() == "":
        raise HTTPException(status_code=400, detail="User task description is required")
    
    status = workflow_engine.execute_user_task(payload.user_task, inject_test_attack=payload.inject_attack)
    return status


@router.get("/task/status")
def get_task_status():
    return workflow_engine.get_status()


@router.get("/task/report")
def get_task_report():
    if not workflow_engine.generated_report:
        raise HTTPException(status_code=444, detail="No generated report exists yet")
    return {
        "report_markdown": workflow_engine.generated_report,
        "filepath": str(workflow_engine.report_filepath)
    }


@router.post("/test/security")
def trigger_security_test(payload: dict):
    attack_type = payload.get("attack_type", "unauthorized_file")
    user_task = payload.get("user_task", "Research EV battery technology and generate a report")
    status = workflow_engine.execute_user_task(user_task, inject_test_attack=attack_type)
    return status


@router.get("/model/metrics")
def get_model_metrics():
    if not METRICS_PATH.exists():
        from ml.evaluate import evaluate_models
        metrics = evaluate_models()
    else:
        with open(METRICS_PATH, "r") as f:
            metrics = json.load(f)
    return metrics


@router.get("/actions/{action_id}/ml-report")
def get_action_ml_report(action_id: int, db: Session = Depends(get_db)):
    action = db.query(ActionLog).filter(ActionLog.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    reasons = json.loads(action.reasons) if action.reasons else []
    risk = round(action.risk_score or 0.0, 1)

    # Re-run ML inference to get class probabilities (not stored in DB)
    from ml.inference import predict_action_risk
    from guard.intent_engine import compute_task_relevance
    from guard.permission_engine import check_permission

    agent_db = db.query(AgentModel).filter(AgentModel.agent_id == action.agent_id).first()
    agent_role = agent_db.role if agent_db else "ResearchAgent"

    perm_res = check_permission(agent_role, action.action_name, action.resource, "none")
    task_relevance = action.task_relevance or compute_task_relevance(action.task or "", action.action_name, action.resource)

    feature_dict = {
        "agent_role": agent_role,
        "tool": action.action_name,
        "operation": action.action_name.split("_")[0] if "_" in action.action_name else "read",
        "permission_level": perm_res["permission_level"],
        "task_relevance": task_relevance,
        "data_sensitivity": 0.9 if "credentials" in (action.resource or "") else 0.2,
        "external_destination": "none",
        "destination_trust": 100.0,
        "action_frequency": (agent_db.actions_count if agent_db else 1),
        "previous_risk": (agent_db.avg_risk_score if agent_db else 0.0),
        "sequence_length": 5,
        "privilege_level": 3 if not perm_res["authorized"] else 1,
        "resource_type": "credentials" if "credentials" in (action.resource or "") else "public_doc",
        "time_of_day": action.timestamp.hour if action.timestamp else 12,
        "suspicious_content_score": 0.85 if "credentials" in (action.resource or "") else 0.05,
        "authorization": 1 if perm_res["authorized"] else 0,
        "historical_anomaly": 1 if (agent_db and agent_db.avg_risk_score > 60) else 0,
        "agent_age": 30,
    }
    ml_res = predict_action_risk(feature_dict)

    # Risk factor breakdown
    risk_factors = []
    if not perm_res["authorized"]:
        risk_factors.append({"factor": "Permission violation", "contribution": "High", "detail": perm_res["reason"]})
    if action.anomaly_status == "ANOMALOUS":
        risk_factors.append({"factor": "Behavioral anomaly", "contribution": "High", "detail": f"IsolationForest score: {action.anomaly_score:.3f}"})
    if task_relevance < 40:
        risk_factors.append({"factor": "Low task relevance", "contribution": "Medium", "detail": f"Action relevance to task: {task_relevance:.1f}%"})
    if ml_res["ml_class"] == "MALICIOUS":
        risk_factors.append({"factor": "Classifier: MALICIOUS", "contribution": "Critical", "detail": f"P(MALICIOUS)={ml_res['class_probabilities']['MALICIOUS']:.2%}"})
    elif ml_res["ml_class"] == "SUSPICIOUS":
        risk_factors.append({"factor": "Classifier: SUSPICIOUS", "contribution": "Medium", "detail": f"P(SUSPICIOUS)={ml_res['class_probabilities']['SUSPICIOUS']:.2%}"})
    if not risk_factors:
        risk_factors.append({"factor": "No significant risk factors", "contribution": "Low", "detail": "Action passed all checks"})

    return {
        "action_id": action.id,
        "agent": action.agent_name,
        "action": action.action_name,
        "resource": action.resource,
        "task": action.task,
        "decision": action.decision,
        "risk_score": risk,
        "risk_level": "CRITICAL" if risk > 80 else ("HIGH" if risk > 60 else ("MEDIUM" if risk > 40 else "LOW")),
        "ml_classifier": {
            "label": ml_res["ml_class"],
            "class_probabilities": ml_res["class_probabilities"],
            "risk_probability": round(ml_res["ml_risk_probability"] * 100, 1),
        },
        "anomaly_detector": {
            "status": action.anomaly_status,
            "score": round(action.anomaly_score or 0.0, 3),
            "interpretation": "Behavior deviates from normal agent patterns" if action.anomaly_status == "ANOMALOUS" else "Behavior is consistent with normal agent patterns",
        },
        "task_relevance": round(task_relevance, 1),
        "permission": {
            "authorized": perm_res["authorized"],
            "level": perm_res["permission_level"],
            "reason": perm_res["reason"],
        },
        "risk_factors": risk_factors,
        "policy_reasons": reasons,
        "recommendation": (
            "Investigate immediately — action was blocked due to policy or permission violation."
            if action.decision == "BLOCK" else
            "Review pending — action requires human approval before execution."
            if action.decision == "ASK" else
            "Action was allowed. No immediate action required."
        ),
    }


@router.get("/model/features")
def get_model_features():
    if not METRICS_PATH.exists():
        from ml.evaluate import evaluate_models
        metrics = evaluate_models()
    else:
        with open(METRICS_PATH, "r") as f:
            metrics = json.load(f)
    return metrics.get("feature_importance", [])


@router.post("/intercept")
def manual_intercept(payload: ActionRequest, db: Session = Depends(get_db)):
    res = intercept_action(
        agent_id=payload.agent_id,
        action_name=payload.action_name,
        resource=payload.resource,
        task=payload.task or "",
        destination=payload.destination or "none",
        data_sensitivity=payload.data_sensitivity or 0.0,
        payload=payload.payload,
        db=db
    )
    return res


# Preset Demo Scenario Endpoints (for backward-compatibility & testing)
@router.post("/demo/normal")
def demo_normal():
    status = workflow_engine.execute_user_task("Research EV battery technology and generate a report")
    return {"scenario": "NORMAL", "status": status}


@router.post("/demo/unauthorized")
def demo_unauthorized():
    status = workflow_engine.execute_user_task("Research EV battery technology", inject_test_attack="unauthorized_file")
    return {"scenario": "UNAUTHORIZED_ACCESS", "status": status}


@router.post("/demo/exfiltration")
def demo_exfiltration():
    status = workflow_engine.execute_user_task("Export quarterly financial data", inject_test_attack="exfiltration")
    return {"scenario": "DATA_EXFILTRATION", "status": status}


@router.post("/demo/prompt-injection")
def demo_prompt_injection():
    results = simulator_instance.run_prompt_injection_scenario()
    return {"scenario": "PROMPT_INJECTION", "processed": len(results), "results": results}


@router.post("/demo/multi-agent")
def demo_multi_agent():
    status = workflow_engine.execute_user_task("Research lithium extraction and refactor auth middleware")
    return {"scenario": "MULTI_AGENT", "status": status}


@router.post("/approval/{approval_id}")
async def handle_approval(approval_id: int, payload: ApprovalDecisionPayload, db: Session = Depends(get_db)):
    app_req = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
    if not app_req:
        raise HTTPException(status_code=404, detail="Approval request not found")

    action = db.query(ActionLog).filter(ActionLog.id == app_req.action_id).first()
    
    if payload.approved:
        app_req.status = "APPROVED"
        app_req.decision_time = datetime.utcnow()
        if action:
            action.status = "EXECUTED_UPON_APPROVAL"
            action.decision = "ALLOW_ONCE"
            exec_res = execute_sandboxed_tool(action.action_name, action.resource)
        msg = "Action approved by user for single execution"
    else:
        app_req.status = "REJECTED"
        app_req.decision_time = datetime.utcnow()
        if action:
            action.status = "REJECTED_BY_USER"
            action.decision = "BLOCK"
        
        # Add Security Event
        sec_event = SecurityEvent(
            agent_id=app_req.agent_id,
            agent_name=app_req.agent_name,
            action_id=app_req.action_id,
            severity="HIGH",
            title=f"User Rejected Action: {app_req.action_name}",
            description=f"User manually rejected execution of {app_req.action_name} on {app_req.resource}",
            reasons=app_req.reasons,
            status="BLOCKED"
        )
        db.add(sec_event)
        msg = "Action rejected by user"

    db.commit()

    # Broadcast update
    await ws_manager.broadcast({
        "type": "APPROVAL_DECISION",
        "approval_id": approval_id,
        "status": app_req.status
    })

    return {"status": app_req.status, "message": msg}


@router.post("/reset")
def reset_database(db: Session = Depends(get_db)):
    db.query(ActionLog).delete()
    db.query(SecurityEvent).delete()
    db.query(ApprovalRequest).delete()
    db.query(AgentModel).delete()
    db.commit()
    workflow_engine.reset_state()
    # Reseed agents
    get_agents(db)
    return {"status": "success", "message": "Database and workflow engine state reset"}
