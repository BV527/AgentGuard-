"""
Core Interceptor for AgentGuard.
Intercepts all agent action requests before execution.
Performs permission check, policy evaluation, task alignment, ML classification, anomaly detection, risk scoring, decision making, logging, and WebSocket broadcasting.
"""

import json
from datetime import datetime
from sqlalchemy.orm import Session

from backend.database import SessionLocal, AgentModel, ActionLog, SecurityEvent, ApprovalRequest
from guard.permission_engine import check_permission
from guard.policy_engine import evaluate_policies
from guard.intent_engine import compute_task_relevance
from guard.risk_engine import calculate_risk_score
from guard.decision_engine import make_decision
from ml.inference import predict_action_risk
from sandbox.sandbox_tools import execute_sandboxed_tool

# Active WebSocket manager reference (set during FastAPI startup)
_ws_manager = None


def set_ws_manager(ws_manager):
    global _ws_manager
    _ws_manager = ws_manager


def intercept_action(
    agent_id: str,
    action_name: str,
    resource: str,
    task: str = "",
    destination: str = "none",
    data_sensitivity: float = 0.0,
    payload: dict = None,
    db: Session = None
) -> dict:
    close_db_on_exit = False
    if db is None:
        db = SessionLocal()
        close_db_on_exit = True

    try:
        # 1. Fetch agent profile
        agent_db = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not agent_db:
            # Map default role from agent_id prefix
            if "research" in agent_id.lower():
                role = "ResearchAgent"
                name = "Research Agent 01"
            elif "coding" in agent_id.lower():
                role = "CodingAgent"
                name = "Coding Agent 01"
            elif "finance" in agent_id.lower():
                role = "FinanceAgent"
                name = "Finance Agent 01"
            else:
                role = "ResearchAgent"
                name = f"Agent {agent_id}"

            agent_db = AgentModel(
                agent_id=agent_id,
                name=name,
                role=role,
                permissions=json.dumps(["allowed_standard_tools"]),
                current_task=task or "Standard Execution",
                status="ACTIVE"
            )
            db.add(agent_db)
            db.commit()
            db.refresh(agent_db)

        agent_role = agent_db.role
        agent_name = agent_db.name
        current_task = task if task else agent_db.current_task

        # 2. Permission Engine Check
        perm_res = check_permission(agent_role, action_name, resource, destination)
        authorized = perm_res["authorized"]
        perm_level = perm_res["permission_level"]
        perm_reason = perm_res["reason"]

        # 3. Intent Engine Alignment
        task_relevance = compute_task_relevance(current_task, action_name, resource)

        # 4. Policy Engine Evaluation
        policy_res = evaluate_policies(
            agent_role, action_name, resource, current_task, destination, data_sensitivity, payload
        )
        policy_risk = policy_res["policy_risk"]
        policy_violations = policy_res["violations"]

        # 5. ML Model Predictions (Classifier + Anomaly Detector)
        feature_dict = {
            "agent_id": agent_id,
            "agent_role": agent_role,
            "tool": action_name,
            "operation": action_name.split("_")[0] if "_" in action_name else "read",
            "permission_level": perm_level,
            "task_relevance": task_relevance,
            "data_sensitivity": data_sensitivity,
            "external_destination": destination or "none",
            "destination_trust": 100.0 if not destination or destination == "none" else (20.0 if "ip" in destination or "temp" in destination else 80.0),
            "action_frequency": agent_db.actions_count + 1,
            "previous_risk": agent_db.avg_risk_score,
            "sequence_length": 5,
            "privilege_level": 3 if not authorized else 1,
            "resource_type": "credentials" if "credentials" in resource else ("code_file" if "code" in resource else "public_doc"),
            "time_of_day": datetime.now().hour,
            "suspicious_content_score": 0.85 if "ignore" in current_task.lower() or "credentials" in resource.lower() else 0.05,
            "authorization": 1 if authorized else 0,
            "historical_anomaly": 1 if agent_db.avg_risk_score > 60 else 0,
            "agent_age": 30
        }

        ml_res = predict_action_risk(feature_dict)
        ml_class = ml_res["ml_class"]
        ml_risk_prob = ml_res["ml_risk_probability"]
        anomaly_score = ml_res["anomaly_score"]
        anomaly_status = ml_res["anomaly_status"]

        # 6. Risk Engine Combination
        risk_score, reasons = calculate_risk_score(
            ml_risk_prob=ml_risk_prob,
            ml_class=ml_class,
            anomaly_score=anomaly_score,
            authorized=authorized,
            permission_reason=perm_reason,
            policy_risk=policy_risk,
            policy_violations=policy_violations,
            task_relevance=task_relevance,
            data_sensitivity=data_sensitivity,
            destination_trust=feature_dict["destination_trust"]
        )

        # 7. Decision Engine
        dec_info = make_decision(risk_score, reasons)
        decision = dec_info["decision"]

        # 8. Database Logging & Status Update
        action_status = "EXECUTED" if decision == "ALLOW" else ("PENDING_APPROVAL" if decision == "ASK" else "BLOCKED")
        
        action_log = ActionLog(
            agent_id=agent_id,
            agent_name=agent_name,
            action_name=action_name,
            resource=resource,
            task=current_task,
            risk_score=risk_score,
            decision=decision,
            ml_prediction=ml_class,
            anomaly_score=anomaly_score,
            anomaly_status=anomaly_status,
            task_relevance=task_relevance,
            reasons=json.dumps(dec_info["reasons"]),
            status=action_status
        )
        db.add(action_log)
        db.commit()
        db.refresh(action_log)

        # Update Agent Stats
        agent_db.actions_count += 1
        agent_db.avg_risk_score = (agent_db.avg_risk_score * (agent_db.actions_count - 1) + risk_score) / agent_db.actions_count
        if decision == "BLOCK":
            agent_db.status = "BLOCKED"
        elif decision == "ASK":
            agent_db.status = "WAITING"
        else:
            agent_db.status = "ACTIVE"
        db.commit()

        # Handle Execution or Incident/Approval record
        execution_result = None
        if decision == "ALLOW":
            execution_result = execute_sandboxed_tool(action_name, resource, payload)
        elif decision == "BLOCK":
            sec_event = SecurityEvent(
                agent_id=agent_id,
                agent_name=agent_name,
                action_id=action_log.id,
                severity="CRITICAL" if risk_score > 90 else "HIGH",
                title=f"Blocked Unauthorized Action: {action_name}",
                description=f"{agent_name} attempted to access '{resource}' which violated security policies.",
                reasons=json.dumps(dec_info["reasons"]),
                status="BLOCKED"
            )
            db.add(sec_event)
            db.commit()
        elif decision == "ASK":
            app_req = ApprovalRequest(
                action_id=action_log.id,
                agent_id=agent_id,
                agent_name=agent_name,
                action_name=action_name,
                resource=resource,
                risk_score=risk_score,
                reasons=json.dumps(dec_info["reasons"]),
                status="PENDING"
            )
            db.add(app_req)
            db.commit()

        result_payload = {
            "action_id": action_log.id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "action_name": action_name,
            "resource": resource,
            "decision": decision,
            "risk_score": risk_score,
            "reasons": dec_info["reasons"],
            "ml_prediction": ml_class,
            "anomaly_score": anomaly_score,
            "anomaly_status": anomaly_status,
            "task_relevance": task_relevance,
            "execution_result": execution_result
        }

        # 9. Broadcast live event via WebSocket manager if available
        if _ws_manager:
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(_ws_manager.broadcast({
                        "type": "ACTION_INTERCEPTED",
                        "data": action_log.to_dict(),
                        "agent": agent_db.to_dict()
                    }))
            except Exception as ws_err:
                print(f"WS Broadcast notice: {ws_err}")

        return result_payload

    finally:
        if close_db_on_exit:
            db.close()
