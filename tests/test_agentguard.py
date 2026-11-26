import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.main import app
from backend.database import init_db
from guard.permission_engine import check_permission
from guard.policy_engine import evaluate_policies
from guard.intent_engine import compute_task_relevance
from guard.decision_engine import make_decision
from guard.interceptor import intercept_action
from agents.workflow_engine import workflow_engine
from backend.config import SANDBOX_DIR

# Ensure database tables exist for tests
init_db()

client = TestClient(app)


def test_permission_engine():
    res_safe = check_permission("ResearchAgent", "search_web", "EV battery research")
    assert res_safe["authorized"] is True

    res_cred = check_permission("ResearchAgent", "read_file", "credentials.txt")
    assert res_cred["authorized"] is False
    assert "credentials" in res_cred["reason"].lower()


def test_policy_engine():
    res = evaluate_policies("FinanceAgent", "external_upload", "customer_pii.csv", "export", destination="unknown_ip_89.2.1.4")
    assert res["policy_risk"] > 40.0
    assert len(res["violations"]) > 0


def test_intent_engine():
    task = "Research EV battery technology and create a report"
    relevance_high = compute_task_relevance(task, "search_web", "EV battery manufacturing report")
    relevance_low = compute_task_relevance(task, "read_file", "credentials.txt")
    assert relevance_high > relevance_low


def test_decision_engine():
    dec_allow = make_decision(25.0, [])
    assert dec_allow["decision"] == "ALLOW"

    dec_ask = make_decision(60.0, ["Moderate risk"])
    assert dec_ask["decision"] == "ASK"

    dec_block = make_decision(90.0, ["High risk"])
    assert dec_block["decision"] == "BLOCK"


def test_interceptor_flow():
    # Safe action
    res_safe = intercept_action(
        agent_id="test_research_01",
        action_name="search_web",
        resource="battery chemistry article",
        task="Research battery technology",
        destination="google.com"
    )
    assert res_safe["decision"] == "ALLOW"

    # Malicious action
    res_block = intercept_action(
        agent_id="test_coding_01",
        action_name="read_file",
        resource="credentials.txt",
        task="Refactor auth",
        destination="none"
    )
    assert res_block["decision"] == "BLOCK"


def test_test_a_normal_execution_workflow():
    # TEST A: User enters task, 3 agents complete, report generated, zero false security alerts
    task_text = "Research electric vehicle battery technology and generate a report"
    status = workflow_engine.execute_user_task(task_text)
    
    assert status["stage"] == "COMPLETED"
    assert status["progress"] == 100
    assert status["has_report"] is True
    assert status["security_alert"] is None
    assert status["total_actions"] >= 5


def test_test_b_unauthorized_action_blocked():
    # TEST B: Unauthorized file access blocked before tool execution, alerts user
    task_text = "Research EV battery technology"
    status = workflow_engine.execute_user_task(task_text, inject_test_attack="unauthorized_file")
    
    assert status["stage"] == "SECURITY_ALERT"
    assert status["security_alert"] is not None
    assert status["security_alert"]["decision"] == "BLOCKED"
    assert status["security_alert"]["action"] == "read_file"
    assert status["security_alert"]["resource"] == "credentials.txt"


def test_test_e_multi_agent_tracking():
    # TEST E: Research, Analysis, and Report agents monitored under same task ID
    task_text = "Analyze battery degradation and compile report"
    status = workflow_engine.execute_user_task(task_text)
    
    agents = status["agents"]
    assert len(agents) == 3
    agent_names = [a["name"] for a in agents]
    assert "Research Agent" in agent_names
    assert "Analysis Agent" in agent_names
    assert "Report Agent" in agent_names


def test_test_f_actual_report_file_exists():
    # TEST F: Verify generated report file exists in sandbox and contains research text
    task_text = "Research EV battery technology and generate a report"
    status = workflow_engine.execute_user_task(task_text)
    
    report_file = SANDBOX_DIR / "ev_battery_research_summary.md"
    assert report_file.exists()
    
    content = report_file.read_text(encoding="utf-8")
    assert "# 🔋 Research Report: Electric Vehicle Battery Technology" in content
    assert "Lithium Iron Phosphate" in content


def test_api_endpoints():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_actions" in data

    response_agents = client.get("/api/agents")
    assert response_agents.status_code == 200
    assert len(response_agents.json()) >= 2

    response_task = client.post("/api/task/start", json={"user_task": "Research battery tech"})
    assert response_task.status_code == 200
    assert response_task.json()["stage"] == "COMPLETED"
