from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class ActionRequest(BaseModel):
    agent_id: str
    action_name: str
    resource: str
    task: Optional[str] = ""
    destination: Optional[str] = None
    data_sensitivity: Optional[float] = 0.0
    payload: Optional[Dict[str, Any]] = None


class InterceptorResponse(BaseModel):
    action_id: int
    agent_id: str
    agent_name: str
    action_name: str
    resource: str
    decision: str  # ALLOW, ASK, BLOCK
    risk_score: float
    reasons: List[str]
    ml_prediction: str
    anomaly_score: float
    anomaly_status: str
    task_relevance: float
    execution_result: Optional[Dict[str, Any]] = None


class ApprovalDecisionPayload(BaseModel):
    approved: bool  # True = ALLOW ONCE, False = BLOCK


class ScenarioPayload(BaseModel):
    scenario_type: str  # normal, unauthorized, exfiltration, prompt_injection, multi_agent


class RiskWeightConfig(BaseModel):
    ml_risk: float = Field(default=0.35, ge=0.0, le=1.0)
    behavior_anomaly: float = Field(default=0.20, ge=0.0, le=1.0)
    permission_violation: float = Field(default=0.20, ge=0.0, le=1.0)
    task_misalignment: float = Field(default=0.10, ge=0.0, le=1.0)
    data_sensitivity: float = Field(default=0.10, ge=0.0, le=1.0)
    destination_risk: float = Field(default=0.05, ge=0.0, le=1.0)
