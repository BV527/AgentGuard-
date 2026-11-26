from datetime import datetime
import json
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AgentModel(Base):
    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False)
    permissions = Column(Text, nullable=False, default="[]")  # JSON array
    current_task = Column(String, nullable=False, default="")
    behavior_profile = Column(String, nullable=False, default="standard")
    status = Column(String, nullable=False, default="ACTIVE")  # ACTIVE, WAITING, BLOCKED, COMPLETED
    actions_count = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "permissions": json.loads(self.permissions) if self.permissions else [],
            "current_task": self.current_task,
            "behavior_profile": self.behavior_profile,
            "status": self.status,
            "actions_count": self.actions_count,
            "avg_risk_score": round(self.avg_risk_score, 1),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ActionLog(Base):
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    agent_id = Column(String, index=True)
    agent_name = Column(String)
    action_name = Column(String)
    resource = Column(String)
    task = Column(String)
    risk_score = Column(Float)
    decision = Column(String)  # ALLOW, ASK, BLOCK
    ml_prediction = Column(String)  # SAFE, SUSPICIOUS, MALICIOUS
    anomaly_score = Column(Float, default=0.0)
    anomaly_status = Column(String, default="NORMAL")  # NORMAL, ANOMALOUS
    task_relevance = Column(Float, default=100.0)
    reasons = Column(Text, default="[]")  # JSON list
    status = Column(String, default="EXECUTED")  # EXECUTED, BLOCKED, PENDING_APPROVAL, REJECTED

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action_name": self.action_name,
            "resource": self.resource,
            "task": self.task,
            "risk_score": round(self.risk_score, 1) if self.risk_score is not None else 0.0,
            "decision": self.decision,
            "ml_prediction": self.ml_prediction,
            "anomaly_score": round(self.anomaly_score, 3) if self.anomaly_score else 0.0,
            "anomaly_status": self.anomaly_status,
            "task_relevance": round(self.task_relevance, 1) if self.task_relevance else 100.0,
            "reasons": json.loads(self.reasons) if self.reasons else [],
            "status": self.status,
        }


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    agent_id = Column(String, index=True)
    agent_name = Column(String)
    action_id = Column(Integer, nullable=True)
    severity = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String)
    description = Column(String)
    reasons = Column(Text, default="[]")  # JSON list
    status = Column(String, default="BLOCKED")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action_id": self.action_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "reasons": json.loads(self.reasons) if self.reasons else [],
            "status": self.status,
        }


class ApprovalRequest(Base):
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action_id = Column(Integer, index=True)
    agent_id = Column(String)
    agent_name = Column(String)
    action_name = Column(String)
    resource = Column(String)
    risk_score = Column(Float)
    reasons = Column(Text, default="[]")
    status = Column(String, default="PENDING")  # PENDING, APPROVED, REJECTED
    decision_time = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action_name": self.action_name,
            "resource": self.resource,
            "risk_score": round(self.risk_score, 1) if self.risk_score else 0.0,
            "reasons": json.loads(self.reasons) if self.reasons else [],
            "status": self.status,
            "decision_time": self.decision_time.isoformat() if self.decision_time else None,
        }


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
