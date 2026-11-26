"""Persisted, evidence-based sequence analysis for AgentGuard."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "output" / "agentguard_events.sqlite3"


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, task_id TEXT, timestamp REAL, agent TEXT, tool TEXT,
            resource TEXT, destination TEXT, decision TEXT, risk_score REAL,
            ml_class TEXT, anomaly_status TEXT, permission_authorized INTEGER,
            policy_violations TEXT, execution_status TEXT, explanation TEXT, trace_json TEXT)""")
        columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
        if "trace_json" not in columns:
            db.execute("ALTER TABLE events ADD COLUMN trace_json TEXT")
        db.execute("""CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY, task_id TEXT, created_at REAL, status TEXT,
            title TEXT, explanation TEXT, evidence TEXT)""")
        db.commit()
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def record_event(event: dict, task_id: str = "default") -> dict:
    """Persist one real interceptor decision and create/update sequence incidents."""
    event = dict(event)
    event_id = event.get("event_id") or str(uuid.uuid4())
    now = time.time()
    event.update(event_id=event_id, task_id=task_id, timestamp=now)
    with _connect() as db:
        trace = {key: event.get(key) for key in (
            "task", "input_trace", "tool_result", "reasons", "permission_result",
            "task_scope", "incident_severity", "comparison_mode", "ml_risk_prob",
            "ml_risk_score", "task_relevance", "data_sensitivity", "threshold_used",
            "ml_prediction", "ml_class_probs", "risk_score")
                 if key in event}
        if "comparison_mode" not in trace:
            mode = (event.get("input_trace") or {}).get("comparison_mode")
            if mode:
                trace["comparison_mode"] = mode
        db.execute("""INSERT OR IGNORE INTO events
            (event_id,task_id,timestamp,agent,tool,resource,destination,decision,risk_score,
             ml_class,anomaly_status,permission_authorized,policy_violations,execution_status,
             explanation,trace_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            event_id, task_id, now, event.get("agent"), event.get("tool"),
            event.get("resource"), event.get("destination"), event.get("decision"),
            event.get("risk_score", 0), event.get("ml_class"), event.get("anomaly_status"),
            int(bool(event.get("authorized"))), json.dumps(event.get("policy_violations", [])),
            event.get("execution_status"), event.get("explanation", ""), json.dumps(trace)))
        rows = db.execute("SELECT * FROM events WHERE task_id=? ORDER BY timestamp DESC LIMIT 12",
                          (task_id,)).fetchall()
        history = [dict(r) for r in reversed(rows)]
        for row in history:
            row.update(json.loads(row.pop("trace_json", None) or "{}"))
        incidents = analyze_sequence(history)
        if event.get("decision") == "BLOCK":
            incidents.append(_finding("Blocked protected action",
                event.get("explanation") or "The interceptor blocked this action before execution.", [event]))
        created = []
        for finding in incidents:
            incident_id = finding["incident_id"]
            cur = db.execute("""INSERT OR IGNORE INTO incidents
                (incident_id,task_id,created_at,status,title,explanation,evidence)
                VALUES (?,?,?,'OPEN',?,?,?)""",
                (incident_id, task_id, now, finding["title"], finding["explanation"],
                 json.dumps(finding["evidence"])))
            if cur.rowcount == 1:
                created.append(finding)
        db.commit()
    event["sequence_incidents"] = created
    return event


def analyze_sequence(events: list[dict]) -> list[dict]:
    """Return findings supported by action records in the supplied workflow history."""
    if not events:
        return []
    findings = []
    denied = [e for e in events if e.get("decision") == "BLOCK" and not
              e.get("authorized", e.get("permission_authorized", True))]
    transfers = [e for e in events if e.get("tool") in {"external_upload", "export_report", "write_file"}
                 and ((e.get("destination") or "none") not in {"none", "internal", "output"})]
    if denied and transfers:
        evidence = [*denied[-2:], *transfers[-2:]]
        findings.append(_finding("Restricted access followed by data movement",
            "The workflow recorded a denied restricted access attempt and a subsequent attempt to move data to an unapproved destination. Both decisions and their model signals are in the evidence.", evidence))
    if len(denied) >= 2:
        findings.append(_finding("Repeated denied actions",
            f"The same workflow contains {len(denied)} denied actions across {len({e.get('agent') for e in denied})} agent(s). Repeated denials warrant review.", denied[-4:]))
    sensitive = [e for e in events if e.get("resource") and any(x in str(e["resource"]).lower() for x in ("credential", "secret", "pii", "private"))]
    if sensitive:
        findings.append(_finding("Sensitive resource access attempt",
            "A recorded action targeted a credential, secret, private-key, or personal-data resource. The interceptor decision and execution status are shown in the evidence.", sensitive[-3:]))
    transitions = [(a,b) for a,b in zip(events,events[1:]) if a.get("agent") != b.get("agent")]
    if any(a.get("tool") in {"read_file","search_data"} and b.get("tool") in {"external_upload","export_report"} for a,b in transitions):
        pair = next((a,b) for a,b in transitions if a.get("tool") in {"read_file","search_data"} and b.get("tool") in {"external_upload","export_report"})
        findings.append(_finding("Unexpected cross-agent tool transition",
            "A read or collection action was followed by an export action from a different agent. This pattern is a correlation signal, not proof of malicious intent.", list(pair)))
    if len(events) >= 10:
        findings.append(_finding("Excessive action frequency",
            f"{len(events)} actions were recorded in the current workflow window; the frequency threshold is 10.", events[-10:]))
    return findings


def _finding(title, explanation, evidence):
    material = {"title": title, "events": [(e.get("event_id"), e.get("decision"), e.get("tool"))
                                            for e in evidence]}
    incident_id = "seq-" + str(uuid.uuid5(uuid.NAMESPACE_OID, json.dumps(material, sort_keys=True)))[:12]
    return {"incident_id": incident_id, "title": title, "explanation": explanation, "evidence": evidence}


def list_events(limit: int = 200) -> list[dict]:
    with _connect() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))]
    for row in rows:
        trace = json.loads(row.pop("trace_json", None) or "{}")
        row.update(trace)
    return rows


def list_incidents() -> list[dict]:
    with _connect() as db:
        rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        for event in item["evidence"]:
            if isinstance(event.get("trace_json"), str):
                event.update(json.loads(event.pop("trace_json") or "{}"))
        result.append(item)
    return result


def set_incident_status(incident_id: str, status: str) -> bool:
    if status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("Invalid incident status")
    with _connect() as db:
        cur = db.execute("UPDATE incidents SET status=? WHERE incident_id=?", (status, incident_id))
        return cur.rowcount == 1
