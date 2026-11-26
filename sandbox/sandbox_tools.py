"""
Sandbox Execution Layer for AgentGuard.
Ensures zero dangerous operations occur on the host machine.
All tools operate strictly within the controlled sandbox directory.
"""

import os
from pathlib import Path
from backend.config import SANDBOX_DIR

# Ensure sandbox directory structure exists
(SANDBOX_DIR / "test_files").mkdir(parents=True, exist_ok=True)
(SANDBOX_DIR / "public_reports").mkdir(parents=True, exist_ok=True)

# Write initial mock files
with open(SANDBOX_DIR / "notes.txt", "w") as f:
    f.write("AgentGuard Research Notes: EV battery chemistry comparison and anode development.\n")

with open(SANDBOX_DIR / "credentials.txt", "w") as f:
    f.write("[MOCK CREDENTIALS FILE]\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=SuperSecretPass123!\n")

with open(SANDBOX_DIR / "test_files" / "temp_build.log", "w") as f:
    f.write("Build log 2026-09-24: compilation successful 0 errors.\n")


def sandbox_read_file(resource_name: str) -> dict:
    target_path = SANDBOX_DIR / os.path.basename(resource_name)
    if not target_path.exists():
        # Fallback to direct sandbox root read
        target_path = SANDBOX_DIR / "notes.txt"
    try:
        content = target_path.read_text(encoding="utf-8")
        return {"status": "success", "content_preview": content[:200]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def sandbox_write_file(resource_name: str, content: str = "Sample content") -> dict:
    target_path = SANDBOX_DIR / os.path.basename(resource_name)
    try:
        target_path.write_text(content, encoding="utf-8")
        return {"status": "success", "path": str(target_path)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def sandbox_delete_file(resource_name: str) -> dict:
    target_path = SANDBOX_DIR / "test_files" / os.path.basename(resource_name)
    try:
        if target_path.exists():
            target_path.unlink()
            return {"status": "success", "deleted": str(target_path)}
        return {"status": "success", "message": "File removed from test sandbox"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def sandbox_search_web(query: str) -> dict:
    return {
        "status": "success",
        "query": query,
        "results": [
            {"title": f"Recent Advances in {query}", "url": f"https://arxiv.org/abs/2609.{query[:4]}"},
            {"title": f"Comprehensive Guide to {query}", "url": f"https://wikipedia.org/wiki/{query}"}
        ]
    }


def sandbox_database_query(query: str) -> dict:
    return {
        "status": "success",
        "query": query,
        "rows_returned": 15,
        "sample_data": [{"id": 101, "record_type": "quarterly_summary", "val": 45000}]
    }


def sandbox_external_upload(destination: str, payload: str = "") -> dict:
    return {
        "status": "simulated_upload_complete",
        "destination": destination,
        "bytes_sent": len(payload),
        "note": "Sandbox simulated upload - no actual network requests sent"
    }


def execute_sandboxed_tool(action_name: str, resource: str, payload: dict = None) -> dict:
    payload = payload or {}
    if "read" in action_name or action_name == "read_file":
        return sandbox_read_file(resource)
    elif "write" in action_name or "edit" in action_name:
        return sandbox_write_file(resource, payload.get("content", "Generated sandbox output"))
    elif "delete" in action_name:
        return sandbox_delete_file(resource)
    elif "search" in action_name:
        return sandbox_search_web(resource or "general research")
    elif "database" in action_name or "query" in action_name:
        return sandbox_database_query(resource or "SELECT * FROM summaries")
    elif "upload" in action_name or "export" in action_name:
        return sandbox_external_upload(payload.get("destination", "trusted_cloud.s3"), resource)
    else:
        return {"status": "success", "executed_action": action_name, "resource": resource}
