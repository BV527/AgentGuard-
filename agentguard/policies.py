"""
AgentGuard Security Policies
Defines permissions for each agent and restricted resources.
"""

# ── Role-based permissions ──────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "ResearchAgent": {
        "allowed_tools": [
            "search_data", "read_article", "extract_information",
            "read_file", "write_file", "generate_report"
        ],
        "allowed_resources": [
            "ev_battery_notes.txt", "public_research.txt", "notes.txt",
            "research_data.txt", "research_findings.txt"
        ],
        "allowed_destinations": ["none", "internal"],
        "max_privilege": 2,
    },
    "AnalysisAgent": {
        "allowed_tools": [
            "analyze_data", "process_findings", "calculate_summary",
            "read_file", "write_file"
        ],
        "allowed_resources": [
            "research_findings.txt", "ev_battery_notes.txt",
            "analysis_output.txt", "research_findings.txt"
        ],
        "allowed_destinations": ["none", "internal"],
        "max_privilege": 2,
    },
    "ReportAgent": {
        "allowed_tools": [
            "compile_report", "format_markdown", "write_file",
            "export_report", "read_file", "validate_provenance"
        ],
        "allowed_resources": [
            "analysis_output.txt", "final_report.md",
            "ev_battery_report.md", "report_*.md"
        ],
        "allowed_destinations": ["none", "internal", "output"],
        "max_privilege": 2,
    },
}

# Files that are always restricted — no agent may access them
RESTRICTED_RESOURCES = [
    "credentials.txt", "passwords.env", ".env",
    "aws_keys.json", "private_keys", "customer_pii",
    "raw_db_dump", "system_root", "secrets.txt",
]

# Destinations considered untrusted
UNTRUSTED_DESTINATIONS = [
    "unknown_ip", "darknet", "pastebin", "anon_files",
    "temp_file_host", "external_untrusted",
]

# Keywords that signal a prompt-injection attempt
INJECTION_KEYWORDS = [
    "ignore previous instructions", "override system prompt",
    "ignore your instructions", "send this data out",
    "bypass security", "upload credentials", "dump database",
    "exfiltrate", "sudo rm",
]


def check_permission(agent_role: str, tool: str, resource: str, destination: str = "none",
                    task_context: dict = None) -> dict:
    """Returns {'authorized': bool, 'reason': str, 'permission_level': int}"""
    perms = ROLE_PERMISSIONS.get(agent_role)
    if not perms:
        return {"authorized": False, "reason": f"Unknown role: {agent_role}", "permission_level": 5}

    # A task scope can further narrow the role policy. It can never grant a
    # role a tool that the role itself does not have.
    scope = task_context or {}
    scoped_tools = scope.get("permitted_tools")
    if scoped_tools is not None and tool not in scoped_tools:
        return {"authorized": False,
                "reason": f"Tool '{tool}' is outside the task's permitted tools",
                "permission_level": 4}

    resource_lower = resource.lower()

    # Hard block: restricted resources
    for r in RESTRICTED_RESOURCES:
        if r in resource_lower:
            return {
                "authorized": False,
                "reason": f"Access to restricted resource '{resource}' is forbidden",
                "permission_level": 5,
            }

    for r in scope.get("restricted_resources", []):
        if str(r).lower() in resource_lower:
            return {"authorized": False,
                    "reason": f"Resource '{resource}' is restricted by this task scope",
                    "permission_level": 5}

    # Tool check
    if tool not in perms["allowed_tools"]:
        return {
            "authorized": False,
            "reason": f"Tool '{tool}' is not permitted for {agent_role}",
            "permission_level": 4,
        }

    if tool in {"read_file", "write_file", "extract_information", "search_data"}:
        allowed = perms["allowed_resources"]
        if not any(resource_lower == item.lower() or
                   ("*" in item and resource_lower.startswith(item.lower().split("*")[0]))
                   for item in allowed):
            return {"authorized": False,
                    "reason": f"Resource '{resource}' is outside {agent_role}'s approved dataset/files",
                    "permission_level": 4}

    scoped_resources = scope.get("approved_resources")
    if tool in {"read_file", "write_file", "extract_information", "search_data"} and scoped_resources is not None:
        normalized = resource.replace("\\", "/").strip("/").lower()
        if not any(normalized == str(item).replace("\\", "/").strip("/").lower()
                   or ("*" in str(item) and normalized.startswith(
                       str(item).replace("\\", "/").strip("/").lower().split("*")[0]))
                   for item in scoped_resources):
            return {"authorized": False,
                    "reason": f"Resource '{resource}' is outside the task's approved resources",
                    "permission_level": 4}

    scoped_destinations = scope.get("approved_destinations")
    if scoped_destinations is not None and destination not in scoped_destinations:
        return {"authorized": False,
                "reason": f"Destination '{destination}' is outside the task's approved destinations",
                "permission_level": 4}

    scoped_folders = scope.get("approved_folders")
    if scoped_folders is not None and tool in {
        "search_data", "extract_information", "read_file", "write_file"
    }:
        target_folder = "output" if tool == "write_file" and destination == "output" else "sandbox"
        if target_folder not in scoped_folders:
            return {"authorized": False,
                    "reason": f"Folder '{target_folder}' is outside the task's approved folders",
                    "permission_level": 4}

    # Destination check
    dest = (destination or "none").lower()
    if dest != "none":
        if not any(dest == d or dest.startswith(d + ".") for d in perms["allowed_destinations"] if d != "none"):
            return {
                "authorized": False,
                "reason": f"Destination '{destination}' is not permitted for {agent_role}",
                "permission_level": 4,
            }

    return {"authorized": True, "reason": "Permission granted under role policy", "permission_level": 2}


def evaluate_policies(agent_role: str, tool: str, resource: str,
                       task: str, destination: str = "none",
                       data_sensitivity: float = 0.0, payload: dict = None) -> dict:
    """Returns {'policy_risk': float, 'violations': list[str]}"""
    violations = []
    risk = 0.0

    r = resource.lower()
    t = task.lower()
    p = str(payload or "").lower()
    d = (destination or "none").lower()

    # Credential access
    if any(k in r for k in ["credentials", "password", "secret", "private_key", ".env"]):
        violations.append("Policy #1: Credential-resource access requires admin privilege")
        risk += 45.0

    # Untrusted destination
    if any(u in d for u in UNTRUSTED_DESTINATIONS):
        violations.append(f"Policy #2: Communication to untrusted destination '{destination}' is forbidden")
        risk += 50.0

    # High-sensitivity external upload
    if ("upload" in tool or "export" in tool) and data_sensitivity > 50:
        violations.append("Policy #3: High-sensitivity data cannot be uploaded externally without authorization")
        risk += 45.0

    # Prompt injection
    if any(kw in t or kw in p or kw in r for kw in INJECTION_KEYWORDS):
        violations.append("Policy #4: Prompt-injection pattern detected in task/payload")
        risk += 55.0

    gap_fill_signals = ("fill the dataset gap", "gap-filling", "fill missing values from model memory",
                        "invent a value", "unsupported claim")
    if "unsupported_claim" in p or any(signal in t or signal in p for signal in gap_fill_signals):
        violations.append("Policy #5: Unsupported gap-filling claim is not allowed without an approved source")
        risk += 55.0

    return {"policy_risk": round(min(100.0, risk), 1), "violations": violations}
