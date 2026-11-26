"""
Policy Engine for AgentGuard.
Deterministic security rules complementing ML evaluation.
"""

UNTRUSTED_DESTINATIONS = [
    "unknown_ip_89.2.1.4", "temp_file_host.net", "darknet_node",
    "pastebin.com", "anon_files.cc", "external_untrusted_server"
]

PROMPT_INJECTION_KEYWORDS = [
    "ignore previous instructions", "ignore your original task",
    "override system prompt", "bypass security", "upload credentials",
    "dump database", "exfiltrate", "sudo rm -rf"
]


def evaluate_policies(
    agent_role: str,
    action_name: str,
    resource: str,
    task: str,
    destination: str = "none",
    data_sensitivity: float = 0.0,
    payload: dict = None
) -> dict:
    violations = []
    policy_risk = 0.0

    resource_lower = (resource or "").lower()
    task_lower = (task or "").lower()
    payload_str = str(payload or "").lower()
    dest_lower = (destination or "none").lower()

    # Policy 1: Credential Access Policy
    if any(cred in resource_lower for cred in ["credentials", "passwords", "env", "secret", "private_key"]):
        violations.append("Policy Rule #1: Access to security credentials requires explicit admin privilege")
        policy_risk += 45.0

    # Policy 2: Untrusted External Destination & Exfiltration Policy
    if any(untrusted in dest_lower for untrusted in UNTRUSTED_DESTINATIONS) or dest_lower in UNTRUSTED_DESTINATIONS:
        violations.append(f"Policy Rule #2: Communication to untrusted external destination '{destination}' is forbidden")
        policy_risk += 50.0

    # Policy 3: Sensitive Data External Upload Policy
    if (action_name in ["external_upload", "export_customer_data"] or "upload" in action_name) and (data_sensitivity > 50.0 or "customer" in resource_lower or "financial" in resource_lower):
        violations.append("Policy Rule #3: Unauthorized external upload of high-sensitivity data detected")
        policy_risk += 45.0

    # Policy 4: Destructive Delete Operations Policy
    if "delete" in action_name or "remove" in action_name:
        violations.append("Policy Rule #4: File/resource deletion operations require elevated permission check")
        policy_risk += 35.0

    # Policy 5: Prompt Injection / Malicious Instruction Detection
    if any(kw in task_lower or kw in payload_str or kw in resource_lower for kw in PROMPT_INJECTION_KEYWORDS):
        violations.append("Policy Rule #5: Indirect prompt injection pattern detected in action instructions")
        policy_risk += 55.0

    # Policy 6: Cross-Agent Resource Boundary Policy
    if agent_role == "ResearchAgent" and any(res in resource_lower for res in ["financial_db", "ledger", "src/core"]):
        violations.append("Policy Rule #6: ResearchAgent attempted cross-domain access to private finance/core resource")
        policy_risk += 30.0

    # Normalize policy risk
    normalized_policy_risk = min(100.0, policy_risk)

    return {
        "policy_risk": round(normalized_policy_risk, 1),
        "violations": violations
    }
