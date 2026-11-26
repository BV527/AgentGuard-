"""
Permission Engine for AgentGuard.
Defines role-based tool and resource access permissions for autonomous agents.
"""

ROLE_PERMISSIONS = {
    "ResearchAgent": {
        "allowed_tools": ["search_web", "read_article", "extract_information", "generate_report", "read_file", "write_file"],
        "allowed_resources": ["public_reports", "web_pages", "research_docs", "notes.txt", "ev_battery_notes.txt"],
        "allowed_destinations": ["none", "google.com", "wikipedia.org", "arxiv.org", "internal_api"],
        "max_privilege_level": 2
    },
    "AnalysisAgent": {
        "allowed_tools": ["analyze_data", "compare_metrics", "process_findings", "read_file", "write_file", "generate_report"],
        "allowed_resources": ["research_notes", "ev_battery_notes.txt", "ev_battery_analysis.txt", "analysis_summary.md"],
        "allowed_destinations": ["none", "internal_api"],
        "max_privilege_level": 2
    },
    "ReportAgent": {
        "allowed_tools": ["compile_report", "format_markdown", "generate_pdf", "write_file", "export_report", "generate_report"],
        "allowed_resources": ["ev_battery_analysis.txt", "ev_battery_research_summary.md", "final_report.md"],
        "allowed_destinations": ["none", "internal_api"],
        "max_privilege_level": 2
    },
    "CodingAgent": {
        "allowed_tools": ["read_project", "edit_code", "run_tests", "git_commit", "read_file", "write_file"],
        "allowed_resources": ["source_code", "test_files", "build_artifacts", "package.json", "README.md"],
        "allowed_destinations": ["none", "github.com", "internal_api"],
        "max_privilege_level": 3
    },
    "FinanceAgent": {
        "allowed_tools": ["read_financial_data", "database_query", "generate_report", "export_summary"],
        "allowed_resources": ["financial_db", "ledger_reports", "revenue_summary", "tax_docs"],
        "allowed_destinations": ["none", "internal_api", "secure_finance_vault"],
        "max_privilege_level": 3
    }
}

RESTRICTED_RESOURCES = [
    "credentials.txt", "passwords.env", ".env", "aws_keys.json",
    "customer_pii", "raw_db_dump", "system_root", "private_keys"
]


def check_permission(agent_role: str, tool: str, resource: str, destination: str = "none") -> dict:
    role_perms = ROLE_PERMISSIONS.get(agent_role)
    
    if not role_perms:
        return {
            "authorized": False,
            "reason": f"Unknown agent role: {agent_role}",
            "permission_level": 1
        }

    # Check restricted resource
    resource_lower = resource.lower()
    for restricted in RESTRICTED_RESOURCES:
        if restricted in resource_lower:
            return {
                "authorized": False,
                "reason": f"Access to sensitive/credential resource '{resource}' requires admin elevation",
                "permission_level": 5
            }

    # Check allowed tool
    if tool not in role_perms["allowed_tools"]:
        return {
            "authorized": False,
            "reason": f"Tool '{tool}' is not in allowed permissions for {agent_role}",
            "permission_level": 4
        }

    # Check external destination if present
    dest_lower = (destination or "none").lower()
    if dest_lower != "none":
        allowed_dest = False
        for allowed in role_perms["allowed_destinations"]:
            if allowed in dest_lower:
                allowed_dest = True
                break
        if not allowed_dest:
            return {
                "authorized": False,
                "reason": f"External destination '{destination}' is unauthorized for {agent_role}",
                "permission_level": 4
            }

    return {
        "authorized": True,
        "reason": "Permission granted under role policy",
        "permission_level": 2
    }
