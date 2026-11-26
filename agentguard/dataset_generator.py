"""
AgentGuard Dataset Generator
Generates a synthetic labeled dataset of agent actions for ML training.
3,000+ records with logically correlated features and labels.
"""

import random
import numpy as np
import pandas as pd
from pathlib import Path

ROLES = ["ResearchAgent", "AnalysisAgent", "ReportAgent"]

TOOLS_BY_ROLE = {
    "ResearchAgent": [
        "search_data", "read_article", "extract_information",
        "read_file", "write_file", "generate_report",
        "read_credentials",  # attacker tool — sometimes injected
        "external_upload",   # out-of-policy for Research
    ],
    "AnalysisAgent": [
        "analyze_data", "process_findings", "calculate_summary",
        "read_file", "write_file",
        "read_credentials",  # out-of-policy
        "external_upload",   # out-of-policy
    ],
    "ReportAgent": [
        "compile_report", "format_markdown", "write_file",
        "export_report", "read_file",
        "read_credentials",  # out-of-policy
        "external_upload",   # out-of-policy
    ],
}

OPERATIONS = ["read", "write", "execute", "delete", "query", "upload", "export"]
DESTINATIONS = [
    "none", "internal", "none", "none",  # skewed toward safe
    "unknown_ip_89.2.1.4", "darknet_node", "temp_file_host.net",
]
RESOURCE_TYPES = [
    "public_doc", "research_notes", "analysis_output",
    "report_file", "credentials", "config_file", "customer_pii",
]


def generate_dataset(num_samples: int = 4000, save_path: Path = None) -> pd.DataFrame:
    random.seed(42)
    np.random.seed(42)

    records = []
    for _ in range(num_samples):
        role = random.choice(ROLES)
        tool = random.choice(TOOLS_BY_ROLE[role])
        operation = random.choice(OPERATIONS)
        resource_type = random.choice(RESOURCE_TYPES)
        destination = random.choice(DESTINATIONS)

        authorization = random.choices([1, 0], weights=[0.72, 0.28])[0]
        permission_level = random.choice([1, 2, 3, 4, 5])
        privilege_level = random.choice([1, 2, 3, 4, 5])
        task_relevance = round(random.uniform(10.0, 100.0), 1)
        data_sensitivity = round(random.uniform(0.0, 100.0), 1)
        suspicious_content_score = round(random.uniform(0.0, 1.0), 2)
        action_frequency = random.randint(1, 50)
        previous_risk = round(random.uniform(0.0, 100.0), 1)
        sequence_length = random.randint(1, 20)
        historical_anomaly = random.choices([0, 1], weights=[0.85, 0.15])[0]
        agent_age = random.randint(1, 365)
        time_of_day = random.randint(0, 23)

        if destination == "none" or destination == "internal":
            destination_trust = 100.0
        elif destination in ["unknown_ip_89.2.1.4", "darknet_node", "temp_file_host.net"]:
            destination_trust = round(random.uniform(0.0, 25.0), 1)
        else:
            destination_trust = round(random.uniform(75.0, 100.0), 1)

        # ── Label logic ──────────────────────────────────────────────
        is_malicious = False
        if tool == "read_credentials" and authorization == 0:
            is_malicious = True
        elif resource_type in ["credentials", "customer_pii"] and authorization == 0:
            is_malicious = True
        elif destination_trust < 30 and data_sensitivity > 50 and authorization == 0:
            is_malicious = True
        elif suspicious_content_score > 0.85 and task_relevance < 30 and authorization == 0:
            is_malicious = True
        elif role == "ResearchAgent" and tool in ["external_upload"] and resource_type == "credentials":
            is_malicious = True

        is_suspicious = False
        if not is_malicious:
            if authorization == 0:
                is_suspicious = True
            elif task_relevance < 40 and data_sensitivity > 40:
                is_suspicious = True
            elif destination_trust < 50 and destination != "none":
                is_suspicious = True
            elif action_frequency > 35 or sequence_length > 15:
                is_suspicious = True
            elif historical_anomaly == 1 and previous_risk > 60:
                is_suspicious = True
            elif suspicious_content_score > 0.60:
                is_suspicious = True
            elif resource_type in ["credentials", "customer_pii"] and task_relevance < 60:
                is_suspicious = True

        label = 2 if is_malicious else (1 if is_suspicious else 0)

        # 2 % random noise
        if random.random() < 0.02:
            label = random.choice([0, 1, 2])

        records.append({
            "agent_role": role,
            "tool": tool,
            "operation": operation,
            "permission_level": permission_level,
            "task_relevance": task_relevance,
            "data_sensitivity": data_sensitivity,
            "external_destination": destination,
            "destination_trust": destination_trust,
            "action_frequency": action_frequency,
            "previous_risk": previous_risk,
            "sequence_length": sequence_length,
            "privilege_level": privilege_level,
            "resource_type": resource_type,
            "time_of_day": time_of_day,
            "suspicious_content_score": suspicious_content_score,
            "authorization": authorization,
            "historical_anomaly": historical_anomaly,
            "agent_age": agent_age,
            "label": label,
        })

    df = pd.DataFrame(records)
    if save_path:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(save_path, index=False)
        print(f"Dataset saved: {save_path}  ({len(df)} records)")
        print(df["label"].value_counts().rename({0: "SAFE", 1: "SUSPICIOUS", 2: "MALICIOUS"}))
    return df


if __name__ == "__main__":
    from pathlib import Path
    generate_dataset(4000, Path("data/synthetic_actions.csv"))
