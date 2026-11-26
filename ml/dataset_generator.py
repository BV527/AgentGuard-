import random
import pandas as pd
import numpy as np
from pathlib import Path
from backend.config import DATASET_PATH

ROLES = ["ResearchAgent", "CodingAgent", "FinanceAgent"]

TOOLS_BY_ROLE = {
    "ResearchAgent": ["search_web", "read_article", "extract_information", "generate_report", "read_file", "write_file", "database_query", "external_upload"],
    "CodingAgent": ["read_project", "edit_code", "run_tests", "git_commit", "read_file", "delete_file", "read_credentials", "external_upload"],
    "FinanceAgent": ["read_financial_data", "database_query", "generate_report", "export_customer_data", "external_upload", "delete_file", "read_credentials"]
}

OPERATIONS = ["read", "write", "execute", "delete", "query", "upload", "export", "connect"]
DESTINATIONS = ["none", "internal_api", "github.com", "trusted_cloud.s3", "unknown_ip_89.2.1.4", "temp_file_host.net", "darknet_node"]
RESOURCE_TYPES = ["public_doc", "code_file", "config_file", "database_table", "financial_record", "credentials", "customer_pii", "system_binary"]


def generate_synthetic_dataset(num_samples: int = 12000, save_path: Path = DATASET_PATH) -> pd.DataFrame:
    random.seed(42)
    np.random.seed(42)

    records = []
    for i in range(num_samples):
        role = random.choice(ROLES)
        agent_id = f"{role.lower()}_0{(i % 3) + 1}"
        tool = random.choice(TOOLS_BY_ROLE[role])
        operation = random.choice(OPERATIONS)
        resource_type = random.choice(RESOURCE_TYPES)
        
        # Base attributes
        authorization = random.choices([1, 0], weights=[0.75, 0.25])[0]
        permission_level = random.choice([1, 2, 3, 4, 5]) # 1=Public, 5=Admin/Root
        privilege_level = random.choice([1, 2, 3, 4, 5])
        
        # Numerical feature generation with realistic distribution
        task_relevance = round(random.uniform(10.0, 100.0), 1)
        data_sensitivity = round(random.uniform(0.0, 100.0), 1)
        suspicious_content_score = round(random.uniform(0.0, 1.0), 2)
        action_frequency = random.randint(1, 50) # actions per minute
        previous_risk = round(random.uniform(0.0, 100.0), 1)
        sequence_length = random.randint(1, 20)
        historical_anomaly = random.choices([0, 1], weights=[0.85, 0.15])[0]
        agent_age = random.randint(1, 365) # days active
        time_of_day = random.randint(0, 23)

        external_destination = random.choice(DESTINATIONS)
        if external_destination == "none":
            destination_trust = 100.0
        elif external_destination in ["internal_api", "trusted_cloud.s3", "github.com"]:
            destination_trust = round(random.uniform(75.0, 100.0), 1)
        else:
            destination_trust = round(random.uniform(0.0, 30.0), 1)

        # Logical rule-based label assignment to ensure realistic ML dataset
        # 0 = SAFE, 1 = SUSPICIOUS, 2 = MALICIOUS
        
        # Explicit Malicious conditions
        is_malicious = False
        if tool in ["read_credentials"] and authorization == 0:
            is_malicious = True
        elif resource_type in ["credentials", "customer_pii"] and authorization == 0:
            is_malicious = True
        elif external_destination in ["unknown_ip_89.2.1.4", "temp_file_host.net", "darknet_node"] and data_sensitivity > 50 and authorization == 0:
            is_malicious = True
        elif tool == "delete_file" and resource_type in ["config_file", "system_binary"] and privilege_level >= 4 and authorization == 0:
            is_malicious = True
        elif suspicious_content_score > 0.85 and task_relevance < 30.0 and authorization == 0:
            is_malicious = True
        elif role == "ResearchAgent" and tool in ["external_upload", "database_query"] and resource_type in ["credentials", "financial_record"]:
            is_malicious = True

        # Explicit Suspicious conditions
        is_suspicious = False
        if not is_malicious:
            if authorization == 0:
                is_suspicious = True
            elif task_relevance < 40.0 and data_sensitivity > 40.0:
                is_suspicious = True
            elif destination_trust < 50.0 and external_destination != "none":
                is_suspicious = True
            elif action_frequency > 35 or sequence_length > 15:
                is_suspicious = True
            elif historical_anomaly == 1 and previous_risk > 60.0:
                is_suspicious = True
            elif suspicious_content_score > 0.60:
                is_suspicious = True
            elif resource_type in ["credentials", "customer_pii"] and task_relevance < 60.0:
                is_suspicious = True

        if is_malicious:
            label = 2
        elif is_suspicious:
            label = 1
        else:
            label = 0

        # Inject minor realistic noise (2% noise)
        if random.random() < 0.02:
            label = random.choice([0, 1, 2])

        record = {
            "agent_id": agent_id,
            "agent_role": role,
            "tool": tool,
            "operation": operation,
            "permission_level": permission_level,
            "task_relevance": task_relevance,
            "data_sensitivity": data_sensitivity,
            "external_destination": external_destination,
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
            "label": label
        }
        records.append(record)

    df = pd.DataFrame(records)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(save_path, index=False)
    print(f"Dataset generated with {len(df)} samples saved to {save_path}")
    print("Class counts:")
    print(df['label'].value_counts())
    return df


if __name__ == "__main__":
    generate_synthetic_dataset()
