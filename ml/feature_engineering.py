from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline

CATEGORICAL_FEATURES = [
    "agent_role",
    "tool",
    "operation",
    "external_destination",
    "resource_type"
]

NUMERICAL_FEATURES = [
    "permission_level",
    "task_relevance",
    "data_sensitivity",
    "destination_trust",
    "action_frequency",
    "previous_risk",
    "sequence_length",
    "privilege_level",
    "time_of_day",
    "suspicious_content_score",
    "authorization",
    "historical_anomaly",
    "agent_age"
]

ALL_FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERICAL_FEATURES


def get_preprocessor():
    categorical_transformer = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    numerical_transformer = StandardScaler()

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
            ("num", numerical_transformer, NUMERICAL_FEATURES),
        ]
    )
    return preprocessor
