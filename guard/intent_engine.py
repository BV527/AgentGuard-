"""
Task / Intent Alignment Engine for AgentGuard.
Uses TF-IDF + Cosine Similarity to evaluate semantic relevance between User Task and requested Action/Resource.
"""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def compute_task_relevance(user_task: str, action_name: str, resource: str) -> float:
    if not user_task or user_task.strip() == "":
        return 100.0 # Default fallback if no task defined

    task_doc = user_task.lower()
    action_doc = f"{action_name} {resource}".replace("_", " ").lower()

    # Expand domain context for known actions to improve TF-IDF matching
    action_expansions = {
        "search_web": "research find information article search web google internet battery EV analysis",
        "read_article": "read article paper report documentation summary EV battery",
        "extract_information": "extract text data findings summary report",
        "generate_report": "write document report summary findings markdown pdf",
        "read_project": "read code source repository file project structure",
        "edit_code": "write code refactor bugfix python javascript feature",
        "run_tests": "unit test pytest jest test execution verification",
        "git_commit": "git commit push branch repository code change",
        "read_financial_data": "finance revenue earnings ledger statement report quarterly",
        "database_query": "sql query select table database records finance analytics"
    }

    if action_name in action_expansions:
        action_doc += " " + action_expansions[action_name]

    try:
        vectorizer = TfidfVectorizer().fit([task_doc, action_doc])
        vecs = vectorizer.transform([task_doc, action_doc])
        sim = cosine_similarity(vecs[0:1], vecs[1:2])[0][0]
        relevance_score = float(sim * 100.0)

        # Apply domain alignment bonus for obviously matching role tasks
        keywords = task_doc.split()
        matches = sum(1 for kw in keywords if len(kw) > 3 and kw in action_doc)
        if matches > 0:
            relevance_score = min(100.0, relevance_score + (matches * 15.0))

        # Clamp between 0.0 and 100.0
        return round(max(5.0, min(100.0, relevance_score)), 1)
    except Exception:
        return 50.0
