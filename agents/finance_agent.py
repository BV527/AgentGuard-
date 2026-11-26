"""
FinanceAgent specialization.
"""

from agents.base_agent import BaseAgent


class FinanceAgent(BaseAgent):
    def __init__(self, agent_id: str = "finance_01", current_task: str = "Analyze Q3 revenue trends and prepare financial summary"):
        super().__init__(
            agent_id=agent_id,
            name="FinanceAgent",
            role="FinanceAgent",
            permissions=["read_financial_data", "database_query", "generate_report"],
            current_task=current_task
        )
