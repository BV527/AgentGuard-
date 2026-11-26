"""
ResearchAgent specialization.
"""

from agents.base_agent import BaseAgent


class ResearchAgent(BaseAgent):
    def __init__(self, agent_id: str = "research_01", current_task: str = "Research EV battery technology and create a report"):
        super().__init__(
            agent_id=agent_id,
            name="ResearchAgent",
            role="ResearchAgent",
            permissions=["search_web", "read_article", "extract_information", "generate_report", "read_file", "write_file"],
            current_task=current_task
        )
