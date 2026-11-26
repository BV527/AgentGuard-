"""
CodingAgent specialization.
"""

from agents.base_agent import BaseAgent


class CodingAgent(BaseAgent):
    def __init__(self, agent_id: str = "coding_01", current_task: str = "Refactor auth middleware and update unit tests"):
        super().__init__(
            agent_id=agent_id,
            name="CodingAgent",
            role="CodingAgent",
            permissions=["read_project", "edit_code", "run_tests", "git_commit", "read_file", "write_file"],
            current_task=current_task
        )
