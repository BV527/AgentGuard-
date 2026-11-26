"""
AnalysisAgent specialization.
Performs synthesis and data comparison of research findings.
"""

from agents.base_agent import BaseAgent


class AnalysisAgent(BaseAgent):
    def __init__(self, agent_id: str = "analysis_01", current_task: str = "Analyze findings and compare battery metrics"):
        super().__init__(
            agent_id=agent_id,
            name="AnalysisAgent",
            role="AnalysisAgent",
            permissions=["analyze_data", "compare_metrics", "process_findings", "read_file", "write_file"],
            current_task=current_task
        )
