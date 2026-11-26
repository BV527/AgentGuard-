"""
ReportAgent specialization.
Compiles analysis into final structured research report documents.
"""

from agents.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    def __init__(self, agent_id: str = "report_01", current_task: str = "Compile analysis into final markdown report"):
        super().__init__(
            agent_id=agent_id,
            name="ReportAgent",
            role="ReportAgent",
            permissions=["compile_report", "format_markdown", "generate_pdf", "write_file", "export_report"],
            current_task=current_task
        )
