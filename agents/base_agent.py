"""
Base Agent class for AgentGuard simulation.
All agent action requests MUST pass through AgentGuard interceptor.
"""

from guard.interceptor import intercept_action


class BaseAgent:
    def __init__(self, agent_id: str, name: str, role: str, permissions: list, current_task: str):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.permissions = permissions
        self.current_task = current_task
        self.status = "ACTIVE"

    def request_action(
        self,
        action_name: str,
        resource: str,
        destination: str = "none",
        data_sensitivity: float = 0.0,
        payload: dict = None
    ) -> dict:
        """
        NEVER execute tools directly. Intercept action via AgentGuard.
        """
        response = intercept_action(
            agent_id=self.agent_id,
            action_name=action_name,
            resource=resource,
            task=self.current_task,
            destination=destination,
            data_sensitivity=data_sensitivity,
            payload=payload
        )
        return response
