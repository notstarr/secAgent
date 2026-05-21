"""secAgent - Security Testing Agent Framework built on Claude Agent SDK."""

from secagent.core.config import AgentConfig
from secagent.core.agent_runner import AgentRunner
from secagent.agents.base_agent import BaseSecAgent
from secagent.agents.sigma_agent import SigmaAgent

__all__ = ["AgentConfig", "AgentRunner", "BaseSecAgent", "SigmaAgent"]
__version__ = "0.1.0"
