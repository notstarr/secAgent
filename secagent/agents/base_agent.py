"""Base security agent class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from secagent.core.agent_runner import AgentRunner
from secagent.core.config import AgentConfig


class BaseSecAgent(ABC):
    """
    Abstract base class for all secAgent agents.

    Subclasses define their own system prompt, tools, and `build_task`
    method that translates high-level parameters into a user message.
    """

    SYSTEM_PROMPT: str = "You are a professional security testing assistant."

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        self.config = config or AgentConfig()
        self.runner = AgentRunner(
            config=self.config,
            system_prompt=self.SYSTEM_PROMPT,
            tools=self._register_tools(),
        )

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    @abstractmethod
    def _register_tools(self) -> list[Any]:
        """Return the list of tool callables this agent exposes."""
        ...

    @abstractmethod
    def build_task(self, **kwargs: Any) -> str:
        """Construct a user-task string from high-level parameters."""
        ...

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, verbose: bool = True, **kwargs: Any) -> str:
        """Build and execute the task."""
        task = self.build_task(**kwargs)
        return self.runner.run(task, verbose=verbose)
