"""Configuration management for secAgent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


@dataclass
class AgentConfig:
    """Global configuration for secAgent."""

    # Anthropic settings
    api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    model: str = field(
        default_factory=lambda: os.environ.get("SECAGENT_MODEL", "claude-opus-4-5-20250929")
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.environ.get("SECAGENT_MAX_TOKENS", "8192"))
    )
    max_iterations: int = field(
        default_factory=lambda: int(os.environ.get("SECAGENT_MAX_ITERATIONS", "50"))
    )

    # Optional OpenAI-compatible endpoint
    openai_compat_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("OPENAI_COMPAT_API_KEY")
    )
    openai_compat_base_url: Optional[str] = field(
        default_factory=lambda: os.environ.get("OPENAI_COMPAT_BASE_URL")
    )
    openai_compat_model: Optional[str] = field(
        default_factory=lambda: os.environ.get("OPENAI_COMPAT_MODEL")
    )

    # Logging
    log_level: str = field(
        default_factory=lambda: os.environ.get("SECAGENT_LOG_LEVEL", "INFO")
    )

    def validate(self) -> None:
        """Validate required configuration values."""
        if not self.openai_compat_api_key and not self.api_key:
            raise ValueError(
                "Either ANTHROPIC_API_KEY or OPENAI_COMPAT_API_KEY must be set."
            )

    def get_effective_model(self) -> str:
        """Return the model to use, preferring compat model if set."""
        return self.openai_compat_model or self.model
