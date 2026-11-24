"""M03 session configuration: the knobs one `run_agent_session` call needs, from the environment.

Nothing here is a contract shape: contract values (ContextBundle, AgentSessionResult, ModelRequest)
are the generated DTOs. The defaults are the design values of 02-nen-tang §Phiên agent (a session
has at most 30 steps and a bounded context) plus the deployment knobs the composition root reads:

    AEGIS_PG_DSN          control-plane PostgreSQL (default of the M02 worker / M03 activity)
    AEGIS_MCP_URL         the M05 MCP endpoint (Streamable HTTP), e.g. http://127.0.0.1:8105/mcp
    AEGIS_MODEL_PROVIDER  openai | anthropic - the provider a live ModelClient would use
    AEGIS_MODEL_NAME      model id for a live client; ignored by the scripted G1 policy
    AEGIS_SESSION_LIVE_MODEL=1  use the live M04 ModelClient instead of the scripted G1 policy
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "DSN_ENV",
    "LIVE_MODEL_ENV",
    "MAX_STEPS",
    "MCP_URL_ENV",
    "MODEL_NAME_ENV",
    "MODEL_PROVIDER_ENV",
    "SessionConfig",
    "SessionConfigError",
]

DSN_ENV = "AEGIS_PG_DSN"
MCP_URL_ENV = "AEGIS_MCP_URL"
MODEL_PROVIDER_ENV = "AEGIS_MODEL_PROVIDER"
MODEL_NAME_ENV = "AEGIS_MODEL_NAME"
LIVE_MODEL_ENV = "AEGIS_SESSION_LIVE_MODEL"

#: 02-nen-tang §Phiên agent: "tối đa 30 bước cho một phiên", the same ceiling
#: `agent_session.steps_used` (0001) checks in the database.
MAX_STEPS = 30
PROVIDERS = ("openai", "anthropic")


class SessionConfigError(RuntimeError):
    """The deployment configuration is missing or contradictory (fail loudly, never guess)."""


@dataclass(frozen=True, slots=True)
class SessionConfig:
    """What a session may do, independent of the campaign policy (which comes in the bundle)."""

    provider: str = "openai"
    model: str = "scripted-lab"
    #: Ceiling for one plan call; the campaign budget decides whether the call may happen at all.
    max_output_tokens: int = 2048
    timeout_seconds: float = 120.0
    #: Spec ceiling; a smaller ContextBundle budget.max_steps wins.
    max_steps: int = MAX_STEPS
    #: Messages kept in the prompt (the current round plus recent history, never the campaign).
    max_history_messages: int = 24
    #: Consecutive in-session rounds without a new job or new tool data before the session idles.
    in_session_idle_rounds: int = 2
    #: Activity heartbeat interval while a model or MCP call is in flight (G1.1d timeout: 3 s).
    heartbeat_seconds: float = 1.0
    #: True only when the deployment has a real provider + prices (OD-2); the G1 default is the
    #: scripted policy, so no provider call can happen by accident.
    live_model: bool = False

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise SessionConfigError(f"provider must be one of {PROVIDERS}, got {self.provider!r}")
        if not 1 <= self.max_steps <= MAX_STEPS:
            raise SessionConfigError(f"max_steps must be 1..{MAX_STEPS}, got {self.max_steps}")
        if self.max_history_messages < 2:
            raise SessionConfigError("max_history_messages must keep at least the system message")
        if self.in_session_idle_rounds < 1:
            raise SessionConfigError("in_session_idle_rounds must be >= 1")
        if self.max_output_tokens < 1:
            raise SessionConfigError("max_output_tokens must be positive")
        if self.heartbeat_seconds <= 0:
            raise SessionConfigError("heartbeat_seconds must be positive")

    @classmethod
    def from_env(cls) -> SessionConfig:
        """Read the process configuration; the DSN and MCP URL are validated by the caller."""
        provider = os.environ.get(MODEL_PROVIDER_ENV) or "openai"
        live = os.environ.get(LIVE_MODEL_ENV) == "1"
        return cls(
            provider=provider,
            model=os.environ.get(MODEL_NAME_ENV) or "scripted-lab",
            live_model=live,
        )


def mcp_url_from_env() -> str:
    url = os.environ.get(MCP_URL_ENV)
    if not url:
        raise SessionConfigError(
            f"{MCP_URL_ENV} is not set: the agent session may only start jobs through the M05 "
            "MCP boundary, so it has to know where that boundary is"
        )
    return url


def dsn_from_env() -> str:
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        raise SessionConfigError(
            f"{DSN_ENV} is not set: M03 needs the control-plane PostgreSQL DSN"
        )
    return dsn
