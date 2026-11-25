"""M03 session configuration: the knobs one `run_agent_session` call needs, from the environment.

Nothing here is a contract shape: contract values (ContextBundle, AgentSessionResult, ModelRequest)
are the generated DTOs. The defaults are the design values of 02-nen-tang §Phiên agent (a session
has at most 30 steps and a bounded context) plus the deployment knobs the composition root reads:

    AEGIS_PG_DSN          control-plane PostgreSQL (default of the M02 worker / M03 activity)
    AEGIS_MCP_URL         the M05 MCP endpoint (Streamable HTTP), e.g. http://127.0.0.1:8105/mcp
    AEGIS_MODEL_PROVIDER  openai | anthropic - the provider the session's plan calls use
    AEGIS_MODEL_NAME      model id for a live client; ignored by the scripted G1 policy
    AEGIS_SESSION_LIVE_MODEL=1  use the live M04 ModelClient instead of the scripted G1 policy

The live model's own settings (base URL, key, prices, timeout, output ceiling) are M04's
`aegis.m04_model.deployment`; in live mode this module takes provider/model/timeout/output ceiling
from that one validated reader, so a worker that cannot call its provider fails at start-up.
`AEGIS_SESSION_LIVE_MODEL` is parsed strictly: unset/`0` is the scripted policy, `1` is live, and
any other value is an error rather than a silent fallback (`build_model` is the single switch).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from aegis.m04_model import deployment

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
MODEL_PROVIDER_ENV = deployment.PROVIDER_ENV
MODEL_NAME_ENV = deployment.MODEL_NAME_ENV
LIVE_MODEL_ENV = deployment.LIVE_MODEL_ENV

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
    model: str = deployment.SCRIPTED_MODEL
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
    #: True only when the deployment has a real provider + prices (G1.6); the default is the
    #: scripted policy, so no provider call can happen by accident.
    live_model: bool = False

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise SessionConfigError(f"provider must be one of {PROVIDERS}, got {self.provider!r}")
        if self.live_model and not self.model.strip():
            raise SessionConfigError(f"a live model needs {MODEL_NAME_ENV}")
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
    def from_env(cls, environ: Mapping[str, str] | None = None) -> SessionConfig:
        """Read the process configuration; the DSN and MCP URL are validated by the caller."""
        source = os.environ if environ is None else environ
        try:
            live = deployment.live_model_enabled(source)
        except deployment.ModelDeploymentError as error:
            raise SessionConfigError(str(error)) from error
        if not live:
            return cls(
                provider=str(source.get(MODEL_PROVIDER_ENV) or "openai"),
                model=str(source.get(MODEL_NAME_ENV) or deployment.SCRIPTED_MODEL),
            )
        # The live deployment is validated here, at start-up: a missing key or price must stop the
        # worker, not turn every session into a provider error.
        live_deployment = deployment.ModelDeployment.from_env(source)
        return cls(
            provider=live_deployment.provider.value,
            model=live_deployment.model,
            max_output_tokens=live_deployment.max_output_tokens,
            timeout_seconds=live_deployment.timeout_seconds,
            live_model=True,
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
