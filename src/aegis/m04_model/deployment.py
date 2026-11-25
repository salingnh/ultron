"""M04 deployment configuration: which provider a live deployment calls, and how (G1.6).

`contracts/interfaces/README.md` §5 keeps endpoint, base URL, credentials, prices and limits in
deployment configuration; this module is that configuration for the one provider a live agent
session uses, read from the environment (or a `.env` file `make run-local` sources):

    AEGIS_SESSION_LIVE_MODEL=1                explicit selection of the live client (G1.6)
    AEGIS_MODEL_PROVIDER                      openai | anthropic
    AEGIS_MODEL_NAME                          model id sent on the wire
    AEGIS_MODEL_BASE_URL                      optional; defaults to the provider's official endpoint
    AEGIS_MODEL_API_KEY                       the credential
    AEGIS_MODEL_PRICE_INPUT_PER_MTOK          USD per million input tokens (required)
    AEGIS_MODEL_PRICE_OUTPUT_PER_MTOK         USD per million output tokens (required)
    AEGIS_MODEL_TIMEOUT_SECONDS               optional; per-call ceiling
    AEGIS_MODEL_MAX_OUTPUT_TOKENS             optional; per-call answer ceiling
    AEGIS_MODEL_GATEWAY                       optional; 1 says the base URL is the LLM gateway

Both standards the owner supports are ordinary driver dialects here: OpenAI Chat Completions
(any OpenAI-compatible base URL, e.g. a self-hosted gateway) and Anthropic Messages. The selection
is explicit: `AEGIS_SESSION_LIVE_MODEL` unset/`0` means the scripted G1 policy, `1` means a live
client, and any other value is a configuration error - never a silent fallback in either direction
(`aegis.m03_agent.activities.build_model` is the single switch).

The gateway (G1.6, `deploy/llm-gateway`) is the one place that rotates upstreams when one runs out
of quota, so `AEGIS_MODEL_GATEWAY=1` means: the base URL is required (never a provider default), the
cost the gateway reports per request is authoritative, and an in-app fallback chain is refused
rather than run in parallel with the gateway's rotation.

Why the prices are required (leader decision 2026-11-25): `aegis.model_usage.cost_usd` and the
campaign budget are only honest with a real price, so a missing price stops start-up instead of
recording a fake `0`. Behind a gateway the configured price is the fallback for an answer the
gateway did not price; it is never a guess, because the same variables must be readable. The
credential is never logged and never returned by `describe()`; a provider error body is passed
through `ModelDeployment.redacted` before it can reach a log or a `model_usage` row.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.m04_model.client import ModelClient
from aegis.m04_model.config import ModelConfig
from aegis.m04_model.transport import HttpTransport, PostJson, Price
from aegis.m04_model.usage import UsageSink

__all__ = [
    "API_KEY_ENV",
    "BASE_URL_ENV",
    "DEFAULT_BASE_URLS",
    "GATEWAY_ENV",
    "INPUT_PRICE_ENV",
    "LIVE_MODEL_ENV",
    "MAX_OUTPUT_TOKENS_ENV",
    "MODEL_NAME_ENV",
    "OUTPUT_PRICE_ENV",
    "PROVIDER_ENV",
    "TIMEOUT_SECONDS_ENV",
    "ModelDeployment",
    "ModelDeploymentError",
    "gateway_enabled",
    "gateway_endpoint",
    "live_model_enabled",
    "model_status",
    "redact",
]

LIVE_MODEL_ENV = "AEGIS_SESSION_LIVE_MODEL"
PROVIDER_ENV = "AEGIS_MODEL_PROVIDER"
MODEL_NAME_ENV = "AEGIS_MODEL_NAME"
BASE_URL_ENV = "AEGIS_MODEL_BASE_URL"
API_KEY_ENV = "AEGIS_MODEL_API_KEY"
INPUT_PRICE_ENV = "AEGIS_MODEL_PRICE_INPUT_PER_MTOK"
OUTPUT_PRICE_ENV = "AEGIS_MODEL_PRICE_OUTPUT_PER_MTOK"
TIMEOUT_SECONDS_ENV = "AEGIS_MODEL_TIMEOUT_SECONDS"
MAX_OUTPUT_TOKENS_ENV = "AEGIS_MODEL_MAX_OUTPUT_TOKENS"
#: 1 says the base URL is the owner's LLM gateway (`deploy/llm-gateway`), not a provider.
GATEWAY_ENV = "AEGIS_MODEL_GATEWAY"

#: Official endpoints: OpenAI includes its `/v1`, Anthropic's base is the origin.
DEFAULT_BASE_URLS: dict[Provider, str] = {
    Provider.openai: "https://api.openai.com/v1",
    Provider.anthropic: "https://api.anthropic.com",
}

#: What `HttpTransport` posts to, appended to the configured base URL.
OPENAI_CHAT_PATH = "/chat/completions"
ANTHROPIC_MESSAGES_PATH = "/messages"

DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_OUTPUT_TOKENS = 2048
MAX_TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_TOKENS = 200_000
#: Values `AEGIS_SESSION_LIVE_MODEL` accepts on either side; anything else is a configuration error.
_LIVE_WORDS = frozenset({"1", "true", "yes", "on"})
_SCRIPTED_WORDS = frozenset({"", "0", "false", "no", "off"})
#: Placeholder the scripted policy labels itself with; a live deployment must name a real model.
SCRIPTED_MODEL = "scripted-lab"


class ModelDeploymentError(RuntimeError):
    """The live-model configuration is missing, malformed or contradictory (fail loudly)."""


def redact(text: str, secret: str) -> str:
    """Mask one secret in `text`; the empty secret is a no-op (nothing to mask)."""
    return text if not secret else text.replace(secret, "***")


def live_model_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Read `AEGIS_SESSION_LIVE_MODEL` strictly: an unrecognised value is an error, not "off"."""
    source = os.environ if environ is None else environ
    raw = str(source.get(LIVE_MODEL_ENV) or "").strip().lower()
    if raw in _LIVE_WORDS:
        return True
    if raw in _SCRIPTED_WORDS:
        return False
    raise ModelDeploymentError(
        f"{LIVE_MODEL_ENV} must be 1 (live provider) or 0/unset (scripted policy), "
        f"got {raw!r}: the model mode is selected explicitly, never guessed"
    )


def gateway_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Read `AEGIS_MODEL_GATEWAY` strictly: the same no-third-state rule as the live flag."""
    source = os.environ if environ is None else environ
    raw = str(source.get(GATEWAY_ENV) or "").strip().lower()
    if raw in _LIVE_WORDS:
        return True
    if raw in _SCRIPTED_WORDS:
        return False
    raise ModelDeploymentError(
        f"{GATEWAY_ENV} must be 1 (the base URL is the LLM gateway) or 0/unset, got {raw!r}"
    )


def _text(source: Mapping[str, str], name: str) -> str:
    return str(source.get(name) or "").strip()


def _required_text(source: Mapping[str, str], name: str, purpose: str) -> str:
    value = _text(source, name)
    if not value:
        raise ModelDeploymentError(f"{name} is not set: {purpose}")
    return value


def _number(
    source: Mapping[str, str],
    name: str,
    *,
    default: float | None,
    minimum: float,
    maximum: float | None = None,
    purpose: str,
) -> float:
    raw = _text(source, name)
    if not raw:
        if default is None:
            raise ModelDeploymentError(f"{name} is not set: {purpose}")
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ModelDeploymentError(f"{name} must be a number, got {raw!r}") from None
    if not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
        bound = f">= {minimum}" if maximum is None else f"{minimum}..{maximum}"
        raise ModelDeploymentError(f"{name} must be {bound}, got {raw!r}: {purpose}")
    return value


def _endpoint(provider: Provider, base_url: str) -> str:
    """The POST target of a base URL, tolerant of the two conventions an operator may paste.

    OpenAI-compatible base URLs conventionally include `/v1` (`https://api.openai.com/v1`, or a
    self-hosted `http://127.0.0.1:1234/v1`), while Anthropic documents the bare origin. A full
    endpoint pasted by mistake is accepted unchanged instead of being doubled.
    """
    base = base_url.rstrip("/")
    if provider is Provider.openai:
        return base if base.endswith(OPENAI_CHAT_PATH) else base + OPENAI_CHAT_PATH
    if base.endswith(ANTHROPIC_MESSAGES_PATH):
        return base
    if base.endswith("/v1"):
        return base + ANTHROPIC_MESSAGES_PATH
    return base + "/v1" + ANTHROPIC_MESSAGES_PATH


def gateway_endpoint(provider: Provider, base_url: str) -> str:
    """The POST target behind the gateway: one base URL (`http://host:4000`, `.../v1` or a full
    endpoint) serves both standards, because the gateway exposes both `/v1/chat/completions` and
    `/v1/messages` under the same credential.
    """
    base = base_url.rstrip("/")
    path = OPENAI_CHAT_PATH if provider is Provider.openai else ANTHROPIC_MESSAGES_PATH
    if base.endswith(path):
        return base
    if not base.endswith("/v1"):
        base = base + "/v1"
    return base + path


@dataclass(frozen=True, slots=True)
class ModelDeployment:
    """One provider, one model, one credential and the real prices of that model.

    `api_key` is excluded from `repr()` and from `describe()`, so an accidental log line or an
    error trace cannot carry it; `redacted()` masks it in provider text before that text is kept.
    """

    provider: Provider
    model: str
    api_key: str = field(repr=False)
    base_url: str
    input_usd_per_million: float
    output_usd_per_million: float
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    #: The base URL is the owner's LLM gateway: its reported cost wins and rotation lives there.
    gateway: bool = False

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ModelDeploymentError(f"{MODEL_NAME_ENV} must name the model to call")
        if not self.api_key.strip():
            raise ModelDeploymentError(f"{API_KEY_ENV} is empty")
        if not 0 < self.input_usd_per_million < math.inf:
            raise ModelDeploymentError(f"{INPUT_PRICE_ENV} must be a positive price")
        if not 0 < self.output_usd_per_million < math.inf:
            raise ModelDeploymentError(f"{OUTPUT_PRICE_ENV} must be a positive price")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ModelDeploymentError(
                f"{BASE_URL_ENV} must be an http(s) URL, got {self.base_url!r}"
            )
        if not 0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ModelDeploymentError(
                f"{TIMEOUT_SECONDS_ENV} must be > 0 and <= {MAX_TIMEOUT_SECONDS}"
            )
        if not 1 <= self.max_output_tokens <= MAX_OUTPUT_TOKENS:
            raise ModelDeploymentError(f"{MAX_OUTPUT_TOKENS_ENV} must be 1..{MAX_OUTPUT_TOKENS}")

    @property
    def endpoint(self) -> str:
        """The exact URL `HttpTransport` posts to (never includes the key)."""
        if self.gateway:
            return gateway_endpoint(self.provider, self.base_url)
        return _endpoint(self.provider, self.base_url)

    @property
    def price(self) -> Price:
        return Price(
            input_usd_per_million=self.input_usd_per_million,
            output_usd_per_million=self.output_usd_per_million,
        )

    def redacted(self, text: str) -> str:
        """`text` with the credential masked; provider error bodies pass through here."""
        return redact(text, self.api_key)

    def transport(self, *, post: PostJson | None = None) -> HttpTransport:
        return HttpTransport(
            endpoints={self.provider: self.endpoint},
            api_keys={self.provider: self.api_key},
            pricing={(self.provider, self.model): self.price},
            redact=self.redacted,
            post=post,
            read_response_cost=self.gateway,
        )

    def client(
        self,
        usage: UsageSink,
        *,
        post: PostJson | None = None,
        config: ModelConfig | None = None,
    ) -> ModelClient:
        """The live M04 client over this deployment, with no attempt chain of its own.

        A gateway already rotates upstreams when one runs out of quota; a fallback chain here would
        rotate a second time, on a different axis, and double the spend on every exhausted call. So
        a gateway deployment refuses one, and the default chain (no fallback) is what runs.
        """
        chain = config or ModelConfig()
        if self.gateway and chain.allow_fallback:
            raise ModelDeploymentError(
                f"{GATEWAY_ENV}=1: the gateway owns rotation; remove the in-app fallback chain "
                "from the live model client"
            )
        return ModelClient(self.transport(post=post), usage, chain)

    def describe(self) -> dict[str, Any]:
        """What a log line or `/healthz` may say: everything except the credential."""
        described: dict[str, Any] = {
            "provider": self.provider.value,
            "model": self.model,
            "endpoint": self.endpoint,
            "price_input_usd_per_mtok": self.input_usd_per_million,
            "price_output_usd_per_mtok": self.output_usd_per_million,
            "timeout_seconds": self.timeout_seconds,
            "max_output_tokens": self.max_output_tokens,
        }
        if self.gateway:
            described["gateway"] = True
            described["cost_source"] = "gateway-reported, else the configured price"
        return described

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ModelDeployment:
        """Read and validate the live deployment; an error names the variable, never the value."""
        source = os.environ if environ is None else environ
        provider_raw = _required_text(
            source, PROVIDER_ENV, "the live model needs a provider (openai or anthropic)"
        ).lower()
        try:
            provider = Provider(provider_raw)
        except ValueError:
            raise ModelDeploymentError(
                f"{PROVIDER_ENV} must be openai or anthropic, got {provider_raw!r}"
            ) from None
        model = _required_text(source, MODEL_NAME_ENV, "the live model needs the model id it calls")
        api_key = _required_text(source, API_KEY_ENV, "the live model needs a provider credential")
        gateway = gateway_enabled(source)
        input_price = _number(
            source,
            INPUT_PRICE_ENV,
            default=None,
            minimum=0.0,
            purpose="the campaign budget is only honest with a real price",
        )
        output_price = _number(
            source,
            OUTPUT_PRICE_ENV,
            default=None,
            minimum=0.0,
            purpose="the campaign budget is only honest with a real price",
        )
        if input_price <= 0 or output_price <= 0:
            raise ModelDeploymentError(
                f"{INPUT_PRICE_ENV} and {OUTPUT_PRICE_ENV} must be > 0: a zero price would record "
                "a cost the campaign did not spend"
            )
        base_url = _text(source, BASE_URL_ENV)
        if gateway:
            base_url = _required_text(
                source,
                BASE_URL_ENV,
                f"{GATEWAY_ENV}=1 names the gateway, so its URL is required "
                "(e.g. http://127.0.0.1:4000/v1)",
            )
        elif not base_url:
            base_url = DEFAULT_BASE_URLS[provider]
        timeout = _number(
            source,
            TIMEOUT_SECONDS_ENV,
            default=DEFAULT_TIMEOUT_SECONDS,
            minimum=0.0,
            maximum=MAX_TIMEOUT_SECONDS,
            purpose="one provider call has to be bounded",
        )
        max_tokens_raw = _text(source, MAX_OUTPUT_TOKENS_ENV)
        try:
            max_tokens = int(max_tokens_raw) if max_tokens_raw else DEFAULT_MAX_OUTPUT_TOKENS
        except ValueError:
            raise ModelDeploymentError(
                f"{MAX_OUTPUT_TOKENS_ENV} must be an integer, got {max_tokens_raw!r}"
            ) from None
        return cls(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            input_usd_per_million=input_price,
            output_usd_per_million=output_price,
            timeout_seconds=timeout,
            max_output_tokens=max_tokens,
            gateway=gateway,
        )


def model_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Which model mode this deployment's environment selects, for `/healthz`.

    It reports configuration, not a probe: the API process reads the same environment the workers
    inherit (`make run-local` exports one set). A malformed selection is reported as `invalid`
    rather than raised, so a health probe still answers while the worker refuses to start.
    """
    source = os.environ if environ is None else environ
    try:
        live = live_model_enabled(source)
    except ModelDeploymentError as error:
        return {"mode": "invalid", "detail": str(error)}
    if not live:
        return {
            "mode": "scripted",
            "provider": _text(source, PROVIDER_ENV) or Provider.openai.value,
            "model": _text(source, MODEL_NAME_ENV) or SCRIPTED_MODEL,
            "selection": f"{LIVE_MODEL_ENV}=0",
        }
    status: dict[str, Any] = {
        "mode": "live",
        "provider": _text(source, PROVIDER_ENV),
        "model": _text(source, MODEL_NAME_ENV),
        "selection": f"{LIVE_MODEL_ENV}=1",
        "api_key": "set" if _text(source, API_KEY_ENV) else "missing",
    }
    try:
        deployment = ModelDeployment.from_env(source)
    except ModelDeploymentError as error:
        status.update({"valid": False, "detail": str(error)})
        return status
    status.update(deployment.describe())
    status["valid"] = True
    return status
