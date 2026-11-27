"""Transport boundary of M04: the only place a model provider is reached.

The drivers never open a socket; they build the provider wire body and normalize the JSON that a
transport returns. `HttpTransport` is the live implementation (endpoint, credential, price table
and timeout are deployment configuration per interfaces §5) and is never constructed by default:
G1 runs the first-class fake driver, and the composition root that would build this transport must
gate it on an explicit live flag. CI tests inject a recorded/scripted transport and send nothing.

Transport failures are normalized into `error.v2` codes; only a `TransportError` may become
`finish_reason=provider_error`. A missing price/key/endpoint is our own configuration bug and
raises instead, so it cannot be mistaken for a provider outage.

The boundary returns `HttpAnswer` (status, body and headers) because a self-hosted gateway prices
the call it routed: `x-litellm-response-cost` is the only per-request cost a LiteLLM gateway
reports, and M04 records it when `read_response_cost` is on (see `aegis.m04_model.deployment`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Protocol, runtime_checkable

from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.raw import usage_tokens

#: Bound one provider body in memory; a hostile or broken endpoint cannot exhaust the activity.
MAX_BODY_BYTES = 1_000_000

#: The per-request USD cost a LiteLLM proxy stamps on the answer it routed.
GATEWAY_COST_HEADER = "x-litellm-response-cost"
#: The distribution whose version the product user agent reports.
DISTRIBUTION = "aegis"

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HttpAnswer:
    """One HTTP answer of the provider boundary: status, body and the response headers."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """One successful provider HTTP answer, before normalization."""

    raw: dict[str, Any]
    latency_ms: int
    cost_usd: float


class TransportError(RuntimeError):
    """Provider call failed at the transport/HTTP layer; becomes `provider_error`."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after_seconds = retry_after_seconds


class PricingUnknown(RuntimeError):
    """The deployment price table has no entry for this provider/model: fix the configuration."""


class MissingEndpoint(RuntimeError):
    """The deployment configuration has no endpoint (or credential) for this provider."""


@runtime_checkable
class ProviderTransport(Protocol):
    """Sends one provider request body and returns the parsed answer plus measured usage."""

    async def send(
        self,
        provider: Provider,
        model: str,
        wire: Mapping[str, Any],
        *,
        timeout_seconds: float,
        headers: Mapping[str, str] | None = None,
    ) -> TransportResponse: ...


@dataclass(frozen=True, slots=True)
class Price:
    """USD per million tokens for one provider/model."""

    input_usd_per_million: float
    output_usd_per_million: float

    def cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        cost = (
            input_tokens * self.input_usd_per_million + output_tokens * self.output_usd_per_million
        ) / 1_000_000
        # aegis.model_usage.cost_usd is numeric(12,6).
        return round(cost, 6)


#: Injected HTTP boundary of `HttpTransport`: `(url, headers, body, timeout) -> HttpAnswer`.
PostJson = Callable[[str, dict[str, str], bytes, float], HttpAnswer]
#: Masks a deployment secret in text this module is about to raise or keep.
Redact = Callable[[str], str]


def _pass_through(text: str) -> str:
    return text


def _post_json(
    url: str, headers: dict[str, str], body: bytes, timeout_seconds: float
) -> HttpAnswer:
    """POST one JSON body with the standard library; an HTTP error is a status, not an exception."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return HttpAnswer(
                status=int(response.status),
                body=response.read(MAX_BODY_BYTES),
                headers=dict(response.headers.items()),
            )
    except urllib.error.HTTPError as error:
        with error:
            return HttpAnswer(
                status=int(error.code),
                body=error.read(MAX_BODY_BYTES),
                headers=dict(error.headers.items()),
            )


def product_agent() -> str:
    """`aegis-ultron/<version>`: the identity a provider (or the gateway log) sees."""
    try:
        version = metadata.version(DISTRIBUTION)
    except (
        metadata.PackageNotFoundError
    ):  # pragma: no cover - the package is installed in every gate
        version = "0"
    return f"aegis-ultron/{version}"


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """One header, matched case-insensitively (HTTP names are not case sensitive)."""
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _reported_cost(headers: Mapping[str, str]) -> float | None:
    """The USD cost a gateway stamped on the answer, or None when it did not report one."""
    raw = _header(headers, GATEWAY_COST_HEADER)
    if raw is None or not raw.strip():
        return None
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "gateway reported an unreadable %s=%r; recording the configured price instead",
            GATEWAY_COST_HEADER,
            raw,
        )
        return None
    if not value > 0:
        # A gateway that does not know the endpoint's price stamps 0 (or nothing). Never record
        # that as a real cost: the configured price is the fallback, and it is always > 0.
        logger.warning(
            "gateway reported %s=%s; recording the configured price instead",
            GATEWAY_COST_HEADER,
            raw,
        )
        return None
    return round(value, 6)


def _http_error_code(status: int) -> ErrorCode:
    if status in {429, 402}:
        # 402 Payment Required is how an upstream says "out of credits" (OpenCode, OpenRouter, a
        # spent provider balance): the same exhausted-quota class as 429, so it is recorded as
        # RATE_LIMITED and the campaign budget sees one kind of quota failure, not two.
        return ErrorCode.RATE_LIMITED
    if status in {408, 504}:
        return ErrorCode.NETWORK_TIMEOUT
    if status in {400, 409, 413, 422}:
        return ErrorCode.INPUT_INVALID
    # 401/403/404/5xx mean the endpoint, credential or provider is wrong, not the agent's input.
    return ErrorCode.INTERNAL_ERROR


def _http_error_message(status: int, payload: bytes) -> str:
    """A short operator-facing message; the provider body is data and never a credential."""
    detail = payload.decode("utf-8", errors="replace").strip()
    message = f"provider returned HTTP {status}"
    if detail:
        message = f"{message}: {detail[:500]}"
    return message


class HttpTransport:
    """Live provider HTTP transport with a deployment price table.

    Constructed only by a composition root behind an explicit live flag (leader decision: G1 runs
    the fake driver; live calls are opt-in). Credentials are passed in, never read from a file here;
    no key or body is logged by this module.
    """

    def __init__(
        self,
        *,
        endpoints: Mapping[Provider, str],
        api_keys: Mapping[Provider, str],
        pricing: Mapping[tuple[Provider, str], Price],
        anthropic_version: str = "2023-06-01",
        post: PostJson | None = None,
        redact: Redact | None = None,
        read_response_cost: bool = False,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._endpoints = dict(endpoints)
        self._api_keys = dict(api_keys)
        self._pricing = dict(pricing)
        self._anthropic_version = anthropic_version
        self._post = post or _post_json
        #: A gateway prices the call it routed, so its reported cost is authoritative; a direct
        #: provider call has no such header and is priced from the deployment's table.
        self._read_response_cost = read_response_cost
        #: Headers every call carries (the product user agent); the credential and content type are
        #: added per call and always win, so an injected header cannot replace them.
        self._extra_headers = dict(extra_headers or {})
        #: Provider text can echo anything it was sent; the deployment masks its credential here so
        #: a `TransportError.message` (which a usage row and a session summary may keep) cannot
        #: carry the key.
        self._redact = redact or _pass_through

    async def send(
        self,
        provider: Provider,
        model: str,
        wire: Mapping[str, Any],
        *,
        timeout_seconds: float,
        headers: Mapping[str, str] | None = None,
    ) -> TransportResponse:
        endpoint = self._endpoints.get(provider)
        if not endpoint:
            raise MissingEndpoint(f"no endpoint configured for provider {provider.value}")
        api_key = self._api_keys.get(provider)
        if not api_key:
            raise MissingEndpoint(f"no credential configured for provider {provider.value}")
        price = self._pricing.get((provider, model))
        if price is None:
            raise PricingUnknown(
                f"no price for {provider.value}/{model}; refusing to record an unknown cost"
            )

        request_headers = {**self._extra_headers, **(headers or {})}
        request_headers.update({"content-type": "application/json", "accept": "application/json"})
        if provider is Provider.openai:
            request_headers["authorization"] = f"Bearer {api_key}"
        else:
            request_headers["x-api-key"] = api_key
            request_headers["anthropic-version"] = self._anthropic_version
        body = json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        started = time.perf_counter()
        try:
            answer = await asyncio.to_thread(
                self._post, endpoint, request_headers, body, timeout_seconds
            )
        except TimeoutError as error:
            raise TransportError(ErrorCode.NETWORK_TIMEOUT, "provider request timed out") from error
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise TransportError(
                    ErrorCode.NETWORK_TIMEOUT, "provider request timed out"
                ) from error
            raise TransportError(
                ErrorCode.INTERNAL_ERROR, self._redact(f"cannot reach provider: {reason}")
            ) from error
        latency_ms = int((time.perf_counter() - started) * 1000)

        if answer.status >= 400:
            raise TransportError(
                _http_error_code(answer.status),
                self._redact(_http_error_message(answer.status, answer.body)),
            )
        try:
            raw: Any = json.loads(answer.body)
        except json.JSONDecodeError as error:
            raise TransportError(
                ErrorCode.INTERNAL_ERROR, "provider response is not JSON"
            ) from error
        if not isinstance(raw, dict):
            raise TransportError(ErrorCode.INTERNAL_ERROR, "provider response is not a JSON object")
        reported = _reported_cost(answer.headers) if self._read_response_cost else None
        if reported is not None:
            return TransportResponse(raw=raw, latency_ms=latency_ms, cost_usd=reported)
        input_tokens, output_tokens = usage_tokens(provider, raw)
        return TransportResponse(
            raw=raw,
            latency_ms=latency_ms,
            cost_usd=price.cost_usd(input_tokens, output_tokens),
        )
