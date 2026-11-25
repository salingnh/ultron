"""Transport boundary of M04: the only place a model provider is reached.

The drivers never open a socket; they build the provider wire body and normalize the JSON that a
transport returns. `HttpTransport` is the live implementation (endpoint, credential, price table
and timeout are deployment configuration per interfaces §5) and is never constructed by default:
G1 runs the first-class fake driver, and the composition root that would build this transport must
gate it on an explicit live flag. CI tests inject a recorded/scripted transport and send nothing.

Transport failures are normalized into `error.v2` codes; only a `TransportError` may become
`finish_reason=provider_error`. A missing price/key/endpoint is our own configuration bug and
raises instead, so it cannot be mistaken for a provider outage.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.raw import usage_tokens

#: Bound one provider body in memory; a hostile or broken endpoint cannot exhaust the activity.
MAX_BODY_BYTES = 1_000_000


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


#: Injected HTTP boundary of `HttpTransport`: `(url, headers, body, timeout) -> (status, body)`.
PostJson = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]
#: Masks a deployment secret in text this module is about to raise or keep.
Redact = Callable[[str], str]


def _pass_through(text: str) -> str:
    return text


def _post_json(
    url: str, headers: dict[str, str], body: bytes, timeout_seconds: float
) -> tuple[int, bytes]:
    """POST one JSON body with the standard library; an HTTP error is a status, not an exception."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return int(response.status), response.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as error:
        with error:
            return int(error.code), error.read(MAX_BODY_BYTES)


def _http_error_code(status: int) -> ErrorCode:
    if status == 429:
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
    ) -> None:
        self._endpoints = dict(endpoints)
        self._api_keys = dict(api_keys)
        self._pricing = dict(pricing)
        self._anthropic_version = anthropic_version
        self._post = post or _post_json
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

        headers = {"content-type": "application/json", "accept": "application/json"}
        if provider is Provider.openai:
            headers["authorization"] = f"Bearer {api_key}"
        else:
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = self._anthropic_version
        body = json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        started = time.perf_counter()
        try:
            status, payload = await asyncio.to_thread(
                self._post, endpoint, headers, body, timeout_seconds
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

        if status >= 400:
            raise TransportError(
                _http_error_code(status), self._redact(_http_error_message(status, payload))
            )
        try:
            raw: Any = json.loads(payload)
        except json.JSONDecodeError as error:
            raise TransportError(
                ErrorCode.INTERNAL_ERROR, "provider response is not JSON"
            ) from error
        if not isinstance(raw, dict):
            raise TransportError(ErrorCode.INTERNAL_ERROR, "provider response is not a JSON object")
        input_tokens, output_tokens = usage_tokens(provider, raw)
        return TransportResponse(
            raw=raw,
            latency_ms=latency_ms,
            cost_usd=price.cost_usd(input_tokens, output_tokens),
        )
