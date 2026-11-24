"""M04 configuration: the fallback chain bound shipped with the client (C07).

`contracts/interfaces/README.md` §5 keeps endpoint, base_url, prices and limits in deployment
configuration, and fixes only the shape of the fallback list: a bounded chain that is used only
when the data policy allows it. `ModelConfig` is that bound; the primary provider/model of a call
comes from `model-request.v2` itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider

MAX_ATTEMPTS = 3
MAX_FALLBACKS = 2


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """One provider/model pair in the attempt chain."""

    provider: Provider
    model: str


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Attempt chain: primary call from the request, then configured fallbacks.

    `allow_fallback` defaults to false: the contract only permits a second provider when the data
    policy allows it (interfaces §5), so the caller has to opt in as well as list a fallback.
    A configured chain longer than `max_attempts - 1` is truncated by `attempts()`, never extended.
    """

    fallback: tuple[ProviderSpec, ...] = ()
    max_attempts: int = 2
    allow_fallback: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= MAX_ATTEMPTS:
            raise ValueError(f"max_attempts must be 1..{MAX_ATTEMPTS}, got {self.max_attempts}")
        if len(self.fallback) > MAX_FALLBACKS:
            raise ValueError(
                f"at most {MAX_FALLBACKS} fallback providers, got {len(self.fallback)}"
            )
        for spec in self.fallback:
            if not spec.model:
                raise ValueError("a fallback provider needs a model name")

    def attempts(self, request: ModelRequest) -> tuple[ProviderSpec, ...]:
        """The bounded attempt chain of this request: primary first, configured fallbacks after."""
        chain = [ProviderSpec(request.provider, request.model)]
        if self.allow_fallback:
            chain.extend(self.fallback)
        return tuple(chain[: self.max_attempts])
