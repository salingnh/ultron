"""M04 — ModelClient drivers (OpenAI chat, Anthropic messages) and usage rows (owner: G1.2a)."""

from __future__ import annotations

from aegis.m04_model.client import ModelClient, output_validator
from aegis.m04_model.config import ModelConfig, ProviderSpec
from aegis.m04_model.drivers import (
    AnthropicMessagesDriver,
    OpenAIChatDriver,
    ProviderDriver,
    provider_error_response,
)
from aegis.m04_model.fake import FakeModelClient
from aegis.m04_model.raw import usage_tokens
from aegis.m04_model.transport import (
    HttpTransport,
    MissingEndpoint,
    Price,
    PricingUnknown,
    ProviderTransport,
    TransportError,
    TransportResponse,
)
from aegis.m04_model.usage import (
    InMemoryUsageSink,
    ModelUsage,
    PostgresUsageSink,
    UsageSink,
    UsageStatus,
    model_usage_row,
)

__all__ = [
    "AnthropicMessagesDriver",
    "FakeModelClient",
    "HttpTransport",
    "InMemoryUsageSink",
    "MissingEndpoint",
    "ModelClient",
    "ModelConfig",
    "ModelUsage",
    "OpenAIChatDriver",
    "PostgresUsageSink",
    "Price",
    "PricingUnknown",
    "ProviderDriver",
    "ProviderSpec",
    "ProviderTransport",
    "TransportError",
    "TransportResponse",
    "UsageSink",
    "UsageStatus",
    "model_usage_row",
    "output_validator",
    "provider_error_response",
    "usage_tokens",
]
