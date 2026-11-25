"""G1.6 live-model deployment: env validation, endpoints, redaction, selection and healthz.

The live path is configuration, so every property here is about failing loudly instead of
guessing: a missing provider, model, key or price stops start-up with the variable's name (never
its value); the selection flag has no third state; and none of the status/log/error surfaces may
carry the credential.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.m03_agent.activities import build_model
from aegis.m03_agent.config import SessionConfig, SessionConfigError
from aegis.m03_agent.fake_policy import ScriptedLabPolicy
from aegis.m04_model import deployment
from aegis.m04_model.client import ModelClient
from aegis.m04_model.deployment import (
    ModelDeployment,
    ModelDeploymentError,
    live_model_enabled,
    model_status,
    redact,
)
from aegis.m04_model.transport import HttpTransport, TransportError
from aegis.m04_model.usage import InMemoryUsageSink, PostgresUsageSink
from aegis.m26_api.app import create_app
from tests.m04_support import budget, recorded, request

SECRET = "sk-g16-deployment-secret"
MODEL_VARIABLES = (
    deployment.LIVE_MODEL_ENV,
    deployment.PROVIDER_ENV,
    deployment.MODEL_NAME_ENV,
    deployment.BASE_URL_ENV,
    deployment.API_KEY_ENV,
    deployment.INPUT_PRICE_ENV,
    deployment.OUTPUT_PRICE_ENV,
    deployment.TIMEOUT_SECONDS_ENV,
    deployment.MAX_OUTPUT_TOKENS_ENV,
)


def live_env(provider: str = "openai", **overrides: str) -> dict[str, str]:
    """A complete live configuration; overrides replace (or, with "", remove) one variable."""
    names = {
        "live": deployment.LIVE_MODEL_ENV,
        "provider": deployment.PROVIDER_ENV,
        "model_name": deployment.MODEL_NAME_ENV,
        "base_url": deployment.BASE_URL_ENV,
        "api_key": deployment.API_KEY_ENV,
        "input_price": deployment.INPUT_PRICE_ENV,
        "output_price": deployment.OUTPUT_PRICE_ENV,
        "timeout_seconds": deployment.TIMEOUT_SECONDS_ENV,
        "max_output_tokens": deployment.MAX_OUTPUT_TOKENS_ENV,
    }
    env = {
        deployment.LIVE_MODEL_ENV: "1",
        deployment.PROVIDER_ENV: provider,
        deployment.MODEL_NAME_ENV: "configured-model",
        deployment.API_KEY_ENV: SECRET,
        deployment.INPUT_PRICE_ENV: "2.0",
        deployment.OUTPUT_PRICE_ENV: "8.0",
    }
    for name, value in overrides.items():
        key = names[name]
        if value == "":
            env.pop(key, None)
        else:
            env[key] = value
    return env


def with_env(monkeypatch: pytest.MonkeyPatch, env: Mapping[str, str]) -> None:
    for name in MODEL_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


# ---------------------------------------------------------------------------
# the selection flag: explicit, never a silent fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", " OFF "])
def test_scripted_selection_is_explicit(value: str) -> None:
    assert live_model_enabled({deployment.LIVE_MODEL_ENV: value}) is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " TRUE "])
def test_live_selection_is_explicit(value: str) -> None:
    assert live_model_enabled({deployment.LIVE_MODEL_ENV: value}) is True


@pytest.mark.parametrize("value", ["2", "maybe", "live", "00"])
def test_an_unknown_flag_value_is_an_error_not_a_default(value: str) -> None:
    with pytest.raises(ModelDeploymentError, match=deployment.LIVE_MODEL_ENV):
        live_model_enabled({deployment.LIVE_MODEL_ENV: value})


# ---------------------------------------------------------------------------
# both standards: endpoints, base URL conventions, optional knobs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "endpoint"),
    [
        ("openai", "https://api.openai.com/v1/chat/completions"),
        ("anthropic", "https://api.anthropic.com/v1/messages"),
    ],
)
def test_default_endpoints_follow_each_standard(provider: str, endpoint: str) -> None:
    assert ModelDeployment.from_env(live_env(provider)).endpoint == endpoint


@pytest.mark.parametrize(
    ("provider", "base_url", "endpoint"),
    [
        ("openai", "http://127.0.0.1:1234/v1", "http://127.0.0.1:1234/v1/chat/completions"),
        (
            "openai",
            "https://gateway.internal/openai/v1/",
            "https://gateway.internal/openai/v1/chat/completions",
        ),
        ("openai", "https://api.test/v1/chat/completions", "https://api.test/v1/chat/completions"),
        ("anthropic", "https://api.anthropic.com", "https://api.anthropic.com/v1/messages"),
        ("anthropic", "https://api.anthropic.com/", "https://api.anthropic.com/v1/messages"),
        (
            "anthropic",
            "https://proxy.internal/anthropic/v1",
            "https://proxy.internal/anthropic/v1/messages",
        ),
        ("anthropic", "https://api.test/v1/messages", "https://api.test/v1/messages"),
    ],
)
def test_a_base_url_is_joined_with_the_standard_path_once(
    provider: str, base_url: str, endpoint: str
) -> None:
    deployment_value = ModelDeployment.from_env(live_env(provider, base_url=base_url))
    assert deployment_value.endpoint == endpoint


def test_optional_timeout_and_output_ceiling_have_bounded_defaults() -> None:
    default = ModelDeployment.from_env(live_env())
    assert (default.timeout_seconds, default.max_output_tokens) == (120.0, 2048)
    tuned = ModelDeployment.from_env(live_env(timeout_seconds="45.5", max_output_tokens="512"))
    assert (tuned.timeout_seconds, tuned.max_output_tokens) == (45.5, 512)
    for overrides in (
        {"timeout_seconds": "0"},
        {"timeout_seconds": "601"},
        {"timeout_seconds": "x"},
    ):
        with pytest.raises(ModelDeploymentError, match=deployment.TIMEOUT_SECONDS_ENV):
            ModelDeployment.from_env(live_env(**overrides))
    for overrides in ({"max_output_tokens": "0"}, {"max_output_tokens": "1.5"}):
        with pytest.raises(ModelDeploymentError, match=deployment.MAX_OUTPUT_TOKENS_ENV):
            ModelDeployment.from_env(live_env(**overrides))


def test_a_non_http_base_url_is_refused() -> None:
    with pytest.raises(ModelDeploymentError, match=deployment.BASE_URL_ENV):
        ModelDeployment.from_env(live_env(base_url="file:///etc/passwd"))


# ---------------------------------------------------------------------------
# validation: the variable is named, the value never is
# ---------------------------------------------------------------------------


def test_a_missing_api_key_names_the_variable_only() -> None:
    with pytest.raises(ModelDeploymentError) as caught:
        ModelDeployment.from_env(live_env(api_key=""))
    message = str(caught.value)
    assert deployment.API_KEY_ENV in message
    assert SECRET not in message


def test_a_missing_model_name_is_an_error() -> None:
    with pytest.raises(ModelDeploymentError, match=deployment.MODEL_NAME_ENV):
        ModelDeployment.from_env(live_env(model_name=""))


@pytest.mark.parametrize("provider", ["", "azure", "open-ai"])
def test_the_provider_must_be_one_of_the_two_standards(provider: str) -> None:
    with pytest.raises(ModelDeploymentError, match=deployment.PROVIDER_ENV):
        ModelDeployment.from_env(live_env(provider))


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("input_price", ""),
        ("output_price", ""),
        ("input_price", "0"),
        ("output_price", "0"),
        ("input_price", "-1.5"),
        ("output_price", "free"),
        ("input_price", "nan"),
    ],
)
def test_a_missing_or_unusable_price_is_an_error_not_zero(variable: str, value: str) -> None:
    with pytest.raises(ModelDeploymentError) as caught:
        ModelDeployment.from_env(live_env(**{variable: value}))
    expected = (
        deployment.INPUT_PRICE_ENV if variable == "input_price" else deployment.OUTPUT_PRICE_ENV
    )
    assert expected in str(caught.value)


def test_no_status_or_repr_surface_carries_the_key() -> None:
    live = ModelDeployment.from_env(live_env())
    assert SECRET not in repr(live)
    assert SECRET not in json.dumps(live.describe())
    assert SECRET not in json.dumps(model_status(live_env()))
    assert redact(f"token {SECRET} rejected", SECRET) == "token *** rejected"
    assert redact("nothing to hide", "") == "nothing to hide"


def test_a_provider_echo_of_the_key_is_redacted_in_the_transport_error() -> None:
    live = ModelDeployment.from_env(live_env())

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        return 401, json.dumps({"error": f"bad credential {headers['authorization']}"}).encode()

    with pytest.raises(TransportError) as caught:
        asyncio.run(
            live.transport(post=post).send(
                live.provider, live.model, {"model": live.model}, timeout_seconds=5
            )
        )
    assert SECRET not in caught.value.message
    assert "***" in caught.value.message


# ---------------------------------------------------------------------------
# status: what /healthz reports
# ---------------------------------------------------------------------------


def test_model_status_reports_scripted_live_and_invalid_without_the_key() -> None:
    scripted = model_status({})
    assert scripted["mode"] == "scripted"
    assert scripted["model"] == deployment.SCRIPTED_MODEL
    assert "api_key" not in scripted

    live = model_status(live_env("anthropic"))
    assert live["mode"] == "live"
    assert live["valid"] is True
    assert (live["provider"], live["model"]) == ("anthropic", "configured-model")
    assert live["endpoint"] == "https://api.anthropic.com/v1/messages"
    assert live["api_key"] == "set"
    assert SECRET not in json.dumps(live)

    incomplete = model_status(live_env(api_key=""))
    assert incomplete["mode"] == "live"
    assert incomplete["valid"] is False
    assert incomplete["api_key"] == "missing"
    assert deployment.API_KEY_ENV in incomplete["detail"]

    invalid = model_status({deployment.LIVE_MODEL_ENV: "perhaps"})
    assert invalid["mode"] == "invalid"
    assert deployment.LIVE_MODEL_ENV in invalid["detail"]


def test_healthz_reports_the_model_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_env(monkeypatch, {})
    body = TestClient(create_app()).get("/healthz").json()
    assert body["status"] == "ok"
    assert body["model"]["mode"] == "scripted"

    with_env(monkeypatch, live_env("openai"))
    live = TestClient(create_app()).get("/healthz").json()["model"]
    assert live["mode"] == "live"
    assert live["model"] == "configured-model"
    assert SECRET not in json.dumps(live)


# ---------------------------------------------------------------------------
# the live call: real wire, real prices, one usage row
# ---------------------------------------------------------------------------


def test_the_live_client_posts_to_the_derived_endpoint_and_prices_the_answer() -> None:
    live = ModelDeployment.from_env(live_env("openai"))
    seen: list[dict[str, Any]] = []
    raw = recorded("openai-completed")

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        seen.append({"url": url, "headers": headers, "body": json.loads(body)})
        return 200, json.dumps(raw).encode()

    sink = InMemoryUsageSink()
    answer = asyncio.run(
        live.client(sink, post=post).complete(
            request(Provider.openai, "configured-model"), budget()
        )
    )
    assert seen[0]["url"] == "https://api.openai.com/v1/chat/completions"
    assert seen[0]["headers"]["authorization"] == f"Bearer {SECRET}"
    # 180 input tokens at $2/M + 9 output at $8/M.
    assert answer.usage.cost_usd == pytest.approx(0.000432)
    assert len(sink.rows) == 1
    assert (sink.rows[0].provider, sink.rows[0].model) == (Provider.openai, "configured-model")
    assert sink.rows[0].cost_usd == pytest.approx(0.000432)


# ---------------------------------------------------------------------------
# the one switch: build_model
# ---------------------------------------------------------------------------


def test_build_model_without_the_flag_is_the_scripted_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_env(monkeypatch, {})
    model = build_model(SessionConfig())
    assert isinstance(model, ScriptedLabPolicy)
    assert (model.provider, model.model) == ("openai", "scripted-lab")


def test_build_model_builds_the_live_client_with_the_real_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_env(monkeypatch, live_env("openai"))
    config = SessionConfig.from_env()
    assert config.live_model is True
    assert (config.provider, config.model) == ("openai", "configured-model")

    model = build_model(config, dsn="postgresql://unused/unused")
    assert isinstance(model, ModelClient)
    assert isinstance(model.transport, HttpTransport)
    assert isinstance(model.usage, PostgresUsageSink)


def test_build_model_refuses_a_live_session_without_a_usage_sink_or_a_matching_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_env(monkeypatch, live_env("openai"))
    monkeypatch.delenv("AEGIS_PG_DSN", raising=False)
    with pytest.raises(SessionConfigError, match="AEGIS_PG_DSN"):
        build_model(SessionConfig.from_env())

    mismatched = SessionConfig(provider="anthropic", model="other-model", live_model=True)
    with pytest.raises(SessionConfigError, match="disagree"):
        build_model(mismatched, dsn="postgresql://unused/unused")


def test_session_config_validation_fails_at_startup_not_on_the_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_env(monkeypatch, live_env(output_price=""))
    with pytest.raises(ModelDeploymentError, match=deployment.OUTPUT_PRICE_ENV):
        SessionConfig.from_env()

    with_env(monkeypatch, {deployment.LIVE_MODEL_ENV: "sometimes"})
    with pytest.raises(SessionConfigError, match=deployment.LIVE_MODEL_ENV):
        SessionConfig.from_env()

    with_env(monkeypatch, {})
    scripted = SessionConfig.from_env()
    assert (scripted.live_model, scripted.model) == (False, "scripted-lab")


def test_the_timeout_and_output_ceiling_reach_the_plan_request() -> None:
    live = ModelDeployment.from_env(live_env(timeout_seconds="30", max_output_tokens="256"))
    config = SessionConfig(
        provider=live.provider.value,
        model=live.model,
        max_output_tokens=live.max_output_tokens,
        timeout_seconds=live.timeout_seconds,
        live_model=True,
    )
    assert (config.max_output_tokens, config.timeout_seconds) == (256, 30.0)
