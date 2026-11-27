"""G1.6: the shipped LLM gateway rotates on quota exhaustion, and M04 reports it honestly.

The gateway is LiteLLM proxy, pinned by digest, and the configuration under test is the one
`make llm-gateway-up` renders: the shipped example (endpoints and their order) merged over the
fixed `deploy/llm-gateway/base.yaml` (no router retries, a per-endpoint cooldown, bodies never
logged), with the environment file holding only the variables the config references. Two fake
upstreams stand in
for the owner's providers - one answers 429 insufficient_quota, the other answers normally - so
nothing here calls a real provider or needs a key.

The container-backed test proves, in order:

1. a request whose first endpoint answers 429 succeeds on the second one (rotation), and each
   endpoint was attempted exactly once (no retry storm);
2. the exhausted endpoint is cooling down, so the next request skips it without touching it;
3. the Anthropic standard (`/v1/messages`) works through the same gateway and skips it too;
4. the status reader shows that cooling endpoint from the proxy's own counters;
5. when every endpoint is exhausted the gateway answers 429 with a clear reason, and M04 records a
   `provider_error` / `RATE_LIMITED` usage row instead of raising;
6. the cost M04 records is the gateway's per-request number, not its own price table.

`tests/test_llm_gateway_payment.py` covers the same rotation for an account that is out of credits
(HTTP 402) in a gateway of its own, so that test does not inherit this module's cooldowns.

The other tests are configuration checks with no container: they keep the example, the fixed base,
the renderer, the validator and the compose isolation from drifting away from what the container
test exercised (including what the renderer and validator refuse).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.deployment import ModelDeployment
from aegis.m04_model.usage import InMemoryUsageSink
from tests.llm_gateway_support import (
    BASE_CONFIG,
    EXAMPLE_CONFIG,
    GATEWAY_DIR,
    MASTER_KEY,
    OWNER_KEYS,
    RENDER_SCRIPT,
    FakeUpstream,
    GatewayProcess,
    gateway_config,
    gateway_env,
    render_owner_files,
    run_render,
    validate_pipeline,
)

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
MODEL_GROUP = "aegis-smart"

#: 11 input + 3 output tokens at the fake endpoints' prices (model_info in the test config).
GATEWAY_COST_USD = 11 * 0.000001 + 3 * 0.000002


@pytest.fixture(scope="module")
def upstreams() -> Iterator[list[FakeUpstream]]:
    started = [FakeUpstream().start(), FakeUpstream().start()]
    try:
        yield started
    finally:
        for upstream in started:
            upstream.stop()


@pytest.fixture(scope="module")
def gateway(upstreams: list[FakeUpstream]) -> Iterator[GatewayProcess]:
    process = GatewayProcess.spawn(gateway_config(upstreams)).start()
    try:
        yield process
    finally:
        process.stop()


def request(provider: Provider) -> ModelRequest:
    return ModelRequest.model_validate(
        {
            "provider": provider.value,
            "model": MODEL_GROUP,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "ping"}]}],
            "campaign_id": CAMPAIGN_ID,
            "session_id": SESSION_ID,
            "trace_id": "0123456789abcdef0123456789abcdef",
            "max_output_tokens": 64,
            "timeout_seconds": 60,
        }
    )


def budget() -> Budget:
    return Budget(remaining_tokens=100_000, remaining_cost_usd=5.0)


def deployment_for(
    gateway: GatewayProcess, provider: str, monkeypatch: pytest.MonkeyPatch
) -> ModelDeployment:
    env = gateway_env(f"{gateway.base_url}/v1", MODEL_GROUP, provider=provider)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return ModelDeployment.from_env()


def complete(
    deployment: ModelDeployment, sink: InMemoryUsageSink, provider: Provider
) -> ModelResponse:
    return asyncio.run(deployment.client(sink).complete(request(provider), budget()))


# ---------------------------------------------------------------------------
# configuration: no container needed
# ---------------------------------------------------------------------------

#: The fixed defaults, as values the validator refuses to see missing from the effective document.
FIXED_BASE = {
    ("router_settings", "num_retries"): 0,
    ("router_settings", "allowed_fails"): 0,
    ("litellm_settings", "turn_off_message_logging"): True,
    ("litellm_settings", "require_auth_for_metrics_endpoint"): True,
    ("general_settings", "disable_spend_logs"): True,
    ("general_settings", "master_key"): "os.environ/AEGIS_MODEL_API_KEY",
}


def test_the_shipped_example_is_endpoints_and_order_only() -> None:
    document = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    assert set(document) == {"group", "endpoints"}, (
        "the owner's file holds endpoints and their order; the fixed defaults live in base.yaml"
    )
    assert isinstance(document["group"], str) and document["group"].strip()
    endpoints = document["endpoints"]
    assert len(endpoints) >= 2, "the example must show a fallback: one endpoint cannot rotate"
    names = [endpoint["name"] for endpoint in endpoints]
    assert len(set(names)) == len(names), "each endpoint needs its own name"
    for endpoint in endpoints:
        assert endpoint["api_key"].startswith("os.environ/"), (
            "keys are variable names; the value lives in .env"
        )
        assert endpoint["model"].split("/")[0] in {"openai", "anthropic"}, (
            "the example covers both standards"
        )


def test_the_base_config_holds_the_defaults_that_must_not_change() -> None:
    document = yaml.safe_load(BASE_CONFIG.read_text(encoding="utf-8"))
    for (section, key), expected in FIXED_BASE.items():
        assert document[section][key] == expected, f"base.yaml: {section}.{key} must be {expected}"
    assert "prometheus" in document["litellm_settings"]["callbacks"], (
        "status reads the proxy's own counters"
    )
    assert document["router_settings"]["cooldown_time"] > 0
    assert "model_list" not in document and "routing_groups" not in (
        document["router_settings"] or {}
    ), "endpoints and their order are the owner's, not the base's"


def test_the_example_renders_into_the_effective_config(tmp_path: Path) -> None:
    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    config_path, environment_path = render_owner_files(
        tmp_path,
        owner,
        environment={"AEGIS_MODEL_API_KEY": MASTER_KEY, **OWNER_KEYS, "LLM_KEY_C": "sk-test-c"},
    )
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    naming = [entry["model_name"] for entry in document["model_list"]]
    assert naming == [entry["name"] for entry in owner["endpoints"]], (
        "the list order is the priority order, unchanged by the renderer"
    )
    for entry in document["model_list"]:
        params = entry["litellm_params"]
        assert params["max_retries"] == 0, "an endpoint is attempted once per request"
        assert params["timeout"] > 0, "the renderer supplies the timeout default"
        assert entry["model_info"]["id"] == entry["model_name"], "status keys on model_info.id"
    group = document["router_settings"]["routing_groups"][0]
    assert group["group_name"] == owner["group"]
    assert group["routing_strategy"] == "priority"
    assert group["model_priorities"] == {
        name: index for index, name in enumerate(naming, start=1)
    }, "priority follows the endpoint order"
    for (section, key), expected in FIXED_BASE.items():
        assert document[section][key] == expected, (
            f"the rendered document must carry {section}.{key}"
        )

    environment = {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in environment_path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert set(environment) == {"AEGIS_MODEL_API_KEY", "LLM_KEY_A", "LLM_KEY_B", "LLM_KEY_C"}, (
        "the container gets exactly the variables the config references, never the whole .env"
    )
    assert environment["AEGIS_MODEL_API_KEY"] == MASTER_KEY
    assert (environment_path.stat().st_mode & 0o777) == 0o600, "the key file is private"
    assert validate_pipeline(config_path, environment_path).returncode == 0


def test_the_renderer_refuses_fixed_settings_left_in_the_owner_file(tmp_path: Path) -> None:
    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    owner["litellm_settings"] = {"turn_off_message_logging": False}
    owner["router_settings"] = {"num_retries": 3}
    result = run_render(tmp_path, owner)
    assert result.returncode == 2, result.stdout
    assert "not allowed here" in result.stderr and "base.yaml" in result.stderr, result.stderr


def test_the_renderer_refuses_a_literal_key_and_a_missing_variable(tmp_path: Path) -> None:
    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    owner["endpoints"][0]["api_key"] = "sk-a-literal-key-in-the-config"
    result = run_render(tmp_path / "literal", owner)
    assert result.returncode == 2 and "never a literal key" in result.stderr, result.stderr

    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    result = run_render(
        tmp_path / "missing",
        owner,
        environment={"AEGIS_MODEL_API_KEY": MASTER_KEY, "LLM_KEY_A": "sk-test-a"},
    )
    assert result.returncode == 2, result.stdout
    assert "LLM_KEY_B" in result.stderr and ".env" in result.stderr, (
        f"the refusal must name the variable to add: {result.stderr}"
    )


def test_the_renderer_refuses_a_group_ultron_does_not_ask_for(tmp_path: Path) -> None:
    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(owner), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(RENDER_SCRIPT),
            "--config",
            str(tmp_path / "config.yaml"),
            "--base",
            str(BASE_CONFIG),
            "--out-dir",
            str(tmp_path / "render"),
            "--expect-group",
            "aegis-some-other-group",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "AEGIS_MODEL_API_KEY": MASTER_KEY, **OWNER_KEYS, "LLM_KEY_C": "sk-c"},
    )
    assert result.returncode == 2, result.stdout
    assert "AEGIS_MODEL_NAME" in result.stderr, (
        f"a mismatch with the name ultron asks for must be refused: {result.stderr}"
    )


def test_the_validator_refuses_a_rendered_config_that_would_not_rotate(tmp_path: Path) -> None:
    owner = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    config_path, environment_path = render_owner_files(
        tmp_path,
        owner,
        environment={"AEGIS_MODEL_API_KEY": MASTER_KEY, **OWNER_KEYS, "LLM_KEY_C": "sk-test-c"},
    )
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    document["litellm_settings"]["turn_off_message_logging"] = False
    document["router_settings"]["num_retries"] = 3
    document["general_settings"]["master_key"] = "os.environ/LITELLM_MASTER_KEY"
    document["model_list"][0]["litellm_params"]["api_key"] = "sk-a-literal-key-in-the-config"
    document["model_list"] = document["model_list"][:1]
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    result = validate_pipeline(config_path, environment_path)
    assert result.returncode == 2, result.stdout
    for expected in (
        "turn_off_message_logging",
        "num_retries",
        "never a literal key",
        "one endpoint cannot rotate",
        "keep it os.environ/AEGIS_MODEL_API_KEY",
    ):
        assert expected in result.stderr, f"the validator must name {expected}: {result.stderr}"


def test_a_native_provider_endpoint_needs_nothing_but_its_model(tmp_path: Path) -> None:
    """`opencode_go/<model>` and `openrouter/<model>` are providers the pinned image knows.

    The owner's OpenCode Go subscription and OpenRouter are reached through LiteLLM's own provider
    adapters: the config names the model and the key variable, and there is no `api_base` to keep
    in step with a provider's URL (the image also supplies the session header OpenCode Go requires,
    which is why M04 sends `x-litellm-session-id`).
    """
    owner = {
        "group": "aegis-smart",
        "endpoints": [
            {
                "name": "opencode-go",
                "model": "opencode_go/deepseek-v4.1-flash",
                "api_key": "os.environ/LLM_KEY_A",
            },
            {
                "name": "openrouter-free",
                "model": "openrouter/nvidia/nemotron-3.5-super-vl:free",
                "api_key": "os.environ/LLM_KEY_B",
            },
        ],
    }
    config_path, environment_path = render_owner_files(
        tmp_path,
        owner,
        environment={"AEGIS_MODEL_API_KEY": MASTER_KEY, "LLM_KEY_A": "sk-a", "LLM_KEY_B": "sk-b"},
    )
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    params = [entry["litellm_params"] for entry in document["model_list"]]
    assert [entry["model"] for entry in params] == [
        "opencode_go/deepseek-v4.1-flash",
        "openrouter/nvidia/nemotron-3.5-super-vl:free",
    ]
    assert all("api_base" not in entry for entry in params), params
    result = validate_pipeline(config_path, environment_path)
    assert result.returncode == 0, result.stderr


def test_the_compose_project_is_loopback_only_and_mounts_only_rendered_files() -> None:
    compose = yaml.safe_load((GATEWAY_DIR / "compose.yaml").read_text(encoding="utf-8"))
    service = compose["services"]["gateway"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    ports = service["ports"]
    assert len(ports) == 1 and ports[0].startswith("127.0.0.1:"), (
        "anything but loopback would let a peer on the network spend the owner's quota"
    )
    mounts = [item for item in service["volumes"] if isinstance(item, str)]
    assert len(mounts) == 1, "the rendered config is the only host mount"
    source, _, options = mounts[0].partition(":/app/config")
    assert source.startswith("${AEGIS_LLM_GATEWAY_RENDER_DIR"), mounts[0]
    assert options.startswith(":ro"), "the gateway never writes the rendered config"
    assert "AEGIS_LLM_GATEWAY_ENV_FILE" in service["env_file"][0], (
        "the container gets the generated subset, never the checkout's .env"
    )
    assert ".env" not in service["env_file"][0].rsplit("/", 1)[-1], (
        "the whole .env must never be handed over"
    )
    assert "LITELLM_MASTER_KEY" not in service["environment"], (
        "the master key is AEGIS_MODEL_API_KEY, from the generated environment file"
    )
    assert not (GATEWAY_DIR / "secrets.env.example").exists(), (
        "the gateway has one secret file now: the checkout's .env"
    )


# ---------------------------------------------------------------------------
# the live gateway: rotation, cooldown, both standards, exhaustion, cost
# ---------------------------------------------------------------------------


def test_the_gateway_rotates_cools_and_reports_exhaustion(
    gateway: GatewayProcess,
    upstreams: list[FakeUpstream],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exhausted, healthy = upstreams
    exhausted.mode, healthy.mode = "rate", "ok"
    deployment = deployment_for(gateway, "openai", monkeypatch)
    sink = InMemoryUsageSink()

    # 1. Rotation: the first endpoint answers 429 insufficient_quota, the second serves the call.
    answer = complete(deployment, sink, Provider.openai)
    assert answer.finish_reason is FinishReason.completed, (
        f"the call must succeed:\n{gateway.logs()}"
    )
    assert exhausted.paths() == ["/v1/chat/completions"], exhausted.paths()
    assert healthy.paths() == ["/v1/chat/completions"], (
        f"one attempt per endpoint, in priority order: a={exhausted.paths()} b={healthy.paths()}"
    )

    # 2. Cost: the gateway's number, not M04's own 9.0/Mtok price (which would be 0.000126).
    assert answer.usage.cost_usd == pytest.approx(GATEWAY_COST_USD), (
        "M04 must record the per-request cost the gateway reported"
    )
    assert sink.rows[-1].cost_usd == pytest.approx(GATEWAY_COST_USD)
    # One M04 attempt: the rotation happened inside the gateway, so the row is `ok`, not
    # `fallback` (that word is for M04's own attempt chain, which a gateway deployment refuses).
    assert sink.rows[-1].status == "ok"

    # 3. The exhausted endpoint is cooling down: the next request skips it without a network call.
    second = complete(deployment, sink, Provider.openai)
    assert second.finish_reason is FinishReason.completed
    assert exhausted.paths() == ["/v1/chat/completions"], "a cooling endpoint is not called again"
    assert healthy.paths() == ["/v1/chat/completions"] * 2

    # 4. The Anthropic standard reaches the same group and skips the same cooling endpoint.
    anthropic = deployment_for(gateway, "anthropic", monkeypatch)
    third = complete(anthropic, sink, Provider.anthropic)
    assert third.finish_reason is FinishReason.completed, (
        f"the Anthropic standard must work:\n{gateway.logs()}"
    )
    assert third.provider is Provider.anthropic
    assert exhausted.paths() == ["/v1/chat/completions"], "still skipped on the Anthropic path"
    assert healthy.paths()[:2] == ["/v1/chat/completions"] * 2
    assert healthy.paths()[2] == "/v1/responses", (
        "this LiteLLM version translates an Anthropic-standard call onto an OpenAI-compatible "
        "endpoint through its Responses API - the second standard really is served"
    )

    # 5. The status reader turns the proxy's counters into the table the owner reads.
    table = gateway.status_table()
    cooling = next(line for line in table.splitlines() if "fake-endpoint-a" in line)
    serving = next(line for line in table.splitlines() if "fake-endpoint-b" in line)
    assert "cooling down" in cooling, table
    assert "cooling down" not in serving, table

    # 6. Every endpoint exhausted: a clear 429, mapped to provider_error/RATE_LIMITED by M04.
    healthy.mode = "rate"
    last = complete(deployment, sink, Provider.openai)
    assert last.finish_reason is FinishReason.provider_error, f"the call must fail cleanly: {last}"
    assert last.error is not None and last.error.code is ErrorCode.RATE_LIMITED
    assert "No deployments available" in last.error.message, last.error.message
    assert sink.rows[-1].error_code is ErrorCode.RATE_LIMITED, "the ledger says why it failed"

    # Nothing in any of those answers may carry a credential.
    for row in sink.rows:
        assert MASTER_KEY not in repr(row)
        for key in OWNER_KEYS.values():
            assert key not in repr(row)
    assert last.error is not None
    assert MASTER_KEY not in last.error.message


def test_the_gateway_never_logs_the_master_key_or_an_upstream_key(gateway: GatewayProcess) -> None:
    logs = gateway.logs(tail=1000)
    assert logs, "the gateway wrote no log line at all"
    assert MASTER_KEY not in logs
    for value in OWNER_KEYS.values():
        assert value not in logs
