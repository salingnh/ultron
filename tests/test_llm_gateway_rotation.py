"""G1.6: the shipped LLM gateway rotates on quota exhaustion, and M04 reports it honestly.

The gateway is LiteLLM proxy, pinned by digest, and the configuration under test is the one
`deploy/llm-gateway/config.example.yaml` documents: a priority routing group over two endpoints, no
router retries, a per-endpoint cooldown, bodies never logged. Two fake upstreams stand in for the
owner's providers - one answers 429 insufficient_quota, the other answers normally - so nothing here
calls a real provider or needs a key.

The container-backed test proves, in order:

1. a request whose first endpoint answers 429 succeeds on the second one (rotation), and each
   endpoint was attempted exactly once (no retry storm);
2. the exhausted endpoint is cooling down, so the next request skips it without touching it;
3. the Anthropic standard (`/v1/messages`) works through the same gateway and skips it too;
4. the status reader shows that cooling endpoint from the proxy's own counters;
5. when every endpoint is exhausted the gateway answers 429 with a clear reason, and M04 records a
   `provider_error` / `RATE_LIMITED` usage row instead of raising;
6. the cost M04 records is the gateway's per-request number, not its own price table.

The other tests are configuration checks with no container: they keep the example, the validator and
the compose isolation from drifting away from what the container test exercised.
"""

from __future__ import annotations

import asyncio
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
    EXAMPLE_CONFIG,
    GATEWAY_DIR,
    MASTER_KEY,
    UPSTREAM_KEYS,
    VALIDATE_SCRIPT,
    FakeUpstream,
    GatewayProcess,
    gateway_config,
    gateway_env,
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


def test_the_shipped_example_is_the_shape_that_gets_tested() -> None:
    document = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    assert len(document["model_list"]) >= 2, "one endpoint cannot rotate"
    for entry in document["model_list"]:
        params = entry["litellm_params"]
        assert params["api_key"].startswith("os.environ/"), "keys come from the environment"
        assert params["max_retries"] == 0, "an endpoint is attempted once per request"
        info = entry["model_info"]
        assert info["id"], "the status table and the metrics key on model_info.id"
        assert info["input_cost_per_token"] > 0 and info["output_cost_per_token"] > 0, (
            "a priced endpoint is what makes the gateway report a real per-request cost"
        )
    router = document["router_settings"]
    assert router["num_retries"] == 0, "rotation is the retry; retrying one endpoint is a storm"
    assert router["allowed_fails"] == 0, "one failure is enough to cool an endpoint down"
    assert router["cooldown_time"] > 0
    group = router["routing_groups"][0]
    assert group["routing_strategy"] == "priority"
    assert (
        set(group["model_priorities"])
        == set(group["models"])
        == {entry["model_name"] for entry in document["model_list"]}
    )
    settings = document["litellm_settings"]
    assert settings["turn_off_message_logging"] is True, "prompts and answers are scan data"
    assert settings["require_auth_for_metrics_endpoint"] is True
    assert "prometheus" in settings["callbacks"], "status reads the proxy's own counters"
    assert document["general_settings"]["master_key"] == "os.environ/LITELLM_MASTER_KEY"
    assert document["general_settings"]["disable_spend_logs"] is True, "no database here"


def test_the_secrets_example_only_names_variables_the_config_refers_to() -> None:
    example = (GATEWAY_DIR / "secrets.env.example").read_text(encoding="utf-8")
    names = {
        line.split("=", 1)[0]
        for line in example.splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    document = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    referenced = {document["general_settings"]["master_key"].split("/", 1)[1]} | {
        entry["litellm_params"]["api_key"].split("/", 1)[1] for entry in document["model_list"]
    }
    assert names == referenced, f"secrets.env.example must document exactly {sorted(referenced)}"


def test_the_validator_refuses_a_config_that_would_not_rotate(tmp_path: Path) -> None:
    document = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    document["litellm_settings"]["turn_off_message_logging"] = False
    document["router_settings"]["num_retries"] = 3
    document["model_list"][0]["litellm_params"]["api_key"] = "sk-a-literal-key-in-the-config"
    document["model_list"] = document["model_list"][:1]
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
    (tmp_path / "secrets.env").write_text("LITELLM_MASTER_KEY=sk-test\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATE_SCRIPT),
            str(tmp_path / "config.yaml"),
            str(tmp_path / "secrets.env"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result.stdout
    for expected in (
        "turn_off_message_logging",
        "num_retries",
        "never a literal key",
        "one endpoint cannot rotate",
    ):
        assert expected in result.stderr, f"the validator must name {expected}: {result.stderr}"


def test_the_compose_project_is_loopback_only_and_the_owner_dir_is_read_only() -> None:
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
    assert len(mounts) == 1, "the owner's config is the only host mount"
    source, _, options = mounts[0].partition(":/app/config")
    assert source.startswith("${AEGIS_LLM_GATEWAY_CONFIG_DIR"), mounts[0]
    assert options.startswith(":ro"), "the gateway never writes the owner's files"
    assert "secrets.env" in service["env_file"][0]
    assert "LITELLM_MASTER_KEY" not in service["environment"], "the key comes from secrets.env only"


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
        for key in UPSTREAM_KEYS.values():
            assert key not in repr(row)
    assert last.error is not None
    assert MASTER_KEY not in last.error.message


def test_the_gateway_never_logs_the_master_key_or_an_upstream_key(gateway: GatewayProcess) -> None:
    logs = gateway.logs(tail=1000)
    assert logs, "the gateway wrote no log line at all"
    assert MASTER_KEY not in logs
    for value in UPSTREAM_KEYS.values():
        assert value not in logs
