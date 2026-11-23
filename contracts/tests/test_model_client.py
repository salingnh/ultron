"""C07 offline suite: ModelClient round-trip/finish/budget/fallback and UNRATED severity fallback.

Runs without a provider or database: the driver behaviour is exercised through the reference
in tests/model_client_ref.py and the JSON Schemas are the source of truth.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
DOCS = [json.loads(path.read_text(encoding="utf-8")) for path in ROOT.rglob("*.schema.json")]
REGISTRY = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in DOCS)
CHECKER = runpy.run_path(str(ROOT / "validation.py"))["format_checker"]()
REF = runpy.run_path(str(ROOT / "tests/model_client_ref.py"))

normalize_response = REF["normalize_response"]
to_wire = REF["to_wire"]
Budget = REF["Budget"]
BudgetDenied = REF["BudgetDenied"]
ProviderError = REF["ProviderError"]
ModelClient = REF["ModelClient"]
ModelConfig = REF["ModelConfig"]
ProviderSpec = REF["ProviderSpec"]
FakeTransport = REF["FakeTransport"]
Step = REF["Step"]
AssessmentStore = REF["AssessmentStore"]
assess_finding = REF["assess_finding"]
link_errors = REF["link_errors"]
severity_dedup_key = REF["severity_dedup_key"]
FINISH_REASONS = REF["FINISH_REASONS"]

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
TRACE_ID = "0123456789abcdef0123456789abcdef"
FINDING_ID = "01934f6a-0000-7000-8000-0000000e0002"
EVIDENCE_ID = "01934f6a-0000-7000-8000-0000000e0001"
SCAN_ID = "01934f6a-0000-7000-8000-0000000c0001"


def errors_of(target: str, instance) -> list[str]:
    validator = Draft202012Validator({"$ref": BASE + target}, registry=REGISTRY, format_checker=CHECKER)
    return [f"/{'/'.join(map(str, error.absolute_path))}: {error.message}" for error in validator.iter_errors(instance)]


def validate_response(response: dict) -> list[str]:
    return errors_of("agent/model-response.v2.schema.json", response)


def validate_request(request: dict) -> list[str]:
    return errors_of("agent/model-request.v2.schema.json", request)


def validate_row(row: dict) -> list[str]:
    return errors_of("finding/severity-assessment.v2.schema.json", row)


def validate_model_output(output) -> list[str]:
    return errors_of("finding/severity-assessment.v2.schema.json#/$defs/ModelOutput", output)


MODEL_OUTPUT_SCHEMA = {"$ref": BASE + "finding/severity-assessment.v2.schema.json#/$defs/ModelOutput"}


def request(provider: str = "openai", model: str = "configured-model") -> dict:
    return {
        "provider": provider,
        "model": model,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Mục tiêu: kiểm example.test"}]}],
        "campaign_id": CAMPAIGN_ID,
        "session_id": SESSION_ID,
        "trace_id": TRACE_ID,
        "max_output_tokens": 512,
        "timeout_seconds": 60,
    }


def tool_message(call: dict, text: str) -> dict:
    return {
        "role": "tool",
        "content": [
            {
                "type": "tool_result",
                "result": {
                    "call_id": call["id"],
                    "name": call["name"],
                    "content": [{"type": "text", "text": text}],
                    "is_error": False,
                },
            }
        ],
    }


OPENAI_TOOL_RAW = {
    "id": "chatcmpl-fake-0001",
    "model": "configured-model-2026-01-01",
    "choices": [
        {
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_01934f6a0000700080000000a0000001",
                        "type": "function",
                        "function": {
                            "name": "dns/enumerate-subdomains",
                            "arguments": '{"targets": ["example.test"]}',
                        },
                    }
                ],
            },
        }
    ],
    "usage": {"prompt_tokens": 120, "completion_tokens": 18},
}

OPENAI_DONE_RAW = {
    "id": "chatcmpl-fake-0002",
    "model": "configured-model-2026-01-01",
    "choices": [
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "Đã gửi job, chờ kết quả."}}
    ],
    "usage": {"prompt_tokens": 180, "completion_tokens": 9},
}

ANTHROPIC_TOOL_RAW = {
    "id": "msg_fake_0001",
    "model": "configured-model-2026-01-01",
    "stop_reason": "tool_use",
    "content": [
        {"type": "text", "text": "Gọi capability dns/resolve."},
        {
            "type": "tool_use",
            "id": "toolu_01934f6a0000700080000000a0000002",
            "name": "dns/resolve",
            "input": {"targets": ["example.test"]},
        },
    ],
    "usage": {"input_tokens": 210, "output_tokens": 42},
}

ANTHROPIC_DONE_RAW = {
    "id": "msg_fake_0002",
    "model": "configured-model-2026-01-01",
    "stop_reason": "end_turn",
    "content": [{"type": "text", "text": "Đã có kết quả phân giải, tổng hợp tiếp."}],
    "usage": {"input_tokens": 240, "output_tokens": 20},
}

MODEL_OUTPUT = {
    "severity": "HIGH",
    "reasons": ["Thành phần nằm trong dải ảnh hưởng và dịch vụ hướng Internet"],
    "source_refs": [{"kind": "evidence", "ref": EVIDENCE_ID}],
    "uncertainty": ["Chưa xác định đường khai thác thực tế"],
    "recommended_actions": ["Yêu cầu rescan sau khi nâng phiên bản"],
}

ASSESSMENT_RAW = {
    "id": "chatcmpl-fake-assessment",
    "model": "configured-model-2026-01-01",
    "choices": [
        {
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(MODEL_OUTPUT, ensure_ascii=False)},
        }
    ],
    "usage": {"prompt_tokens": 300, "completion_tokens": 90},
}


def finding(revision: int = 3) -> dict:
    return {
        "finding_id": FINDING_ID,
        "campaign_id": CAMPAIGN_ID,
        "input_revision": revision,
        "provider": "openai",
        "model": "configured-model",
        "inputs": {"scanner_severity": "high", "exposure": "unknown", "criticality": "unknown"},
        "raw_signals": [
            {"kind": "finding", "ref": FINDING_ID},
            {"kind": "finding_source", "ref": f"{FINDING_ID}/{SCAN_ID}/trivy", "value": "scanner_severity=high"},
            {"kind": "evidence", "ref": EVIDENCE_ID},
        ],
    }


def assessment_kwargs(**overrides) -> dict:
    kwargs = {
        "trigger": "scan",
        "session_id": SESSION_ID,
        "trace_id": TRACE_ID,
        "budget": Budget(1.0),
        "validate_output": validate_model_output,
        "validate_row": validate_row,
        "response_schema": MODEL_OUTPUT_SCHEMA,
    }
    kwargs.update(overrides)
    return kwargs


class FinishNormalization(unittest.TestCase):
    def test_provider_reasons_map_to_the_six_normalized_values(self):
        cases = [
            ("openai", dict(OPENAI_DONE_RAW)),
            ("openai", dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "length", "message": {"content": '{"sev'}}])),
            ("openai", dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "content_filter", "message": {"content": None}}])),
            ("anthropic", dict(ANTHROPIC_DONE_RAW)),
            ("anthropic", dict(ANTHROPIC_DONE_RAW, stop_reason="max_tokens")),
            ("anthropic", dict(ANTHROPIC_DONE_RAW, stop_reason="refusal", content=[])),
        ]
        expected = ["completed", "truncated", "refused", "completed", "truncated", "refused"]
        for (provider, raw), want in zip(cases, expected, strict=True):
            with self.subTest(provider=provider, want=want):
                response = normalize_response(provider, raw)
                self.assertEqual(response["finish_reason"], want)
                self.assertEqual(validate_response(response), [])
                self.assertNotIn("parsed", response)
                if want != "refused":
                    self.assertIn("message", response)

    def test_finish_enum_is_the_locked_six(self):
        schema = json.loads((ROOT / "agent/model-response.v2.schema.json").read_text())
        self.assertEqual(tuple(schema["$defs"]["FinishReason"]["enum"]), FINISH_REASONS)

    def test_unknown_finish_keeps_content_as_invalid_output(self):
        raw = dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "banana", "message": {"content": "lạ"}}])
        response = normalize_response("openai", raw)
        self.assertEqual(response["finish_reason"], "invalid_output")
        self.assertEqual(response["message"]["content"][0]["text"], "lạ")
        self.assertEqual(validate_response(response), [])

    def test_empty_provider_response_is_provider_error(self):
        response = normalize_response("anthropic", {"id": "msg_x", "stop_reason": "end_turn", "content": []})
        self.assertEqual(response["finish_reason"], "provider_error")
        self.assertEqual(response["error"]["code"], "INTERNAL_ERROR")
        self.assertNotIn("message", response)
        self.assertEqual(validate_response(response), [])


class ToolCallRoundTrip(unittest.TestCase):
    def test_two_openai_rounds_keep_ids_names_and_raw_arguments(self):
        transport = FakeTransport(
            Step(raw=OPENAI_TOOL_RAW, latency_ms=800, cost_usd=0.0004),
            Step(raw=OPENAI_DONE_RAW, latency_ms=500, cost_usd=0.0002),
        )
        client = ModelClient(ModelConfig(), transport)
        first = client.complete(request(), Budget(1.0))
        self.assertEqual(first["finish_reason"], "tool_calls")
        self.assertEqual(validate_response(first), [])

        call = first["message"]["content"][-1]["call"]
        second_request = request()
        second_request["messages"] += [first["message"], tool_message(call, '{"job_id":"01934f6a-0000-7000-8000-0000000d0001"}')]
        self.assertEqual(validate_request(second_request), [])
        self.assertEqual(link_errors(second_request["messages"]), [])

        second = client.complete(second_request, Budget(1.0))
        self.assertEqual(second["finish_reason"], "completed")
        self.assertEqual(validate_response(second), [])
        self.assertEqual(first["provider_meta"]["response_id"], OPENAI_TOOL_RAW["id"])
        self.assertEqual(first["provider_meta"]["model_version"], OPENAI_TOOL_RAW["model"])
        self.assertEqual(first["provider_meta"]["raw_finish_reason"], "tool_calls")

        wire = transport.calls[1]["wire"]
        assistant = next(message for message in wire["messages"] if message["role"] == "assistant")
        self.assertEqual(assistant["tool_calls"][0]["id"], call["id"])
        self.assertEqual(assistant["tool_calls"][0]["function"]["name"], call["name"])
        self.assertEqual(assistant["tool_calls"][0]["function"]["arguments"], call["arguments_raw"])
        tool = next(message for message in wire["messages"] if message["role"] == "tool")
        self.assertEqual(tool["tool_call_id"], call["id"])

    def test_two_anthropic_rounds_keep_tool_use_input(self):
        transport = FakeTransport(
            Step(raw=ANTHROPIC_TOOL_RAW, latency_ms=900),
            Step(raw=ANTHROPIC_DONE_RAW, latency_ms=420),
        )
        client = ModelClient(ModelConfig(), transport)
        first = client.complete(request("anthropic"), Budget(1.0))
        self.assertEqual(first["finish_reason"], "tool_calls")
        call = first["message"]["content"][-1]["call"]

        second_request = request("anthropic")
        second_request["messages"] += [first["message"], tool_message(call, "192.0.2.10")]
        second = client.complete(second_request, Budget(1.0))
        self.assertEqual(second["finish_reason"], "completed")

        wire = transport.calls[1]["wire"]
        assistant = next(message for message in wire["messages"] if message["role"] == "assistant")
        tool_use = next(block for block in assistant["content"] if block["type"] == "tool_use")
        self.assertEqual(tool_use["id"], call["id"])
        self.assertEqual(tool_use["input"], call["arguments"])
        result = next(block for block in wire["messages"][-1]["content"] if block["type"] == "tool_result")
        self.assertEqual(result["tool_use_id"], call["id"])

    def test_orphan_and_duplicate_tool_results_are_rejected(self):
        call = {"id": "call_1", "name": "dns/resolve", "arguments": {}}
        assistant = {"role": "assistant", "content": [{"type": "tool_call", "call": call}]}
        good = tool_message(call, "ok")
        self.assertEqual(link_errors([assistant, good]), [])

        orphan = tool_message({"id": "call_2", "name": "dns/resolve"}, "ok")
        self.assertTrue(link_errors([assistant, orphan]))
        self.assertTrue(link_errors([assistant, good, good]))


class ModelClientExecution(unittest.TestCase):
    def test_invalid_and_truncated_output_keep_raw_text(self):
        bad_json_schema = dict(
            OPENAI_DONE_RAW,
            choices=[
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"severity": "BANANA", "reasons": []}'},
                }
            ],
        )
        response = normalize_response("openai", bad_json_schema, validate=validate_model_output)
        self.assertEqual(response["finish_reason"], "invalid_output")
        self.assertNotIn("parsed", response)
        self.assertIn("BANANA", response["message"]["content"][0]["text"])
        self.assertEqual(validate_response(response), [])

        truncated = normalize_response(
            "openai",
            dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "length", "message": {"content": '{"severity": "HI'}}]),
            validate=validate_model_output,
        )
        self.assertEqual(truncated["finish_reason"], "truncated")
        self.assertNotIn("parsed", truncated)
        self.assertEqual(truncated["message"]["content"][0]["text"], '{"severity": "HI')
        self.assertEqual(validate_response(truncated), [])

    def test_refusal_keeps_provider_text_and_has_no_parsed(self):
        raw = dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "stop", "message": {"content": None, "refusal": "Tôi không thể hỗ trợ."}}])
        response = normalize_response("openai", raw, validate=validate_model_output)
        self.assertEqual(response["finish_reason"], "refused")
        self.assertNotIn("parsed", response)
        self.assertEqual(validate_response(response), [])
        self.assertIn("không thể", response["message"]["content"][0]["text"])

    def test_budget_denied_before_any_provider_call(self):
        transport = FakeTransport()
        client = ModelClient(ModelConfig(), transport)
        with self.assertRaises(BudgetDenied):
            client.complete(request(), Budget(0.0))
        self.assertEqual(transport.calls, [])
        self.assertEqual(len(client.usage), 1)
        usage = client.usage[0]
        self.assertEqual(usage["status"], "budget_denied")
        self.assertEqual(usage["error_code"], "POLICY_DENIED")
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["cost_usd"]), (0, 0, 0.0))
        self.assertEqual(usage["trace_id"], TRACE_ID)

    def test_provider_error_then_configured_fallback(self):
        config = ModelConfig(fallback=(ProviderSpec("anthropic", "fallback-model"),), max_attempts=2)
        transport = FakeTransport(
            Step(error=ProviderError("NETWORK_TIMEOUT", "primary unreachable")),
            Step(raw=ANTHROPIC_DONE_RAW, latency_ms=1200, cost_usd=0.0011),
        )
        client = ModelClient(config, transport)
        response = client.complete(request(), Budget(1.0))
        self.assertEqual(response["finish_reason"], "completed")
        self.assertEqual(response["provider"], "anthropic")
        self.assertEqual(validate_response(response), [])
        self.assertEqual([call["provider"] for call in transport.calls], ["openai", "anthropic"])
        self.assertEqual([row["status"] for row in client.usage], ["error", "fallback"])
        self.assertEqual(client.usage[0]["error_code"], "NETWORK_TIMEOUT")
        self.assertEqual(client.usage[1]["model"], "fallback-model")

    def test_invalid_output_is_not_hidden_by_fallback(self):
        config = ModelConfig(fallback=(ProviderSpec("anthropic", "fallback-model"),), max_attempts=2)
        transport = FakeTransport(
            Step(raw=dict(OPENAI_DONE_RAW, choices=[{"finish_reason": "stop", "message": {"content": '{"severity": "BANANA"}'}}])),
            Step(raw=ANTHROPIC_DONE_RAW),
        )
        client = ModelClient(config, transport)
        response = client.complete(request(), Budget(1.0), validate=validate_model_output)
        self.assertEqual(response["finish_reason"], "invalid_output")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual([row["status"] for row in client.usage], ["ok"])

    def test_fallback_attempts_are_capped_by_config(self):
        config = ModelConfig(
            fallback=(ProviderSpec("anthropic", "fallback-1"), ProviderSpec("openai", "fallback-2")),
            max_attempts=2,
        )
        transport = FakeTransport(
            Step(error=ProviderError("NETWORK_TIMEOUT", "primary")),
            Step(error=ProviderError("NETWORK_TIMEOUT", "fallback-1")),
            Step(raw=OPENAI_DONE_RAW),
        )
        client = ModelClient(config, transport)
        response = client.complete(request(), Budget(1.0))
        self.assertEqual(response["finish_reason"], "provider_error")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual([row["status"] for row in client.usage], ["error", "error"])

    def test_fallback_is_off_without_config_or_policy(self):
        for config in (ModelConfig(), ModelConfig(allow_fallback=False, fallback=(ProviderSpec("anthropic", "x"),))):
            with self.subTest(config=config):
                transport = FakeTransport(
                    Step(error=ProviderError("RATE_LIMITED", "slow down")),
                    Step(raw=ANTHROPIC_DONE_RAW),
                )
                client = ModelClient(config, transport)
                response = client.complete(request(), Budget(1.0))
                self.assertEqual(response["finish_reason"], "provider_error")
                self.assertEqual(response["error"]["code"], "RATE_LIMITED")
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(validate_response(response), [])


class SeverityFallback(unittest.TestCase):
    def test_first_failure_records_unrated_with_raw_signals(self):
        store = AssessmentStore()
        transport = FakeTransport(Step(error=ProviderError("TOOL_UNAVAILABLE", "provider down")))
        client = ModelClient(ModelConfig(), transport)
        row, appended = assess_finding(
            store=store, client=client, finding=finding(), **assessment_kwargs()
        )
        self.assertTrue(appended)
        self.assertEqual(validate_row(row), [])
        self.assertEqual(row["severity"], "UNRATED")
        self.assertNotIn("source_refs", row)
        self.assertEqual(row["raw_signals"], finding()["raw_signals"])
        self.assertEqual(row["assessed_by"], {"kind": "rule"})
        self.assertEqual(row["dedup_key"], f"severity:{FINDING_ID}:3")
        self.assertEqual(row["failure"]["code"], "TOOL_UNAVAILABLE")
        self.assertEqual(row["failure"]["finish_reason"], "provider_error")
        self.assertEqual(row["failure"]["attempt"], 1)
        self.assertEqual(store.rows, [row])
        self.assertEqual([usage["status"] for usage in client.usage], ["error"])

    def test_budget_denied_assessment_has_no_finish_reason(self):
        store = AssessmentStore()
        transport = FakeTransport()
        client = ModelClient(ModelConfig(), transport)
        row, appended = assess_finding(
            store=store, client=client, finding=finding(), **assessment_kwargs(budget=Budget(0.0))
        )
        self.assertTrue(appended)
        self.assertEqual(transport.calls, [])
        self.assertEqual(validate_row(row), [])
        self.assertEqual(row["severity"], "UNRATED")
        self.assertEqual(row["failure"]["code"], "POLICY_DENIED")
        self.assertNotIn("finish_reason", row["failure"])

    def test_success_marks_agent_origin_and_keeps_snapshot(self):
        store = AssessmentStore()
        transport = FakeTransport(Step(raw=ASSESSMENT_RAW, latency_ms=1000))
        client = ModelClient(ModelConfig(), transport)
        row, appended = assess_finding(
            store=store, client=client, finding=finding(), **assessment_kwargs(trigger="operator_request")
        )
        self.assertTrue(appended)
        self.assertEqual(validate_row(row), [])
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["source_refs"], MODEL_OUTPUT["source_refs"])
        self.assertEqual(row["trigger"], "operator_request")
        self.assertEqual(row["inputs"], finding()["inputs"])
        self.assertEqual(row["assessed_by"]["kind"], "agent")
        self.assertEqual(row["assessed_by"]["session_id"], SESSION_ID)
        self.assertEqual(row["assessed_by"]["model"], "configured-model-2026-01-01")
        self.assertEqual(row["assessed_by"]["prompt_version"], "severity-v1")
        self.assertNotIn("failure", row)
        self.assertNotIn("raw_signals", row)

    def test_reassessment_is_a_new_row_and_same_revision_is_deduplicated(self):
        store = AssessmentStore()
        first_client = ModelClient(ModelConfig(), FakeTransport(Step(error=ProviderError("NETWORK_TIMEOUT", "down"))))
        first, appended = assess_finding(store=store, client=first_client, finding=finding(3), **assessment_kwargs())
        self.assertTrue(appended)
        snapshot = copy.deepcopy(first)

        retry_client = ModelClient(ModelConfig(), FakeTransport(Step(raw=ASSESSMENT_RAW)))
        same, appended = assess_finding(store=store, client=retry_client, finding=finding(3), **assessment_kwargs())
        self.assertFalse(appended)
        self.assertIs(same, first)
        self.assertEqual(retry_client.usage, [])
        self.assertEqual(len(store.rows), 1)

        second_client = ModelClient(ModelConfig(), FakeTransport(Step(raw=ASSESSMENT_RAW, latency_ms=800)))
        newer, appended = assess_finding(store=store, client=second_client, finding=finding(4), **assessment_kwargs())
        self.assertTrue(appended)
        self.assertEqual(len(store.rows), 2)
        self.assertEqual(store.rows[0], snapshot)
        self.assertIsNot(newer, first)
        self.assertEqual(newer["severity"], "HIGH")
        self.assertEqual(newer["input_revision"], 4)
        self.assertEqual(newer["dedup_key"], severity_dedup_key(FINDING_ID, 4))

    def test_source_refs_are_required_without_failure_and_forbidden_with_it(self):
        base = {
            "severity": "HIGH",
            "reasons": ["có căn cứ"],
            "source_refs": [{"kind": "evidence", "ref": EVIDENCE_ID}],
            "uncertainty": [],
            "recommended_actions": [],
            "inputs": {"scanner_severity": "high"},
            "trigger": "scan",
            "input_revision": 3,
            "dedup_key": severity_dedup_key(FINDING_ID, 3),
            "assessed_by": {"kind": "rule"},
        }
        self.assertEqual(validate_row(base), [])
        without_refs = copy.deepcopy(base)
        del without_refs["source_refs"]
        self.assertTrue(validate_row(without_refs))

        unrated = copy.deepcopy(base)
        del unrated["source_refs"]
        unrated.update(
            severity="UNRATED",
            raw_signals=[{"kind": "finding", "ref": FINDING_ID}],
            failure={"code": "INTERNAL_ERROR", "message": "thất bại", "attempt": 1},
        )
        self.assertEqual(validate_row(unrated), [])
        with_refs = copy.deepcopy(unrated)
        with_refs["source_refs"] = base["source_refs"]
        self.assertTrue(validate_row(with_refs))
        agent_origin = copy.deepcopy(unrated)
        agent_origin["assessed_by"] = {
            "kind": "agent",
            "session_id": SESSION_ID,
            "model": "configured-model",
            "prompt_version": "severity-v1",
        }
        self.assertTrue(validate_row(agent_origin))


if __name__ == "__main__":
    unittest.main()
