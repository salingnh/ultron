"""BBOT NDJSON -> ResultEnvelope, validated against the v2 contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from aegis_g02 import bbot_map

JOB_ID = "0192f0aa-0000-7000-8000-000000000001"
CAMPAIGN_ID = "0192f0aa-0000-7000-8000-000000000002"
SCOPE_ID = "0192f0aa-0000-7000-8000-000000000003"


def build(fixture: Path) -> dict:
    events = bbot_map.read_events(fixture)
    parsed = bbot_map.map_events(events, observed_at="2026-11-20T00:00:00Z")
    payload = fixture.read_bytes()
    return bbot_map.build_envelope(
        parsed,
        job_id=JOB_ID,
        campaign_id=CAMPAIGN_ID,
        scope_id=SCOPE_ID,
        capability="dns.enumerate_subdomains",
        provider={
            "name": "bbot",
            "version": "3.0.2",
            "adapter_version": "0.1.0",
            "image_digest": "sha256:" + "a" * 64,
        },
        policy_version="roe-1",
        seed_targets=["dns:acme-lab.example"],
        input_fingerprint=hashlib.sha256(payload).hexdigest(),
        started_at="2026-11-20T00:00:00Z",
        finished_at="2026-11-20T00:01:00Z",
        trace_id="b" * 32,
    )


def test_envelope_validates_against_contract(bbot_fixture: Path, envelope_schema: dict, contracts_dir: Path):
    envelope = build(bbot_fixture)
    # Resolve the contracts/-relative $refs with a referencing registry.
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    resources = []
    for path in contracts_dir.rglob("*.schema.json"):
        doc = json.loads(path.read_text())
        rel = path.relative_to(contracts_dir).as_posix()
        uri = f"https://aegis.io/contracts/{rel}"
        resources.append((uri, Resource.from_contents(doc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)
    validator = Draft202012Validator(envelope_schema, registry=registry, format_checker=FormatChecker())
    # The schema's own $id anchors internal $refs; validate through it.
    errors = sorted(validator.iter_errors(envelope), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)
    assert json.loads(json.dumps(envelope)) == envelope  # JSON round-trip safe


def test_mapping_content(bbot_fixture: Path):
    envelope = build(bbot_fixture)
    assets = {(a["kind"], a["canonical_key"]) for a in envelope["results"]["assets"]}
    assert ("domain", "dns:www.acme-lab.example") in assets
    assert ("domain", "dns:api.acme-lab.example") in assets
    assert ("ip", "ip:192.0.2.10") in assets
    assert ("service", "service:192.0.2.10:443/tcp") in assets
    assert ("url", "url:https://www.acme-lab.example:443/") in assets
    assert ("email", "email:security@acme-lab.example") in assets

    rels = {(r["type"], r["from"], r["to"]) for r in envelope["results"]["relationships"]}
    assert ("SUBDOMAIN_OF", "dns:www.acme-lab.example", "dns:acme-lab.example") in rels
    assert ("RESOLVES_TO", "dns:www.acme-lab.example", "ip:192.0.2.10") in rels
    assert ("EXPOSES", "ip:192.0.2.10", "service:192.0.2.10:443/tcp") in rels
    assert ("HAS_ENDPOINT", "app:https://www.acme-lab.example:443", "url:https://www.acme-lab.example:443/") in rels

    predicates = {o["predicate"] for o in envelope["results"]["observations"]}
    assert {"net.port_state", "http.status", "http.technology", "net.asn", "dns.resolves"} <= predicates

    assert envelope["provenance"]["seed_targets"] == ["dns:acme-lab.example"]
    assert envelope["dedup_key"] == f"job:{JOB_ID}:envelope"
    # The fixture contains one FINDING event with no mapping yet: the envelope
    # must say partial instead of dropping data silently.
    assert envelope["status"] == "partial"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", envelope["event_id"])


def test_repeat_mapping_is_stable(bbot_fixture: Path):
    first = build(bbot_fixture)
    second = build(bbot_fixture)
    first.pop("event_id"), second.pop("event_id")
    assert first == second
