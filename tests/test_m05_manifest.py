"""Manifest admission and the immutable registry (M05, OI-5/P7, OI-12, X-1 pins)."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from typing import Any

import pytest
import yaml

from aegis.m05_registry.manifest import (
    ManifestRejected,
    admit_manifest,
    manifest_sha256,
    parse_document,
    schema_reference_path,
)
from aegis.m05_registry.registry import (
    InMemoryManifestRegistry,
    ManifestNotFound,
    ManifestVersionConflict,
)
from tests.db_support import connect, migrated_database, requires_postgres
from tests.support import REPO_ROOT

FIXTURES = REPO_ROOT / "contracts/fixtures"
MODULE = "M05"


def _bytes(name: str) -> bytes:
    return (FIXTURES / "valid" / name).read_bytes()


def _reference() -> Any:
    path = REPO_ROOT / "contracts/tests/manifest_binding.py"
    spec = importlib.util.spec_from_file_location("aegis_manifest_binding_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REFERENCE = _reference()


@pytest.mark.parametrize(
    "name", ["manifest.subfinder.yaml", "manifest.dnsx.yaml", "manifest.naabu.yaml"]
)
def test_valid_fixtures_are_admitted_and_hash_their_bytes(name: str) -> None:
    raw = _bytes(name)
    record = admit_manifest(raw)
    assert record.sha256 == hashlib.sha256(raw).hexdigest()
    assert record.raw == raw
    assert record.pins()["manifest_sha256"] == manifest_sha256(raw)


def test_pins_match_the_conformance_reference_task() -> None:
    for provider in ("subfinder", "dnsx"):
        record = admit_manifest(_bytes(f"manifest.{provider}.yaml"))
        task = yaml.safe_load((FIXTURES / "valid" / f"approved-task.{provider}.json").read_text())
        assert REFERENCE.check_manifest_binding(task, record.raw) == []


def test_a_manifest_declaring_the_deny_set_is_refused() -> None:
    document = parse_document(_bytes("manifest.subfinder.yaml"))
    document["spec"]["permissions"]["egressSources"][0]["hosts"] = ["169.254.169.254"]
    with pytest.raises(ManifestRejected, match="deny set"):
        admit_manifest(yaml.safe_dump(document, sort_keys=False).encode())


@pytest.mark.parametrize(
    "fixture,message",
    [
        ("manifest.egress-source-in-deny-set.yaml", "deny set"),
        ("manifest.args-free-string.yaml", "argv"),
        ("manifest.args-embedded-placeholder.yaml", "placeholder"),
    ],
)
def test_the_contract_negative_fixtures_are_refused(fixture: str, message: str) -> None:
    raw = (FIXTURES / "invalid" / fixture).read_bytes()
    with pytest.raises(ManifestRejected, match=message):
        admit_manifest(raw)


def test_unknown_input_schema_is_refused() -> None:
    document = parse_document(_bytes("manifest.subfinder.yaml"))
    document["spec"]["inputSchemaRef"] = "schema://dns/does-not-exist/v2"
    with pytest.raises(ManifestRejected, match="does not resolve"):
        admit_manifest(yaml.safe_dump(document, sort_keys=False).encode())


def test_target_bound_manifest_needs_a_ports_input_field() -> None:
    document = parse_document(_bytes("manifest.naabu.yaml"))
    assert document["spec"]["permissions"]["targetBinding"] == "required"
    schema = schema_reference_path("schema://network/discover-services/v2")
    assert schema is not None
    # The fixture input schema has `ports`; without it the binding could not be built from input.
    document["spec"]["inputSchemaRef"] = "schema://dns/enumerate-subdomains/v2"
    with pytest.raises(ManifestRejected, match="ports"):
        admit_manifest(yaml.safe_dump(document, sort_keys=False).encode())


def test_duplicate_yaml_keys_are_refused() -> None:
    raw = _bytes("manifest.subfinder.yaml").replace(
        b"metadata:\n  name: subfinder\n",
        b"metadata:\n  name: subfinder\n  name: other\n",
    )
    with pytest.raises(ManifestRejected, match="repeats the YAML key"):
        admit_manifest(raw)


def test_non_object_and_non_utf8_manifests_are_refused() -> None:
    with pytest.raises(ManifestRejected, match="YAML object"):
        admit_manifest(b"- just\n- a list\n")
    with pytest.raises(ManifestRejected, match="UTF-8"):
        admit_manifest(b"\xff\xfe")


def test_in_memory_registry_is_immutable_by_bytes() -> None:
    registry = InMemoryManifestRegistry()
    registered_by = {"kind": "module", "id": MODULE}
    record = registry.register(_bytes("manifest.subfinder.yaml"), registered_by=registered_by)
    assert registry.register(record.raw, registered_by=registered_by) is record
    assert registry.get(record.sha256) is record
    assert registry.resolve("dns.enumerate_subdomains").sha256 == record.sha256
    with pytest.raises(ManifestNotFound, match="no 'latest' fallback"):
        registry.get("0" * 64)
    with pytest.raises(ManifestNotFound):
        registry.resolve("dns.resolve")

    changed = parse_document(record.raw)
    changed["spec"]["budget"]["cpu"] = 2
    with pytest.raises(ManifestVersionConflict, match="new adapter_version"):
        registry.register(
            yaml.safe_dump(changed, sort_keys=False).encode(),
            registered_by=registered_by,
        )


@requires_postgres
def test_postgres_registry_stores_exact_bytes_and_refuses_a_reused_version() -> None:
    from aegis.m05_registry.registry import PostgresManifestRegistry

    with migrated_database() as dsn:
        registry = PostgresManifestRegistry(lambda: connect(dsn))
        registered_by = {"kind": "module", "id": MODULE}
        raw = _bytes("manifest.subfinder.yaml")
        record = registry.register(raw, registered_by=registered_by)
        assert registry.register(raw, registered_by=registered_by).sha256 == record.sha256
        fetched = registry.get(record.sha256)
        assert fetched.raw == raw
        assert fetched.pins() == record.pins()
        assert registry.resolve("dns.enumerate_subdomains").sha256 == record.sha256

        changed = parse_document(raw)
        changed["spec"]["budget"]["cpu"] = 2
        with pytest.raises(ManifestVersionConflict):
            registry.register(
                yaml.safe_dump(changed, sort_keys=False).encode(),
                registered_by=registered_by,
            )

        with connect(dsn) as conn:
            stored = conn.execute(
                "SELECT manifest_sha256, encode(sha256(manifest_utf8), 'hex') "
                "FROM provider_manifest"
            ).fetchall()
            assert stored == [(record.sha256, record.sha256)]
            # Append-only: an accepted pin can never be edited or removed.
            with pytest.raises(Exception, match="append-only|forbid"):
                with conn.transaction():
                    conn.execute(
                        "UPDATE provider_manifest SET capability = 'dns.resolve' "
                        "WHERE manifest_sha256 = %s",
                        (record.sha256,),
                    )
            with pytest.raises(Exception, match="append-only|forbid"):
                with conn.transaction():
                    conn.execute(
                        "DELETE FROM provider_manifest WHERE manifest_sha256 = %s", (record.sha256,)
                    )
            # The hash must describe the bytes it names.
            with pytest.raises(Exception, match="sha256_describes_bytes"):
                with conn.transaction():
                    conn.execute(
                        "INSERT INTO provider_manifest (manifest_sha256, capability, provider, "
                        "provider_version, adapter_version, image_digest, input_schema_ref, "
                        "manifest_utf8, registered_by) VALUES (%s, 'dns.resolve', "
                        "'dnsx', 'v1.2.2', "
                        "'1.0.0', %s, 'schema://dns/resolve/v2', %s, '{\"kind\": \"module\", "
                        '"id": "M05"}\')',
                        ("f" * 64, "sha256:" + "1" * 64, raw),
                    )
