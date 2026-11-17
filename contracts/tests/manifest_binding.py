"""Offline conformance checks for the immutable manifest selected by M05.

This validates contract artifacts, not executor behavior or HMAC signatures.
"""
from __future__ import annotations

import hashlib

import yaml


def manifest_sha256(raw: bytes) -> str:
    """Hash the exact stored manifest bytes; do not reserialize YAML first."""
    return hashlib.sha256(raw).hexdigest()


def check_manifest_binding(task: dict, raw: bytes) -> list[str]:
    """Call after schema validation of both the task and its manifest."""
    try:
        manifest = yaml.safe_load(raw)
    except yaml.YAMLError:
        return ["manifest is not valid YAML"]
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    meta = manifest.get("metadata", {})
    spec = manifest.get("spec", {})
    expected = {
        "manifest_sha256": manifest_sha256(raw),
        "provider": meta.get("name"),
        "adapter_version": meta.get("version"),
        "capability": spec.get("capability"),
        "provider_version": spec.get("providerVersion"),
        "image_digest": spec.get("runtime", {}).get("imageDigest"),
    }
    return [f"{field}: task does not match pinned manifest"
            for field, value in expected.items() if task.get(field) != value]
