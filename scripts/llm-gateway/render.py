#!/usr/bin/env python3
"""Render what the gateway container starts from (G1.6).

    python3 scripts/llm-gateway/render.py \\
        --config ~/.config/ultron/llm-gateway/config.yaml \\
        --base deploy/llm-gateway/base.yaml \\
        --out-dir .local/llm-gateway [--expect-group aegis-smart]

Two inputs, two owners:

* the owner's `config.yaml` (outside the checkout) lists endpoints and their order only;
* `deploy/llm-gateway/base.yaml` holds the defaults that must never vary per deployment (no
  request/response body logging, one attempt per endpoint, a cooldown after a failure, /metrics
  behind the master key, no spend log, and the master key).

This script merges them into the one document the proxy boots with, and writes the environment file
the container gets: exactly the variables that document references through `os.environ/<NAME>`, taken
from this process's environment (the checkout's `.env`, which the calling script sourced). The whole
`.env` is never handed over, and no value is printed - not here, not by any caller.

Two files land in `--out-dir`:

    config.yaml    the effective LiteLLM config (variable NAMES only, no secrets)
    gateway.env    KEY=VALUE for the referenced names only, mode 0600

Every refusal names the line to fix and exits 2, because a gateway that starts with a silently
ignored setting is worse than one that does not start at all.
"""

from __future__ import annotations

import argparse
import copy
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - the gate installs PyYAML, a host may not have it
    print(
        "render: PyYAML is missing; run through `make llm-gateway-*` (uv) or install pyyaml",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

ENV_REFERENCE = "os.environ/"
DEFAULT_TIMEOUT = 120

#: What the owner's file may contain. Everything else belongs to base.yaml (or is a typo).
TOP_LEVEL_KEYS = {"group", "endpoints"}
ENDPOINT_KEYS = {
    "name",
    "model",
    "api_base",
    "api_key",
    "timeout",
    "input_cost_per_token",
    "output_cost_per_token",
}
PRICE_KEYS = ("input_cost_per_token", "output_cost_per_token")

#: Keys the owner's file used to hold, with what to do instead - the cutover is a file edit, so the
#: error has to say where the setting went.
MOVED_KEYS = {
    "model_list": (
        "each endpoint is now one item under `endpoints` "
        "(name, model, api_base, api_key, optional prices)"
    ),
    "router_settings": (
        "the order is the order of `endpoints`; retry/cooldown defaults are fixed in "
        "deploy/llm-gateway/base.yaml"
    ),
    "litellm_settings": "privacy/metrics defaults are fixed in deploy/llm-gateway/base.yaml",
    "general_settings": (
        "the master key is fixed to AEGIS_MODEL_API_KEY (the same .env value ultron sends) "
        "in deploy/llm-gateway/base.yaml"
    ),
}


class Refused(Exception):
    """The owner's configuration cannot become a gateway; the message says what to change."""


def load_document(path: Path, label: str) -> Mapping[str, Any]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise Refused(f"{label}: {path}: {error}") from None
    except yaml.YAMLError as error:
        raise Refused(f"{label}: {path}: not valid YAML: {error}") from None
    if not isinstance(document, Mapping):
        raise Refused(f"{label}: {path}: the document must be a mapping")
    return document


def env_reference(value: Any) -> str | None:
    """The variable a config value names, when it is an `os.environ/NAME` reference."""
    if isinstance(value, str) and value.startswith(ENV_REFERENCE):
        return value[len(ENV_REFERENCE) :].strip()
    return None


def check_unknown(where: str, keys: set[str], allowed: set[str]) -> None:
    unknown = sorted(keys - allowed)
    if not unknown:
        return
    hints = [f"{key}: {MOVED_KEYS[key]}" for key in unknown if key in MOVED_KEYS]
    detail = f" ({'; '.join(hints)})" if hints else ""
    raise Refused(
        f"{where}: {', '.join(unknown)} is not allowed here{detail}. "
        f"This file holds only {', '.join(sorted(allowed))}."
    )


def price(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise Refused(f"{where}: expected a positive number of USD per token")
    return float(value)


def render_endpoint(index: int, entry: Any) -> dict[str, Any]:
    where = f"endpoints[{index}]"
    if not isinstance(entry, Mapping):
        raise Refused(f"{where}: expected a mapping (name, model, api_key, ...)")
    check_unknown(where, set(entry), ENDPOINT_KEYS)

    name = str(entry.get("name") or "").strip()
    if not name:
        raise Refused(f"{where}: `name` is required (it is what the status table shows)")
    where = f"endpoints[{index}]({name})"

    model = str(entry.get("model") or "").strip()
    if not model:
        raise Refused(f"{where}: `model` is required, e.g. openai/gpt-4o-mini or anthropic/claude-...")

    key_name = env_reference(entry.get("api_key"))
    if key_name is None:
        raise Refused(
            f"{where}: `api_key` must name a variable, written os.environ/LLM_KEY_A - never a "
            "literal key (this file is not the place for secrets)"
        )
    if not key_name:
        raise Refused(f"{where}: `api_key` names an empty variable")

    params: dict[str, Any] = {"model": model, "api_key": ENV_REFERENCE + key_name}
    api_base = entry.get("api_base")
    if api_base is not None:
        base = str(api_base).strip()
        if not base.startswith(("http://", "https://")):
            raise Refused(f"{where}: `api_base` must be an http(s) URL, got {base!r}")
        params["api_base"] = base
    timeout = entry.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise Refused(f"{where}: `timeout` must be a positive number of seconds")
    params["timeout"] = int(timeout)
    # One attempt per endpoint: the next endpoint in the group is the retry.
    params["max_retries"] = 0

    info: dict[str, Any] = {"id": name}
    given = [key for key in PRICE_KEYS if entry.get(key) is not None]
    if given and len(given) != len(PRICE_KEYS):
        missing = ", ".join(key for key in PRICE_KEYS if key not in given)
        raise Refused(
            f"{where}: set both prices or neither (missing {missing}); a half-priced endpoint "
            "reports a wrong cost instead of none"
        )
    for key in given:
        info[key] = price(entry[key], f"{where}.{key}")

    return {"model_name": name, "litellm_params": params, "model_info": info}


def render(owner: Mapping[str, Any], base: Mapping[str, Any], expect_group: str | None) -> dict:
    check_unknown("config.yaml", set(owner), TOP_LEVEL_KEYS)

    group = str(owner.get("group") or "").strip()
    if not group:
        raise Refused("config.yaml: `group` is required (it is the name ultron asks for)")
    if expect_group and group != expect_group:
        raise Refused(
            f"config.yaml: group is {group!r} but AEGIS_MODEL_NAME in .env is {expect_group!r}; "
            "they must be the same routing group"
        )

    entries = owner.get("endpoints")
    if not isinstance(entries, list) or not entries:
        raise Refused("config.yaml: `endpoints` must be a non-empty list")
    model_list = [render_endpoint(index, entry) for index, entry in enumerate(entries)]
    repeated = sorted(name for name, count in Counter(e["model_name"] for e in model_list).items() if count > 1)
    if repeated:
        raise Refused(f"config.yaml: endpoint name {', '.join(repeated)} is used twice")

    # The fixed defaults are the floor: without them the container would boot with a shape this
    # repository never tested, so their absence is a repository bug, not an owner error.
    for section in ("router_settings", "litellm_settings", "general_settings"):
        if not isinstance(base.get(section), Mapping) or not base[section]:
            raise Refused(f"base.yaml: {section} is missing - this is a repository bug")

    router: dict[str, Any] = copy.deepcopy(dict(base["router_settings"]))
    router["routing_groups"] = [
        {
            "group_name": group,
            "models": [entry["model_name"] for entry in model_list],
            "routing_strategy": "priority",
            # List order is the priority: one endpoint per number, lower first.
            "model_priorities": {
                entry["model_name"]: index for index, entry in enumerate(model_list, start=1)
            },
        }
    ]
    return {
        "model_list": model_list,
        "router_settings": router,
        "litellm_settings": copy.deepcopy(dict(base["litellm_settings"])),
        "general_settings": copy.deepcopy(dict(base["general_settings"])),
    }


def referenced_names(document: Any) -> list[str]:
    """Every `os.environ/<NAME>` the effective document refers to, sorted and unique."""
    names: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        else:
            name = env_reference(node)
            if name:
                names.add(name)

    walk(document)
    return sorted(names)


def write_private(path: Path, text: str) -> None:
    """Write a file only the current user can read, atomically (never a readable half-file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def gateway_environment(names: list[str], source: Mapping[str, str]) -> str:
    """The `KEY=VALUE` lines the container gets: the referenced names, nothing else."""
    missing = [name for name in names if not source.get(name)]
    if missing:
        raise Refused(
            f".env: {', '.join(missing)} is referenced by config.yaml but not set (or empty) there. "
            "Add the key to the checkout's .env - it is the only file that holds secrets."
        )
    lines = []
    for name in names:
        value = source[name]
        if "\n" in value or "\r" in value:
            raise Refused(f".env: {name} must be a single line (a newline would inject a setting)")
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="render the LLM gateway config and environment")
    parser.add_argument("--config", required=True, type=Path, help="the owner's config.yaml")
    parser.add_argument("--base", required=True, type=Path, help="deploy/llm-gateway/base.yaml")
    parser.add_argument("--out-dir", required=True, type=Path, help="where the two files are written")
    parser.add_argument(
        "--expect-group",
        default="",
        help="the routing group name ultron asks for (AEGIS_MODEL_NAME); a mismatch is refused",
    )
    arguments = parser.parse_args(argv[1:])

    try:
        owner = load_document(arguments.config, "config")
        base = load_document(arguments.base, "base")
        document = render(owner, base, arguments.expect_group or None)
        names = referenced_names(document)
        environment = gateway_environment(names, dict(os.environ))
    except Refused as refusal:
        print(f"render: {refusal}", file=sys.stderr)
        return 2

    arguments.out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(arguments.out_dir, 0o700)
    (arguments.out_dir / "config.yaml").write_text(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    write_private(arguments.out_dir / "gateway.env", environment)

    group = document["router_settings"]["routing_groups"][0]
    order = " -> ".join(group["models"])
    print(
        f"render: group {group['group_name']}, {len(document['model_list'])} endpoints "
        f"({order}); {len(names)} variables from .env: {', '.join(names)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
