#!/usr/bin/env python3
"""Check the owner's LLM gateway files before a container exists (G1.6).

    python3 scripts/llm-gateway/validate.py <config.yaml> <secrets.env>

`make llm-gateway-up` and `make llm-gateway-reload` run this first: a typo in the routing order or
a key name that is not in secrets.env would otherwise surface as a proxy that starts and then
fails the first campaign, minutes later. Everything checked here is a property this repository
relies on, not a general LiteLLM linter:

* the master key exists (a proxy without one answers anyone on the loopback port);
* every deployment is reachable: `api_key` names a variable that secrets.env really sets;
* every endpoint is priced, so the gateway can report a real per-request cost (helper only - M04
  falls back to its own price and says so, but a missing price means the invoice and the ledger
  disagree);
* every routing group member exists, priorities cover exactly the members, and there is at least
  one group (the client asks for a group name, never an endpoint);
* retries are bounded (`num_retries`/`max_retries`), so an exhausted pool cannot become a storm;
* request/response bodies are never logged, and `/metrics` keeps its auth on.

Secrets are read to check that a name exists and is non-empty; no value is printed.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - the gate installs PyYAML, a host may not have it
    print(
        "validate: PyYAML is missing; run through `make llm-gateway-*` (uv) or install pyyaml",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

ENV_REFERENCE = "os.environ/"


class Report:
    """Errors stop the stack; warnings are printed and the stack starts."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def parse_secrets(path: Path) -> dict[str, str]:
    """`KEY=VALUE` lines of a secrets file; a duplicate or malformed line is an error, not a guess."""
    secrets: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path.name}:{number}: expected KEY=VALUE")
        name, _, value = line.partition("=")
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if not name or any(character.isspace() for character in name):
            raise ValueError(f"{path.name}:{number}: '{name}' is not a variable name")
        if name in secrets:
            raise ValueError(f"{path.name}:{number}: {name} is set twice")
        secrets[name] = value
    return secrets


def reference(value: Any) -> str | None:
    """The variable a config value names, when it is an `os.environ/NAME` reference."""
    if isinstance(value, str) and value.startswith(ENV_REFERENCE):
        return value[len(ENV_REFERENCE) :].strip()
    return None


def check_key(
    report: Report, secrets: Mapping[str, str], where: str, value: Any, *, required: bool
) -> None:
    if value is None and not required:
        return
    name = reference(value)
    if name is None:
        report.error(f"{where}: set it to os.environ/<NAME>, never a literal key in config.yaml")
        return
    if name not in secrets:
        report.error(f"{where}: {name} is not set in secrets.env")
    elif not secrets[name]:
        report.error(f"{where}: {name} is empty in secrets.env")


def positive_price(report: Report, where: str, info: Mapping[str, Any], name: str) -> bool:
    value = info.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return False
    return True


def check(document: Mapping[str, Any], secrets: Mapping[str, str]) -> Report:
    report = Report()

    general = document.get("general_settings") or {}
    check_key(
        report, secrets, "general_settings.master_key", general.get("master_key"), required=True
    )
    if general.get("disable_spend_logs") is not True:
        report.error(
            "general_settings.disable_spend_logs: set it to true - this deployment has no database"
        )

    settings = document.get("litellm_settings") or {}
    if settings.get("turn_off_message_logging") is not True:
        report.error(
            "litellm_settings.turn_off_message_logging: set it to true - prompts and answers "
            "contain scan data and must never be logged"
        )
    if settings.get("require_auth_for_metrics_endpoint") is not True:
        report.error(
            "litellm_settings.require_auth_for_metrics_endpoint: keep /metrics behind the master key"
        )
    callbacks = settings.get("callbacks") or []
    if "prometheus" not in callbacks:
        report.warn(
            "litellm_settings.callbacks: 'prometheus' is missing - "
            "`make llm-gateway-status` cannot show which endpoint is cooling down"
        )

    deployments = document.get("model_list") or []
    if not isinstance(deployments, list) or not deployments:
        report.error("model_list: at least one endpoint is required")
        deployments = []

    names: dict[str, str] = {}
    ids: set[str] = set()
    unpriced: list[str] = []
    for index, entry in enumerate(deployments):
        if not isinstance(entry, Mapping):
            report.error(f"model_list[{index}]: expected a mapping")
            continue
        model_name = str(entry.get("model_name") or "").strip()
        params = entry.get("litellm_params") or {}
        info = entry.get("model_info") or {}
        label = f"model_list[{index}]({model_name or 'unnamed'})"
        if not model_name:
            report.error(f"{label}: model_name is required (the routing group refers to it)")
        elif model_name in names:
            report.error(f"{label}: model_name {model_name!r} is used twice")
        else:
            names[model_name] = label
        if not str(params.get("model") or "").strip():
            report.error(f"{label}: litellm_params.model is required (e.g. openai/gpt-4o-mini)")
        check_key(
            report,
            secrets,
            f"{label}.litellm_params.api_key",
            params.get("api_key"),
            required=True,
        )
        if params.get("max_retries") not in (0, "0", None):
            report.error(
                f"{label}.litellm_params.max_retries: set it to 0 - an endpoint is attempted once "
                "per request; the next endpoint in the group is the retry"
            )
        deployment_id = str(info.get("id") or model_name)
        if deployment_id in ids:
            report.error(f"{label}.model_info.id: {deployment_id!r} is used twice")
        ids.add(deployment_id)
        if not (
            positive_price(report, label, info, "input_cost_per_token")
            and positive_price(report, label, info, "output_cost_per_token")
        ):
            unpriced.append(model_name or label)
    if unpriced:
        report.warn(
            "no per-endpoint price (input_cost_per_token/output_cost_per_token) for "
            + ", ".join(unpriced)
            + ": the gateway reports 0 for those endpoints and M04 records its configured price"
        )

    router = document.get("router_settings") or {}
    if router.get("num_retries") not in (0, "0", None):
        report.error(
            "router_settings.num_retries: set it to 0 - rotation across the group is the retry, "
            "and retrying inside one endpoint is how a retry storm starts"
        )
    groups = router.get("routing_groups") or []
    if not isinstance(groups, list) or not groups:
        report.error(
            "router_settings.routing_groups: add one - ultron asks for a group name, and the "
            "group's model_priorities are the ordered fallback"
        )
        groups = []
    for index, group in enumerate(groups):
        if not isinstance(group, Mapping):
            report.error(f"routing_groups[{index}]: expected a mapping")
            continue
        group_name = str(group.get("group_name") or "").strip()
        label = f"routing_groups[{index}]({group_name or 'unnamed'})"
        members = [str(member) for member in (group.get("models") or [])]
        if not group_name:
            report.error(f"{label}: group_name is required")
        if not members:
            report.error(f"{label}: models is required")
        for member in members:
            if member not in names:
                report.error(f"{label}: {member!r} is not a model_list model_name")
        strategy = group.get("routing_strategy")
        if strategy != "priority":
            report.warn(
                f"{label}: routing_strategy is {strategy!r}; only 'priority' makes the fallback "
                "order deterministic"
            )
        priorities = group.get("model_priorities") or {}
        if strategy == "priority":
            if set(priorities) != set(members):
                report.error(
                    f"{label}: model_priorities must name exactly the group's models "
                    f"({', '.join(members) or 'none'})"
                )
            elif sorted(priorities.values()) != sorted(set(priorities.values())):
                report.warn(
                    f"{label}: two endpoints share a priority, so they share traffic instead of "
                    "falling back in order"
                )
    if len(deployments) < 2:
        report.error(
            "model_list: one endpoint cannot rotate; add a second one (that is the point of the "
            "gateway)"
        )
    return report


def summarise(document: Mapping[str, Any]) -> str:
    groups = (document.get("router_settings") or {}).get("routing_groups") or []
    deployments = document.get("model_list") or []
    order = []
    for group in groups:
        if not isinstance(group, Mapping):
            continue
        priorities = group.get("model_priorities") or {}
        ordered = sorted(priorities, key=lambda name: priorities[name])
        order.append(f"{group.get('group_name')}: {' -> '.join(ordered)}")
    return (
        f"config ok: {len(deployments)} endpoints, " + "; ".join(order) + "; "
        "message logging off, /metrics behind the master key"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    config_path, secrets_path = Path(argv[1]), Path(argv[2])
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        print(f"config: {config_path}: {error}", file=sys.stderr)
        return 2
    if not isinstance(document, Mapping):
        print(f"config: {config_path}: the document must be a mapping", file=sys.stderr)
        return 2
    try:
        secrets = parse_secrets(secrets_path)
    except (OSError, ValueError) as error:
        print(f"secrets: {error}", file=sys.stderr)
        return 2

    report = check(document, secrets)
    for warning in report.warnings:
        print(f"validate: warning: {warning}", file=sys.stderr)
    if report.errors:
        for error in report.errors:
            print(f"validate: error: {error}", file=sys.stderr)
        return 2
    print(f"validate: {summarise(document)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
