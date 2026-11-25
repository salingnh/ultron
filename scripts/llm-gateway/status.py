#!/usr/bin/env python3
"""Print the gateway's routing state: every endpoint, its order, and whether it is cooling down.

    python3 scripts/llm-gateway/status.py <config.yaml> <model_info.json> <metrics.txt>

The proxy does not expose a "cooling down" API, but the Prometheus callback it is configured with
does: `litellm_deployment_state` is 0 (healthy), 1 (partial) or 2 (complete outage / cooling down)
per deployment, and `litellm_deployment_cooled_down_total` counts how often each one was cooled and
why. Both are keyed by the `model_info.id` this repository's example config sets, so the table below
matches the owner's YAML line by line. No request is sent from here: reading the state costs
nothing and cannot spend quota.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

STATE_NAMES = {0: "healthy", 1: "partial", 2: "cooling down"}
METRIC = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?P<labels>.*)\})?\s+(?P<value>[-\d.eE+]+)$"
)
LABEL = re.compile(r'(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>[^"]*)"')


def metric_rows(text: str) -> list[tuple[str, dict[str, str], float]]:
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC.match(line.strip())
        if match is None:
            continue
        labels = {
            item.group("key"): item.group("value")
            for item in LABEL.finditer(match.group("labels") or "")
        }
        rows.append((match.group("name"), labels, float(match.group("value"))))
    return rows


def states(rows: list[tuple[str, dict[str, str], float]]) -> dict[str, tuple[int, float]]:
    """model_id -> (state, cooldown count); the state label wins when a metric repeats."""
    by_id: dict[str, tuple[int, float]] = {}
    for name, labels, value in rows:
        model_id = labels.get("model_id")
        if not model_id:
            continue
        if name == "litellm_deployment_state":
            by_id[model_id] = (int(value), by_id.get(model_id, (0, 0.0))[1])
        elif name == "litellm_deployment_cooled_down_total":
            current = by_id.get(model_id, (0, 0.0))[0]
            by_id[model_id] = (current, by_id.get(model_id, (0, 0.0))[1] + value)
    return by_id


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    config = yaml.safe_load(Path(argv[1]).read_text(encoding="utf-8")) or {}
    info = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    rows = metric_rows(Path(argv[3]).read_text(encoding="utf-8"))

    deployments: dict[str, Mapping[str, Any]] = {}
    for entry in info.get("data") or []:
        params = entry.get("litellm_params") or {}
        metadata = entry.get("model_info") or {}
        deployment_id = str(metadata.get("id") or entry.get("model_name"))
        deployments[deployment_id] = {
            "model_name": entry.get("model_name"),
            "model": params.get("model"),
            "api_base": params.get("api_base"),
            "input_cost": metadata.get("input_cost_per_token"),
            "output_cost": metadata.get("output_cost_per_token"),
        }

    observed = states(rows)
    groups = (config.get("router_settings") or {}).get("routing_groups") or []
    for group in groups:
        name = group.get("group_name")
        priorities = group.get("model_priorities") or {}
        ordered = sorted(group.get("models") or [], key=lambda member: priorities.get(member, 0))
        print(f"model group {name}  endpoints {len(ordered)}")
        for member in ordered:
            entry = deployments.get(member)
            if entry is None:
                print(f"  ['not loaded']  {member}: configured but absent from the proxy")
                continue
            seen = observed.get(member)
            cool_downs = 0.0 if seen is None else seen[1]
            # No sample yet is not "healthy": the proxy only writes the gauge once it has routed a
            # request (or cooled the endpoint down), and a status line must not invent a probe.
            label = (
                "no traffic yet"
                if seen is None
                else STATE_NAMES.get(seen[0], f"unknown({seen[0]})")
            )
            priced = entry["input_cost"] is not None and entry["output_cost"] is not None
            print(
                f"  priority {priorities.get(member, '?')}  [{label:12}]  {member}  "
                f"{entry['model']}  {entry['api_base'] or '(provider default)'}"
            )
            print(
                f"      cost: {'gateway-reported' if priced else 'not priced here, M04 price used'}"
                f"  cooldowns: {int(cool_downs)}"
            )
    if not groups:
        print("model group: none configured (router_settings.routing_groups is empty)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
