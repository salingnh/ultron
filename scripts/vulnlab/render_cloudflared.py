#!/usr/bin/env python3
"""Render the Cloudflare Tunnel ingress from `deploy/vulnlab/.env` (G1.6 slice E).

Run by `make vulnlab-up` when — and only when — `AEGIS_VULNLAB_TUNNEL_TOKEN` is set. The output is
`deploy/vulnlab/.run/cloudflared/config.yml`, the single read-only mount of the stack.

The token is never read beyond "is it present": it reaches cloudflared through the container
environment, not through this file, and nothing here prints it. Every hostname placeholder must be
filled with a valid lowercase FQDN; a leftover `@NAME@` is an error, not an empty hostname.

Cloudflare's token-managed ("remotely-managed") tunnels take their ingress from the dashboard, not
from a local file. The rendered ingress is therefore the source of truth the owner mirrors in the
dashboard; `make vulnlab-status` compares the dashboard-independent facts (which hostnames the lab
declares) and the first `make vulnlab-test PROFILE=internet` shows whether the live tunnel agrees.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.vulnlab.catalog import CATALOG_PATH, HOSTNAME, load_catalog  # noqa: E402

DEFAULT_ENV = REPO / "deploy" / "vulnlab" / ".env"
DEFAULT_TEMPLATE = REPO / "deploy" / "vulnlab" / "cloudflared" / "config.yml.template"
DEFAULT_OUT = REPO / "deploy" / "vulnlab" / ".run" / "cloudflared" / "config.yml"
PLACEHOLDER = re.compile(r"@AEGIS_[A-Z0-9_]+@")


class RenderError(RuntimeError):
    """The ingress cannot be rendered; the message names the variable or the placeholder."""


def read_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise RenderError(f"{path} is missing: run make vulnlab-up (it creates it from .env.example)")
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            raise RenderError(f"{path}: unsupported line {line!r} (expected NAME=value)")
        values[name.strip()] = value.strip()
    return values


def render(env_path: Path = DEFAULT_ENV, template_path: Path = DEFAULT_TEMPLATE, out_path: Path = DEFAULT_OUT) -> Path:
    values = read_env(env_path)
    if not values.get("AEGIS_VULNLAB_TUNNEL_TOKEN"):
        raise RenderError(
            "AEGIS_VULNLAB_TUNNEL_TOKEN is empty: the tunnel profile needs a token; without it the "
            "lab runs lab-only and no ingress is rendered"
        )
    catalog = load_catalog(CATALOG_PATH)
    rendered = template_path.read_text(encoding="utf-8")
    for case in catalog.cases:
        if case.host_env is None:
            continue
        hostname = (values.get(case.host_env) or "").strip().lower()
        if not hostname:
            raise RenderError(f"{case.host_env} is empty (case {case.id})")
        if not HOSTNAME.match(hostname):
            raise RenderError(f"{case.host_env} is not a lowercase FQDN: {hostname!r}")
        placeholder = f"@{case.host_env}@"
        if placeholder not in rendered:
            raise RenderError(f"{template_path} has no {placeholder} placeholder")
        rendered = rendered.replace(placeholder, hostname)
    leftover = sorted(set(PLACEHOLDER.findall(rendered)))
    if leftover:
        raise RenderError(f"{template_path}: placeholders without a value: {leftover}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    os.chmod(out_path, 0o644)
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    arguments = parser.parse_args(argv)
    try:
        written = render(arguments.env_file, arguments.template, arguments.out)
    except (RenderError, OSError) as error:
        print(f"[vulnlab] render error: {error}", file=sys.stderr)
        return 1
    print(f"[vulnlab] cloudflared ingress rendered: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
