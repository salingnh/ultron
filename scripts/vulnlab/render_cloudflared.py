#!/usr/bin/env python3
"""Render the documented mirror of the Cloudflare Tunnel ingress (G1.6 slice E).

The tunnel is **remotely managed**: ingress rules live in the Cloudflare dashboard, not in a local
file. This script therefore has no runtime role - `make vulnlab-up` neither renders nor mounts an
ingress file. It renders the template against `deploy/vulnlab/.env` so the mirror can be compared
with the dashboard, or saved outside the repository with `--out`.

The token is not read at all here: it is input to cloudflared, not to the ingress. Every hostname
placeholder must be filled with a valid lowercase FQDN; a leftover `@AEGIS_...@` is an error, not an
empty hostname.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.vulnlab.catalog import CATALOG_PATH, HOSTNAME, load_catalog  # noqa: E402

DEFAULT_ENV = REPO / "deploy" / "vulnlab" / ".env"
DEFAULT_TEMPLATE = REPO / "deploy" / "vulnlab" / "cloudflared" / "config.yml.template"
PLACEHOLDER = re.compile(r"@AEGIS_[A-Z0-9_]+@")


class RenderError(RuntimeError):
    """The mirror cannot be rendered; the message names the variable or the placeholder."""


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


def render(env_path: Path = DEFAULT_ENV, template_path: Path = DEFAULT_TEMPLATE) -> str:
    """The template with every `@AEGIS_...@` hostname placeholder filled from `env_path`."""
    values = read_env(env_path)
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
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the mirror here instead of stdout (keep it outside the repository)",
    )
    arguments = parser.parse_args(argv)
    try:
        rendered = render(arguments.env_file, arguments.template)
    except (RenderError, OSError) as error:
        print(f"[vulnlab] render error: {error}", file=sys.stderr)
        return 1
    if arguments.out is None:
        print(rendered, end="")
        return 0
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(rendered, encoding="utf-8")
    print(f"[vulnlab] documented ingress mirror written: {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
