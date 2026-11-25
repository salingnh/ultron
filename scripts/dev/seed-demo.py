#!/usr/bin/env python3
"""Create a demo campaign through `POST /api/v2/campaigns` on the local stack.

    scripts/dev/seed-demo.py --api-url http://127.0.0.1:8000 --token <operator token>
    AEGIS_DEV_TOKEN=<token> make seed-demo          # same thing through make

The body is the contract's own valid `campaign-create` fixture, so the demo campaign can never
drift from the contract; only its name is made unique and its RoE is pinned to the lab network
profile (`network_profile: lab`, G1.6) - a dev campaign must not egress to the internet. The token
is the one `make run-local` printed (only its sha256 is stored on disk, so it cannot be recovered
later).

Exit codes: 0 = created, 1 = the API refused (its `error.v2` body is printed), 2 = usage.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "contracts/fixtures/valid/campaign-create.json"
TOKEN_ENV = "AEGIS_DEV_TOKEN"


def campaign_body(name: str) -> dict[str, object]:
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))
    body["name"] = name
    body["policy"]["network_profile"] = "lab"
    return body


def post_campaign(api_url: str, token: str, body: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/v2/campaigns",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"seed-demo-{uuid.uuid4().hex}",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - loopback URL
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or "campaign_id" not in payload:
        raise SystemExit(f"seed-demo: unexpected answer: {payload!r}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a demo campaign through POST /campaigns.")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("AEGIS_API_URL", "http://127.0.0.1:8000"),
        help="API base URL without /api/v2 (default: %(default)s)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get(TOKEN_ENV),
        help=f"operator token (default: ${TOKEN_ENV})",
    )
    parser.add_argument("--name", default=None, help="campaign name (default: a demo name)")
    arguments = parser.parse_args(argv)
    if not arguments.token:
        parser.error(f"no operator token: pass --token or set {TOKEN_ENV}")

    name = arguments.name or f"Demo {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}"
    try:
        created = post_campaign(arguments.api_url, arguments.token, campaign_body(name))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        print(f"seed-demo: {error.code} {error.reason}: {body}", file=sys.stderr)
        return 1
    except urllib.error.URLError as error:
        print(f"seed-demo: cannot reach {arguments.api_url}: {error.reason}", file=sys.stderr)
        return 1

    campaign_id = created["campaign_id"]
    base = f"{arguments.api_url.rstrip('/')}/api/v2/campaigns/{campaign_id}"
    print(f"seed-demo: campaign {campaign_id} ({name})")
    print(f"  get   {base}")
    print(f"  flow  {base}/flow")
    print(f"  events {base}/events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
