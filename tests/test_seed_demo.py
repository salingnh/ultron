"""`scripts/dev/seed-demo.py`: the demo campaign it creates is the contract's own example.

The script is a development tool, so it is tested where it can be wrong: the body must satisfy
`campaign/campaign-create.v2`, and the POST must create a campaign the API can then read (the same
request the script sends, over a real socket).
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from aegis import validation
from tests import campaign_support as support
from tests.db_support import migrated_database, requires_postgres
from tests.g15a_support import api_app
from tests.http_support import serve

pytestmark = requires_postgres

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/dev/seed-demo.py"
CAMPAIGN_CREATE = "campaign/campaign-create.v2.schema.json"


@pytest.fixture(scope="module")
def seed() -> Iterator[ModuleType]:
    spec = importlib.util.spec_from_file_location("aegis_seed_demo", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module


def test_the_demo_body_is_a_valid_campaign_create(seed: ModuleType) -> None:
    body = seed.campaign_body("seed demo")
    validation.validate(CAMPAIGN_CREATE, body)
    assert body["name"] == "seed demo"
    assert body["targets"]  # the fixture's seeds, untouched


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def test_the_script_creates_a_campaign_the_api_can_read(seed: ModuleType, dsn: str) -> None:
    token = support.OPERATORS["op-soc-1"]
    with serve(api_app(dsn)) as base:
        created = seed.post_campaign(base, token, seed.campaign_body("seed demo http"))
        assert created["status"] == "CREATED"
        with httpx.Client(base_url=base, timeout=10.0) as client:
            read = client.get(
                f"/api/v2/campaigns/{created['campaign_id']}",
                headers={"authorization": f"Bearer {token}"},
            )
    assert read.status_code == 200, read.text
    assert read.json()["name"] == "seed demo http"


def test_main_reports_a_refused_token(seed: ModuleType, dsn: str, capsys: Any) -> None:
    with serve(api_app(dsn)) as base:
        exit_code = seed.main(["--api-url", base, "--token", "not-a-token", "--name", "denied"])
    assert exit_code == 1
    assert "401" in capsys.readouterr().err
