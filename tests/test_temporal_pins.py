"""The Temporal server and the tools that write its schema are one release.

`temporalio/server` creates no schema: `make dev-up` runs `temporal-sql-tool` from
`temporalio/admin-tools`, whose schema files must be the ones that server expects.
"""

import re
from pathlib import Path

IMAGES = Path(__file__).resolve().parents[1] / "deploy" / "dev" / "images.env"


def pinned_tag(variable: str, repository: str) -> str:
    match = re.search(
        rf"^{variable}=docker\.io/temporalio/{repository}:(\d+\.\d+\.\d+)@sha256:[0-9a-f]{{64}}$",
        IMAGES.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, f"{variable} must pin temporalio/{repository} by version and digest"
    return match[1]


def test_server_and_schema_tools_are_the_same_release() -> None:
    assert pinned_tag("AEGIS_TEMPORAL_IMAGE", "server") == pinned_tag(
        "AEGIS_TEMPORAL_ADMIN_TOOLS_IMAGE", "admin-tools"
    )
