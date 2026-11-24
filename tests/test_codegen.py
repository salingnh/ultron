"""`scripts/codegen.py` is what makes the contract-to-DTO step reviewable: it must be
deterministic (only schema bytes and the lockfile decide the output) and it must notice every way
the committed tree can drift from a fresh generation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from tests.support import REPO_ROOT, _codegen


def test_root_class_name_follows_the_file_path() -> None:
    codegen = cast(Any, _codegen())
    cases = {
        "contracts/capability/approved-task.v2.schema.json": "ApprovedTask",
        "contracts/ingestion/result-envelope.v2.schema.json": "ResultEnvelope",
        "contracts/capability/provider-manifest.v2.schema.json": "ProviderManifest",
        "contracts/capabilities/dns/enumerate-subdomains.v2.schema.json": "EnumerateSubdomains",
        "contracts/common/ids.v2.schema.json": "Ids",
    }
    for path, expected in cases.items():
        assert codegen.root_class_name(Path(path)) == expected


def test_schema_discovery_ignores_fixtures() -> None:
    codegen = cast(Any, _codegen())
    files = codegen.schema_files()
    assert files, "the contract bundle has schemas"
    assert all("fixtures" not in path.parts for path in files)
    assert all(path.suffixes[-2:] == [".schema", ".json"] for path in files)


def test_compare_sees_missing_stale_and_changed_files(tmp_path: Path) -> None:
    codegen = cast(Any, _codegen())
    committed = tmp_path / "committed"
    fresh = tmp_path / "fresh"
    for tree, names in (
        (committed, {"same.py": "a\n", "stale.py": "old\n", "changed.py": "old\n"}),
        (fresh, {"same.py": "a\n", "changed.py": "new\n", "missing.py": "new\n"}),
    ):
        for name, content in names.items():
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            (tree / name).write_text(content)

    missing, stale, changed = codegen.compare(committed, fresh)
    assert missing == ["missing.py"]
    assert stale == ["stale.py"]
    assert changed == ["changed.py"]


def test_generated_tree_is_committed_and_current() -> None:
    # The full regeneration runs in `make codegen-check`; this cheap assertion keeps a missing tree
    # from looking green when someone runs only pytest.
    target = REPO_ROOT / "src/aegis/contracts_gen"
    assert (target / "__init__.py").is_file()
    assert list(target.rglob("*_v2_schema.py")), "generated DTO modules are committed"
