"""Regression tests for the smoke anomalies (item 61): broker image hash, ports, and httpx -duc."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]


def test_broker_image_tag_depends_on_build_context_content(tmp_path: Path) -> None:
    script = REPO / "scripts/dev/broker-image.sh"
    tag_one = subprocess.check_output([str(script), "--tag-only"], text=True).strip()
    assert tag_one.startswith("localhost/aegis-broker:g16-")
    assert len(tag_one.rsplit("g16-", 1)[1]) == 12

    copy_root = tmp_path / "repo"
    (copy_root / "scripts/dev").mkdir(parents=True)
    (copy_root / "deploy/broker").mkdir(parents=True)
    (copy_root / "src/aegis").mkdir(parents=True)
    shutil.copy2(script, copy_root / "scripts/dev/broker-image.sh")
    shutil.copy2(REPO / "deploy/broker/Containerfile", copy_root / "deploy/broker/Containerfile")
    shutil.copy2(REPO / "src/aegis/__init__.py", copy_root / "src/aegis/__init__.py")
    shutil.copytree(REPO / "src/aegis/m06_runner", copy_root / "src/aegis/m06_runner")

    copied_script = copy_root / "scripts/dev/broker-image.sh"
    tag_same = subprocess.check_output([str(copied_script), "--tag-only"], text=True).strip()
    assert tag_same == tag_one

    broker_py = copy_root / "src/aegis/m06_runner/broker.py"
    broker_py.write_text(broker_py.read_text(encoding="utf-8") + "\n# mutated\n", encoding="utf-8")
    tag_mutated = subprocess.check_output([str(copied_script), "--tag-only"], text=True).strip()
    assert tag_mutated != tag_one


def test_subfinder_waybackarchive_declares_ports_80_and_443() -> None:
    for path in (
        REPO / "adapters/m08/subfinder/manifest.yaml",
        REPO / "contracts/fixtures/valid/manifest.subfinder.yaml",
    ):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        sources = manifest["spec"]["permissions"]["egressSources"]
        by_id = {source["id"]: source for source in sources}
        assert sorted(by_id["waybackarchive"]["ports"]) == [80, 443]


def test_httpx_manifest_disables_update_check_telemetry() -> None:
    for path in (
        REPO / "adapters/m08/httpx/manifest.yaml",
        REPO / "contracts/fixtures/valid/manifest.httpx.yaml",
    ):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        spec = manifest["spec"]
        args = spec["runtime"]["argsTemplate"]
        assert "-duc" in args
        assert spec["permissions"]["egressMode"] == "broker"
        assert spec["permissions"]["proxyAware"] is True
