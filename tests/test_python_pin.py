"""`.python-version` is the one exact Python pin: uv and the gates read it, every image matches it.

An image is pinned by digest, which cannot be derived from a version number, so each reference also
carries the exact version in its tag and this test holds that tag to the pin.
"""

import platform
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ROOT / ".python-version"

#: Where Python image references live today; a new one elsewhere under these trees is checked too.
SEARCHED = ("deploy", "scripts", "tests/container")
EXPECTED_FILES = {
    "deploy/broker/Containerfile",
    "deploy/dev/images.env",
    "deploy/lab/images.env",
    "deploy/lab/inventory.json",
    "deploy/vulnlab/images.env",
    "tests/container/Containerfile",
}
PYTHON_IMAGE = re.compile(r"docker\.io/library/python(?::(?P<tag>[\w.-]+))?@sha256:[0-9a-f]{64}")


def pinned_version() -> str:
    return PIN_FILE.read_text(encoding="utf-8").strip()


def image_tags() -> dict[str, list[str | None]]:
    found: dict[str, list[str | None]] = {}
    for tree in SEARCHED:
        for path in sorted((ROOT / tree).rglob("*")):
            # `.run` holds a running lab's generated files, some unreadable by design.
            if not path.is_file() or {".run", "__pycache__"} & set(path.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            tags = [match["tag"] for match in PYTHON_IMAGE.finditer(text)]
            if tags:
                found[path.relative_to(ROOT).as_posix()] = tags
    return found


def test_the_pin_is_one_exact_patch_release() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", pinned_version())


def test_this_interpreter_is_the_pinned_one() -> None:
    assert platform.python_version() == pinned_version()


def test_every_python_image_is_the_pinned_version() -> None:
    found = image_tags()

    assert EXPECTED_FILES <= set(found)
    wrong = {
        name: tags
        for name, tags in found.items()
        if any(tag is None or not tag.startswith(f"{pinned_version()}-") for tag in tags)
    }
    assert wrong == {}
