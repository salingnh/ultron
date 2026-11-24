"""Test-support module: contract fixtures, generated DTO lookup, codegen helpers."""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import yaml
from pydantic import BaseModel

from aegis.common.repo import repository_root

REPO_ROOT = repository_root()
FIXTURES = REPO_ROOT / "contracts" / "fixtures"
GENERATED_PACKAGE = "aegis.contracts_gen"


def load_fixture(relative: str) -> Any:
    """Load a fixture from contracts/fixtures (JSON or YAML)."""
    path = FIXTURES / relative
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)


@cache
def fixture_index() -> dict[str, dict[str, str]]:
    """The contract fixture index: valid/invalid fixture -> schema reference."""
    index = load_fixture("index.yaml")
    if not isinstance(index, dict) or "valid" not in index or "invalid" not in index:
        raise RuntimeError("contracts/fixtures/index.yaml must have `valid` and `invalid` maps")
    return cast(dict[str, dict[str, str]], index)


def valid_fixtures() -> dict[str, str]:
    return fixture_index()["valid"]


def invalid_fixtures() -> dict[str, str]:
    return fixture_index()["invalid"]


@cache
def _codegen() -> Any:
    """scripts/codegen.py as a module (it is a script, not an importable package)."""
    path = REPO_ROOT / "scripts" / "codegen.py"
    spec = importlib.util.spec_from_file_location("aegis_codegen_for_tests", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def dto_module(schema_reference: str) -> ModuleType:
    """The generated module of a contract schema (`contracts/`-relative path)."""
    path = Path(schema_reference.split("#")[0])
    module = ".".join(
        [
            GENERATED_PACKAGE,
            *(part.replace("-", "_") for part in path.parent.parts),
            path.name.removesuffix(".json").replace("-", "_").replace(".", "_"),
        ]
    )
    return importlib.import_module(module)


def root_dto(schema_reference: str) -> type[BaseModel]:
    """The generated root model of a contract schema, named by the codegen convention."""
    path = Path(schema_reference.split("#")[0])
    candidate: object = getattr(
        dto_module(schema_reference), _codegen().root_class_name(path), None
    )
    if not (isinstance(candidate, type) and issubclass(candidate, BaseModel)):
        raise AssertionError(f"no generated root model for {schema_reference}")
    return candidate
