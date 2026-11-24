"""Subfinder v2.17.0 parser: the tool's JSONL output -> ResultEnvelope records (M08, G1.3b).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m08.subfinder.parser:parse`), so the module is
stdlib-only and has no clock, no network, no environment and no database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads the file Subfinder writes with `-json -o /out/result.jsonl`: one JSON object per line
carrying `host` (plus `input`/`source`/`timestamp`, which this version ignores). Only `host`
becomes identity; the collector (M06) stamps `observed_at` and copies the task pins into
`provenance`, so nothing here depends on when or where the job ran.

Mapping (the manifest's `emits` block):
  * a `domain` asset per discovered name that is neither an input target nor a repeat;
  * `asset.seen: true` for each of those names;
  * `SUBDOMAIN_OF` from each new name to every input target.

Canonical keys follow `aegis-norm/1` for a tool-written ASCII name: lowercase, one trailing root
dot dropped, `dns:` prefix. The keys this parser produces are checked against the contract
`CanonicalKey` format and the predicate registry in `tests/test_adapters_conformance.py`; a key
the contract would reject fails that test rather than reaching M27.

`input.max_results` (schema default 10000) is the schema's own cap on how many results the adapter
keeps, so the cap is applied here, after collection, in file order (contracts/capabilities/README.md
§First DNS chain, "Trần tham số"). `coverage.subjects` stays the full input target list: the job
checked every target, it only kept the first N discoveries.

A line whose JSON is malformed or that has no `host` raises `ParserInputError`: a truncating or
corrupt output file is a job error the runner quarantines, never a quietly partial result.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_MAX_RESULTS", "ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.jsonl"
#: `local_ref` of the raw file M06 stores and hands to the parser (collector evidence list).
RAW_REF = "raw"
DEFAULT_MAX_RESULTS = 10000
DOMAIN_CONFIDENCE = 0.7
RELATIONSHIP_CONFIDENCE = 1.0


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map Subfinder's JSONL in `output_dir` to assets, observations, relationships, coverage."""
    targets = sorted({_domain_key(value) for value in _input_targets(task)})
    limit = _max_results(task)
    assets: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, record in _records(Path(output_dir)):
        if len(seen) >= limit:
            break
        key = _host_key(record, line_number)
        if key in targets or key in seen:
            # Discovering the seed back, or the same name twice, is not a new asset.
            continue
        seen.add(key)
        asset: dict[str, Any] = {
            "kind": "domain",
            "canonical_key": key,
            "discovered_from": targets,
            "confidence": DOMAIN_CONFIDENCE,
            "evidence_refs": _evidence_refs(),
        }
        aliases = _aliases(key)
        if aliases:
            asset["aliases"] = aliases
        assets.append(asset)
        observations.append(
            {
                "subject": key,
                "predicate": "asset.seen",
                "value": True,
                "confidence": DOMAIN_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
        )
        relationships.extend(
            {
                "type": "SUBDOMAIN_OF",
                "from": key,
                "to": parent,
                "confidence": RELATIONSHIP_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
            for parent in targets
        )
    return {
        "assets": assets,
        "observations": observations,
        "relationships": relationships,
        "findings": [],
        "coverage_subjects": targets,
    }


def _records(directory: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """`(line number, object)` for every non-empty line of the tool's output file."""
    path = directory / RESULT_FILE
    if not path.is_file():
        raise ParserInputError(f"{RESULT_FILE} is missing: the tool wrote no result file")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ParserInputError(f"{RESULT_FILE} is not UTF-8 text: {error}") from error
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} is not JSON ({error.msg})"
            ) from error
        if not isinstance(record, dict):
            raise ParserInputError(f"{RESULT_FILE}:{line_number} is not a JSON object")
        yield line_number, record


def _host_key(record: dict[str, Any], line_number: int) -> str:
    host = record.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no host")
    return _domain_key(host)


def _input_targets(task: dict[str, Any]) -> list[str]:
    targets = (task.get("input") or {}).get("targets")
    if not isinstance(targets, list) or not targets:
        raise ParserInputError("the approved task carries no input.targets")
    return [str(value) for value in targets]


def _max_results(task: dict[str, Any]) -> int:
    value = (task.get("input") or {}).get("max_results", DEFAULT_MAX_RESULTS)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ParserInputError(f"input.max_results must be a positive integer, got {value!r}")
    return value


def _domain_key(value: str) -> str:
    text = value.strip().lower().rstrip(".")
    return text if text.startswith("dns:") else f"dns:{text}"


def _aliases(key: str) -> list[dict[str, str]]:
    """The A-label host written as the U-label the analyst reads (punycode only)."""
    host = key.removeprefix("dns:")
    try:
        decoded = host.encode("ascii").decode("idna")
    except UnicodeError:
        return []
    return [{"namespace": "original", "value": decoded}] if decoded != host else []


def _evidence_refs() -> list[dict[str, str]]:
    """The raw file this parser read; the collector stores it under `local_ref` `raw`."""
    return [{"local_ref": RAW_REF}]
