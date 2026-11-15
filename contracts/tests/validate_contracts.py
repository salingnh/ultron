#!/usr/bin/env python3
"""Kiểm tra toàn bộ hợp đồng trong contracts/ (chạy trong CI: python3 -I contracts/tests/validate_contracts.py).

1. Mọi *.schema.json hợp lệ theo JSON Schema 2020-12, $id khớp đường dẫn file.
2. Mọi $ref (kể cả trong OpenAPI) trỏ tới file và JSON Pointer tồn tại.
3. Fixture valid/* đạt, invalid/* bị từ chối (fixtures/index.yaml).
4. Kiểm chéo: predicate trong fixture có trong registry; loại sự kiện, trạng thái finding, mã lỗi khớp giữa
   JSON Schema, DDL PostgreSQL và tài liệu.
Thoát mã 1 nếu có lỗi.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def load(path: Path):
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)


# 1. Nạp schema
schemas: dict[str, dict] = {}
for p in sorted(ROOT.rglob("*.schema.json")):
    rel = p.relative_to(ROOT).as_posix()
    doc = load(p)
    if doc.get("$id") != BASE + rel:
        fail(f"{rel}: $id phải là {BASE + rel}, đang là {doc.get('$id')}")
    try:
        Draft202012Validator.check_schema(doc)
    except Exception as exc:  # noqa: BLE001
        fail(f"{rel}: schema không hợp lệ: {exc}")
    schemas[rel] = doc

registry = Registry().with_resources((BASE + rel, Resource.from_contents(doc)) for rel, doc in schemas.items())


# 2. Kiểm $ref
def resolve_pointer(doc, pointer: str):
    node = doc
    for part in [x for x in pointer.lstrip("/").split("/") if x]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def walk_refs(node, here: Path, rel: str):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            file_part, _, pointer = ref.partition("#")
            target = (here.parent / file_part).resolve() if file_part else here
            try:
                doc = load(target) if file_part else load(here)
                resolve_pointer(doc, pointer)
            except (FileNotFoundError, KeyError, TypeError) as exc:
                fail(f"{rel}: $ref hỏng {ref} ({exc.__class__.__name__})")
        for v in node.values():
            walk_refs(v, here, rel)
    elif isinstance(node, list):
        for v in node:
            walk_refs(v, here, rel)


for p in list(ROOT.rglob("*.schema.json")) + [ROOT / "api/openapi.v1.yaml"]:
    walk_refs(load(p), p, p.relative_to(ROOT).as_posix())

openapi = load(ROOT / "api/openapi.v1.yaml")
if not str(openapi.get("openapi", "")).startswith("3.1"):
    fail("api/openapi.v1.yaml: phải là OpenAPI 3.1")
op_ids = [op["operationId"] for path in openapi["paths"].values() for m, op in path.items() if isinstance(op, dict) and "operationId" in op]
if len(op_ids) != len(set(op_ids)):
    fail("OpenAPI: operationId trùng")
SPEC_ENDPOINTS = {
    ("post", "/campaigns"), ("get", "/campaigns/{campaign_id}"), ("post", "/campaigns/{campaign_id}/pause"),
    ("post", "/campaigns/{campaign_id}/resume"), ("post", "/campaigns/{campaign_id}/cancel"),
    ("get", "/campaigns/{campaign_id}/events"), ("get", "/capabilities"), ("post", "/jobs"), ("get", "/jobs/{job_id}"),
    ("post", "/jobs/{job_id}/cancel"), ("post", "/ingestion/results"), ("get", "/assets/{asset_id}/graph"),
    ("get", "/findings"), ("get", "/findings/{finding_id}"), ("post", "/findings/{finding_id}/transitions"),
    ("get", "/findings/{finding_id}/history"), ("get", "/assets/{asset_id}/history"), ("get", "/reports/delta"),
}
present = {(m, path) for path, ops in openapi["paths"].items() for m in ops if m in {"get", "post", "put", "patch", "delete"}}
for missing in sorted(SPEC_ENDPOINTS - present):
    fail(f"OpenAPI thiếu endpoint đặc tả: {missing[0].upper()} {missing[1]}")
for path, ops in openapi["paths"].items():
    for m, op in ops.items():
        if m == "post" and isinstance(op, dict) and op.get("operationId", "").startswith(("create", "submit", "transition", "update")):
            names = [p.get("$ref", "") for p in op.get("parameters", [])]
            if "#/components/parameters/IdempotencyKey" not in names:
                fail(f"OpenAPI {m.upper()} {path}: POST tạo tài nguyên phải có Idempotency-Key")


# 3. Fixture
def validator_for(target: str) -> Draft202012Validator:
    file_part, _, pointer = target.partition("#")
    schema = {"$ref": BASE + file_part + (("#" + pointer) if pointer else "")}
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


index = load(ROOT / "fixtures/index.yaml")
for fixture, target in index["valid"].items():
    errs = sorted(validator_for(target).iter_errors(load(ROOT / "fixtures" / fixture)), key=str)
    for e in errs[:5]:
        fail(f"fixtures/{fixture}: phải hợp lệ nhưng lỗi tại /{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}")
for fixture, target in index["invalid"].items():
    if validator_for(target).is_valid(load(ROOT / "fixtures" / fixture)):
        fail(f"fixtures/{fixture}: phải bị từ chối nhưng lại hợp lệ")

# 4. Kiểm chéo
predicates = set(load(ROOT / "ingestion/predicates.v1.yaml")["predicates"])
for fixture in index["valid"]:
    data = load(ROOT / "fixtures" / fixture)
    for obs in (data.get("results") or {}).get("observations", []):
        if obs["predicate"] not in predicates:
            fail(f"fixtures/{fixture}: predicate {obs['predicate']} không có trong registry")
manifest = load(ROOT / "fixtures/valid/manifest.subfinder.yaml")
for pred in manifest["spec"].get("emits", {}).get("predicates", []):
    if pred not in predicates:
        fail(f"manifest subfinder: predicate {pred} không có trong registry")
m = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)", manifest["spec"]["inputSchemaRef"])
if not m or f"capabilities/{m[1]}/{m[2]}.v{m[3]}.schema.json" not in schemas:
    fail("manifest subfinder: inputSchemaRef không ánh xạ được tới file schema")



def check_manifest(path: Path, data: dict) -> list[str]:
    """Luật conformance ngoài JSON Schema: không shell, placeholder chỉ trỏ tới trường của input schema."""
    out = []
    spec = data.get("spec", {})
    args = spec.get("runtime", {}).get("argsTemplate", [])
    if args and Path(str(args[0])).name in {"sh", "bash", "ash", "dash", "zsh", "busybox"}:
        out.append(f"{path}: argsTemplate không được gọi shell")
    mm = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)", spec.get("inputSchemaRef", ""))
    props = set(schemas.get(f"capabilities/{mm[1]}/{mm[2]}.v{mm[3]}.schema.json", {}).get("properties", {})) if mm else set()
    for a in args:
        for field in re.findall(r"\$\{input\.([a-z0-9_]+)\}", str(a)):
            if field not in props:
                out.append(f"{path}: placeholder input.{field} không có trong input schema")
    return out


for e in check_manifest(Path("fixtures/valid/manifest.subfinder.yaml"), manifest):
    fail(e)
if not check_manifest(Path("x"), load(ROOT / "fixtures/invalid/manifest.tag-not-digest.yaml")):
    fail("check_manifest: không bắt được manifest gọi shell")
manifest_validator = validator_for("capability/provider-manifest.v1.schema.json")
for mp in sorted((ROOT.parent / "adapters").glob("**/manifest.yaml")):
    data = load(mp)
    for e in list(manifest_validator.iter_errors(data))[:5]:
        fail(f"{mp.relative_to(ROOT.parent)}: {e.message[:200]}")
    for e in check_manifest(mp.relative_to(ROOT.parent), data):
        fail(e)

ddl = (ROOT / "db/postgres/0001_init.sql").read_text(encoding="utf-8")


def ddl_enum(column_regex: str) -> set[str]:
    hit = re.search(column_regex + r".*?CHECK \(\w+ IN \(([^)]*)\)\)", ddl, re.S)
    return set(re.findall(r"'([^']+)'", hit[1])) if hit else set()


event_types = set(schemas["events/event-envelope.v1.schema.json"]["properties"]["type"]["enum"])
event_files = {p.name.removesuffix(".schema.json") for p in (ROOT / "events").glob("*.v1.schema.json") if p.name != "event-envelope.v1.schema.json"}
if event_types != event_files:
    fail(f"Sự kiện: enum {sorted(event_types)} khác file {sorted(event_files)}")
if len(event_types) != 9:
    fail(f"Sự kiện: đặc tả có 9 sự kiện v1, đang có {len(event_types)}")
if ddl_enum(r"CREATE TABLE outbox_event.*?type\s+text") != event_types:
    fail("outbox_event.type trong DDL lệch với danh mục sự kiện")
statuses = set(schemas["finding/finding-status.v1.schema.json"]["enum"])
if ddl_enum(r"CREATE TABLE finding \(.*?status\s+text") != statuses:
    fail("finding.status trong DDL lệch với finding-status.v1")
for t in load(ROOT / "finding/transitions.v1.yaml")["transitions"]:
    for s in ([t["from"]] if not isinstance(t["from"], list) else t["from"]) + [t["to"]]:
        if s is not None and s not in statuses:
            fail(f"transitions.v1.yaml: trạng thái lạ {s}")
codes = schemas["common/error.v1.schema.json"]["$defs"]["ErrorCode"]["enum"]
if len(codes) != 14:
    fail(f"Mã lỗi: đặc tả có 14 mã, đang có {len(codes)}")
job_status = set(schemas["capability/job.v1.schema.json"]["$defs"]["JobStatus"]["enum"])
if ddl_enum(r"CREATE TABLE scan_job.*?status\s+text\s+NOT NULL DEFAULT 'QUEUED'\s+") != job_status:
    fail("scan_job.status trong DDL lệch với job.v1")

if errors:
    print(f"THẤT BẠI: {len(errors)} lỗi")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(schemas)} schema, {len(index['valid'])} fixture hợp lệ, {len(index['invalid'])} fixture bị từ chối đúng, OpenAPI {len(op_ids)} operation")
