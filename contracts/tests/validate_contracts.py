#!/usr/bin/env python3
"""Kiểm tra toàn bộ hợp đồng trong contracts/ (chạy trong CI: python3 -I contracts/tests/validate_contracts.py).

1. Mọi *.schema.json hợp lệ theo JSON Schema 2020-12, $id khớp đường dẫn file.
2. Mọi $ref (kể cả trong OpenAPI) trỏ tới file và JSON Pointer tồn tại.
3. Fixture valid/* đạt, invalid/* bị từ chối (fixtures/index.yaml).
4. Kiểm chéo: predicate trong fixture có trong registry; loại sự kiện, trạng thái finding, mã lỗi khớp giữa
   JSON Schema, DDL PostgreSQL và tài liệu.
5. Kiểm đầy đủ OpenAPI 3.1 và bắt buộc đăng ký mọi semantic format dùng trong schema.
Thoát mã 1 nếu có lỗi.
"""
from __future__ import annotations

import json
import re
import runpy
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
errors: list[str] = []
check_manifest_binding = runpy.run_path(str(ROOT / "tests/manifest_binding.py"))["check_manifest_binding"]
conformance = runpy.run_path(str(ROOT / "validation.py"))
FORMAT_CHECKER = conformance["format_checker"]()
DENIED_EGRESS_HOST = conformance["denied_egress_host"]


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
        fmt = node.get("format")
        if isinstance(fmt, str) and fmt not in FORMAT_CHECKER.checkers:
            fail(f"{rel}: format không có validator: {fmt}")
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


for p in list(ROOT.rglob("*.schema.json")) + [ROOT / "api/openapi.v2.yaml"]:
    walk_refs(load(p), p, p.relative_to(ROOT).as_posix())

openapi = load(ROOT / "api/openapi.v2.yaml")
for error in conformance["openapi_errors"](openapi, ROOT / "api/openapi.v2.yaml"):
    fail(f"OpenAPI3.1 {error}")
if not str(openapi.get("openapi", "")).startswith("3.1"):
    fail("api/openapi.v2.yaml: phải là OpenAPI 3.1")
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


# Ma trận producer → consumer (OI-13). Mỗi event phải khai bên nhận và có mặt trong bảng của README;
# capability chưa có provider phải được đánh dấu "chưa đăng ký" thay vì lặng lẽ nằm trong danh mục.
CONTRACT_README = (ROOT / "README.md").read_text()
for event_file in sorted((ROOT / "events").glob("*.schema.json")):
    event = json.loads(event_file.read_text())
    if "Bên nhận:" not in event.get("description", ""):
        fail(f"events/{event_file.name}: description phải khai 'Bên nhận:' (ma trận producer/consumer)")
    if f"events/{event_file.name}" not in CONTRACT_README:
        fail(f"events/{event_file.name}: chưa có trong ma trận producer/consumer của contracts/README.md")
if "chưa đăng ký" not in CONTRACT_README:
    fail("README: capability chưa có provider (network.discover_services) phải được đánh dấu chưa đăng ký")
if not (ROOT / "capabilities/network/discover-services.v2.schema.json").exists() or \
        "network/discover-services.v2" not in CONTRACT_README:
    fail("README: ma trận phải nêu network/discover-services")

# Hình dạng endpoint: `proposed` bị cấm sau S1 follow-up (OI-11); `deferred` phải nói lý do.
SHAPE_STATUSES = {"locked", "deferred"}
for path, ops in openapi["paths"].items():
    for m, op in ops.items():
        if m not in {"get", "post"} or not isinstance(op, dict):
            continue
        status = op.get("x-aegis-status", "locked")
        if status not in SHAPE_STATUSES:
            fail(f"OpenAPI {m.upper()} {path}: x-aegis-status={status!r} không hợp lệ "
                 f"(chỉ {sorted(SHAPE_STATUSES)}; endpoint không gắn nhãn mặc định là locked)")
        if status == "deferred" and not op.get("x-aegis-reason"):
            fail(f"OpenAPI {m.upper()} {path}: endpoint deferred phải có x-aegis-reason")
if openapi["paths"]["/campaigns/{campaign_id}/flow"]["get"].get("x-aegis-status") != "locked":
    fail("OpenAPI GET /campaigns/{campaign_id}/flow phải khóa hình dạng (G1.5a đọc wait_reason/cancel)")

# 3. Fixture
def validator_for(target: str) -> Draft202012Validator:
    file_part, _, pointer = target.partition("#")
    schema = {"$ref": BASE + file_part + (("#" + pointer) if pointer else "")}
    return Draft202012Validator(schema, registry=registry, format_checker=FORMAT_CHECKER)


index = load(ROOT / "fixtures/index.yaml")
for fixture, target in index["valid"].items():
    errs = sorted(validator_for(target).iter_errors(load(ROOT / "fixtures" / fixture)), key=str)
    for e in errs[:5]:
        fail(f"fixtures/{fixture}: phải hợp lệ nhưng lỗi tại /{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}")
for fixture, target in index["invalid"].items():
    if validator_for(target).is_valid(load(ROOT / "fixtures" / fixture)):
        fail(f"fixtures/{fixture}: phải bị từ chối nhưng lại hợp lệ")

# 4. Kiểm chéo
predicates = set(load(ROOT / "ingestion/predicates.v2.yaml")["predicates"])
for fixture in index["valid"]:
    data = load(ROOT / "fixtures" / fixture)
    for obs in (data.get("results") or {}).get("observations", []):
        if obs["predicate"] not in predicates:
            fail(f"fixtures/{fixture}: predicate {obs['predicate']} không có trong registry")
MANIFEST_FIXTURES = ["valid/manifest.subfinder.yaml", "valid/manifest.dnsx.yaml"]
manifests = {name: load(ROOT / "fixtures" / name) for name in MANIFEST_FIXTURES}
for name, manifest in manifests.items():
    for pred in manifest["spec"].get("emits", {}).get("predicates", []):
        if pred not in predicates:
            fail(f"fixtures/{name}: predicate {pred} không có trong registry")
    m = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)", manifest["spec"]["inputSchemaRef"])
    if not m or f"capabilities/{m[1]}/{m[2]}.v{m[3]}.schema.json" not in schemas:
        fail(f"fixtures/{name}: inputSchemaRef không ánh xạ được tới file schema")

# Mọi output graph-queries phải công bố truncated + limits_applied; nếu không, người đọc không
# phân biệt được "toàn bộ" với "bị cắt" (05 §cổng G5/G6, 04 §Tiêu chí thêm tool).
graph_queries = schemas["mcp/graph-queries.v2.schema.json"]["$defs"]
for qname, query in graph_queries.items():
    output = query.get("properties", {}).get("output", {})
    required = set(output.get("required", []))
    for field in ("truncated", "limits_applied"):
        if field not in required:
            fail(f"mcp/graph-queries.v2 {qname}.output: bắt buộc phải có {field}")
    limits = output.get("properties", {}).get("limits_applied", {})
    if limits.get("additionalProperties") is not False:
        fail(f"mcp/graph-queries.v2 {qname}.limits_applied: phải đóng danh sách trường (additionalProperties=false)")
    if "timeout_ms" not in limits.get("required", []):
        fail(f"mcp/graph-queries.v2 {qname}.limits_applied: thiếu trần timeout_ms")
if set(graph_queries) != {
        "get_asset_neighbors", "get_recent_observations", "get_unverified_hypotheses",
        "get_package_cve_matches", "summarize_campaign_delta", "get_evidence_excerpt"}:
    fail(f"mcp/graph-queries.v2: phải giữ đúng sáu truy vấn, đang có {sorted(graph_queries)}")



_ARGV_SCALAR_TYPES = {"integer", "number", "boolean"}


def _argv_eligible(prop: dict | None) -> bool:
    """True when a value of this input field can be substituted without becoming an extra flag.

    Allowed: numbers/booleans; a string fixed by its enum; an array of those. Everything else (free
    string, object, array of free strings, or a $ref the registry has to resolve) is refused, because
    a value like `-rf` would reach argv as a flag instead of a value.
    """
    if not isinstance(prop, dict) or "$ref" in prop:
        return False
    kind = prop.get("type")
    if kind in _ARGV_SCALAR_TYPES:
        return True
    if kind == "string":
        return isinstance(prop.get("enum"), list) and len(prop["enum"]) > 0
    if kind == "array":
        return _argv_eligible(prop.get("items"))
    return False


def check_manifest(path: Path, data: dict) -> list[str]:
    """Luật conformance ngoài JSON Schema: không shell, và cách argsTemplate render input.

    Rule (OI-12, interfaces/README.md): an element is a literal or exactly one whole placeholder
    `${input.<field>}`; an array field renders one argv element per item; only scalar/enum values are
    substitutable. Nothing is joined, quoted or split, so the value can never become a flag.
    """
    out = []
    spec = data.get("spec", {})
    args = spec.get("runtime", {}).get("argsTemplate", [])
    if args and Path(str(args[0])).name in {"sh", "bash", "ash", "dash", "zsh", "busybox"}:
        out.append(f"{path}: argsTemplate không được gọi shell")
    mm = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)", spec.get("inputSchemaRef", ""))
    input_schema = schemas.get(f"capabilities/{mm[1]}/{mm[2]}.v{mm[3]}.schema.json", {}) if mm else {}
    props = input_schema.get("properties", {})
    # OI-5: the deny set is a platform constant that takes precedence over egressSources, so a manifest
    # may not declare a source inside it (loopback, link-local/metadata incl. fe80::/10, multicast,
    # unspecified, NAT64/6to4/Teredo). Binding = (resolved targets ∪ egressSources) − deny set.
    for source in spec.get("permissions", {}).get("egressSources", []):
        for host in source.get("hosts", []):
            if DENIED_EGRESS_HOST(str(host)):
                out.append(f"{path}: egressSources {source.get('id')!r} khai host {host!r} thuộc tập luôn chặn "
                           f"(deny set thắng egressSources; broker không bao giờ mở tới đó)")
    for a in args:
        element = str(a)
        placeholders = re.findall(r"\$\{([^}]*)\}", element)
        if len(placeholders) > 1:
            out.append(f"{path}: argv element {element!r} chứa {len(placeholders)} placeholder")
            continue
        if not placeholders:
            continue
        match = re.fullmatch(r"\$\{input\.([a-z0-9_]+)\}", element)
        if not match:
            out.append(f"{path}: placeholder trong {element!r} phải chiếm trọn một argv element dạng ${{input.<field>}}")
            continue
        field = match[1]
        prop = props.get(field)
        if prop is None:
            out.append(f"{path}: placeholder input.{field} không có trong input schema")
        elif not _argv_eligible(prop):
            out.append(f"{path}: input.{field} không được chèn vào argv "
                       f"(chỉ số/boolean/chuỗi enum/mảng của chúng; chuỗi tự do có thể thành cờ)")
    return out


for name, manifest in manifests.items():
    for e in check_manifest(Path(f"fixtures/{name}"), manifest):
        fail(e)
for provider in ("subfinder", "dnsx"):
    for e in check_manifest_binding(
            load(ROOT / f"fixtures/valid/approved-task.{provider}.json"),
            (ROOT / f"fixtures/valid/manifest.{provider}.yaml").read_bytes()):
        fail(f"approved-task {provider} fixture: {e}")
receipt_ref = openapi["paths"]["/ingestion/results"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
if receipt_ref != {"$ref": "../ingestion/ingest-receipt.v2.schema.json"}:
    fail("OpenAPI receipt must reference the shared IngestReceipt schema")
if not check_manifest(Path("x"), load(ROOT / "fixtures/invalid/manifest.tag-not-digest.yaml")):
    fail("check_manifest: không bắt được manifest gọi shell")
for broken, expect in [
        ("fixtures/invalid/manifest.args-free-string.yaml", "không được chèn vào argv"),
        ("fixtures/invalid/manifest.args-embedded-placeholder.yaml", "chiếm trọn một argv element"),
        ("fixtures/invalid/manifest.egress-source-in-deny-set.yaml", "thuộc tập luôn chặn")]:
    found = [e for e in check_manifest(Path("x"), load(ROOT / broken)) if expect in e]
    if not found:
        fail(f"check_manifest: không bắt được {broken} ({expect})")
manifest_validator = validator_for("capability/provider-manifest.v2.schema.json")
for mp in sorted((ROOT.parent / "adapters").glob("**/manifest.yaml")):
    data = load(mp)
    for e in list(manifest_validator.iter_errors(data))[:5]:
        fail(f"{mp.relative_to(ROOT.parent)}: {e.message[:200]}")
    for e in check_manifest(mp.relative_to(ROOT.parent), data):
        fail(e)

ddl = (ROOT / "db/postgres/0001_baseline.sql").read_text(encoding="utf-8")


def ddl_enum(table: str, column: str) -> set[str]:
    """The enum a column's CHECK publishes, in either DDL spelling.

    The baseline is written from the catalog (`CONSTRAINT <table>_<column>_check CHECK ((<column> =
    ANY (ARRAY['a'::text, ...])))`); an older file spelled the same constraint
    `CHECK (col IN ('a', ...))`. Both are one constraint in the database, so the gate accepts both.
    """
    block = re.search(rf"CREATE TABLE (?:aegis\.)?{table} \((.*?)\n\);", ddl, re.S)
    if block is None:
        return set()
    hit = re.search(
        rf"{column} text[^\n]*CHECK \(\w+ IN \(([^)]*)\)\)", block.group(1), re.S
    ) or re.search(
        rf"CONSTRAINT {table}_{column}_check CHECK \(\((?:::text)?"
        rf"(?:[a-z_]+\.)?{column} = ANY \(ARRAY\[(.*?)\]\)\)\)",
        block.group(1),
        re.S,
    )
    return set(re.findall(r"'([^']+)'", hit[1])) if hit is not None else set()


event_types = set(schemas["events/event-envelope.v2.schema.json"]["properties"]["type"]["enum"])
event_files = {p.name.removesuffix(".schema.json") for p in (ROOT / "events").glob("*.v2.schema.json") if p.name != "event-envelope.v2.schema.json"}
if event_types != event_files:
    fail(f"Sự kiện: enum {sorted(event_types)} khác file {sorted(event_files)}")
if len(event_types) != 9:
    fail(f"Sự kiện: đặc tả có 9 sự kiện v2, đang có {len(event_types)}")
migration = ddl
migration_event_types = set(re.findall(r"'([a-z.]+\.v2)'", migration))
if migration_event_types != event_types:
    fail("outbox_event.type trong DDL lệch với danh mục sự kiện")
statuses = set(schemas["finding/finding-status.v2.schema.json"]["enum"])
if ddl_enum("finding", "status") != statuses:
    fail("finding.status trong DDL lệch với finding-status.v2")
for t in load(ROOT / "finding/transitions.v2.yaml")["transitions"]:
    for s in ([t["from"]] if not isinstance(t["from"], list) else t["from"]) + [t["to"]]:
        if s is not None and s not in statuses:
            fail(f"transitions.v2.yaml: trạng thái lạ {s}")
codes = schemas["common/error.v2.schema.json"]["$defs"]["ErrorCode"]["enum"]
if len(codes) != 14:
    fail(f"Mã lỗi: schema hiện hành có 14 mã, đang có {len(codes)}")
job_status = set(schemas["capability/job.v2.schema.json"]["$defs"]["JobStatus"]["enum"])
if ddl_enum("scan_job", "status") != job_status:
    fail("scan_job.status trong DDL lệch với job.v2")

severity_schema = schemas["finding/severity-assessment.v2.schema.json"]
if ddl_enum("severity_assessment", "severity") != set(severity_schema["$defs"]["Severity"]["enum"]):
    fail("severity_assessment.severity trong DDL lệch với severity-assessment.v2")
if ddl_enum("severity_assessment", "kind") != set(severity_schema["properties"]["assessed_by"]["properties"]["kind"]["enum"]):
    fail("severity_assessment.kind trong DDL lệch với assessed_by.kind của severity-assessment.v2")
if ddl_enum("severity_assessment", "trigger") != set(severity_schema["$defs"]["Trigger"]["enum"]):
    fail("severity_assessment.trigger trong DDL lệch với trigger của severity-assessment.v2")
finish_reasons = set(schemas["agent/model-response.v2.schema.json"]["$defs"]["FinishReason"]["enum"])
if finish_reasons != {"completed", "tool_calls", "truncated", "refused", "invalid_output", "provider_error"}:
    fail(f"FinishReason của model-response.v2 phải là sáu giá trị chuẩn hóa C07, đang là {sorted(finish_reasons)}")
if severity_schema["properties"]["failure"]["$ref"].rsplit("/", 1)[-1] != "Failure":
    fail("severity-assessment.v2: failure phải trỏ tới $defs/Failure")

if errors:
    print(f"THẤT BẠI: {len(errors)} lỗi")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(schemas)} schema, {len(index['valid'])} fixture hợp lệ, {len(index['invalid'])} fixture bị từ chối đúng, OpenAPI {len(op_ids)} operation")
