# Subfinder adapter (M08)

Bọc `subfinder` (ProjectDiscovery) theo `dns.enumerate_subdomains`. Tác giả adapter chỉ viết
**manifest, parser và fixture**; `describe`/`validate`/`start`/`status`/`cancel`/`collect`/`health`
do lõi cài qua `ContainerRunner` ([interfaces §1](../../../../contracts/interfaces/README.md)).

| Hạng mục | Giá trị |
| --- | --- |
| Capability | `dns.enumerate_subdomains` |
| Input schema | `schema://dns/enumerate-subdomains/v2` |
| Tool | subfinder `v2.17.0` (phát hành 2026-10-08, 47 ngày trước khi nhận) |
| Image | `docker.io/projectdiscovery/subfinder:v2.17.0@sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf` |
| Giấy phép | MIT (attribution: repo upstream, giữ nguyên trong image; SBOM SPDX 2.3 (134 package) ở `spikes/g0.2-sandbox/sbom/`) |
| Adapter version | `1.0.0` |
| Manifest | [`manifest.yaml`](manifest.yaml) — byte trùng `contracts/fixtures/valid/manifest.subfinder.yaml` (test so byte, lệch là fail) |
| Parser | `adapters.m08.subfinder.parser:parse` |

Pin table và luật nâng pin: [04 §Chọn provider](../../../../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md).

## Adapter nhận vào registry thế nào

Không có file cấu hình riêng: M05 đăng ký mọi `adapters/**/manifest.yaml` lúc khởi động
(`aegis.m26_api.manifests.adapter_manifests`, dùng bởi cả API M26 và MCP server). Thêm tool =
thêm package có `manifest.yaml`; sửa byte manifest = version adapter mới (registry từ chối cùng
`(capability, provider, provider_version, adapter_version)` với byte khác).

## Parser

`parse(output_dir, task, evidence)` đọc `result.jsonl` (`-json -o /out/result.jsonl`, mỗi dòng
một object `{"host", "input", "source"}`) và trả `assets`/`observations`/`relationships`/
`findings`/`coverage_subjects`:

- mỗi tên mới không trùng target đầu vào → asset `domain` + `asset.seen: true` + `SUBDOMAIN_OF`
  tới từng target; tên punycode có thêm alias `original` dạng U-label;
- `coverage.subjects` = đúng tập target đầu vào (đã sắp xếp);
- `input.max_results` (mặc định 10000) là trần của schema, adapter cắt sau thu thập theo thứ tự
  file;
- parser thuần: không mạng, không env, không đồng hồ, không DB; cùng fixture → cùng output. Dòng
  JSON hỏng hoặc thiếu `host` ném `ParserInputError` (job bị quarantine), không bỏ qua im lặng.

Keys dùng quy ước `aegis-norm/1` cho tên ASCII do tool ghi (lowercase, bỏ một dấu chấm gốc,
tiền tố `dns:`). Test adapter kiểm từng key qua format `CanonicalKey` của contract và từng
predicate qua `contracts/ingestion/predicates.v2.yaml`.

## Fixture

[`fixtures/lab/`](fixtures/lab) là output thật của lần chạy trên lab được uỷ quyền (G0.4c):
`result.jsonl` byte-for-byte (sha256 trong `run.json`), `expected.json` là kết quả parser, và
`run.json` ghi image/args/zone để tái lập. Vì sao fixture không phải file tự soạn: parser phải
chịu được đúng thứ tool ghi ra, không phải thứ mình đoán.

Kiểm: `tests/test_adapters_conformance.py` (tự phát hiện mọi `adapters/**/manifest.yaml`) chạy
bộ conformance `contracts/tests/conformance/harness.py` với parser thật, so envelope với
`contracts/fixtures/valid/result-envelope.subfinder.json`, rồi kiểm fixture lab ở trên (chạy hai
lần giống hệt, khớp `expected.json`, khớp danh sách host của `deploy/lab/fixtures/subfinder.expected.json`).
