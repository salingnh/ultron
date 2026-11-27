# DNSx adapter (M08) — the "second tool"

Bọc `dnsx` (ProjectDiscovery) theo `dns.resolve`. Đây là tool thứ hai của G1: toàn bộ package nằm
dưới `adapters/m08/dnsx/` và **không sửa một dòng nào trong `src/aegis/`** — đó là cổng
"thêm tool không đổi lõi". Tác giả adapter chỉ viết **manifest, parser và fixture**;
`describe`/`validate`/`start`/`status`/`cancel`/`collect`/`health` do lõi cài qua `ContainerRunner`
([interfaces §1](../../../../contracts/interfaces/README.md)).

| Hạng mục | Giá trị |
| --- | --- |
| Capability | `dns.resolve` |
| Input schema | `schema://dns/resolve/v2` |
| Tool | dnsx `v1.2.2` (phát hành 2025-02-01; upstream có v1.3.x nhưng không có image — pin là bản image mới nhất) |
| Image | `docker.io/projectdiscovery/dnsx:v1.2.2@sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec` |
| Giấy phép | MIT (attribution: repo upstream, giữ nguyên trong image; SBOM SPDX 2.3 (138 package) ở `spikes/g0.2-sandbox/sbom/`) |
| Adapter version | `1.0.2` |
| Manifest | [`manifest.yaml`](manifest.yaml) — byte trùng `contracts/fixtures/valid/manifest.dnsx.yaml` (test so byte) |
| Parser | `adapters.m08.dnsx.parser:parse` |

Pin table, ghi chú lệch phiên bản upstream và luật nâng pin: [04 §Chọn provider](../../../../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md).

## Parser

`parse(output_dir, task, evidence)` đọc `result.jsonl` (`-silent -json -o /out/result.jsonl`, mỗi
dòng một object cho một tên được truy vấn: `host`, `ttl`, các tập bản ghi `a`/`aaaa`/`cname`…,
`status_code`):

- mỗi địa chỉ trong `a`/`aaaa` → observation `dns.record {type, value, ttl}`, asset `ip` với
  `discovered_from` là tên đầu tiên trả về địa chỉ đó, `asset.seen: true`, và cạnh `RESOLVES_TO`;
- `dns.resolves: true` chỉ cho tên thật sự có câu trả lời; tên NXDOMAIN/REFUSED (hoặc không có
  địa chỉ) không sinh observation — báo "resolves" cho tên không phân giải được là nói sai trong
  graph, còn khẳng định "không phân giải" là `polarity: absent`, thuộc quyết định chính sách chứ
  không phải mặc định của parser;
- `coverage.subjects` = đúng tập target đầu vào (đã sắp xếp): NXDOMAIN/REFUSED vẫn là subject đã
  kiểm;
- parser thuần: không mạng, không env, không đồng hồ, không DB; cùng fixture → cùng output. Dòng
  JSON hỏng, thiếu `host`, `ttl` không phải số nguyên dương hoặc địa chỉ không hợp lệ ném
  `ParserInputError` (job bị quarantine), không bỏ qua im lặng.

### Không emit (cần quyết định contract trước)

- **`mx`/`ns`/`txt`**: manifest đã pin không hỏi DNSx các bản ghi này.
- **`cname`** (từ adapter 1.0.2, manifest có `-cname`): đích CNAME được emit thành observation
  `dns.record` `{type: CNAME, value, ttl}` trên tên được hỏi, **không** thành asset hay cạnh riêng.
  M05 dùng chuỗi CNAME này làm provenance để quyết định target `ip:`/`service:` có được quét chủ động
  hay chỉ thụ động (CNAME ra ngoài `authorized_suffixes`, xem `02-nen-tang.md` §Ký target).
- **`soa`/`ns`/`raw_resp`**: không phải định danh tài sản; SOA thuộc zone, không thuộc tên được
  hỏi.

Keys dùng `aegis-norm/1`: địa chỉ qua `ipaddress` (`2001:DB8::10` → `2001:db8::10`, `::ffff:203.0.113.10`
→ `203.0.113.10` như M27), tên lowercase, bỏ một dấu chấm gốc, tiền tố `dns:`. Test adapter kiểm
từng key qua format `CanonicalKey` và từng predicate qua `contracts/ingestion/predicates.v2.yaml`.

## Fixture

[`fixtures/lab/`](fixtures/lab): `result.jsonl` là output byte-for-byte của lần chạy lab được uỷ
quyền (`make lab-dnsx`, sha256 trong `run.json`), gồm cả 6 tên trong `deploy/lab/fixtures/targets.txt`
(5 tên trong zone + `example.com` là đối chứng âm REFUSED, `ghost.lab` là NXDOMAIN). `expected.json`
là kết quả parser; test đối chiếu nó với danh sách probe độc lập
`deploy/lab/fixtures/dnsx.expected.json` (địa chỉ, cạnh `RESOLVES_TO`, và việc hai tên không có câu
trả lời không được báo là phân giải).

Kiểm: `tests/test_adapters_conformance.py` (phát hiện mọi `adapters/**/manifest.yaml`, không nêu
tên provider) chạy bộ conformance `contracts/tests/conformance/harness.py` với parser thật và so
envelope với `contracts/fixtures/valid/result-envelope.dnsx.json`, rồi kiểm fixture lab ở trên.
