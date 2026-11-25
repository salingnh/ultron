# fingerprintx adapter (M08) — `service.fingerprint`

Bọc `fingerprintx` (Praetorian) theo capability mới `service.fingerprint` (G1.6b): nhận các khóa
`service:<ip>:<port>/tcp` đã biết mở, trả về giao thức, banner và sản phẩm/phiên bản/CPE của dịch
vụ. Toàn bộ package nằm dưới `adapters/m08/fingerprintx/`; lõi chỉ thêm một luật renderer chung
(`runtime.targetsFormat`, xem dưới) — không có mã nào của tool trong `src/aegis/`.

| Hạng mục | Giá trị |
| --- | --- |
| Capability | `service.fingerprint` |
| Input schema | `schema://service/fingerprint/v2` — `targets` (khóa `service:…/tcp`), `ports`, `timeout_ms` |
| Tool | fingerprintx `v1.1.19` (2026-01-01) |
| Image | `localhost/aegis/fingerprintx:v1.1.19@sha256:b52677ad03e665840e96ddf1f6f85aa27eac2900eb2926298d77e95aa8e164e1`, build từ [`deploy/lab/tools/fingerprintx/Dockerfile`](../../../../deploy/lab/tools/fingerprintx/Dockerfile) |
| Giấy phép | Apache-2.0 (LICENSE + NOTICE upstream; image chỉ chứa binary tĩnh + CA) |
| Adapter version | `1.0.0` |
| Manifest | [`manifest.yaml`](manifest.yaml) — byte trùng `contracts/fixtures/valid/manifest.fingerprintx.yaml` |
| Parser | `adapters.m08.fingerprintx.parser:parse` |
| Lab run | [`fixtures/lab/`](fixtures/lab/) — bytes thật của lần chạy G1.6b; chạy lại: `make lab-fingerprintx` |

Upstream **không phát hành image container** (chỉ có Dockerfile trong repo). Pin vì vậy là ba phần:
tag nguồn `v1.1.19`, digest hai base image trong Dockerfile, và digest của image build ra ghi ở
`deploy/lab/images.env`. Đổi một trong ba là một lần nâng pin: build lại, cập nhật `images.env`,
`manifest.yaml` và bản copy contract trong cùng commit, rồi ghi lại fixture lab.

## Manifest và mạng

- `acceptsTargetKinds: [service]`, `targetBinding: required` + `targetPorts: from_input`: broker chỉ
  mở đúng (địa chỉ trong khóa) × (`input.ports`); M05 dựng binding đã ký, M06 kiểm lại.
- `runtime.targetsFormat: host_port`: M06 ghi `/in/targets.txt` là `host:port` (bỏ tiền tố `service:`
  và hậu tố `/tcp`). Target `/udp` bị từ chối trước khi tạo container vì file không biểu diễn được
  transport; plugin UDP của fingerprintx là cờ mức job (`-U`), không mức target.
- `egressMode: l3` + `proxyAware: false` — khai báo trung thực: fingerprintx tự `dial` mục tiêu,
  không có cờ SOCKS/HTTP proxy (chỉ plugin HTTP hưởng `HTTPS_PROXY` qua transport mặc định của Go),
  nên nó xin kênh L3: gateway lọc theo tập IP:port đã ký mà công cụ không cần biết proxy. Profile
  lab chạy nó trên mạng lab; một deployment chỉ có broker L7 sẽ từ chối (M06 kiểm trước khi tạo
  container), không để job timeout im lặng.

## Parser

`parse(output_dir, task, evidence)` đọc `result.jsonl` (`-l /in/targets.txt --json -o …`); mỗi dòng
là một dịch vụ đã nhận dạng: `ip`, `port`, `protocol`, `transport`, `version` (với plugin HTTP là
header `Server`) và `metadata` riêng của plugin (`banner`, `cpes`, `responseHeaders`…).

- Khóa dịch vụ dựng từ `ip`/`port`/`transport` (IPv6 bọc `[]`, IPv4-mapped thu về IPv4 như
  `aegis-norm/1`); một dòng nói về dịch vụ **không nằm trong** `input.targets` là output hỏng
  (`ParserInputError`), không được gán bừa. `transport != tcp` cũng là lỗi: schema đã từ chối target
  `/udp`, nên dòng UDP nghĩa là job chạy argv khác bản pin.
- `service.protocol` = tên protocol plugin báo (lowercase): `http`, `https`, `ssh`, `dns`…
- `service.banner` = `metadata.banner` (SSH/FTP/SMTP…) nếu có, ngược lại `version` top-level; không có
  thì **không** sinh observation (banner rỗng không phải bằng chứng).
- `service.product` = `{product, version, cpe}` theo luật CPE 2.3 đã viết trong docstring của parser:
  1. CPE của tool (`metadata.cpes`) nếu version cụ thể → dùng nguyên;
  2. CPE của tool có version `*` → lấy `vendor:product` của tool, điền version đọc được từ
     `version`/banner (`nginx/1.29.8`, `OpenSSH_9.2p1`, `SimpleHTTP/0.6 Python/3.12.16`);
  3. không có CPE → bảng nhỏ `CPE_PRODUCTS` trong parser (chỉ mục NVD rõ ràng), thiếu thì
     `vendor == product`;
  4. version chỉ giữ ký tự CPE 2.3, bỏ `v` đầu; **không có version thì không có CPE** — CPE dạng
     `*` không chứng minh phiên bản nào và sẽ làm bước nối CVE sau này khớp sai.
- Parser thuần (không mạng/env/đồng hồ/DB); cùng file → cùng output. Dòng JSON hỏng, `port` sai,
  `ip` không hợp lệ → `ParserInputError`.

Không emit: `asset.seen`/`net.port_state` (port scanner sở hữu), `http.technology` (httpx sở hữu),
và bất kỳ observation `http.*` nào — fingerprintx chỉ nói về dịch vụ, không nói về ứng dụng.

## Fixture

`fixtures/lab/result.jsonl` là output thật của lần chạy trên lab G1.6b (nginx 1.29.8 trên
10.114.53.21:8080 và 10.114.53.22:8443, CoreDNS của lab trên 10.114.53.53:53; mạng `aegis-lab-lab`,
không route ra ngoài). `run.json` ghi lệnh, pin, digest của file; `expected.json` là kết quả parse.
Test đối chiếu với fixture độc lập [`deploy/lab/fixtures/fingerprintx.expected.json`](../../../../deploy/lab/fixtures/fingerprintx.expected.json)
(dựng từ inventory lab, không từ parser) chứ không chỉ so parser với chính nó.
