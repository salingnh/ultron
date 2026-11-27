# httpx adapter (M08) — `web.probe_http`

Bọc `httpx` (ProjectDiscovery) theo capability mới `web.probe_http` (G1.6b): nhận các dịch vụ
`service:<ip>:<port>/tcp` đã được fingerprint nhận là HTTP/HTTPS, trả về **Application** asset
(`app:<scheme>://<host>:<port>`), cạnh `SERVES` Service→Application, và các observation
`http.status`/`http.title`/`http.headers`/`http.technology`/`tls.certificate`. Package nằm dưới
`adapters/m08/httpx/`.

| Hạng mục | Giá trị |
| --- | --- |
| Capability | `web.probe_http` |
| Input schema | `schema://web/probe-http/v2` — `targets` (khóa `service:…/tcp`), `ports`, `concurrency`, `timeout_seconds` |
| Tool | httpx `v1.12.0` (2026-09-08) |
| Image | `docker.io/projectdiscovery/httpx:v1.12.0@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc` |
| Giấy phép | MIT |
| Adapter version | `1.0.0` |
| Manifest | [`manifest.yaml`](manifest.yaml) — byte trùng `contracts/fixtures/valid/manifest.httpx.yaml` |
| Parser | `adapters.m08.httpx.parser:parse` |
| Lab run | [`fixtures/lab/`](fixtures/lab/) — bytes thật của lần chạy G1.6b; chạy lại: `make lab-httpx` |

## Manifest và mạng

- `acceptsTargetKinds: [service]`, `targetBinding: required` + `targetPorts: from_input`: binding
  egress là (địa chỉ trong khóa) × (`input.ports`).
- `runtime.targetsFormat: host_port`: `/in/targets.txt` chứa `host:port` **không scheme**; httpx tự
  thử HTTPS rồi HTTP (hành vi mặc định, không `-no-fallback`), nên một dịch vụ TLS trả về
  `https://…` kèm certificate còn dịch vụ HTTP trả về `http://…`. Target `/udp` bị từ chối.
- `proxyAware: true` — httpx có `-proxy` (http **hoặc socks5**) và mặc định đọc
  `HTTP_PROXY/HTTPS_PROXY/NO_PROXY`; broker là đường ra duy nhất của job. Bằng chứng trong PR là lần
  chạy lab có proxy chặn ở giữa (xem "Proxy verification" dưới).
- argv cố định: `-json -silent -tech-detect -cpe -tls-grab -irh -irr -threads
  ${input.concurrency} -timeout ${input.timeout_seconds} -no-color`. `-irr` (include response) giữ
  cả body trong JSONL: một trang in sản phẩm/phiên bản trong body (trang 404 của Tomcat in
  `Apache Tomcat/9.0.30`) chỉ đọc được nhờ nó. Body nằm trong file raw mà M06 lưu (bằng chứng), và
  `budget.maxOutputMb` của manifest chặn kích thước; khi quét internet nhiều trang lớn thì trần này
  là thứ siết trước. Tên trường là `concurrency` (không phải `threads`)
  để M05 cưỡng chế trần `budget.maxConcurrency` như mọi provider khác; `-threads` là cách httpx
  nhận giá trị đó. httpx v1.12 luôn `InsecureSkipVerify` khi dò (không có cờ `-insecure`): việc đọc
  certificate không phụ thuộc CA, và đó là lý do manifest không cần mount CA của lab.

## Parser

`parse(output_dir, task, evidence)` đọc `result.jsonl`; mỗi dòng là một URL đã trả lời HTTP, kèm
`input` (dòng trong file target), `status_code`, `title`, `header`, `tech`, `cpe`, `tls`.

- **Gán về dịch vụ**: dòng kết quả được gán về target bằng đúng `input` của nó (`host:port`); `input`
  không nằm trong `input.targets` là output hỏng (`ParserInputError`), không suy đoán theo IP/host.
- **Application**: một asset `kind: application`, `canonical_key: app:<scheme>://<host>:<port>`
  (`aegis-norm/1`, luôn nêu port kể cả 80/443), `discovered_from` = khóa service; kèm một cạnh
  `SERVES` từ service đó. Chuyển hướng không được theo (không `-follow-redirects`), nên không sinh
  asset cho host khác.
- Observation trên application: `http.status` (int), `http.title` (chỉ khi khác rỗng),
  `http.headers` (tên lowercase, sắp xếp, tối đa 32 header × 512 ký tự — response đầy đủ nằm trong
  raw evidence), `http.technology` (mỗi mục `<name>` hoặc `<name>:<version>`, tên lowercase, version
  chuẩn hóa), `tls.certificate` (`{subject_cn, sans[], issuer, not_before, not_after, sha256}`, thời
  gian UTC `Z`, sha256 từ `fingerprint_hash.sha256`).
- `service.product` trên **service**, theo thứ tự bằng chứng: CPE có version cụ thể; CPE không
  version của chính tool (`apache:tomcat:*`) + version đọc được trong response (body/title
  `Apache Tomcat/9.0.30`, header `X-Jenkins: 2.138`); technology có version (`jenkins:2.138`) qua
  bảng `TECHNOLOGY_CPES`; cuối cùng là bảng `PRODUCT_SIGNALS`. Không có version ở đâu thì **không**
  sinh observation — CPE `*` không chứng minh phiên bản và sẽ khớp CVE sai.
- Không emit `service.protocol`: fingerprintx sở hữu khẳng định đó; hai producer với hai chuỗi khác
  nhau sẽ biến một service thành mâu thuẫn.

## Proxy verification

httpx có `-proxy` cho mọi kết nối; PR G1.6b kèm lần chạy lab đặt một SOCKS5 CONNECT proxy của task
giữa httpx và hai dịch vụ web, proxy từ chối mọi đích ngoài binding đã ký, và kết quả vẫn là hai
application đúng. Script: `scripts/lab/httpx-proxy-check.sh` (chỉ chạy lab, dùng container của task,
tự dọn). Đây là bằng chứng cho `proxyAware: true`; không có nó thì provider phải khai `false` như
fingerprintx.

## Fixture

`fixtures/lab/result.jsonl` là output thật của lần chạy G1.6b trên `aegis-lab-lab`.
`run.json` ghi lệnh, pin và digest file; `expected.json` là kết quả parse. Test đối chiếu với
[`deploy/lab/fixtures/httpx.expected.json`](../../../../deploy/lab/fixtures/httpx.expected.json)
(dựng từ inventory: origin, service, status, title, technology) chứ không chỉ so parser với chính nó.
