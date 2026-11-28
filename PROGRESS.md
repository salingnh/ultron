# PROGRESS

## Hiện trạng

| Hạng mục | Trạng thái |
| --- | --- |
| Giai đoạn | G0 đạt: contract khóa ở mức schema/DDL/test (#26), kết luận spike (#13/#9/#7), môi trường dev + CI (#14), lab mục tiêu (#27). OD-2 chuyển sang G1 với fake model; Product Team ký cổng đã ghi nhận (leader ký dưới ủy quyền của chủ, 2026-11-24). Chưa có dịch vụ sản phẩm chạy trọn vòng |
| Git | `main` @ `9184d46`: đã gộp contract S1.1–S1.7 + follow-up (#26), kết luận spike G0.1/G0.2/G0.3a (#13/#9/#7), G0.3b (#19/#22), G0.3c (#18), G0.4d (#21), môi trường dev + CI (#14); lab G0.4c ở PR #27 (`deploy/lab/`). Mã spike nằm trên nhánh `spike/*` (chỉ để tham chiếu, không merge) |
| Kiến trúc | Theo D29: AI agent/MCP/sandbox/metadata/graph/S3/UI; model cấu hình trực tiếp, job dùng priority/dependency |
| Tài liệu | Một bộ ở đường dẫn chính. Ngày 2026-11-17 hoàn tất ma trận 367 mục đối chiếu với nguồn trước hợp nhất; mỗi mục có đích hiện hành hoặc căn cứ thay thế, phần còn hiệu lực bị rơi đã được bổ sung |
| Nội dung đã giữ | Use case, context/ledger/stop conditions, adapter/chain, ontology/identity/provenance, ingestion gates, correlation/finding và kiểm thử/vận hành |
| Nội dung đã loại | Phương án nền tảng bị thay thế, phân tầng/phân nhóm, workflow duyệt cũ, nhánh ngoài phạm vi và claim benchmark/OSS chưa có bằng chứng; không dùng việc chưa implement làm lý do bỏ yêu cầu đã chốt |
| Contract | Bundle v2 khóa cho S1: 37 schema, 26 fixture hợp lệ, 30 fixture bị từ chối đúng, 23 operation OpenAPI; migration 0005–0014. C02/C03/C06/C08 ở [05](docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#các-contract-đã-khóa-c02c08), C04 ở [graph/model.md](contracts/graph/model.md#c04--thứ-tự-công-bố-đã-khóa-ở-s13) |
| F1–F3 | Đã sửa receipt dùng một schema, một đường gửi MCP và ghim manifest/adapter trong task/job; migration 0003 cho pin bất biến, 0006 sửa lại định nghĩa `job_fingerprint` (X-1) |
| Rà contract | Review độc lập S1.5c PASS ở mức contract sau hai vòng; các blocker R-1, R-2a/b, R-3, R-4 đóng ở 0014. OI-4/OD-5 còn chờ chủ sản phẩm |
| Bảo toàn nội dung | Đối chiếu 35 nguồn text tại HEAD trước viết lại và 26 tài liệu hiện hành; 28 quyết định D, 12 lựa chọn OSS, các bảng chốt 12/13-11, FR/NFR, SDK/ingestion, API/event/query và logic chi tiết. Sáu cặp Word/8 hình đã đối chiếu ở lượt trước. Không còn mục trong ma trận thiếu đích hoặc bị loại không có căn cứ |
| Triển khai | Chưa có dịch vụ sản phẩm: không chạy scanner thật, LLM thật, E2E hay deploy. Môi trường dev + CI (#14) và lab G0.4c (#27, `deploy/lab/`) đã có trên `main`; scanner chỉ chạy trong lab nội bộ đã được phép |

## Còn mở

- Cổng G0: không còn điều kiện mở. OD-2 (provider/model LLM) chuyển sang G1 — provider thật bật bằng `AEGIS_SESSION_LIVE_MODEL=1` + `AEGIS_MODEL_*` (OpenAI Chat Completions hoặc Anthropic Messages, base URL tùy chọn, giá bắt buộc; G1.6, PR #62), mặc định scripted policy cho CI/demo; Product Team ký cổng đã ghi nhận — leader ký dưới ủy quyền của chủ ngày 2026-11-24.
- Trước khi viết code G1: tám điều kiện ở TASKS §G1 (E-1, R-5, P3a/P3c, OI-7, R-6, throughput projector, `normalization_version`, OI-4/OD-5), mỗi điều kiện ghi task G1 sở hữu.
- Chưa kiểm runtime: xem mục "Chưa kiểm runtime" dưới đây. Schema xanh và số đo spike không thay nghiệm thu runtime.

## Bằng chứng kiểm chứng

Hai mức được tách riêng: **đã kiểm ở mức contract** (schema/DDL/test chạy được) và **đã chứng minh bằng spike** (số đo trên máy dev). Không mức nào là nghiệm thu runtime sản phẩm.

### Đã kiểm ở mức contract (chưa phải runtime)

Lượt chạy 2026-11-24 trên `integ/g0-s1-contracts` @ `15c02b9` (nay ở `main` @ `9184d46` qua #26), venv Python 3.12.13 (jsonschema 4.26.0, psycopg 3.3.9), PostgreSQL 16.16 trong container dùng một lần, chạy đúng lệnh của [contracts/README.md §Kiểm tra](contracts/README.md#kiểm-tra):

- 15 bộ Python/134 test, 0 skip. Validator: 37 schema, 26 fixture hợp lệ, 30 fixture bị từ chối đúng, 23 operation. Conformance Subfinder+DNSx, identity golden 23 test, lifecycle 9 + race 4, hash/receipt 9 + concurrency 4, outbox 15, legacy policy 6, egress/actor 11, migration hygiene 7 (gồm DocLinks và luật ghim `search_path`).
- Chuỗi sạch `0001→0014` (14 migration) + 11 test SQL: rc=0; 56/56 hàm schema `aegis` ghim `search_path`; smoke 10/10, lifecycle 8/8, decision binding 16/16 + cancel 4/4, outbox 8/8 + 4/4 + 4/4, actor 6/6, seed guard và dispatch hold đều bị chặn đúng.
- 2026-11-24: chuỗi migration 0001–0017 gộp thành `0001_baseline.sql` và bỏ cơ chế dữ liệu cũ theo quyết định chủ sản phẩm (PR #56). Leader tự kiểm: so catalog chuỗi cũ với baseline, 143/143 object của outbox C04/graph giống hệt; không còn chuỗi nâng cấp.
- Kết quả khớp review độc lập S1.5c (re-review 2 @ `15c02b9`), nên không phải lần chạy duy nhất của chuỗi này.
- Lượt bảo toàn 2026-11-17 (giữ làm mốc, không phải nghiệm thu runtime): Cypher smoke Neo4j 5.26.28 đạt 4/4 (constraints chạy hai lần, upsert giữ 2 asset/1 finding/1 evidence/3 cạnh, ID trùng bị chặn); 26 Markdown/HTML và 98 link/anchor/ảnh tương đối hợp lệ; rà 367 mục giữ 23/23 method/path API và 33 schema có đích thay thế, 72/76 file contracts giữ hash của lần kiểm trước. Cypher smoke chạy ở lượt đó và trong CI PR #14, nhưng **không** nằm trong §Kiểm tra nên không tính vào lần chạy trên.

### Đã chứng minh bằng spike (số đo, `nhánh@sha`)

- **G0.1** `spike/g0.1-temporal-langgraph@8c20a1e` (#13): 10 test xanh. Worker bị SIGKILL giữa activity thì tiếp tục từ checkpoint, còn 1 job/1 lần dispatch; replay 29 event/19,4 KB tất định, đổi lệnh đầu thì replay báo `TMPRL1100`; cancel job 120 s dừng dưới 20 s; Continue-As-New giữ cursor; ready query p95 1,09 ms trên 5.000 job `QUEUED` dùng index `scan_job_ready_order`. Chọn phiên agent chạy trong activity (29 event/19.467 B) thay vì workflow-per-session (41 event/32.208 B).
- **G0.2** `spike/g0.2-sandbox@e1c2a25` (#9, kết luận + bảng pin): 42 unit + 21 test Podman (rootless Podman 5.8.9, cgroup v2 có thật). OOM/pids/cpu/rootfs read-only/uid 65534/cap-drop ALL xác nhận bằng số đo; container không tới được PG/Neo4j/S3/Temporal/loopback/link-local/metadata, gồm cả `::ffff:127.0.0.1`, NAT64/6to4/Teredo; DNS tắt theo job và broker kiểm lại sau redirect; collector chỉ nhận file thường với trần byte/file; parser không mở được socket. Bảng pin 4 tool: subfinder v2.17.0 (MIT), dnsx v1.2.2 (MIT), bbot 3.0.2 (AGPL-3.0), naabu v2.7.0 (MIT), kèm digest và SBOM SPDX. Naabu SYN bị hạ xuống CONNECT rootless dù có `NET_RAW` → G1 giữ `rawSocket=false`.
- **G0.3a** `spike/g0.3-mcp@6372e4c` (#7): 42 test với MCP 2.3.0 (`2025-11-25`). `_meta` thiếu/sai → `-32602` kèm `error.v2`; 100 lần cùng `idempotency_key` → 1 job (`approved` 1/`duplicate` 99). p95 `tools/call` handler 0,62 ms, HTTP JSON 3,64 ms, SSE 5,54 ms; 16 request đồng thời 272,7 call/s trên fake registry — NFR-04 (<300 ms p95) đạt ở mức fake, chưa phải registry PostgreSQL.
- **G0.3b** `spike/g0.3-graph@cf58b49` (+`a686b80` cho lần đo 0013): 100 writer cùng `canonical_key` → 1 node, 0 retry; 100 key khác nhau 473 ops/s. Rebuild 2.799 event đạt 174,5 event/s, 2.465 node/2.743 cạnh, so từng property và đối chiếu PostgreSQL 0 lệch; replay lại 67 event đã chiếu không đổi graph. 0013 (đã gộp): watermark chờ có trần (`lock_timeout` 5 s, 55P03, không bỏ im lặng) → 0 lần refresh bị chặn so với 921–1.163 lần trước, end-to-end 167 so với 133 event/s, p50 commit 0,185 so với 0,148 s.
- **G0.3c** (#18 @ `6158696`): `aegis-norm/1` là trục version riêng; 54 vector chấp nhận/37 bị từ chối/7 nhóm thu gọn, 23 test; replay giữ nguyên canonical key.
- **G0.4a/b** (#14 @ `9f25513`): `make dev-up` từ volume rỗng → 4 dịch vụ healthy, migration chạy một lần mỗi file và từ chối sửa migration đã áp; `make dev-down` xoá đúng project của mình. CI đọc danh sách cổng từ `contracts/README.md` nên không có bản sao thứ hai: chạy thử trên nhánh `integ` @ `8ea163d` đạt (13 bộ python, 16 file chuỗi sạch, 18 file chuỗi nâng cấp); CI của chính PR (dựa trên `main`, chưa có S1) chạy 3/7/8, run `45251769962` xanh 1m27s, run `45248059340` với fixture cố ý hỏng thì đỏ.
- **G0.4d** (#21 @ `df9448e`): đơn giá đo được metadata 3.526 B/asset, graph 447 B/asset, WAL 1.030 B/event. Đỉnh NFR-03 833 event/s so với trần projector 168–175 event/s (thiếu 4,9 lần); backlog G1 ước 14 card ≈ 63 person-day, W1→W5.
- **G0.4c** (PR #27, `deploy/lab/`): CoreDNS 1.15.0 làm resolver có thẩm quyền cho `lab.aegis.test` và một passive-source stub nội bộ, trên mạng `aegis-lab-lab` internal, không publish cổng. `make lab-up` healthy: DNS trả `www.lab.aegis.test NOERROR A 203.0.113.10; AAAA 2001:db8::10`, stub healthy, `internal=true`, không port. `make lab-check` chạy hai lần liền PASS: inventory 10 record/6 probe/3 passive name/4 pin; Subfinder v2.17.0 trả 3 host qua stub; DNSx v1.2.2 trả 6 probe, gồm NXDOMAIN (`ghost`) và REFUSED (`example.com`). Container chạy uid 1000, `CapEff=CapBnd=0`, `NoNewPrivs=1`, chỉ route `10.114.53.0/24`; TCP tới `1.1.1.1:443`/`9.9.9.9:53` trả `ENETUNREACH`. `make lab-down` chỉ xoá project `aegis-lab`.

### Chưa kiểm runtime

- Không có code sản phẩm M01–M28: không chạy pipeline thật, không có UI/SSE, không có projector/outbox/dispatcher sản phẩm.
- MCP, registry, latency mới đo trên fake registry và template Cypher; graph query tools chưa chạy qua MCP (thuộc G1.2b).
- Sandbox/egress mới đo trên container của spike với listener giả; chưa có M06/broker sản phẩm, chưa thử IPv6 egress thật, seccomp tùy chỉnh hay host hết cgroup delegation.
- HMAC của ApprovedTask, restart-reconcile của M06: chưa có implementation để kiểm.
- LLM thật (OD-2): client live cho cả hai chuẩn đã có (G1.6, PR #62), kiểm bằng transport ghi sẵn; chưa chạy bằng key thật — chủ chạy `make llm-smoke`. Soak 7 ngày: chưa chạy. Lab G0.4c đã chạy Subfinder/DNSx thật trong container nhưng không phải runner sản phẩm (G1.3a).
- CI chạy trên `main` qua #14 và trên PR G0.4c (#27); lần chạy tay của cổng contract trước đó ghi ở mục trên.

## Hồ sơ cổng G0

Đối chiếu theo [bằng chứng giao hàng](docs/living/02-ke-hoach-trien-khai.md#bằng-chứng-giao-hàng) của kế hoạch (G0 và điều kiện ký cổng); trạng thái chỉ dựa trên bằng chứng ở trên.

| Điều kiện G0 | Trạng thái | Căn cứ |
| --- | --- | --- |
| Kết luận spike đã gộp: G0.1, G0.2, G0.3a, graph (G0.3b), identity (G0.3c) | đạt | #13/#9/#7/#19/#18 trên `main`; văn bản kết luận trong PR tương ứng |
| Schema + DB sạch | đạt | Một migration `0001_baseline.sql` (thay chuỗi 0001–0017, PR #56); gate ở contracts/README "Kiểm tra" |
| Bảng pin version/digest/license | đạt | #9 trên `main`: 4 tool + digest + SBOM SPDX; văn bản ở [04-module-ket-noi-oss.md §Chọn provider](docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#chọn-provider-và-quản-lý-phiên-bản) |
| Registry (conformance Subfinder+DNSx) | đạt | S1.5b đã gộp: `contracts/tests/test_conformance.py` + fixture DNSx |
| Môi trường dev + CI | đạt | #14 trên `main`: `make dev-up/down`, CI đọc cổng từ `contracts/README.md` |
| Lab và fixture | đạt | `deploy/lab/` (#27): lab DNS + passive stub, `make lab-up/down`, inventory + authorization item 51 2026-11-24; fixture schema/parser/conformance đã gộp ở S1.5b |
| Backlog G1 + sizing lưu trữ lâu dài | đạt | TASKS §G1 (G1.1–G1.5 + 8 điều kiện review); [02-nen-tang.md §Định cỡ](docs/living/dac-ta-ky-thuat/02-nen-tang.md#định-cỡ-dung-lượng-và-tải-g04d) (G0.4d, #21 đã gộp) |
| Contract được review | đạt ở mức contract | Review độc lập S1.5c (re-review 2 @ `15c02b9`): PASS mức contract; blocker R-1/R-2a/R-2b/R-3/R-4 đóng ở 0014. OI-4 chờ OD-5 |
| Kiểm hạn chế sandbox | đạt | G0.2 (#9) 63 test — chưa phải runner sản phẩm (G1.3a) |
| Kiểm scheduling | đạt | G0.1 (#13) ready query + dependency/priority; implementation thuộc G1.1d |

**Cổng G0: đạt.** Mọi dòng bằng chứng ở trên đã đạt và nằm trên `main`. Hai mục từng mở được chốt như sau: OD-2 (provider/model LLM) không chặn G0 — provider thật bật bằng `AEGIS_SESSION_LIVE_MODEL=1` + `AEGIS_MODEL_*` (OpenAI Chat Completions hoặc Anthropic Messages, base URL tùy chọn, giá bắt buộc; G1.6, PR #62), mặc định scripted policy cho CI/demo; Product Team ký cổng đã ghi nhận — leader ký dưới ủy quyền của chủ ngày 2026-11-24. Điều kiện OD-5/OI-4 và bảy điều kiện G1 còn lại vẫn phải xong cùng task G1 sở hữu (TASKS §G1).

## Tiếp theo

Mở G1 theo TASKS: G1.1a trước, tám điều kiện review phải xong cùng task sở hữu; G1 mặc định chạy scripted policy; provider thật bật bằng `AEGIS_SESSION_LIVE_MODEL=1` (G1.6). Cập nhật sau mỗi lần merge hoặc deploy (update after every merge or deploy).
- G1.6 slice E (PR #65): `deploy/vulnlab` (7 pinned origins, internal + lab networks, podman TTL auto-stop) và catalog `tests/vulnlab` + `make vulnlab-test`; lab lộ đúng 7/7, assertion CVE ứng viên đã định nghĩa cho slice A/B/C; tunnel internet chờ đăng nhập Cloudflare MCP.
- G1.6 (integ/g16-discovery, 2026-11-25): trên lab, chuỗi seed → Subfinder → DNSx → Naabu → fingerprintx/httpx → ứng viên CVE chạy thật: demo-g16b, demo-g16c PASS (CVE-2021-41773, CVE-2021-23017, CVE-2020-1938 kèm KEV/EPSS), vulnlab-test lab 7/7; PG == Neo4j. Migration 0004 (CVE matching), 0005 (internet profile); baseline bất biến. Chưa chạy trên mục tiêu internet thật.
- G1.6 (integ/g16-discovery, 2026-11-27): chạy thật trên internet. Thụ động icomm.vn (78 tên), salingnh.com (0 tên, không có A). Chủ động icomm.vn qua 3 seed IP (zone có wildcard), 1 job, 2 req/s/host, 2 kết nối: port 22/80/443/2222 (.17), 22/80/443 (.15); OpenSSH 8.9p1 Ubuntu, NetBird; 32 CVE ứng viên/64 cặp, không KEV; audit 0 deny; PG == Neo4j. Hai lần review an toàn độc lập: lần 2 kết luận an toàn ở trần thấp kể cả L3. Intel đầy đủ (NVD 432k CVE, KEV tự làm mới, EPSS); demo-g1, demo-g16c PASS, vulnlab-test lab 7/7. Stack thử nghiệm của chủ: UI 127.0.0.1:5174. Chưa merge vào main.
- G2 (integ/g2-findings, 2026-11-28): đã gộp nền G2 (#131 projector/soak), G2-A finding + vòng đời (#133 contract, #134 engine/API, #130 màn Findings) và backlog g18 (#128 N7 DNS, #129 intel sync, #132 distro, #135 coverage chủ động + matcher trong chuỗi, gộp qua #136); CI 3/3 @`7f9bd0e`. Runtime đã kiểm trên UI/API/PostgreSQL thật với fixture ngoại tuyến: finding CANDIDATE do M20 tạo, chi tiết/bằng chứng (chưa có URL tải ký), lịch sử, chuyển trạng thái của operator có seq + Idempotency-Key, 409 seq cũ, quyền theo token, `finding.changed.v2` producer M26. Chưa kiểm: severity bằng model thật, xác minh động, soak. Chưa merge vào main (lên cùng G2).
- G2-D (integ/g2-findings, 2026-11-28): chuỗi phân tích artifact Trivy (PR #141, MERGED @36bc4b2, migration 0013). Runtime demo-g2d trên stack riêng: campaign image digest → 1 job `vuln.scan_artifact` SUCCEEDED → 110 package asset + 260 finding CANDIDATE (provider trivy) với evidence; PG 110 edge == Neo4j; image KHÔNG chạy (lưu oci-archive, quét như tệp), `networkAccess: none`, DB offline mount read-only + ghim sha256 (lệch → DEPENDENCY_MISSING). Kiểm độc lập: 117 test trên PostgreSQL riêng pass. Syft+Grype (đối chiếu đa nguồn) đang làm PR 2/2. Chưa merge vào main.
- G2-D PR 2/2 (integ/g2-findings, 2026-11-28): Syft (SBOM) + Grype (vuln) thêm vào chuỗi artifact (PR #144, MERGED @af0810f, không migration). Runtime demo-g2d: 3 job (syft/trivy/grype), image không chạy, network none, Grype DB offline ghim sha256 (lệch → DEPENDENCY_MISSING); 111 package/69 thấy bởi cả 3; 450 finding, 250 có provider {trivy,grype} và 700 source (1 finding/N source). Ca 3-provider ở mức engine (provider thứ ba là fixture). Kiểm độc lập: 93 test trên PostgreSQL riêng pass. Chưa merge vào main.
