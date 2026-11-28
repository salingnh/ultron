# TASKS

G0 đã gộp đủ contract (#26), kết luận spike (#13/#9/#7), môi trường dev + CI (#14) và lab mục tiêu (#27). Cổng G0 đạt theo [PROGRESS](PROGRESS.md) mục Hồ sơ cổng G0: OD-2: provider thật bật bằng `AEGIS_SESSION_LIVE_MODEL=1` + `AEGIS_MODEL_*` (OpenAI Chat Completions hoặc Anthropic Messages, base URL tùy chọn, giá bắt buộc; G1.6, PR #62), mặc định scripted policy cho CI/demo; Product Team ký cổng đã ghi nhận (leader ký dưới ủy quyền của chủ, 2026-11-24). Thứ tự và nghiệm thu theo [quyết định kiến trúc](docs/s1/00-thanh-phan-va-quyet-dinh.md). Đây là backlog duy nhất. Chỉ làm giai đoạn đang mở trừ phần chủ sản phẩm trực tiếp yêu cầu. Trạng thái kiểm chứng ở PROGRESS, cổng giao hàng ở kế hoạch triển khai.

## G0 — khóa contract và spike

- [x] DOC.1 Đối chiếu 367 mục logic/quyết định với nguồn trước hợp nhất; phục hồi phần còn hiệu lực trong bộ tài liệu hiện hành, giữ phạm vi G2–G4 và bổ sung các task bị rơi. Đây là nghiệm thu bảo toàn tài liệu, không đóng cổng S1/runtime.
- [x] S1.0 Sửa F1–F3: receipt dùng một schema, AgentSessionResult chỉ trả job đã gửi MCP, ApprovedTask ghim adapter_version/manifest_sha256; bổ sung migration và kiểm hồi quy offline/DB. Chưa phải executor triển khai.
- [x] S1.1 Khóa seed reference xuyên request/task/result/provenance cho keyword/CIDR; kiểm cùng campaign và giữ seed gốc (C02).
- [x] S1.2 Khóa canonical hash/receipt/idempotency và vòng đời partial/late/cancel/attempt; kiểm retry, crash và callback cạnh tranh (C03/C06).
- [x] S1.3 Chọn và chứng minh outbox/revision ordering chịu rollback/commit đảo thứ tự, với nhiều connection và quyền ghi (C04).
- [x] S1.4 Hoàn thiện Message/ToolCall/ToolResult, finish/error và fallback severity; fake driver kiểm round-trip, invalid/truncated/refused và lần đầu chưa có assessment (C07).
- [x] S1.5 Khóa input/output schema cho chuỗi tool đầu tiên, actor/provenance mọi job, query limits/truncation và registry/adapter conformance; review cổng S1 (C05).
- [x] S1.6 Khóa đường chuyển campaign/cấu hình đã lưu sang contract hiện hành: snapshot JSON cũ bất biến và current_policy_version không tự thành cấu hình mới. Tạo snapshot hợp lệ, xử lý job đang chạy/chờ và test; không tự resume dữ liệu cũ. — Đã bỏ 2026-11-24: chuỗi migration gộp thành `0001_baseline.sql`, không còn đường chuyển dữ liệu cũ (chưa có DB thật).
- [x] S1.7 Đóng N01–N06 ở [C08](docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c08--kiểm-biên-schema-và-openapi): OpenAPI đầy đủ, identity/input, severity event, khung giờ, usage và response đúng phạm vi; kiểm conformance Python 3.12 và migration giữ lịch sử.
- [x] G0.1 Spike Temporal/LangGraph restart/replay/cancel; quyết định cách lồng phiên theo kết quả (#13).
- [x] G0.2 Spike Podman/network/resource limits và raw socket; kiểm parser/collector isolation; BBOT thụ động: ánh xạ JSON → ResultEnvelope và giấy phép bản pin; khóa version/digest/giấy phép tool được chọn (#9).
- [x] G0.3a Spike MCP transport/_meta/idempotency/query và đo latency (#7).
- [x] G0.3b Spike graph upsert đồng thời và replay/rebuild (kết luận ở #19, migration 0013 ở #22).
- [x] G0.3c Khóa quy tắc chuẩn hóa/identity có golden fixtures (#18).
- [x] G0.4a/b Dựng môi trường dev PostgreSQL/Neo4j/S3/Temporal/Podman trên máy đã có, bootstrap bằng một lệnh; nối schema/conformance vào CI (#14).
- [x] G0.4c Lab mục tiêu được phép và fixture schema/parser/adapter trên lab: lab DNS nội bộ + passive stub, Subfinder/DNSx chạy tái lập được và so fixture (#27, `deploy/lab/`).
- [x] G0.4d Đo capacity/sizing theo mục tiêu NFR, ước lượng backlog từ workload đã khóa (#21).

## G1 — vòng nền tảng

- [ ] G1.1 Khung repo/CI lint+test, fake cho sáu interface để tích hợp độc lập; Campaign/job API, Temporal worker, priority/dependency scheduler; chặn cycle/cross-campaign, audit actor.
- [ ] G1.2 Agent + ModelClient; MCP registry/call/query, context và ledger có budget/provenance, điều kiện dừng theo progress.
- [ ] G1.3 ContainerRunner/collector/parser, adapter DNSx/Subfinder; thêm tool thứ hai không sửa lõi.
- [ ] G1.4 Ingestion G1–G7, metadata/S3/graph projector/query; idempotency/replay/history và nguồn gốc.
- [ ] G1.5 UI campaign/job/dependency/graph, SSE; demo trọn vòng và phục hồi sau restart.

Điều kiện phải xong trước khi viết code G1, lấy từ review cổng S1 và kết quả spike G0 (mỗi dòng ghi task G1 sở hữu):

- [ ] E-1: binding egress phải nằm trong ApprovedTask đã ký, hoặc M06 có luật tính lại rõ ràng; hiện hai chỗ của interfaces mô tả khác nhau (chủ: G1.1c/1.3a).
- [ ] R-5: deny set của broker phải chuẩn hoá literal trước khi so (`127.1`, `2130706433`, `0x7f000001`, `::/96`, `fec0::/10`, `fd00:ec2::254`, `100.100.100.200`) và có test broker (chủ: G1.3a).
- [ ] P3a/P3c: ref `{canonical_key}` chưa buộc vào asset đã biết của campaign, và `input.targets` ↔ `target_refs` mới chỉ là luật M05, chưa có kiểm lại ở M06 (chủ: G1.1c, G1.3a).
- [ ] OI-7: HMAC của ApprovedTask chưa có canonical signing input, key id/rotation và test verify (chủ: G1.1c).
- [ ] R-6: dispatcher phải đặt statement/idle-in-transaction timeout để không giữ writer khoá sau mỗi lần refresh watermark (chủ: G1.1d).
- [ ] Projector đo ~170 event/s, đỉnh NFR-03 ~833 event/s: cần projector phân vùng/batch theo key và một con số nghiệm thu (chủ: G1.4b).
- [ ] Asset cần `normalization_version` trước khi ghi, để đổi `aegis-norm` sau này re-key được (chủ: G1.4a).
- [ ] OI-4/OD-5: cơ chế operator identity và luật `requested_by` cho job do agent đề xuất (chủ: G1.1b, G1.1c; chờ chủ sản phẩm).

## G2 — MVP

- [ ] G2.1 Khóa tool network/web/artifact và kiểm thử credential theo dependency dữ liệu; hoàn thiện manifest/input/parser/conformance, gồm tham số Nuclei chính thức/tùy chỉnh và xác minh credential. Chưa có schema thì chưa đăng ký tool. (Đã xong chuỗi artifact Trivy: PR #141, 0013, image không chạy, DB offline ghim; Syft/Grype đang làm PR 2/2.)
- [ ] G2.2 Finding/evidence, xác minh động bằng tool có đối chứng âm, correlation theo snapshot và severity do agent có lý do/nguồn; mọi finding được đánh giá trong ngân sách campaign (hết ngân sách thì UNRATED có lý do); feed/asset thay đổi kích hoạt đánh giá lại mà không cần chờ lần quét mới; JSON report + delta. Telegram chuyển sang G3 (quyết định chủ 2026-11-28).
- [ ] G2.3 Pause/resume/cancel, recovery, budget/error, kiểm prompt injection và sandbox; kiểm backup/restore mức MVP.
- [ ] RoE khung giờ cho phép (allowed time windows): hoãn khỏi G1 theo quyết định chủ 2026-11-24; làm lại cùng Clock port tiêm được + test đồng hồ cố định cả trong/ngoài cửa sổ.
- [ ] G2.4 Đóng băng workload rồi soak 7 ngày/10.000 bước; chứng minh không trùng job/mất provenance, dependency đúng, UI báo lỗi/kết quả trung thực.

## G3 — thêm tool theo nhu cầu

- [ ] G3.1 Giao source/secret, cloud/cluster, JS/binary theo tool đã chọn; khóa schema/reference cho repo, tài khoản cloud, cluster và artifact; mỗi tool có parser/conformance, raw/provenance và coverage limitations. So sánh ba provider secret trên fixture độc lập.
- [ ] G3.2 Enricher theo domain/email/keyword, SpiderFoot-ng thụ động, tìm mã công khai và tra cứu rò rỉ domain tổ chức bằng API key người vận hành; quét lại chọn lọc theo delta/freshness, giữ lịch sử/source chain và đo số job tiết kiệm.
- [ ] G3.3 Metadata tham chiếu PoC M19 có nguồn/thời điểm và trạng thái review, không tải/chạy mã.
- [ ] G3.4 Email/keyword tới finding (chuyển từ cổng G2, quyết định chủ 2026-11-28) và cảnh báo Telegram cho thay đổi finding/feed của M24.

## G4 — vận hành quy mô

- [ ] G4.1 Benchmark tải/latency và capacity; backup/restore đạt RPO/RTO mục tiêu, replay/rebuild, runbook và dashboard đã diễn tập.
- [ ] G4.2 Mở rộng Verifier/severity cho các họ finding G3; khóa contract SARIF/HTML, report delta/tổng hợp, gán chủ xử lý và rescan; kiểm output đúng chuẩn, evidence và vòng đời finding.
- [ ] G4.3 Tích hợp CI gọi API quét image/repo khi build, giữ digest/commit, credential cấp riêng và idempotency.

Các phương án kỹ thuật chưa khóa được ghi ngay tại đặc tả liên quan; không có backlog từ tài liệu nguồn cũ để agent tự suy thêm phạm vi.

## G1.6 — discovery sâu, mạng internet, LLM thật (item 61, nhánh integ/g16-discovery)

- [x] Port: Naabu + dịch vụ lab bản cũ, đồ thị IP → Service (#66).
- [x] Fingerprint: fingerprintx/httpx, product/version/CPE thật (#68, #77).
- [x] CVE/CTI: feed NVD/KEV/EPSS, ứng viên AFFECTED_BY (#64).
- [x] Lab CVE + catalog testcase, tunnel opt-in qua Cloudflare (#65, #73, #74, #76).
- [x] Profile internet, DNS qua broker, gateway L3 (#63, #70, #72).
- [x] LLM thật OpenAI/Anthropic qua `.env` (#62).
- [x] UI đồ thị/bảng dịch vụ/panel CVE (#75).
- [x] LLM gateway xoay vòng endpoint: LiteLLM proxy do chủ cấu hình (#78); chưa có lần gọi thật bằng key của chủ.
- [x] Quét internet trên domain của chủ: thụ động icomm.vn/salingnh.com; chủ động icomm.vn qua seed IP (zone có wildcard) dưới trần thấp, sau hai lần review an toàn độc lập (#83, #87, #88, #93, #96, #98, #99, #105).
- [x] UI vận hành: form tạo campaign + ủy quyền có cấu trúc, panel RoE, nhật ký agent, ngân sách/bộ đếm thật (#84, #85, #89, #91, #97, #104).
- [x] Intel đầy đủ: NVD mọi năm resumable, KEV từ cisagov/kev-data tự làm mới, khớp CVE đúng ngữ nghĩa cấu hình NVD, rút ứng viên lỗi thời (#95, #100, #101, #102, #103, #106).
- [x] Sửa lỗi từ stack thử nghiệm: đồ thị 500, CORS khi lỗi, context graph của agent, ngân sách phiên, khả năng thấy ứng viên theo campaign (#90, #94, #101, #104); rò volume test/CI (#92).
- [ ] Xếp hạng/thu gọn danh sách CVE trong bảng dịch vụ (ultron-agy).
- [ ] Khớp CVE theo bản vá của distro (Ubuntu/Debian tracker hoặc OSV) trước xác minh G2.
- [ ] N7: bộ đọc upstream DNS của broker kiểm rcode/qid.
- [ ] Redis version: chuyển sang bản release fingerprintx đầu tiên đọc INFO (không pin pre-release); AJP chưa có detector.
- [ ] Follow-up: MCP truy vấn CVE cho service/app; lịch tự động chạy `make intel-sync` (M02); bằng chứng nền tảng (OS) cho cấu hình "chạy trên".
