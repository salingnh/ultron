# TASKS

G0 đang mở, theo [quyết định kiến trúc](docs/s1/00-thanh-phan-va-quyet-dinh.md). Đây là backlog duy nhất. Chỉ làm giai đoạn đang mở trừ phần chủ sản phẩm trực tiếp yêu cầu. Trạng thái kiểm chứng ở PROGRESS, cổng giao hàng ở kế hoạch triển khai.

## G0 — khóa contract và spike

- [x] DOC.1 Đối chiếu 367 mục logic/quyết định với nguồn trước hợp nhất; phục hồi phần còn hiệu lực trong bộ tài liệu hiện hành, giữ phạm vi G2–G4 và bổ sung các task bị rơi. Đây là nghiệm thu bảo toàn tài liệu, không đóng cổng S1/runtime.
- [x] S1.0 Sửa F1–F3: receipt dùng một schema, AgentSessionResult chỉ trả job đã gửi MCP, ApprovedTask ghim adapter_version/manifest_sha256; bổ sung migration và kiểm hồi quy offline/DB. Chưa phải executor triển khai.
- [ ] S1.1 Khóa seed reference xuyên request/task/result/provenance cho keyword/CIDR; kiểm cùng campaign và giữ seed gốc (C02).
- [ ] S1.2 Khóa canonical hash/receipt/idempotency và vòng đời partial/late/cancel/attempt; kiểm retry, crash và callback cạnh tranh (C03/C06).
- [ ] S1.3 Chọn và chứng minh outbox/revision ordering chịu rollback/commit đảo thứ tự, với nhiều connection và quyền ghi (C04).
- [ ] S1.4 Hoàn thiện Message/ToolCall/ToolResult, finish/error và fallback severity; fake driver kiểm round-trip, invalid/truncated/refused và lần đầu chưa có assessment (C07).
- [ ] S1.5 Khóa input/output schema cho chuỗi tool đầu tiên, actor/provenance mọi job, query limits/truncation và registry/adapter conformance; review cổng S1 (C05).
- [ ] S1.6 Khóa đường chuyển campaign/cấu hình đã lưu sang contract hiện hành: snapshot JSON cũ bất biến và current_policy_version không tự thành cấu hình mới. Tạo snapshot hợp lệ, xử lý job đang chạy/chờ và test; không tự resume dữ liệu cũ.
- [x] S1.7 Đóng N01–N06 ở [C08](docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c08--kiểm-biên-schema-và-openapi): OpenAPI đầy đủ, identity/input, severity event, khung giờ, usage và response đúng phạm vi; kiểm conformance Python 3.12 và migration giữ lịch sử.
- [ ] G0.1 Spike Temporal/LangGraph restart/replay/cancel; quyết định cách lồng phiên theo kết quả.
- [ ] G0.2 Spike Podman/network/resource limits và raw socket; kiểm parser/collector isolation; BBOT thụ động: ánh xạ JSON → ResultEnvelope và giấy phép bản pin; khóa version/digest/giấy phép tool được chọn.
- [ ] G0.3 Spike MCP transport/_meta/idempotency/query và đo latency, graph upsert đồng thời và replay/rebuild; khóa quy tắc chuẩn hóa/identity có golden fixtures.
- [ ] G0.4 Dựng môi trường dev PostgreSQL/Neo4j/S3/Temporal/Podman trên máy đã có, bootstrap bằng một lệnh; lab mục tiêu được phép và fixture schema/parser/adapter; nối schema/conformance vào CI; đo capacity/sizing theo mục tiêu NFR, ước lượng backlog từ workload đã khóa.

## G1 — vòng nền tảng

- [ ] G1.1 Khung repo/CI lint+test, fake cho sáu interface để tích hợp độc lập; Campaign/job API, Temporal worker, priority/dependency scheduler; chặn cycle/cross-campaign, audit actor.
- [ ] G1.2 Agent + ModelClient; MCP registry/call/query, context và ledger có budget/provenance, điều kiện dừng theo progress.
- [ ] G1.3 ContainerRunner/collector/parser, adapter DNSx/Subfinder; thêm tool thứ hai không sửa lõi.
- [ ] G1.4 Ingestion G1–G7, metadata/S3/graph projector/query; idempotency/replay/history và nguồn gốc.
- [ ] G1.5 UI campaign/job/dependency/graph, SSE; demo trọn vòng và phục hồi sau restart.

## G2 — MVP

- [ ] G2.1 Khóa tool network/web/artifact và kiểm thử credential theo dependency dữ liệu; hoàn thiện manifest/input/parser/conformance, gồm tham số Nuclei chính thức/tùy chỉnh và xác minh credential. Chưa có schema thì chưa đăng ký tool.
- [ ] G2.2 Finding/evidence, xác minh động bằng tool có đối chứng âm, correlation theo snapshot và severity do agent có lý do/nguồn; feed/asset thay đổi kích hoạt đánh giá lại và Telegram mà không cần chờ lần quét mới; JSON report.
- [ ] G2.3 Pause/resume/cancel, recovery, budget/error, kiểm prompt injection và sandbox; kiểm backup/restore mức MVP.
- [ ] G2.4 Đóng băng workload rồi soak 7 ngày/10.000 bước; chứng minh không trùng job/mất provenance, dependency đúng, UI báo lỗi/kết quả trung thực.

## G3 — thêm tool theo nhu cầu

- [ ] G3.1 Giao source/secret, cloud/cluster, JS/binary theo tool đã chọn; khóa schema/reference cho repo, tài khoản cloud, cluster và artifact; mỗi tool có parser/conformance, raw/provenance và coverage limitations. So sánh ba provider secret trên fixture độc lập.
- [ ] G3.2 Enricher theo domain/email/keyword, SpiderFoot-ng thụ động, tìm mã công khai và tra cứu rò rỉ domain tổ chức bằng API key người vận hành; quét lại chọn lọc theo delta/freshness, giữ lịch sử/source chain và đo số job tiết kiệm.
- [ ] G3.3 Metadata tham chiếu PoC M19 có nguồn/thời điểm và trạng thái review, không tải/chạy mã.

## G4 — vận hành quy mô

- [ ] G4.1 Benchmark tải/latency và capacity; backup/restore đạt RPO/RTO mục tiêu, replay/rebuild, runbook và dashboard đã diễn tập.
- [ ] G4.2 Mở rộng Verifier/severity cho các họ finding G3; khóa contract SARIF/HTML, report delta/tổng hợp, gán chủ xử lý và rescan; kiểm output đúng chuẩn, evidence và vòng đời finding.
- [ ] G4.3 Tích hợp CI gọi API quét image/repo khi build, giữ digest/commit, credential cấp riêng và idempotency.

Các phương án kỹ thuật chưa khóa được ghi ngay tại đặc tả liên quan; không có backlog từ tài liệu nguồn cũ để agent tự suy thêm phạm vi.
