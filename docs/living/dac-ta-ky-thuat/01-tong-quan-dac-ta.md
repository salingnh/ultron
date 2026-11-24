# Thành phần và hợp đồng

## Cấu trúc sản phẩm

Agent lập kế hoạch; MCP chuẩn hóa lời gọi; sandbox thực thi tool; PostgreSQL lưu metadata; Neo4j lưu quan hệ asset; S3 lưu raw; UI biểu diễn kế hoạch và kết quả. Temporal quản lý workflow bền vững, LangGraph quản lý phiên suy luận.

## Hợp đồng chung

Bộ [contracts](../../../contracts/README.md) là nguồn hình dạng dữ liệu. Tên file/endpoint/schema lấy từ bộ này, không tự định nghĩa lại. Những hình dạng còn thiếu trước cổng S1 được chỉ ngay trong đặc tả liên quan và TASKS; chưa được coi là hỗ trợ runtime.

- Campaign: objective, seeds, execution settings, budget, actor và trạng thái.
- Tool manifest: capability, provider/version, schema input/output, inputDefaults, image digest, permissions, resource limits, parser.
- Request: input, rationale, priority và depends_on; campaign/session lấy từ ngữ cảnh xác thực của lời gọi MCP.
- ApprovedTask: kết quả kiểm hợp đồng của M05, ghim adapter_version/manifest_sha256 để M06 resolve đúng cấu hình thực thi bất biến, có chữ ký M05; không phải quyết định phê duyệt của con người.
- ResultEnvelope: kết quả chuẩn hóa, coverage, errors, raw references và provenance.
- Query: schema đọc graph/evidence có giới hạn và lọc campaign.

## Các bất biến

Job chỉ chạy sau khi dependencies SUCCEEDED; priority cao không vượt qua dependency. Chỉ tool/version đã đăng ký được chọn. Mỗi lần quét mới có scan_cycle mới, retry không sinh bản ghi trùng. Lịch sử dữ liệu không xóa; trạng thái hiện tại có lịch sử. Finding xác nhận có SHA-256/evidence.

## Nghiệm thu

MCP → sandbox → ingestion → graph/UI chạy trọn; tool thứ hai thêm chỉ bằng adapter; input sai bị từ chối; không dependency cycle/cross-campaign; không job trùng khi retry; sandbox không chạm control/data; có thể replay dữ liệu và dựng lại graph.

## Yêu cầu chức năng và đường nghiệm thu

Mã FR giữ liên hệ với các yêu cầu nghiệp vụ trước khi hợp nhất. Nội dung dưới được điều chỉnh theo kiến trúc hiện hành và định dạng output đang giao. Đây là yêu cầu phải triển khai, chưa phải kết quả đã đạt.

| ID | Yêu cầu | Module | Task/cổng | Bằng chứng cần có |
| --- | --- | --- | --- | --- |
| FR-001 | Tạo campaign từ domain, IP/CIDR, URL, email, keyword | M01 | S1.1, G1.1 | Giữ seed gốc, snapshot cấu hình và actor; seed reference xuyên luồng |
| FR-002 | Ngân sách, rate/concurrency (khung giờ hoãn sang G2) | M01/M05 | G1.1, G2.3 | Mọi job dùng đúng snapshot; hết budget thì không dispatch |
| FR-003 | Tìm provider tương thích capability/schema | M05 | S1.5, G1.3 | Từ chối capability/input lạ; tool thứ hai không sửa lõi |
| FR-004 | Start/status/cancel/collect thống nhất | M06 | G1.3 | Một invocation một container; retry không nhân job; hủy/timeout có kết quả trung thực |
| FR-005 | Agent nhiều vòng, context hữu hạn và checkpoint | M03/M04 | S1.4, G1.2 | Restart tiếp tục từ state, ledger và idempotency key |
| FR-006 | Campaign durable, pause/resume/cancel | M02 | G0.1, G2.3 | Fault injection không mất tiến độ hoặc chạy trùng |
| FR-007 | Discovery domain/IP/service/endpoint | M08/M09/M10 | G2.1 | Đồ thị đủ chuỗi và provenance tới seed/job |
| FR-008 | Artifact/image/SBOM/package | M13/M14 | G2.1 | Digest/commit của nguồn đi cùng SBOM, pURL và evidence |
| FR-009 | Đối chiếu CVE/OSV/KEV/EPSS theo snapshot | M18/M20 | G2.2 | Có source/time/match method; feed đổi thì đánh giá lại và cảnh báo |
| FR-010 | Hợp nhất thực thể và dedup | M07/M27 | G0.3, G1.4 | Replay và nhiều writer không tạo canonical entity trùng |
| FR-011 | Evidence có checksum/provenance | M28 | G1.4 | Finding có evidence hoặc lý do unsupported; restore kiểm lại hash |
| FR-012 | UI campaign/job/graph/error minh bạch | M26 | G1.5 | Xem tiến độ không cần log; lỗi có code và next_action |
| FR-013 | Enrichment và pivot có nguồn | M08 | G3.2 | Nguồn domain/email/keyword và lookup rò rỉ domain có source chain/API key cấu hình |
| FR-014 | Phân tích JS/source map/repo | M12/M15 | G3.1 | Endpoint/package/finding giữ vị trí và artifact/commit nguồn |
| FR-015 | Phân tích tĩnh binary/app | M16 | G3.1 | Tool cô lập, output có coverage và hạn chế phân tích; pseudocode không là source gốc |
| FR-016 | Kiểm chứng động và credential | M17/M21 | G2.1/G2.2 | Tool/input được khóa, có actor/evidence/đối chứng âm; không VERIFIED chỉ từ suy đoán |
| FR-017 | Quét lại chọn lọc theo delta/freshness | M02/M23 | G3.2 | Giữ lịch sử, tạo scan_cycle mới; không chạy lại toàn bộ tài sản không đổi một cách ngầm định |
| FR-018 | Agent đánh giá severity có lý do/nguồn | M20 | S1.4, G2.2 | Assessment theo input snapshot; lỗi có trạng thái chưa đánh giá, giữ raw/history |
| FR-019 | JSON report ở G2; SARIF/HTML, delta và quy trình xử lý ở G4 | M24 | G2.2, G4.2 | Output đúng chuẩn có evidence/citation; gán chủ xử lý, gợi ý và rescan dẫn tới lịch sử FIXED/REGRESSED |
| FR-020 | Tích hợp Git/registry/cloud và gọi API từ CI khi build | M11/M12/M13 | G3.1, G4.3 | Credential vận hành gắn job/mục tiêu; không cấp ngầm cho agent; image/repo giữ digest/commit |

Chi tiết hành vi tại module/tool/dữ liệu; TASKS là nguồn trạng thái công việc. Có một dòng yêu cầu không đồng nghĩa capability đã được đăng ký trong bộ schema mẫu.

## NFR và mục tiêu đo

Các ngưỡng này là mục tiêu thiết kế đã có trước khi hợp nhất, không phải benchmark đã đạt. G0 khóa workload/phần cứng và cách đo; việc điều chỉnh mục tiêu phải ghi rõ, không được mất số mục tiêu do rút gọn tài liệu.

| ID | Thuộc tính | Mục tiêu/điều kiện kiểm |
| --- | --- | --- |
| NFR-01 | Độ bền | Campaign 7 ngày, từ 10.000 bước; restart không mất trạng thái; mục tiêu khôi phục worker trong 5 phút |
| NFR-02 | Toàn vẹn | Retry/idempotency không trùng; raw SHA-256; lịch sử bất biến, trạng thái hiện tại có history. Ca nghiệm thu: 100 lần cùng request/key chỉ một job; replay 1.000 event không trùng; 1.000 envelope đồng thời không tạo asset trùng; hai lần quét giữ đủ FindingRun |
| NFR-03 | Tải và đồng thời | Mục tiêu 50 job đồng thời, queue delay P95 <2 phút; bài kiểm upsert 100 writer không trùng node. G4 đo backpressure/ingestion với workload artifact 10 GB và graph 1 triệu node; khóa giới hạn từng tool trước khi chạy |
| NFR-04 | Độ trễ | Registry P95 <300 ms với 100 provider; ingestion P95 <30 giây với output <1 MB; API nội bộ mục tiêu 99,5% sẵn sàng/tháng |
| NFR-05 | Chính sách dữ liệu | Lưu vĩnh viễn, không mask secret theo AGENTS; dữ liệu/backup được bảo vệ theo nền tảng |
| NFR-06 | Quan sát | 100% tác vụ có campaign/job/trace; 100% job lỗi có phân loại và next_action |
| NFR-07 | Tích hợp | Adapter phát hành độc lập, có compatibility/conformance; diễn tập thêm CLI đơn giản trong tối đa 2 ngày công |
| NFR-08 | Thực thi | Mọi job qua M05, sandbox không privileged và không vào control/data; có nguồn gốc mục tiêu |
| NFR-09 | Cảnh báo sớm | KEV từ công bố tới ingest <2 giờ; EPSS <24 giờ; feed đổi kích hoạt đánh giá/cảnh báo từ tri thức đã lưu |

Mục tiêu backup/restore duy trì tại tài liệu nền tảng. Kết quả kiểm thực tế chỉ ghi ở PROGRESS; các smoke/schema test hiện có chưa chứng minh những mục tiêu tải/latency này.
