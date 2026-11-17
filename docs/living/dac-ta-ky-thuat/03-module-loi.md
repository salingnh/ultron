# Trách nhiệm module lõi

Mã module chỉ truy vết trách nhiệm kỹ thuật trong các thành phần của nền tảng.

| Module | Trách nhiệm | Hợp đồng/đầu ra |
| --- | --- | --- |
| M01 | Campaign, seed và cấu hình chạy có version | Campaign API, metadata |
| M02 | Workflow/queue, retry, timer, priority/dependency, pause/resume/cancel | Job và lịch sử điều phối |
| M03 | Agent chọn tool/input, lập kế hoạch, đọc tri thức, dừng theo budget | MCP request, hypothesis, session |
| M04 | ModelClient, driver provider/model, budget/cost | Message/tool call và usage |
| M05 | Registry, input validation, giới hạn, dependency và điều kiện mục tiêu | ApprovedTask hoặc lỗi có next_action |
| M06 | ContainerRunner, collector, parser cô lập | Raw references và ResultEnvelope |
| M07 | Canonical asset identity, alias và metadata | Asset/observation |
| M18 | Feed tình báo theo snapshot và nguồn | intel.revision.v2 |
| M19 | Metadata tham chiếu PoC | Dữ liệu tham khảo cho finding, không tải/chạy mã |
| M20 | Correlation, dedup finding và severity có lý do | finding.changed.v2, assessment history |
| M21 | Đối chiếu bằng chứng bằng tool đã đăng ký | Finding transition với evidence |
| M23 | Graph projection và các truy vấn đăng ký | knowledge.delta.v2, graph query |
| M24 | Báo cáo và theo dõi finding; JSON ở G2, SARIF/HTML ở G4; Telegram | Report/alert/triage history |
| M25 | Audit, metrics, trace | Bằng chứng hoạt động của hệ thống |
| M26 | UI/API/SSE | Campaign/job/graph/evidence view |
| M27 | Kiểm schema/provenance/checksum, dedup, chuẩn hóa | Metadata/outbox |
| M28 | EvidenceStore S3, raw bất biến, đoạn trích | evidence_id, URI, SHA-256 |

M27 nhận ResultEnvelope từ collector. File raw do tool sinh nằm ở S3; không có runtime import/REST riêng trong bộ thực thi hiện hành. Các module điều phối sở hữu bảng metadata của mình; scanner/adapter không ghi DB trực tiếp.

Mọi module có idempotency, lỗi chuẩn và provenance. Không VERIFIED khi thiếu bằng chứng; không suy FIXED chỉ từ việc chưa thấy. Severity của finding là đánh giá kết quả, không điều khiển quyền tool.

Phần nền tảng thực thi/metadata/graph/MCP được giao trước; các bộ xử lý kết quả và tool chuyên biệt có task riêng. Không suy tất cả module đã triển khai từ việc có dòng trong bảng này.

## M18/M20/M24 — đánh giá lại và cảnh báo sớm

M18 đọc API/file máy đọc được của NVD, OSV, CISA KEV và FIRST EPSS; GHSA là nguồn bổ sung. Mỗi bản ghi có nguồn, snapshot/version và thời điểm; thay đổi schema nguồn phải được phát hiện và báo lỗi. Feed lỗi không làm dừng scanner đã dispatch; UI/assessment phải cho thấy nguồn intel đang cũ hoặc thiếu.

Có hai nguồn kích hoạt M20: asset/observation/package thay đổi và intel thay đổi. CVE mới, CVE vào KEV hoặc EPSS thay đổi phải được đối chiếu chọn lọc với tài sản/finding liên quan đã lưu. Đường này hoạt động trên tri thức hiện có, không đợi lịch quét mới. Snapshot cũ vẫn giữ để tái lập đánh giá.

M20 lưu phương pháp match và từng nguồn scanner, không khử nguồn tại adapter. Finding mới, bằng chứng mới, intel mới hoặc yêu cầu đánh giá lại kích hoạt assessment. Cảnh báo phải dùng kết quả hiện tại có nguồn; khi đánh giá lỗi, yêu cầu nghiệp vụ là UNRATED kèm tín hiệu thô. Hình dạng fallback/attempt hiện còn phải khóa ở C07, chưa được coi đã implement.

M24 nhận thay đổi finding/severity, khử trùng delivery khi retry và gửi Telegram theo template/group id cấu hình. Ngưỡng gửi vẫn cần chốt; không tự mặc định một ngưỡng severity. JSON report và lịch sử triage phải dẫn tới raw/evidence; rescan có bằng chứng mới mới đủ để kết luận FIXED.

Giữ cảnh báo asset mới trong G2 bên cạnh finding/intel thay đổi. G4 giao SARIF/HTML hợp chuẩn, báo cáo delta giữa hai thời điểm và bản tổng hợp từ graph, gán chủ xử lý, gợi ý khắc phục và yêu cầu rescan. Bản xuất giữ nguồn/evidence và giá trị theo chính sách dữ liệu. API/format hiện hành còn JSON; G4 phải khóa contract xuất/triage và kiểm chuẩn trước khi mở định dạng mới.

Ca nghiệm thu: giả lập CVE vừa vào KEV hoặc EPSS đổi → tìm package/asset liên quan → đánh giá lại → Telegram có dẫn chứng; không chạy lại scanner chỉ để có thông báo. Mục tiêu độ trễ tại bảng NFR của đặc tả tổng quan, chưa có số đo vận hành.

## M21 — kiểm chứng động

M21 dùng tool đã đăng ký để kiểm phiên bản/phản hồi, đối chiếu scanner, chạy mẫu kiểm hoặc kiểm chứng động và credential theo input được khóa. Kết quả phải tách VERIFIED, CORROBORATED và chưa đủ căn cứ; finding mức cao có đối chứng âm phù hợp loại kiểm. Giá trị PoC tham khảo không tự nâng trạng thái finding. Mọi transition ghi nguồn, thời điểm, actor và evidence có checksum.

G4 mở rộng Verifier và đánh giá severity cho finding mã nguồn, secret, cloud, JS và binary của G3; năng lực lõi CVE/dịch vụ/credential và severity vẫn phải đạt ở G2.

## M19 — metadata tham chiếu

G3 giữ chỉ mục CVE → tham chiếu PoC, gồm trạng thái có tham chiếu, source_type, source_reputation, published_at, safe_validation_available và review_status. Nguồn/thời điểm phải truy được; chỉ xử lý metadata, không tải hay chạy mã. Tín hiệu này phục vụ M20, không là bằng chứng VERIFIED.
