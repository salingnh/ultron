# DESIGN: giao diện nền tảng

## Màn hình

- Campaign: mục tiêu, objective, ngân sách, concurrency, pause/resume/cancel.
- Kế hoạch/job: tool, input, priority, depends_on, trạng thái, lý do chờ, lỗi và kết quả. React Flow hiển thị dependency, không dùng các tầng quyền thao tác.
- Graph: asset/quan hệ, provenance, observed_at, lọc theo campaign và truy nguyên job.
- Findings/evidence: mức nghiêm trọng, lý do, trạng thái, nguồn, SHA-256, raw reference và đoạn trích. Finding severity không dùng để quyết định job được phép chạy.
- Tool catalogue: tên, version, input schema, sandbox requirements, health và output.
- Báo cáo/triage ở G4: gán chủ xử lý, đổi trạng thái có lý do, report delta/tổng hợp và xuất SARIF/HTML; JSON cơ bản có ở G2. Chỉ mở control xuất sau khi contract tương ứng đạt.

SSE cập nhật trạng thái; UI ghi rõ dữ liệu chưa có, kết quả chưa đủ và lỗi. Query có phân trang, giới hạn node/edge và timeout; hiển thị dữ liệu bị cắt, không làm người xem tưởng đã thấy toàn bộ graph. Model/provider cấu hình trực tiếp ở vận hành. Private ingress/VPN, single-tenant, chưa có đăng nhập người dùng ở MVP. Không vẽ UI cho tool chưa có contract triển khai.

## Nguyên tắc trình bày

Giao diện là công cụ vận hành: mật độ thông tin cao, đọc nhanh bằng bảng, luồng job và graph; không hero hoặc minh họa trang trí. Người xem thấy agent đã làm gì mà không cần đọc log. Mỗi bước, node, cạnh và finding mở được tool/version, job, nguồn gốc, thời điểm và bằng chứng.

Nhãn giao diện dùng tiếng Việt; giữ thuật ngữ finding, endpoint, CVE, KEV, EPSS và canonical key. Secret và credential vận hành được xử lý theo AGENTS; phần bằng chứng hiển thị giá trị đầy đủ. Mỗi lỗi có mã chuẩn, mô tả và next_action. Trạng thái luôn có nhãn chữ; màu chỉ hỗ trợ đọc.

## Màu và typography mặc định

Đây là các mặc định thiết kế đã có trước khi hợp nhất; chủ sản phẩm có thể đổi khi chốt UI. Khai báo bằng CSS custom properties, hỗ trợ sáng/tối qua prefers-color-scheme và data-theme.

| Token | Sáng | Tối | Mục đích |
| --- | --- | --- | --- |
| --bg | #F2F5F8 | #0E161D | Nền trang |
| --surface | #FFFFFF | #16222C | Thẻ, bảng, panel |
| --ink | #12202B | #E6EDF3 | Chữ chính |
| --muted | #4A5B69 | #9FB0BE | Chữ phụ |
| --line | #CBD5DE | #2C3C49 | Viền |
| --subtle | #E6ECF1 | #121C25 | Nền nhóm |
| --accent / --accent-bg | #1D4ED8 / #E3ECFF | #9BBBFF / #1B2D55 | Liên kết, thông tin |
| --success / --success-bg | #0F766E / #DAF2EE | #62D6C7 / #11352F | Thành công, verified |
| --warning / --warning-bg | #9A4506 / #FCE8D0 | #F4B874 / #3B2A14 | Cần chú ý |
| --neutral / --neutral-bg | #55616B / #E7EBEE | #A3AFB9 / #222E38 | Trung tính |

Chữ đạt tương phản tối thiểu 4.5:1. Các trạng thái cần phân biệt phải có nhãn và khác độ sáng; ưu tiên cặp xanh dương/cam. Severity dùng nhãn chữ và chip; bảng màu từng severity được chốt cùng màn hình finding.

- Font giao diện: IBM Plex Sans 400/500/600, fallback system-ui, -apple-system, Segoe UI, Roboto, sans-serif.
- Code, ID, canonical key, hash và mã module: JetBrains Mono 500, fallback ui-monospace, Menlo, Consolas, monospace.
- Thang chữ: 12.5 / 13.5 / 15 / 20 / 26–36 px; nhấn bằng độ đậm. Số trong bảng dùng tabular-nums.
- Font và thư viện phục vụ tại chỗ hoặc qua registry nội bộ; không gửi dữ liệu nhạy cảm ra dịch vụ bên ngoài để dựng UI.

## Component và bố cục

| Component | Quy tắc |
| --- | --- |
| Chip trạng thái | Bo tròn, chữ 12.5px, có nhãn chữ cùng màu |
| Thẻ tài sản/module | Viền 1px, bo 8px, padding 10–12px, ID font mono, nhãn phụ căn phải |
| ID/hash | Có nút sao chép và hiển thị canonical key |
| Bảng | Đầu cột cố định, lọc phía trên, cursor pagination, mở panel chi tiết bên phải |
| Panel nguồn gốc | Tool/version, job, asset nguồn, observed_at, confidence và evidence SHA-256 |
| Timeline | Hiển thị từng lần chạy và cả lần không còn thấy finding |
| Rỗng/đang tải/lỗi | Có giải thích; skeleton cho bảng/graph; lỗi kèm bước tiếp theo |

Trang nội dung rộng khoảng 1120–1440px; flow và graph dùng toàn khung. Lề nhỏ nhất 16px, khoảng cách theo bội số 4px; không cuộn ngang trang, graph cuộn trong khung riêng. Chuyển động chỉ dùng để thể hiện dữ liệu mới đến.
