# PROGRESS: AEGIS–Vanguard

> Nhật ký tiến độ cho AI agent. Cập nhật sau mỗi task hoặc PR: thêm dòng vào "Đã hoàn thành", ghi lỗi vào "Đang lỗi hoặc bị chặn", sửa "Bước tiếp theo". Ghi ngày theo định dạng YYYY-MM-DD. Không xóa lịch sử, chỉ ghi thêm.

## Trạng thái hiện tại

- **Giai đoạn đang mở:** GĐ0 Chuẩn bị (chưa bắt đầu; chưa chốt ngày bắt đầu).
- **Cổng gần nhất đã qua:** chưa có.
- **Mã sản phẩm:** chưa có. Repo mới chứa tài liệu.
- **Quyết định còn mở:** không có (theo kế hoạch bản chốt 13/11/2026).

## Đã hoàn thành

| Ngày | Việc | Tham chiếu |
| --- | --- | --- |
| 2026-11-12 | Bộ tài liệu thiết kế 00–04, đặc tả kỹ thuật, kế hoạch triển khai, đánh giá OSS | `docs/` |
| 2026-11-13 | Chốt toàn bộ quyết định Product Team (phạm vi quét, secret dạng rõ, agent đánh giá mức nghiêm trọng, không đo precision/recall, lưu vĩnh viễn, Podman, MCP, Telegram) | `docs/living/02-ke-hoach-trien-khai.md` mục 10 |
| 2026-11-14 | Đưa tài liệu vào repo (`docs/living`, `docs/source`) và thêm bộ file hướng dẫn cho AI agent (PRD, ARCHITECTURE, DESIGN, RULES, TASKS, PROGRESS, AGENTS, CLAUDE) | PR đầu tiên |

## Đang lỗi hoặc bị chặn

| Ngày | Vấn đề | Ảnh hưởng | Người xử lý |
| --- | --- | --- | --- |
| 2026-11-14 | Ba sơ đồ nhúng (kiến trúc tổng thể, hai lộ trình) không xuất được sang Markdown trong `docs/living/` | Thiếu hình minh họa; nội dung chữ vẫn đủ | Product Team (xuất ảnh từ Claude Docs nếu cần) |
| 2026-11-14 | Ngôn ngữ backend và cấu trúc thư mục mới là đề xuất | Cần khóa ở epic S1 trước khi subagent viết mã | Agent review kiến trúc + Product Team |
| 2026-11-14 | Giấy phép Nerva và dnstwist chưa xác minh | Chặn đóng gói adapter tương ứng | T0.7 |

## Bước tiếp theo

1. T0.1 Chốt ngày bắt đầu, cấu hình agent review kiến trúc và bảo mật.
2. T0.2–T0.6 Chạy năm spike (ưu tiên spike 1, 2, 4 vì nằm trên đường găng).
3. T0.7 Lập bảng pin phiên bản và giấy phép.
4. T0.8 Dựng môi trường dev; T0.10 dựng lab.
5. T0.11 Khóa backlog GĐ1, demo cổng G0.

## Rủi ro cần theo dõi

- Spike 1 thất bại (LangGraph không lồng an toàn trong Temporal) → thiết kế lại S2; không bắt đầu S2 trước kết luận.
- Một máy không đủ tải ở GĐ3–GĐ4 → theo dõi tải từ GĐ2; Kubernetes là thay bộ chạy.
- Không giới hạn phạm vi khi chạy công cụ thật ở GĐ2 → chấp nhận theo quyết định 13/11; bắt buộc ghi nguồn gốc và audit.
