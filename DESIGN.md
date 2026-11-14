# DESIGN: AEGIS–Vanguard

> Hướng dẫn giao diện cho AI agent khi làm M26 (Web UI). Phần **đã chốt** lấy từ đặc tả và kế hoạch. Phần **đề xuất** (màu, font) lấy từ trang [bản đồ module](docs/living/04-ban-do-module.html), là ngôn ngữ hình ảnh duy nhất dự án đang có; dùng làm mặc định cho đến khi Product Team đổi.

## 1. Nguyên tắc

1. **Công cụ vận hành, không phải trang marketing.** Mật độ thông tin cao, gọn, đọc nhanh. Không hero, không minh họa trang trí.
2. **Cho thấy agent đã làm gì.** Người xem phải thấy chiến dịch chạy và đồ thị lớn dần **mà không cần đọc log** (tiêu chí epic S8a).
3. **Mọi thứ truy được về bằng chứng.** Mỗi nút đồ thị, mỗi finding, mỗi bước trong luồng quét đều mở được nguồn gốc: công cụ nào, từ tài sản nào, job nào, bằng chứng nào.
4. **Lỗi là công dân hạng nhất.** 100% job lỗi hiện kèm phân loại lỗi (mã lỗi chuẩn) và bước tiếp theo.
5. **Không che dữ liệu.** Secret hiển thị dạng rõ theo quyết định 13/11. Không thêm lớp mask.
6. **Tiếng Việt** cho nhãn giao diện; giữ nguyên thuật ngữ kỹ thuật (finding, endpoint, CVE, KEV, EPSS).

## 2. Màn hình (đã chốt)

| Màn hình | Giai đoạn | Nội dung | Thư viện |
| --- | --- | --- | --- |
| Tạo và quản lý chiến dịch | GĐ1 | Năm loại đầu vào (IP, domain, URL, email, từ khóa), RoE, pause/resume/cancel, trạng thái và ngân sách | React |
| Luồng quét | GĐ1 | Agent lập kế hoạch → điểm kiểm → container chạy → kết quả vào kho, cập nhật thời gian thực; xem chi tiết từng bước | React Flow + ELK hoặc dagre, SSE |
| Đồ thị tri thức | GĐ1 | Tài sản và quan hệ, nguồn gốc từng nút và từng cạnh, lớn dần theo thời gian thực | Cytoscape.js (Sigma.js nếu vượt vài chục nghìn nút) |
| Findings và job lỗi | GĐ2 | Danh sách finding có lọc, mở được bằng chứng và dẫn chứng; dòng thời gian qua các lần chạy (`FindingRun`); danh sách job lỗi kèm phân loại | React |
| Báo cáo và đổi trạng thái | GĐ4 | Đổi trạng thái finding kèm lý do, báo cáo delta giữa hai thời điểm, xuất SARIF, JSON, HTML | React |

Chưa có đăng nhập ở MVP. Truy cập qua private ingress hoặc VPN.

## 3. Màu sắc (đề xuất)

Định nghĩa bằng CSS custom properties trên `:root`, có bản tối qua `prefers-color-scheme` và `[data-theme]`.

| Token | Sáng | Tối | Dùng cho |
| --- | --- | --- | --- |
| `--bg` | `#F2F5F8` | `#0E161D` | Nền trang |
| `--surface` | `#FFFFFF` | `#16222C` | Thẻ, bảng, panel |
| `--ink` | `#12202B` | `#E6EDF3` | Chữ chính |
| `--muted` | `#4A5B69` | `#9FB0BE` | Chữ phụ, nhãn |
| `--line` | `#CBD5DE` | `#2C3C49` | Viền, đường kẻ |
| `--layer` | `#E6ECF1` | `#121C25` | Nền nhóm, vùng phân tầng |
| `--use` / `--use-bg` | `#1D4ED8` / `#E3ECFF` | `#9BBBFF` / `#1B2D55` | Nhấn chính, liên kết, trạng thái thông tin |
| `--wrap` / `--wrap-bg` | `#0F766E` / `#DAF2EE` | `#62D6C7` / `#11352F` | Thành công, đã xác minh |
| `--own` / `--own-bg` | `#9A4506` / `#FCE8D0` | `#F4B874` / `#3B2A14` | Cảnh báo, cần chú ý |
| `--def` / `--def-bg` | `#55616B` / `#E7EBEE` | `#A3AFB9` / `#222E38` | Trung tính, tắt, để sau |

Quy tắc:
- Chữ đạt tương phản tối thiểu 4.5:1 trên nền của nó.
- Màu không bao giờ là kênh duy nhất: trạng thái và mức nghiêm trọng luôn có **nhãn chữ** đi kèm.
- Các màu cần phân biệt nhau phải khác cả độ sáng, không chỉ khác sắc độ; ưu tiên cặp xanh dương/cam thay cho đỏ/xanh lá.
- Mức nghiêm trọng do agent đánh giá: dùng nhãn chữ + chip màu; bảng màu cụ thể cho từng mức chốt khi làm M20/M24 ở GĐ2–GĐ4.

## 4. Font chữ (đề xuất)

- Chữ giao diện: **IBM Plex Sans** (400, 500, 600), dự phòng `system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif`.
- Mã, ID, khóa chuẩn, hash, mã module: **JetBrains Mono** (500), dự phòng `ui-monospace, Menlo, Consolas, monospace`.
- Thang chữ gọn, 4–5 cỡ: 12.5 / 13.5 / 15 (thân) / 20 (tiêu đề mục) / 26–36 (tiêu đề trang). Nhấn bằng độ đậm, không thêm cỡ.
- Số trong bảng dùng `font-variant-numeric: tabular-nums`.

## 5. Thành phần (component)

| Thành phần | Mô tả |
| --- | --- |
| Chip | Bo tròn hoàn toàn, chữ 12.5px, nền `--*-bg`, chữ `--*`; dùng cho trạng thái finding, công cụ, giai đoạn |
| Thẻ module/tài sản | Nền `--surface`, viền 1px `--line`, bo 8px, padding 10–12px; dòng đầu có mã (font mono) và nhãn phụ căn phải |
| Mã định danh | Luôn font mono, có nút sao chép; hiển thị khóa chuẩn (`dns:…`, `purl:…`) |
| Bảng | Đầu cột cố định, phân trang theo cursor, lọc ở trên; hàng mở được panel chi tiết bên phải |
| Panel nguồn gốc | Với mỗi nút, cạnh, finding: công cụ, phiên bản, job, tài sản gốc, `observed_at`, độ tin cậy, link bằng chứng (SHA-256) |
| Dòng thời gian | Lịch sử theo từng lần chạy, kể cả lần "không còn thấy" |
| Trạng thái lỗi | Mã lỗi chuẩn + mô tả + `next_action`; không bao giờ chỉ là "Error" |
| Trạng thái rỗng và đang tải | Có chữ giải thích; skeleton cho bảng và đồ thị |

## 6. Bố cục

- Rộng tối đa khoảng 1120–1440px cho trang nội dung; màn hình luồng quét và đồ thị dùng toàn khung.
- Lề 16px trên điện thoại, không cuộn ngang trang (đồ thị tự cuộn bên trong khung của nó).
- Khoảng cách theo bội số 4px.

## 7. Không làm

- Không đưa dữ liệu nhạy cảm ra dịch vụ bên ngoài (font và thư viện tự host hoặc lấy từ registry nội bộ khi triển khai).
- Không thêm hoạt ảnh trang trí; chuyển động chỉ khi nó cho thấy dữ liệu mới đến.
- Không dựng giao diện cho tính năng nằm ngoài phạm vi (đăng nhập, multi-tenant, red-team).
