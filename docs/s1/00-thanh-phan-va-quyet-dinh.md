# Quyết định kiến trúc và cổng contract S1

## D29 — chỉ đạo chủ sản phẩm ngày 2026-11-16

Thiết kế theo các thành phần: AI agent điều phối; sandbox thực thi tool; MCP chuẩn hóa lời gọi agent–tool; CSDL metadata; CSDL graph tài sản/quan hệ; giao diện; S3 raw; collector/ingestion. Không có tier/profile hoặc cơ chế đổi tên tương đương để phân loại quyền chạy. Priority và dependency chỉ mô tả thứ tự công việc.

CPU/RAM/timeout, cách ly mạng, schema validation, ngân sách và provenance là thuộc tính thực thi cụ thể. Model dùng provider/model cấu hình trực tiếp. Tool chuyên biệt được tích hợp qua adapter, không là nền tảng bắt buộc mới.

Phạm vi nghiệp vụ vẫn gồm pentest chủ động, xác minh động và kiểm thử credential. Các năng lực được biểu diễn bằng tool/input, priority và dependency. Việc hợp nhất giữ các quyết định còn hiệu lực về bằng chứng, cảnh báo và chất lượng finding tại nguồn phụ trách; thay đổi mô hình điều phối không tự hủy các yêu cầu đó.

## Lựa chọn triển khai giữ lại

Python 3.14; Temporal + LangGraph; Podman rootless; UUIDv7; PostgreSQL metadata; Neo4j projection; SeaweedFS/S3; collector tải raw và parser cô lập; evidence SHA-256; lịch sử append-only và trạng thái có history; React/TypeScript cho UI. Các lựa chọn này đã có trong thiết kế, chưa có bằng chứng triển khai dịch vụ.

`policy_version`, `policy_snapshot`, `policy_decision` và ApprovedTask là tên kỹ thuật cho cấu hình/kiểm hợp đồng thực thi, không tạo quy trình phê duyệt thủ công. Actor áp dụng cho mọi job.

## Một bộ tài liệu và một bộ contract hiện hành

Nội dung ở nguồn chính theo [chỉ mục](../README.md). Các tài liệu cũ đã đối chiếu và xóa; quyết định đã thay thế tra qua Git. Không giữ đặc tả của phương án không dùng hoặc kế hoạch tự mở lại phương án đó.

Version schema/API/event được khai báo ở [contracts](../../contracts/README.md), chỉ phục vụ tương thích giao tiếp. Contract hiện còn là bản nháp trước S1. Không tăng số version tài liệu hay tạo bộ tài liệu song song mỗi lần điều chỉnh.

## Luồng phải ghép nối được

MCP request → kiểm tool/input/defaults/targets/budget/dependency → ApprovedTask ghim manifest → sandbox → collector/parser → ResultEnvelope → ingestion/metadata/outbox → graph/query/UI.

Nghiệm thu yêu cầu schema thống nhất, fixture đúng/sai, clean/upgrade DB, registry/adapter conformance và truy nguyên actor/evidence. Các kiểm tra này không đồng nghĩa nghiệm thu MVP chạy thật.

## Điều kiện chưa đạt trước cổng S1

| Nội dung | Nguồn chi tiết | Task |
| --- | --- | --- |
| Seed reference; hash/idempotency; partial/late/cancel | [Dữ liệu](../living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md) | S1.1/S1.2 |
| Outbox/revision chịu rollback và commit đảo thứ tự | [Graph](../../contracts/graph/model.md#c04--thứ-tự-công-bố-đã-khóa-ở-s13) | S1.3 |
| ModelClient round-trip, severity fallback | [Interface](../../contracts/interfaces/README.md#phần-cần-khóa-của-modelclient-và-severity--c07) | S1.4 |
| Input schema tool và nguồn gốc actor | [Adapter](../living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#contract-tool-và-actor--c05-đã-khóa-s15a) | S1.5 |
| Chuyển cấu hình/campaign đã lưu bằng contract cũ | Đã bỏ: gộp thành [baseline](../../contracts/README.md#dữ-liệu-và-migration) theo quyết định chủ sản phẩm 2026-11-24 (chưa có dữ liệu thật) | S1.6 (bỏ) |

Các mục trên đã được đưa vào nguồn hiện hành, chưa phải đã implement/kiểm xong. Không coi việc xóa tài liệu cũ là đóng các lỗi contract.

<!-- CI skip probe; never merged -->
