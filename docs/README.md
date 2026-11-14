# Tài liệu dự án AEGIS–Vanguard

Hệ thống rà quét lỗ hổng nội bộ do AI agent điều phối. Thư mục này gom toàn bộ tài liệu dự án tính đến ngày 14/11/2026.

## Đọc gì trước

Bộ tài liệu hiện hành nằm trong [`living/`](living/). Đây là bản xuất Markdown từ các tài liệu sống trên Claude Docs, đã được viết lại thống nhất theo các quyết định ngày 12 và 13/11/2026. Khi có mâu thuẫn với tài liệu trong `source/`, bản trong `living/` được ưu tiên.

| Tài liệu | Nội dung |
| --- | --- |
| [00 Tổng quan hệ thống hợp nhất](living/00-tong-quan-he-thong-hop-nhat.md) | Tóm tắt, quyết định chốt, phạm vi, kiến trúc, an toàn, lộ trình, KPI. Thay thế tài liệu 00 cũ |
| [01 Đặc tả kỹ thuật](living/dac-ta-ky-thuat/README.md) | 28 module, nền tảng, dữ liệu, API và sự kiện (5 phần) |
| [02 Kế hoạch triển khai](living/02-ke-hoach-trien-khai.md) | Giai đoạn GĐ0 đến GĐ4, cổng nghiệm thu, đầu ra từng module |
| [03 Đánh giá OSS](living/03-danh-gia-oss.md) | Bọc nguyên hay tự dựng: Flowsint, LiteLLM, REA, Amass và các bộ công cụ |
| [04 Bản đồ module](living/04-ban-do-module.html) | Sơ đồ module theo tầng kiến trúc (trang HTML, mở bằng trình duyệt) |

Lưu ý: ba sơ đồ nhúng (kiến trúc tổng thể và lộ trình) trong tài liệu 00 và 02 không xuất được sang Markdown, chỗ đó chỉ còn dòng ghi chú `[embedded content: …]`. Bản gốc có sơ đồ vẫn nằm trên Claude Docs.

## Tài liệu nguồn

[`source/`](source/) giữ nguyên các file gốc đã tải lên dự án, kèm bản chuyển sang Markdown trong [`source/markdown/`](source/markdown/) để đọc và so sánh trên GitHub.

| File gốc | Ghi chú |
| --- | --- |
| `00_Tong_quan_du_an_AEGIS_Vanguard.docx` | Tổng quan dự án, đã được thay bằng `living/00` |
| `01_Thiet_ke_kien_truc_HLD.docx` | Thiết kế kiến trúc HLD |
| `02_Dac_ta_chuc_nang_va_modules_OSS.docx` | Đặc tả chức năng và module OSS |
| `03_Mo_hinh_du_lieu_KnowledgeGraph_API.docx` | Mô hình dữ liệu, Knowledge Graph, API |
| `04_Trien_khai_An_toan_Kiem_thu_Roadmap.docx` | Triển khai, an toàn, kiểm thử, roadmap |
| `Đặc Tả Hệ Thống Rà Quét Lỗ Hổng AI.docx` | Đặc tả gốc "Offensive Vaccine" (tham khảo) |
| `dac-ta-ky-thuat-aegis-vanguard-v2.6.html` | Bản HTML SPEC v2.6 (tham khảo) |
| `deep-research-report.md` | Báo cáo deep-research (UDEP), tham khảo |
