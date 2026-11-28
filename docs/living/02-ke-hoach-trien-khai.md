# Kế hoạch theo kiến trúc tool-first

D29 là nguồn phạm vi hiện hành. Chưa có ngày bắt đầu hoặc ước lượng tuần được duyệt cho thiết kế này; không tái dùng lịch của kiến trúc cũ.

| Giai đoạn | Đầu ra | Cổng nghiệm thu |
| --- | --- | --- |
| G0 — đang mở | Contract, schema/DDL, spike Temporal/LangGraph, MCP, sandbox/network và graph | Contract được review; clean/upgrade DB; kiểm hạn chế sandbox và scheduling |
| G1 — nền tảng | Một vòng agent → MCP → sandbox → raw/metadata/graph → UI; DNSx và Subfinder | Thêm tool thứ hai không sửa lõi; priority/dependency hoạt động; restart/retry không trùng |
| G2 — MVP | Chuỗi network/web/artifact, xác minh động/credential, finding có evidence, đánh giá lại theo feed và báo cáo JSON | Workflow trọn vòng; finding có provenance/đối chứng; feed đổi kích hoạt đánh giá lại và báo cáo delta; soak 7 ngày/10.000 bước; không dependency sai/cross-campaign |
| G3 — mở rộng tool | Source/secret, cloud/cluster, JS/binary, OSINT (gồm email/keyword tới finding), cảnh báo Telegram và metadata tham chiếu | Adapter có schema/parser/conformance, đầu vào repo/cloud/cluster/artifact, chuỗi tri thức sinh job tiếp theo |
| G4 — vận hành | Hiệu năng, backup/restore, Verifier/severity mở rộng, SARIF/HTML, xử lý finding, CI và runbook | Kiểm RPO/RTO, replay/rebuild/tải, chuẩn bản xuất và finding đóng bằng rescan |

Tool cụ thể là backlog tích hợp, không phải lớp quyền riêng. Cần ước lượng lại sau spike; giai đoạn sau chỉ mở khi cổng trước đạt hoặc chủ sản phẩm chỉ đạo khác.

## Thứ tự kỹ thuật

Contract → metadata/ingestion + MCP/sandbox → agent/workflow + graph/UI → tool chain → kiểm bền và vận hành. Fake services giúp phát triển độc lập sau khi schema được khóa; chưa có implementation không được ghi là đã sẵn sàng.

## Điều kiện điều phối

Dependency thành công trước, priority sau; tôn trọng concurrency, thời gian và budget. Nếu tiền nhiệm lỗi/hủy, UI hiện lý do job chờ, agent có thể lập job mới. Chọn tool bằng input/schema và dữ liệu có sẵn; không thêm nhãn phân loại tác động hoặc gói quét.

## Bằng chứng giao hàng

| Cổng | Demo/bằng chứng bắt buộc |
| --- | --- |
| G0 | Kết luận spike, schema/clean-upgrade DB; bảng pin version/digest/license; registry và môi trường dev; lab và fixture; backlog G1 cùng sizing cho lưu trữ lâu dài |
| G1 | Campaign thật → agent/MCP → container → metadata/raw/graph/UI; cắm thêm tool thứ hai bằng manifest/parser; tắt worker giữa job rồi tiếp tục không trùng; audit và cách ly mạng |
| G2 | Domain/IP/URL tới finding; xác minh động/credential qua tool đã khóa, kiểm dạng khai thác chỉ trong lab cô lập; mọi finding có severity có nguồn hoặc UNRATED có lý do theo C07 và ngân sách; giả lập feed đổi rồi có đánh giá lại và báo cáo JSON/delta từ dữ liệu sẵn có; soak đạt và UI chỉ rõ lỗi |
| G3 | Email/keyword tới finding; Telegram báo thay đổi finding/feed; artifact JS sinh endpoint và job kế; secret trong fixture có vị trí/hash/fingerprint; static binary có coverage; lookup nguồn domain có provenance; diễn tập tích hợp scanner có bấm giờ |
| G4 | Load/capacity theo NFR, replay/rebuild/concurrency, diễn tập restore đạt RPO/RTO, kiểm prompt injection và runbook/dashboard có bằng chứng |

G1/đầu G2 chạy soak rút gọn 24–48 giờ để phát hiện lỗi sớm; cổng G2 vẫn yêu cầu đủ 7 ngày sau đóng băng workload. G4 chạy lại soak ở quy mô mở rộng, đồng thời demo finding CANDIDATE → VERIFIED → FIXED bằng rescan, bản xuất SARIF/HTML hợp chuẩn và pipeline CI quét image/repo.

Đối chiếu đầy đủ theo [FR/NFR](dac-ta-ky-thuat/01-tong-quan-dac-ta.md#yêu-cầu-chức-năng-và-đường-nghiệm-thu). Product Team ký nhận từng cổng G0–G4 dựa trên bằng chứng; hồ sơ gate ghi rõ điều kiện đạt, chưa đạt và việc được nhận xử lý tiếp. Chưa đạt điều kiện gate thì giai đoạn sau chưa mở, trừ chỉ đạo của chủ sản phẩm đã được ghi nhận.
