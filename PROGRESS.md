# PROGRESS

## Hiện trạng

| Hạng mục | Trạng thái |
| --- | --- |
| Giai đoạn | G0; repo có tài liệu, schema/DDL/fixture/test; chưa có dịch vụ sản phẩm chạy trọn vòng |
| Git | Hợp nhất nhánh redesign/pentest-repositioning-s1 vào main theo yêu cầu; baseline nguồn 23490be, các mục S1.1–S1.6 vẫn mở |
| Kiến trúc | Theo D29: AI agent/MCP/sandbox/metadata/graph/S3/UI; model cấu hình trực tiếp, job dùng priority/dependency |
| Tài liệu | Một bộ ở đường dẫn chính. Ngày 2026-11-17 hoàn tất ma trận 367 mục đối chiếu với nguồn trước hợp nhất; mỗi mục có đích hiện hành hoặc căn cứ thay thế, phần còn hiệu lực bị rơi đã được bổ sung |
| Nội dung đã giữ | Use case, context/ledger/stop conditions, adapter/chain, ontology/identity/provenance, ingestion gates, correlation/finding và kiểm thử/vận hành |
| Nội dung đã loại | Phương án nền tảng bị thay thế, phân tầng/phân nhóm, workflow duyệt cũ, nhánh ngoài phạm vi và claim benchmark/OSS chưa có bằng chứng; không dùng việc chưa implement làm lý do bỏ yêu cầu đã chốt |
| Contract | Một bundle hiện hành còn bản nháp trước S1; version giao tiếp nằm ở schema/API/event, không có bộ tài liệu theo version |
| F1–F3 | Đã sửa receipt chung, một đường gửi MCP và ghim manifest/adapter trong task/job; migration 0003 cho pin bất biến |
| Rà contract | Đã đối chiếu 76 file trong 10 nhóm; N01–N06 đã sửa và có kiểm hồi quy; S1.1–S1.6 còn mở |
| Bảo toàn nội dung | Đối chiếu 35 nguồn text tại HEAD trước viết lại và 26 tài liệu hiện hành; 28 quyết định D, 12 lựa chọn OSS, các bảng chốt 12/13-11, FR/NFR, SDK/ingestion, API/event/query và logic chi tiết. Sáu cặp Word/8 hình đã đối chiếu ở lượt trước. Không còn mục trong ma trận thiếu đích hoặc bị loại không có căn cứ |
| Triển khai | Chưa triển khai/chạy dịch vụ sản phẩm; không chạy scanner, LLM hoặc E2E sản phẩm |

## Còn mở

S1.1–S1.6 trong TASKS: seed reference, canonical hash/receipt, lifecycle partial/late/cancel, outbox ordering, ModelClient/severity, tool schema/actor và chuyển cấu hình đã lưu. [Kiểm biên schema/OpenAPI C08](docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c08--kiểm-biên-schema-và-openapi) đã được sửa ở S1.7. Chi tiết duy trì tại nguồn phụ trách; chưa đạt cổng S1 hoặc MVP chỉ nhờ các kiểm tra dưới đây.

Migration chuyển cấu trúc/giữ snapshot, chưa chuyển policy_snapshot JSON và current_policy_version của campaign cũ thành cấu hình mới hợp lệ. Chưa tự resume campaign/job cũ. Scheduler, isolation và agent recovery chưa có implementation sản phẩm để xác minh.

Theo chỉ đạo tiếp tục giữ logic cũ ngoài phần chủ sản phẩm đã đổi, đã khôi phục quyết định 13/11 về pivot theo seed/provenance và không dùng allowlist phạm vi; bỏ điều kiện xác minh/duyệt riêng từng asset do lần viết lại tự thêm. Campaign nội bộ/ủy quyền, schema, nguồn gốc, ngân sách và cách ly mạng vẫn giữ. S1.5 còn phải khóa declared sources/target binding của egress và query truncation.

## Bằng chứng kiểm chứng

Các kiểm Python/DB/Cypher bên dưới đã chạy ở lượt sửa contract trước; lượt bảo toàn logic chỉ sửa tài liệu. Schema/code/SQL/fixture giữ hash, bốn README/model của contracts được làm rõ. Không diễn giải các test trước thành nghiệm thu runtime hoặc nghiệm thu yêu cầu G3/G4 vừa phục hồi.

- PASS trên Python 3.12.16: validator 34 schema, 9 fixture hợp lệ, 6 fixture bị từ chối đúng, 23 operation; 17 test contract/conformance, gồm F1–F3 và N01–N06. Các kiểm tra chạy trong container tách mạng sau khi cài dependency.
- PASS OpenAPI 3.1 đầy đủ; validator bắt cả response ngoài chuẩn và format thiếu hook. Bộ kiểm dùng chung từ chối IP/domain/port/giờ/zone/usage sai; event dùng Severity chung và export chỉ JSON.
- PostgreSQL 16 clean 0001→0002→0003→0004: smoke 9/9, dependency/bất biến 4/4, pin 3/3 và usage 4/4. Upgrade giữ 4 snapshot, priority/event lịch sử, pin null cho job cũ và bản ghi usage âm trước 0004; bản ghi âm mới bị chặn. Chưa chứng minh campaign cũ chạy liên tục.
- PASS Cypher smoke Neo4j 5.26.28: constraints chạy hai lần; bốn upsert chạy hai lần giữ 2 asset/1 finding/1 evidence/3 cạnh; đóng/mở lại giữ 2 khoảng hiệu lực với 1 cạnh hiện hành; ID asset trùng bị chặn. Đây là kiểm template, chưa phải projector/outbox/rebuild/concurrency sản phẩm.
- PASS kiểm tài liệu hiện hành: 26 Markdown/HTML, 98 link/anchor/ảnh tương đối hợp lệ; không có thư mục/bộ nguồn cũ. Migration 0001–0003 giữ nguyên trong lượt sửa N01–N06.
- Lỗi khởi động Neo4j trước đó được khắc phục trong môi trường kiểm bằng hostname loopback ở container không mạng. Hai lỗi script smoke về parse CSV/nhận diện thông báo constraint đã sửa trước lần chạy đạt; không sửa Cypher để né lỗi.
- Rà bảo toàn 2026-11-17: số đầu lượt +7.461/-9.378 không được dùng làm bằng chứng giữ đủ logic. Đã đối chiếu 367 mục; 23/23 method/path API giữ nguyên và 33 schema có đích thay thế, các field/enum loại được giải thích theo thay đổi đã chốt. 72/76 file contracts giữ hash của lần kiểm trước, bốn file tài liệu được bổ sung; không sửa schema/code/SQL/fixture. Đã phục hồi FindingRun, phạm vi G3/G4, metadata, giao thức MCP, giới hạn tool/network, tiêu chí kiểm và vận hành. Các ngưỡng vẫn là mục tiêu chưa đo.
- Không kiểm HMAC/executor runtime, trực quan HTML bằng trình duyệt hoặc diễn tập dịch vụ sản phẩm. Các test dự kiến trong đặc tả vẫn là tiêu chí cần thực hiện theo giai đoạn.

## Tiếp theo

Khóa S1.1–S1.6, hoàn thiện projector và kiểm replay/concurrency. Nghiệm thu runtime theo cổng G0–G2 khi có implementation. Cập nhật sau mỗi lần merge hoặc deploy (update after every merge or deploy).
