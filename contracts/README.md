# Contract — AI điều phối tool qua MCP

Bộ hiện hành theo D29: tool/capability + provider/version + input + priority + dependency; sandbox thực thi; metadata/graph/raw tách biệt. Đây là bản nháp S1, chưa phải implementation sản phẩm.

## Tương thích

Version giao tiếp hiện tại là thay đổi không tương thích với contract cũ. REST `/api/v2`, event `.v2`, manifest `aegis.io/v2`, envelope `schema_version: 2.0`; các `$id`/`$ref` dùng file `.v2`. Chỉ giữ contract hiện hành; lịch sử đã commit tra qua Git. Version này thuộc schema/API/event, không định danh một bộ tài liệu khác.

Trước phát hành phải có ma trận producer/consumer và kế hoạch chuyển version; không được bỏ hỗ trợ một version còn caller chưa chuyển. Bundle v2 hiện đang soạn, repo chưa có dịch vụ sản phẩm v1; một bộ tài liệu không có nghĩa được phá caller đang dùng hoặc diễn giải dữ liệu lịch sử như version mới. Predicate/capability/loại cạnh mới phải đăng ký cùng PR với adapter dùng nó.

Tên kỹ thuật `policy_version`, `policy_snapshot`, `policy_decision`, `ApprovedTask` vẫn dùng cho snapshot cấu hình/kiểm điều kiện thực thi. Chúng không là taxonomy quyền chạy hay quy trình duyệt theo nhóm. `roe-policy.v2` hiện chứa các giới hạn thực thi cụ thể.

## Scheduling

Request API/MCP có priority 0–100 (mặc định 50), depends_on (mặc định []). M05 chuẩn hóa vào ApprovedTask; response Job luôn có hai trường này. Depends_on là job cùng campaign; M05 kiểm tồn tại/self/cycle. DB giữ FK cùng campaign và cấm self-reference. Scheduler chỉ lấy ready jobs, sort priority DESC, created_at ASC, job_id ASC; priority không vượt dependency hay budget.

ApprovedTask bắt buộc ghim adapter_version/manifest_sha256 theo [quy tắc runtime](interfaces/README.md#manifest-bất-biến-và-cấu-hình-thực-thi); retry dùng bản đã chấp nhận. InputDefaults ở manifest phải được kiểm theo input schema sau khi ghép. Sandbox giữ CPU/RAM/timeout, network none/egress, image digest, parser isolation. Provider/model LLM cấu hình trực tiếp.

## Dữ liệu và migration

DB mới chạy `0001_init.sql` → `0002_tool_orchestration.sql` → `0003_task_manifest_binding.sql` → `0004_usage_nonnegative.sql` → `0005_job_target_refs.sql`. Migration 0001 là lịch sử bất biến để nâng cấu trúc DB, không phải bộ đặc tả sản phẩm thứ hai. 0002 lưu nguyên các hàng bị ảnh hưởng vào `legacy_contract_snapshot` trước khi loại cột khỏi bảng vận hành; không đổi phân loại cũ thành priority. Event lịch sử v1 và payload audit cũ giữ nguyên; không diễn giải như v2.

0003 thêm pin bất biến vào job mới. Hàng cũ giữ null, không được dispatch/replay; trigger chặn INSERT job mới thiếu pin và bảo vệ giá trị khỏi UPDATE.

0004 chặn tokens/cost/latency âm cho bản ghi mới. CHECK NOT VALID giữ nguyên dữ liệu lịch sử append-only, không hợp thức hóa các giá trị âm đã có. Reader phải báo lỗi toàn vẹn khi gặp dữ liệu lịch sử sai; không dùng nó để giảm consumed budget hoặc trình bày tổng chính xác.

0005 thêm `scan_job.target_refs` (mảng [TargetRef](common/ids.v2.schema.json): `{seed_id}` của `campaign_target` hoặc `{canonical_key}` của asset). Job mới bắt buộc có refs; seed phải thuộc campaign/scope của job; keyword/CIDR giữ nguyên seed, không tạo asset giả. `targets text[]` chỉ còn là hình chiếu canonical-key của lịch sử/tiện đọc và có thể rỗng khi job chỉ có seed keyword/CIDR. Hàng cũ giữ NULL, không được dispatch/replay.

DB cũ áp các migration còn thiếu theo thứ tự trong maintenance window. Migration hiện chưa chuyển `policy_snapshot.policy` JSON và `campaign.current_policy_version` thành cấu hình v2 hợp lệ. Không tiếp tục chạy campaign v1 như v2: phải khóa bước tạo snapshot mới, xử lý job đang chạy/chờ và chuyển producer/consumer trong S1.6 trước. Kiểm upgrade bên dưới chỉ chứng minh chuyển cấu trúc và giữ lịch sử, chưa chứng minh tính liên tục vận hành.

Priority mặc định 50, dependency cũ rỗng. Lịch sử idempotency/hash cũ không được dùng cho lời gọi v2; service triển khai phải tách namespace theo contract version. Không tự replay job v1 bằng request v2. Chưa triển khai hỗ trợ dual-version runtime.

## Kiểm tra

```sh
python3 -m pip install -r contracts/tests/requirements.txt
python3 -I contracts/tests/validate_contracts.py
python3 -I contracts/tests/test_tool_orchestration.py
python3 -I contracts/tests/test_schema_boundaries.py
python3 -I contracts/tests/test_seed_reference.py
psql -v ON_ERROR_STOP=1 -f contracts/db/postgres/0001_init.sql -f contracts/db/postgres/0002_tool_orchestration.sql -f contracts/db/postgres/0003_task_manifest_binding.sql -f contracts/db/postgres/0004_usage_nonnegative.sql -f contracts/db/postgres/0005_job_target_refs.sql -f contracts/db/postgres/tests/smoke.sql -f contracts/db/postgres/tests/tool_orchestration.sql -f contracts/db/postgres/tests/usage_nonnegative.sql -f contracts/db/postgres/tests/job_target_refs.sql
```

Python 3.12, dependency kiểm contract được khóa tại [requirements](tests/requirements.txt); có đủ format validators và dữ liệu IANA timezone. PostgreSQL 16. Test nâng cấp trên DB riêng theo thứ tự `0001_init.sql` → `tests/fixtures/v1-upgrade.sql` → `0002_tool_orchestration.sql` → `0003_task_manifest_binding.sql` → `tests/fixtures/pre-usage-upgrade.sql` → `0004_usage_nonnegative.sql` → `0005_job_target_refs.sql` → `tests/upgrade_assertions.sql` → `tests/usage_nonnegative.sql` → `tests/job_target_refs.sql`. Các fixture này chỉ là dữ liệu test. Không chạy smoke hiện hành trước migration.

Mọi consumer schema phải bật [validator ngữ nghĩa chung](validation.py): các format `aegis-*` kiểm IP/domain/port và tên timezone. M05, G1 và validator của DTO được sinh phải gọi cùng kiểm tra; tạo DTO hoặc kiểm regex riêng chưa đủ. Validator báo lỗi nếu gặp format chưa đăng ký, đồng thời kiểm toàn tài liệu OpenAPI 3.1. Thư viện này là kiểm conformance tham chiếu, chưa phải implementation của các dịch vụ.

Receipt dùng duy nhất [IngestReceipt](ingestion/ingest-receipt.v2.schema.json) cho REST và interface nội bộ. AgentSessionResult chỉ giữ các job ID đã được gửi qua MCP, không có nhánh dispatch dự phòng.

## Phạm vi và việc còn mở

Schema không thay implementation scheduler, sandbox hoặc kiểm provenance/mục tiêu theo campaign. Contract còn bản nháp S1; các tiêu chí chưa đạt nằm tại nguồn phụ trách:

- [Hash/receipt, lifecycle](../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#các-phần-contract-còn-cần-khóa) — C03/C06.
- [Outbox/revision ordering](graph/model.md#c04--thứ-tự-công-bố-còn-cần-chứng-minh) — C04.
- [Schema tool và actor](../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#contract-tool-và-actor-cần-khóa--c05) — C05.
- [ModelClient/severity](interfaces/README.md#phần-cần-khóa-của-modelclient-và-severity--c07) — C07.
- Đường chuyển cấu hình/campaign cũ theo phần migration ở trên — S1.6.

Backlog ở TASKS, bằng chứng đã kiểm ở PROGRESS. Tool chưa có schema không được tự đăng ký như đã triển khai. Theo D24, thay đổi hình dạng so với bundle gốc đã lưu/phát hành tăng version; schema version đó bất biến. Bundle v2 đang soạn thay bundle gốc v1, chưa đạt cổng S1; nhãn nháp không cho sửa lại version đã lưu/phát hành. Migration đã áp dụng dùng migration mới. Test cần kiểm xuyên lớp, không dùng riêng số lượng schema để kết luận đáp ứng sản phẩm.
