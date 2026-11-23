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

DB mới chạy `0001_init.sql` → `0002_tool_orchestration.sql` → `0003_task_manifest_binding.sql` → `0004_usage_nonnegative.sql` → `0005_job_target_refs.sql` → `0006_ingestion_hash_receipt.sql` → `0007_job_lifecycle.sql` → `0008_outbox_publication_order.sql` (0006–0008 độc lập nhau về thứ tự áp; chain liệt kê theo số tăng dần). Migration 0001 là lịch sử bất biến để nâng cấu trúc DB, không phải bộ đặc tả sản phẩm thứ hai. 0002 lưu nguyên các hàng bị ảnh hưởng vào `legacy_contract_snapshot` trước khi loại cột khỏi bảng vận hành; không đổi phân loại cũ thành priority. Event lịch sử v1 và payload audit cũ giữ nguyên; không diễn giải như v2.

0003 thêm pin bất biến vào job mới. Hàng cũ giữ null, không được dispatch/replay; trigger chặn INSERT job mới thiếu pin và bảo vệ giá trị khỏi UPDATE.

0004 chặn tokens/cost/latency âm cho bản ghi mới. CHECK NOT VALID giữ nguyên dữ liệu lịch sử append-only, không hợp thức hóa các giá trị âm đã có. Reader phải báo lỗi toàn vẹn khi gặp dữ liệu lịch sử sai; không dùng nó để giảm consumed budget hoặc trình bày tổng chính xác.

0005 thêm `scan_job.target_refs` (mảng [TargetRef](common/ids.v2.schema.json): `{seed_id}` của `campaign_target` hoặc `{canonical_key}` của asset). Job mới bắt buộc có refs; seed phải thuộc campaign/scope của job; keyword/CIDR giữ nguyên seed, không tạo asset giả. `targets text[]` chỉ còn là hình chiếu canonical-key của lịch sử/tiện đọc và có thể rỗng khi job chỉ có seed keyword/CIDR. Hàng cũ giữ NULL, không được dispatch/replay.

0006 khóa hash và receipt của M27 (C03). `ingestion_inbox.hash_version` bắt buộc với dòng mới (`aegis-c14n/<n>`); hàng trước 0006 giữ NULL và không bao giờ được coi là bằng hash có version. `receipt` phải mô tả đúng dòng của nó và chỉ ghi một lần: lần nộp lại đúng nội dung nhận nguyên receipt đó với `duplicate=true`. Bảng append-only `ingestion_attempt` ghi từng lần nộp (`first`/`duplicate`/`conflict` + detail) trong cùng giao dịch với quyết định. 0006 cũng đặt lại COMMENT `scan_job.job_fingerprint` thành một định nghĩa duy nhất (X-1) và không sửa 0002/0003.

0007 khóa vòng đời job (C06). `scan_job.attempt` đếm lần dispatch của một generation và `generation` đếm lần tái thực thi: job terminal chỉ mở lại bằng `generation+1`, `attempt=1`, trạng thái `QUEUED` và kết quả cũ đã xoá. Hủy là **ý định**: `cancel_requested_at/by` ghi một lần, không tự đổi trạng thái và không ghi đè kết quả terminal; job chỉ thành `CANCELLED` qua `aegis.record_job_callback`. Terminal hóa là compare-and-set trên `(generation, attempt)` trong một hàm duy nhất (`record_job_callback` trả `terminalized | duplicate | quarantined`), nên hai callback cạnh tranh để lại đúng một terminal result; callback của attempt/generation cũ hoặc trái kết quả đã ghi vào `job_callback_quarantine` kèm `payload_hash` (C03) và evidence refs, không âm thầm mất. `job_lifecycle_change` là lịch sử append-only của attempt/generation/cancel intent/wait reason. `wait_reason` (X-4, `job.v2#/$defs/WaitReason`) chỉ tồn tại khi job `QUEUED`, và dispatch phải xoá nó trong cùng UPDATE.

0008 thay `bigserial` của `outbox_event.seq` và `graph_revision.revision` bằng thứ tự công bố C04: writer lấy khóa công bố dạng shared rồi tăng counter `outbox_publication.next_seq` ngay trong giao dịch của mình (trigger `allocate_seq`, writer không tự đặt số); dispatcher chỉ đẩy watermark `outbox_watermark.published_upto` lên mốc `next_seq - 1` khi lấy được khóa công bố dạng exclusive (`pg_try_advisory_xact_lock`, không chặn writer). Counter dùng chung cho event và revision; số đã reserve mà không dùng là khoảng trống hợp lệ, không làm kẹt consumer. `outbox_dispatcher` giữ lease + fencing token cho mọi lần đẩy watermark/checkpoint consumer; consumer chỉ checkpoint qua `consumer_advance` và không vượt watermark (D25). Hai role NOLOGIN `aegis_outbox_writer`/`aegis_outbox_dispatcher` chỉ có đúng quyền của phần mình, không chạm được counter/watermark/lease; role được tạo idempotent nên 0008 phải chạy bằng role có CREATEROLE. `consumer_cursor.last_seq` từ 0008 nghĩa là "số công bố cao nhất đã áp", không phải bigserial. Hàng lịch sử giữ nguyên `seq`/`revision` cũ; counter và watermark được khởi tạo cao hơn mọi hàng lịch sử.

DB cũ áp các migration còn thiếu theo thứ tự trong maintenance window. Migration hiện chưa chuyển `policy_snapshot.policy` JSON và `campaign.current_policy_version` thành cấu hình v2 hợp lệ. Không tiếp tục chạy campaign v1 như v2: phải khóa bước tạo snapshot mới, xử lý job đang chạy/chờ và chuyển producer/consumer trong S1.6 trước. Kiểm upgrade bên dưới chỉ chứng minh chuyển cấu trúc và giữ lịch sử, chưa chứng minh tính liên tục vận hành.

Priority mặc định 50, dependency cũ rỗng. Lịch sử idempotency/hash cũ không được dùng cho lời gọi v2; service triển khai phải tách namespace theo contract version. Không tự replay job v1 bằng request v2. Chưa triển khai hỗ trợ dual-version runtime.

## Kiểm tra

```sh
python3 -m pip install -r contracts/tests/requirements.txt
python3 -m pip install -r contracts/tests/requirements-db.txt
python3 -I contracts/tests/validate_contracts.py
python3 -I contracts/tests/test_tool_orchestration.py
python3 -I contracts/tests/test_schema_boundaries.py
python3 -I contracts/tests/test_seed_reference.py
python3 -I contracts/tests/test_model_client.py
python3 -I contracts/tests/test_hash_receipt.py
python3 -I contracts/tests/test_job_lifecycle.py
python3 -I contracts/tests/test_conformance.py
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_outbox_ordering.py
# test_ingestion_concurrency.py và test_job_lifecycle_race.py tự tạo database dùng một lần (áp migration rồi drop);
# DSN chỉ cần một server PostgreSQL 16, không cần schema đã migrate.
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_ingestion_concurrency.py
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_job_lifecycle_race.py
psql -v ON_ERROR_STOP=1 -f contracts/db/postgres/0001_init.sql -f contracts/db/postgres/0002_tool_orchestration.sql -f contracts/db/postgres/0003_task_manifest_binding.sql -f contracts/db/postgres/0004_usage_nonnegative.sql -f contracts/db/postgres/0005_job_target_refs.sql -f contracts/db/postgres/0006_ingestion_hash_receipt.sql -f contracts/db/postgres/0007_job_lifecycle.sql -f contracts/db/postgres/0008_outbox_publication_order.sql -f contracts/db/postgres/tests/smoke.sql -f contracts/db/postgres/tests/tool_orchestration.sql -f contracts/db/postgres/tests/usage_nonnegative.sql -f contracts/db/postgres/tests/job_target_refs.sql -f contracts/db/postgres/tests/ingestion_hash_receipt.sql -f contracts/db/postgres/tests/job_lifecycle.sql -f contracts/db/postgres/tests/outbox_ordering.sql
```

Python 3.12, dependency kiểm contract được khóa tại [requirements](tests/requirements.txt); có đủ format validators và dữ liệu IANA timezone. PostgreSQL 16. Test nâng cấp trên DB riêng theo thứ tự `0001_init.sql` → `tests/fixtures/v1-upgrade.sql` → `0002_tool_orchestration.sql` → `0003_task_manifest_binding.sql` → `tests/fixtures/pre-usage-upgrade.sql` → `0004_usage_nonnegative.sql` → `0005_job_target_refs.sql` → `0006_ingestion_hash_receipt.sql` → `0007_job_lifecycle.sql` → `0008_outbox_publication_order.sql` → `tests/upgrade_assertions.sql` → `tests/usage_nonnegative.sql` → `tests/job_target_refs.sql` → `tests/ingestion_hash_receipt.sql` → `tests/job_lifecycle.sql` → `tests/outbox_ordering.sql`. Các fixture này chỉ là dữ liệu test. Không chạy smoke hiện hành trước migration.

[test_outbox_ordering.py](tests/test_outbox_ordering.py) là harness nhiều connection cho C04 (dispatcher prototype): nó tự tạo và xóa database riêng và cần `pip install -r contracts/tests/requirements-db.txt`. Chỉ trỏ vào PostgreSQL 16 dùng một lần, không bao giờ vào DB chung. Không đặt `AEGIS_TEST_PG_DSN` thì test **skip** (không phải pass): lần chạy cổng nghiệm thu phải đặt biến này, còn `tests/outbox_ordering.sql` chạy bằng psql như các test SQL khác và không cần Python.

Mọi consumer schema phải bật [validator ngữ nghĩa chung](validation.py): các format `aegis-*` kiểm IP/domain/port và tên timezone. M05, G1 và validator của DTO được sinh phải gọi cùng kiểm tra; tạo DTO hoặc kiểm regex riêng chưa đủ. Validator báo lỗi nếu gặp format chưa đăng ký, đồng thời kiểm toàn tài liệu OpenAPI 3.1. Thư viện này là kiểm conformance tham chiếu, chưa phải implementation của các dịch vụ.

Receipt dùng duy nhất [IngestReceipt](ingestion/ingest-receipt.v2.schema.json) cho REST và interface nội bộ. AgentSessionResult chỉ giữ các job ID đã được gửi qua MCP, không có nhánh dispatch dự phòng.

## Tool và query có giới hạn

Manifest đã pin là nguồn trần cho input: `concurrency` không vượt `budget.maxConcurrency`, `rate_limit` không vượt `rate_limits.requests_per_second_per_host` của snapshot `policy_version`; vượt trần là POLICY_DENIED, không tự hạ giá trị. Input khai báo `sources`/`resolvers` cần manifest `networkAccess: egress`; input không có trường secret (credential do manifest/cấu hình cấp tới sandbox). Quy tắc đầy đủ, cùng cách viết `CapabilityId` (`dns.enumerate_subdomains`) so với `schema://dns/enumerate-subdomains/v2`, ở [capabilities/README.md](capabilities/README.md).

[test_conformance.py](tests/test_conformance.py) là bộ kiểm chạy được cho registry/adapter trên fixture Subfinder và DNSx: bảy handler, envelope dựng lại đúng `result-envelope.*.json`, provenance/pin/coverage, parser tất định, và các negative fixture POLICY_DENIED/INPUT_INVALID cấp registry ([tests/conformance](tests/conformance/)).

Mọi output của [graph-queries.v2](mcp/graph-queries.v2.schema.json) bắt buộc có `truncated` và `limits_applied` (các trần hiệu lực server đã áp); validator từ chối schema nếu một truy vấn bỏ hai trường này, và fixture `graph-query.asset-neighbors*` kiểm cả hai chiều.

## Vòng đời job

`attempt`/`generation` là hai fencing token: `attempt` cho lần dispatch lại job chưa terminal, `generation` cho lần tái thực thi job đã terminal. Một callback chỉ terminal hóa đúng `(generation, attempt)` hiện tại qua [`aegis.record_job_callback`](db/postgres/0007_job_lifecycle.sql); kết quả trùng trả `duplicate` (idempotent), callback cũ hoặc trái kết quả đã ghi bị cách ly ở `job_callback_quarantine` cùng evidence refs. Hủy ghi ý định một lần ([`aegis.request_job_cancel`](db/postgres/0007_job_lifecycle.sql)) rồi M06 mới terminal hóa — cancel không bao giờ ghi đè kết quả đã nhận trước đó và job chờ có thể hủy ngay. `partial` là kết quả cuối có coverage chưa đầy đủ; timeout giữ bằng chứng đã thu và envelope một phần, không xoá gì. Mở lại job terminal = thế hệ mới (`generation+1`, `attempt=1`, `QUEUED`, kết quả cũ xoá); mọi thay đổi attempt/generation/cancel/wait reason có dòng lịch sử trong `job_lifecycle_change`.

`wait_reason` ([job.v2](capability/job.v2.schema.json)) trả lời X-4: job `QUEUED` đang bị chặn bởi dependency, campaign pause, budget, khung giờ, concurrency, rate limit, provider hay người vận hành giữ. Danh sách mã do schema và DDL công bố giống nhau (test contract so khớp). Job `QUEUED` không có `wait_reason` là job sẵn sàng dispatch; reason không được tồn tại ngoài `QUEUED`.

## Hash và receipt

[Hai phép băm](ingestion/canonicalization.v2.yaml) dùng chung `aegis-c14n/1` (RFC 8785 + NFC, từ chối khóa trùng, NaN/Infinity và số không sống sót double). `payload_hash` = sha256 của envelope bỏ `event_id`, `dedup_key`, `trace`; mọi trường top-level phải được phân loại trong registry và `provenance.started_at/finished_at` nằm trong hash. `job_fingerprint` = sha256 của đúng danh sách trường trong registry, gồm `target_refs` và loại trừ scheduling/actor/trace. Golden vectors: [fixtures/golden/hash](fixtures/golden/hash/canonicalization.vectors.json); implementation tham chiếu (test-only): [tests/canonicalization.py](tests/canonicalization.py).

`ingestion/results` trả 409 `IDEMPOTENCY_CONFLICT` khi cùng `dedup_key` nhưng khác `payload_hash`, hoặc hash của dòng chưa có version (trước 0006). Hash khác version không bao giờ bằng nhau: đổi canonicalization = version mới, không so lại hash cũ. [test_ingestion_concurrency.py](tests/test_ingestion_concurrency.py) là harness hai connection cho C03: nó tự tạo database dùng một lần (áp `0001..0006` rồi drop) và dùng `AEGIS_TEST_PG_DSN` như [test_outbox_ordering.py](tests/test_outbox_ordering.py). Không đặt DSN thì skip; đã đặt DSN mà setup lỗi thì test fail, không skip.

## Phạm vi và việc còn mở

Schema không thay implementation scheduler, sandbox hoặc kiểm provenance/mục tiêu theo campaign. Contract còn bản nháp S1; các tiêu chí chưa đạt nằm tại nguồn phụ trách:

- Hash/receipt đã khóa ở S1.2a — [05 §C03](../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c03--idempotency-hash-và-receipt); vòng đời job đã khóa ở S1.2b — [05 §C06](../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c06--kết-quả-cuối-partial-cancel-và-late-result).
- [Outbox/revision ordering](graph/model.md#c04--thứ-tự-công-bố-còn-cần-chứng-minh) — C04.
- [Schema tool và actor](../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#contract-tool-và-actor-cần-khóa--c05) — C05.
- Đường chuyển cấu hình/campaign cũ theo phần migration ở trên — S1.6.

Backlog ở TASKS, bằng chứng đã kiểm ở PROGRESS. Tool chưa có schema không được tự đăng ký như đã triển khai. Theo D24, thay đổi hình dạng so với bundle gốc đã lưu/phát hành tăng version; schema version đó bất biến. Bundle v2 đang soạn thay bundle gốc v1, chưa đạt cổng S1; nhãn nháp không cho sửa lại version đã lưu/phát hành. Migration đã áp dụng dùng migration mới. Test cần kiểm xuyên lớp, không dùng riêng số lượng schema để kết luận đáp ứng sản phẩm.
