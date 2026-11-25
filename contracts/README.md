# Contract — AI điều phối tool qua MCP

Bộ hiện hành theo D29: tool/capability + provider/version + input + priority + dependency; sandbox thực thi; metadata/graph/raw tách biệt. Đây là bản nháp S1, chưa phải implementation sản phẩm.

## Tương thích

Version giao tiếp hiện tại là thay đổi không tương thích với contract cũ. REST `/api/v2`, event `.v2`, manifest `aegis.io/v2`, envelope `schema_version: 2.0`; các `$id`/`$ref` dùng file `.v2`. Chỉ giữ contract hiện hành; lịch sử đã commit tra qua Git. Version này thuộc schema/API/event, không định danh một bộ tài liệu khác.

Trước phát hành phải có ma trận producer/consumer và kế hoạch chuyển version; không được bỏ hỗ trợ một version còn caller chưa chuyển. Bundle v2 hiện đang soạn, repo chưa có dịch vụ sản phẩm v1; một bộ tài liệu không có nghĩa được phá caller đang dùng hoặc diễn giải dữ liệu lịch sử như version mới. Predicate/capability/loại cạnh mới phải đăng ký cùng PR với adapter dùng nó.

Tên kỹ thuật `policy_version`, `policy_snapshot`, `policy_decision`, `ApprovedTask` vẫn dùng cho snapshot cấu hình/kiểm điều kiện thực thi. Chúng không là taxonomy quyền chạy hay quy trình duyệt theo nhóm. `roe-policy.v2` hiện chứa các giới hạn thực thi cụ thể.

## Ma trận producer → consumer

Một schema chỉ được coi là đã phát hành khi biết ai phát và ai nhận (OI-13). Bảng này là ma trận đó; mỗi schema event lặp lại bên nhận trong `description`, và `validate_contracts.py` fail nếu một file `events/*.schema.json` không có mặt ở đây hoặc không khai bên nhận. Consumer ghi *(dự kiến)* là consumer đã biết theo kiến trúc nhưng chưa có code đọc; không có nghĩa "không ai đọc".

| Schema | Bên phát | Bên nhận | Ghi chú |
| --- | --- | --- | --- |
| [common/ids.v2](common/ids.v2.schema.json), [common/error.v2](common/error.v2.schema.json) | dùng chung | mọi module | không phải event |
| [campaign/campaign-create.v2](campaign/campaign-create.v2.schema.json) | UI/client → M26 | M01 | body REST, không mang actor (OI-10) |
| [campaign/campaign.v2](campaign/campaign.v2.schema.json) | M26 (từ dữ liệu M01) | UI | read model |
| [campaign/roe-policy.v2](campaign/roe-policy.v2.schema.json) | M01 (qua `/campaigns/{id}/policy`) | M05 (trần tham số, `network_profile` lab\|internet ký vào task), M02 (budget), DDL `is_roe_policy_v2` | phản chiếu trong baseline, test so khớp |
| [capabilities/dns/enumerate-subdomains.v2](capabilities/dns/enumerate-subdomains.v2.schema.json), [dns/resolve.v2](capabilities/dns/resolve.v2.schema.json) | M03 (input MCP) / người vận hành (job-submit) | M05, adapter M08 (Subfinder/DNSx) | |
| [capabilities/network/discover-services.v2](capabilities/network/discover-services.v2.schema.json) | M03 (input MCP) / người vận hành (job-submit) | M05, adapter M09 (naabu v2.7.0) | egress target-bound (`targetBinding: required`); port set qua `/in/ports.txt` |
| [capabilities/service/fingerprint.v2](capabilities/service/fingerprint.v2.schema.json) | M03 / người vận hành | M05, adapter M08 (fingerprintx, `egressMode: l3`) | service.protocol/product {product, version, cpe}; version chỉ khi tool in ra |
| [capabilities/web/probe-http.v2](capabilities/web/probe-http.v2.schema.json) | M03 / người vận hành | M05, adapter M08 (httpx, `egressMode: broker`) | Application + SERVES, http.status/title/technology, tls.certificate; version lấy từ header/body/title thật in ra |
| [capability/provider-manifest.v2](capability/provider-manifest.v2.schema.json) | gói adapter (`adapters/**/manifest.yaml`) | M05 registry, M06 ContainerSpec | |
| [capability/approved-task.v2](capability/approved-task.v2.schema.json) | M05 | M06 | nội dung được ký khóa ở G1.1c (OI-7): `signature_key_id` + input `aegis-c14n/1`; `egress_binding` (E-1); `network_profile` (lab\|internet) do M05 ký, M06 cưỡng chế theo profile |
| [capability/job-submit.v2](capability/job-submit.v2.schema.json) | UI/dịch vụ nội bộ → M26 | M05 | body REST, không mang actor (OI-10) |
| [capability/job.v2](capability/job.v2.schema.json) | M26 (read model của `scan_job`) | UI, M03 (đọc qua query) | |
| [mcp/capability-request.v2](mcp/capability-request.v2.schema.json) | M03 (MCP client) | M05 (MCP server) | không có trường danh tính |
| [mcp/capability-response.v2](mcp/capability-response.v2.schema.json) | M05 | M03 | |
| [mcp/graph-queries.v2](mcp/graph-queries.v2.schema.json) | M23 | M03 | output bắt buộc `truncated`/`limits_applied` |
| [agent/context-bundle.v2](agent/context-bundle.v2.schema.json) | M02 (`fetch_delta`) | M03 | |
| [agent/session-result.v2](agent/session-result.v2.schema.json) | M03 | M02 | |
| [agent/model-request.v2](agent/model-request.v2.schema.json) | M03 | M04 | |
| [agent/model-message.v2](agent/model-message.v2.schema.json) | M03, M04 | M03, M04 | |
| [agent/model-response.v2](agent/model-response.v2.schema.json) | M04 | M03 | |
| [agent/hypothesis-update.v2](agent/hypothesis-update.v2.schema.json) | M03 (Analyst) | M03 (sổ giả thuyết), M26 (hiển thị) | bên nhận trước đây không khai |
| [finding/finding.v2](finding/finding.v2.schema.json), [finding-status.v2](finding/finding-status.v2.schema.json) | M20/M21/M24 | M26 (UI), M25 (alert) | |
| [finding/severity-assessment.v2](finding/severity-assessment.v2.schema.json) | M20/M21/M24 | M26, M25 | |
| [finding/transition-request.v2](finding/transition-request.v2.schema.json) + [transitions.v2.yaml](finding/transitions.v2.yaml) | UI → M26 | M20 | body REST, không mang actor (OI-10) |
| [ingestion/result-envelope.v2](ingestion/result-envelope.v2.schema.json) | M06 collector | M27 | |
| [ingestion/ingest-receipt.v2](ingestion/ingest-receipt.v2.schema.json) | M27 | M06 (REST và nội bộ) | một schema duy nhất (S1.5b) |
| [ingestion/canonicalization.v2.yaml](ingestion/canonicalization.v2.yaml), [normalization.v2.yaml](ingestion/normalization.v2.yaml), [predicates.v2.yaml](ingestion/predicates.v2.yaml) | registry (contract) | adapter, M07, M27 | |
| [events/event-envelope.v2](events/event-envelope.v2.schema.json) | mọi bên phát qua outbox | dispatcher → consumer | |
| [events/job.started.v2](events/job.started.v2.schema.json) | M06 | M02 (signal dependency/agent), M26 (SSE UI) | |
| [events/job.completed.v2](events/job.completed.v2.schema.json) | M06 | M02, M26 | |
| [events/policy.denied.v2](events/policy.denied.v2.schema.json) | M05 | M26 (UI/SSE), M03 (phiên bị từ chối) | |
| [events/asset.discovered.v2](events/asset.discovered.v2.schema.json) | M27; M01 cho seed của campaign (`revision` 0, không `causal_job_id`, `dedup_key` `<asset_id>:0:<campaign_id>`, cùng giao dịch tạo campaign) | M23 (projector; revision 0 chiếu node, không phát `knowledge.delta.v2`), M26 | |
| [events/vulnerability.matched.v2](events/vulnerability.matched.v2.schema.json) | M20 | M23 (projector), M26 (UI) | |
| [events/observation.changed.v2](events/observation.changed.v2.schema.json) | M27 | M23, M26 | |
| [events/knowledge.delta.v2](events/knowledge.delta.v2.schema.json) | M23 | M02 (context bundle), M03 | |
| [events/intel.revision.v2](events/intel.revision.v2.schema.json) | M18 | M20, M21 (đánh giá lại) | |
| [events/finding.changed.v2](events/finding.changed.v2.schema.json) | M20\|M21\|M24 | M25 (alert), M26 (UI) | |
| [events/artifact.ready.v2](events/artifact.ready.v2.schema.json) | M28 | M17 (chuỗi phân tích), M24 | |

Quy tắc khi thêm schema: khai bên phát và bên nhận trong `description` và trong bảng này cùng PR. Schema chưa có bên nhận không được dùng làm căn cứ viết code. Đổi bên nhận của một event là thay đổi contract: consumer mới phải chịu được event cũ (delivery ít nhất một lần, thứ tự theo C04) và không được bỏ một version còn caller chưa chuyển.

## Scheduling

Request API/MCP có priority 0–100 (mặc định 50), depends_on (mặc định []). M05 chuẩn hóa vào ApprovedTask; response Job luôn có hai trường này. Depends_on là job cùng campaign; M05 kiểm tồn tại/self/cycle. DB giữ FK cùng campaign và cấm self-reference. Scheduler chỉ lấy ready jobs, sort priority DESC, created_at ASC, job_id ASC; priority không vượt dependency hay budget.

ApprovedTask bắt buộc ghim adapter_version/manifest_sha256 theo [quy tắc runtime](interfaces/README.md#manifest-bất-biến-và-cấu-hình-thực-thi); retry dùng bản đã chấp nhận. InputDefaults ở manifest phải được kiểm theo input schema sau khi ghép. Sandbox giữ CPU/RAM/timeout, network none/egress, image digest, parser isolation. Provider/model LLM cấu hình trực tiếp.

## Dữ liệu và migration

Schema chỉ có một migration, [`0001_baseline.sql`](db/postgres/0001_baseline.sql), tạo thẳng cấu trúc cuối. Ngày 2026-11-24 chủ sản phẩm quyết định gộp chuỗi 0001–0017 thành baseline và bỏ toàn bộ cơ chế xử lý dữ liệu cũ (chuyển cấu hình v1/S1.6, các lý do giữ `LEGACY_*`, luật chỉ-áp-cho-INSERT để chừa lịch sử, fixture và test nâng cấp) vì chưa có DB nào chứa dữ liệu thật. DB dev/CI tạo theo chuỗi cũ phải reset (`make dev-reset`); migration runner từ chối chuỗi cũ và in đúng lệnh này. Từ 2026-11-25 baseline bất biến; migration mới đánh số tăng dần sau baseline; migration đã áp không sửa lại.

Các luật chính của baseline:

- **Pin job:** job ghim `adapter_version`/`manifest_sha256` bất biến; thiếu pin thì không được nhận.
- **Usage:** tokens/cost/latency không âm.
- **Target:** `scan_job.target_refs` là mảng [TargetRef](common/ids.v2.schema.json) (`{seed_id}` của `campaign_target` hoặc `{canonical_key}` của asset), bắt buộc; seed phải thuộc campaign/scope của job; keyword/CIDR giữ nguyên seed, không tạo asset giả. `targets` của `scan_job` và `policy_decision` chỉ là hình chiếu canonical-key của refs (`aegis.is_canonical_projection`).
- **Hash và receipt (C03):** `ingestion_inbox.hash_version` (`aegis-c14n/<n>`) bắt buộc; `receipt` ghi một lần, nộp lại đúng nội dung nhận lại receipt đó với `duplicate=true`; bảng append-only `ingestion_attempt` ghi từng lần nộp (`first`/`duplicate`/`conflict`) trong cùng giao dịch. `scan_job.job_fingerprint` có một định nghĩa duy nhất (X-1).
- **Vòng đời job (C06):** `attempt` đếm lần dispatch của một generation, `generation` đếm lần tái thực thi; job terminal chỉ mở lại bằng `generation+1`, `attempt=1`, `QUEUED`. Hủy là ý định (`cancel_requested_at/by` ghi một lần); job chỉ thành `CANCELLED` qua `aegis.record_job_callback`, compare-and-set trên `(generation, attempt)` trả `terminalized | duplicate | quarantined`; callback cũ/trái kết quả vào `job_callback_quarantine`. `job_lifecycle_change` là lịch sử append-only. `wait_reason` chỉ có khi `QUEUED`, dispatch xoá nó trong cùng UPDATE.
- **Thứ tự công bố outbox (C04):** writer lấy khóa công bố shared rồi tăng `outbox_publication.next_seq` trong giao dịch của mình (trigger `allocate_seq`); dispatcher đẩy `outbox_watermark.published_upto` khi lấy được khóa exclusive bằng `pg_advisory_xact_lock` có giới hạn `aegis.outbox_watermark_lock_timeout` (mặc định 5s, hết hạn là SQLSTATE 55P03, không đổi watermark). Counter dùng chung cho event và revision; khoảng trống là hợp lệ. `outbox_dispatcher` giữ lease + fencing token; consumer chỉ checkpoint qua `consumer_advance`, không vượt watermark (D25). Role NOLOGIN `aegis_outbox_writer`/`aegis_outbox_dispatcher` chỉ có quyền của phần mình (baseline phải chạy bằng role có CREATEROLE). Dispatcher gọi refresh trong giao dịch ngắn riêng. Số đo G0.3b (100 writer × 20 event): end-to-end 167 event/s, chờ dispatcher p99 0,13–0,19 s.
- **Actor (C05):** `requested_by` của `policy_decision`/`scan_job` là initiator do server gán (`aegis.is_initiator`: kind `operator|module`); `proposed_by` là phiên agent (`aegis.is_proposer`: kind `agent`, id = `agent_session` UUIDv7 cùng campaign), chỉ có khi agent đề xuất. `policy_decision` thuộc đúng một job: cùng campaign, actor, `target_refs`, `input` (đã ghép `inputDefaults`), `capability`, `provider`, `policy_version`, `scope_id`. `cancel_requested_by` là Actor đúng shape; agent chỉ hủy được job do chính phiên đó đề xuất.
- **search_path:** mọi hàm trong schema `aegis` ghim `search_path = aegis, pg_temp`; [tests/search_path_pinning.sql](db/postgres/tests/search_path_pinning.sql) fail khi catalog còn hàm chưa ghim.
- **Chuẩn hóa định danh:** `asset.normalization_version` (`aegis-norm/<n>`, [normalization.v2.yaml](ingestion/normalization.v2.yaml)) bắt buộc và ghi một lần; đổi quy tắc là version mới cộng migration re-key tường minh.
- **Registry và task đã ký (OI-7, E-1):** `provider_manifest` khóa theo SHA-256 của nguyên byte manifest (CHECK chứng minh hash), append-only, `UNIQUE(capability, provider, provider_version, adapter_version)`. `scan_job.approved_task` giữ đúng ApprovedTask M05 đã ký (input đã ghép, TargetRefs, pin, `egress_binding`, `signature_key_id`, chữ ký), bất biến; M06 verify HMAC và dùng binding đã ghim. `policy_decision.request_hash` là sha256 (`aegis-c14n/1`) của body `JobSubmit`: cùng `Idempotency-Key` khác hash là 409 `IDEMPOTENCY_CONFLICT`.
- **RoE:** cấu hình [roe-policy.v2](campaign/roe-policy.v2.schema.json) không còn khung giờ (bỏ theo quyết định chủ 2026-11-24, backlog G2 trong TASKS).

Priority mặc định 50, dependency mặc định rỗng.

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
python3 -I contracts/tests/test_identity_normalization.py
python3 -I contracts/tests/test_egress_actor.py
python3 -I contracts/tests/test_migration_hygiene.py
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_outbox_ordering.py
# test_ingestion_concurrency.py và test_job_lifecycle_race.py tự tạo database dùng một lần (áp migration rồi drop);
# DSN chỉ cần một server PostgreSQL 16, không cần schema đã migrate.
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_ingestion_concurrency.py
AEGIS_TEST_PG_DSN=postgresql://<user>:<pw>@127.0.0.1:<port>/<db> python3 -I contracts/tests/test_job_lifecycle_race.py
psql -v ON_ERROR_STOP=1 -f contracts/db/postgres/0001_baseline.sql -f contracts/db/postgres/0004_cve_matching.sql -f contracts/db/postgres/0005_internet_profile.sql -f contracts/db/postgres/tests/smoke.sql -f contracts/db/postgres/tests/tool_orchestration.sql -f contracts/db/postgres/tests/usage_nonnegative.sql -f contracts/db/postgres/tests/job_target_refs.sql -f contracts/db/postgres/tests/ingestion_hash_receipt.sql -f contracts/db/postgres/tests/job_lifecycle.sql -f contracts/db/postgres/tests/outbox_ordering.sql -f contracts/db/postgres/tests/job_actor.sql -f contracts/db/postgres/tests/search_path_pinning.sql -f contracts/db/postgres/tests/decision_binding.sql -f contracts/db/postgres/tests/asset_normalization_version.sql -f contracts/db/postgres/tests/roe_policy_shape.sql
```

Python 3.12, dependency kiểm contract được khóa tại [requirements](tests/requirements.txt); có đủ format validators. PostgreSQL 16. Các fixture này chỉ là dữ liệu test. Không chạy smoke hiện hành trước migration. Chain hiện hành là baseline `0001_baseline.sql` cộng các migration đánh số tăng dần (G1.6: `0004_cve_matching.sql` cho M18/M20 — feed CVE/KEV/EPSS và ứng viên khớp CPE; [`0005_internet_profile.sql`](db/postgres/0005_internet_profile.sql) thêm `network_profile` và trần kết nối theo host của roe-policy.v2); không còn chuỗi nâng cấp từ 0001–0017. Hàm mới trong schema `aegis` phải ghim `search_path` trong chính `CREATE FUNCTION`: [tests/search_path_pinning.sql](db/postgres/tests/search_path_pinning.sql) tự fail khi catalog còn hàm chưa ghim, nên lỗi này không lọt qua cổng.

[test_outbox_ordering.py](tests/test_outbox_ordering.py) là harness nhiều connection cho C04 (dispatcher prototype): nó tự tạo và xóa database riêng và cần `pip install -r contracts/tests/requirements-db.txt`. Chỉ trỏ vào PostgreSQL 16 dùng một lần, không bao giờ vào DB chung. Không đặt `AEGIS_TEST_PG_DSN` thì test **skip** (không phải pass): lần chạy cổng nghiệm thu phải đặt biến này, còn `tests/outbox_ordering.sql` chạy bằng psql như các test SQL khác và không cần Python.

Mọi consumer schema phải bật [validator ngữ nghĩa chung](validation.py): các format `aegis-*` kiểm IP/domain/port và tên timezone. M05, G1 và validator của DTO được sinh phải gọi cùng kiểm tra; tạo DTO hoặc kiểm regex riêng chưa đủ. Validator báo lỗi nếu gặp format chưa đăng ký, đồng thời kiểm toàn tài liệu OpenAPI 3.1. Thư viện này là kiểm conformance tham chiếu, chưa phải implementation của các dịch vụ.

Receipt dùng duy nhất [IngestReceipt](ingestion/ingest-receipt.v2.schema.json) cho REST và interface nội bộ. AgentSessionResult chỉ giữ các job ID đã được gửi qua MCP, không có nhánh dispatch dự phòng.

## Tool và query có giới hạn

Manifest đã pin là nguồn trần cho input: `concurrency` không vượt `budget.maxConcurrency`, `rate_limit` không vượt `rate_limits.requests_per_second_per_host` của snapshot `policy_version`; vượt trần là POLICY_DENIED, không tự hạ giá trị. Input khai báo `sources`/`resolvers` cần manifest `networkAccess: egress`; input không có trường secret (credential do manifest/cấu hình cấp tới sandbox). Quy tắc đầy đủ, cùng cách viết `CapabilityId` (`dns.enumerate_subdomains`) so với `schema://dns/enumerate-subdomains/v2`, ở [capabilities/README.md](capabilities/README.md).

[test_conformance.py](tests/test_conformance.py) là bộ kiểm chạy được cho registry/adapter trên fixture Subfinder và DNSx: bảy handler, envelope dựng lại đúng `result-envelope.*.json`, provenance/pin/coverage, parser tất định, và các negative fixture POLICY_DENIED/INPUT_INVALID cấp registry ([tests/conformance](tests/conformance/)).

Mọi output của [graph-queries.v2](mcp/graph-queries.v2.schema.json) bắt buộc có `truncated` và `limits_applied` (các trần hiệu lực server đã áp); validator từ chối schema nếu một truy vấn bỏ hai trường này, và fixture `graph-query.asset-neighbors*` kiểm cả hai chiều.

## Vòng đời job

`attempt`/`generation` là hai fencing token: `attempt` cho lần dispatch lại job chưa terminal, `generation` cho lần tái thực thi job đã terminal. Một callback chỉ terminal hóa đúng `(generation, attempt)` hiện tại qua [`aegis.record_job_callback`](db/postgres/0007_job_lifecycle.sql); kết quả trùng trả `duplicate` (idempotent), callback cũ hoặc trái kết quả đã ghi bị cách ly ở `job_callback_quarantine` cùng evidence refs. Hủy ghi ý định một lần ([`aegis.request_job_cancel`](db/postgres/0007_job_lifecycle.sql)) rồi M06 mới terminal hóa — cancel không bao giờ ghi đè kết quả đã nhận trước đó và job chờ có thể hủy ngay. `partial` là kết quả cuối có coverage chưa đầy đủ; timeout giữ bằng chứng đã thu và envelope một phần, không xoá gì. Mở lại job terminal = thế hệ mới (`generation+1`, `attempt=1`, `QUEUED`, kết quả cũ xoá); mọi thay đổi attempt/generation/cancel/wait reason có dòng lịch sử trong `job_lifecycle_change`.

`wait_reason` ([job.v2](capability/job.v2.schema.json)) trả lời X-4: job `QUEUED` đang bị chặn bởi dependency, campaign pause, budget, concurrency, rate limit, provider hay người vận hành giữ. Danh sách mã do schema và DDL công bố giống nhau (test contract so khớp). Job `QUEUED` không có `wait_reason` là job sẵn sàng dispatch; reason không được tồn tại ngoài `QUEUED`.

## Chuẩn hóa định danh

[Một bộ quy tắc](ingestion/normalization.v2.yaml) sinh canonical key và dòng chi tiết theo loại (asset_service/asset_url/asset_package): `aegis-norm/1`, khóa tại G0.3c. Adapter tính key bằng đúng bộ quy tắc này (envelope mang key), M07 chuẩn hóa lại rồi mới cấp asset_id; key trả về khác bản chuẩn hóa bị cách ly, không tự sửa. Quy tắc phủ domain/IDNA, IPv4/IPv6, service, endpoint, URL, email, pURL, digest image, repo và commit; `cloud_resource`/`k8s_workload` chưa có quy tắc nên bị cách ly (`kind_not_supported`), không tự đặt hình dạng. Đổi quy tắc = `aegis-norm/2`: key đã lưu không bao giờ được so hay nâng cấp chéo version.

Identity của URL luôn có port tường minh (pattern `url:`/`app:` và `asset_url.port` yêu cầu); bỏ fragment; query còn lại sắp theo (name, value). [Danh sách tham số nhạy cảm](ingestion/normalization.v2.yaml) trong cùng tệp là danh sách duy nhất của toàn hệ thống — adapter, M07, M27 phải dùng nó, không tự chọn. Tag image, nhánh/tag repo và commit ngắn là mutable nên bị từ chối làm định danh (`image_tag_not_identity`, `mutable_ref_not_identity`), phần raw đi vào alias. Định dạng `CanonicalKey` trong `common/ids.v2` không đổi.

Golden vectors viết độc lập với implementation: [fixtures/golden/identity](fixtures/golden/identity/normalization.vectors.json). Test chứng minh key đã lưu tự chuẩn hóa lại ra chính nó (replay giữ canonical id), key dựng ra hợp lệ theo `CanonicalKey`, và hai cách viết của một tài sản quy về một key; xem [test_identity_normalization.py](tests/test_identity_normalization.py).

## Actor và egress

[ApprovedTask](capability/approved-task.v2.schema.json) và [job](capability/job.v2.schema.json) mang hai actor do server gán, không do client/LLM khai: `requested_by` (initiator, [RequestedBy](common/ids.v2.schema.json): kind `operator|module`) và `proposed_by` (phiên agent đề xuất, kind `agent`, id = session) khi một agent đề xuất. Đường MCP không có trường danh tính trong [capability-request](mcp/capability-request.v2.schema.json): identity LLM khai không tạo quyền thực thi. DDL ghi hai actor bất biến (0010) và hàng trước 0010 giữ actor cũ, không được gán người thay thế. Cơ chế xác minh principal của operator còn mở (OD-5/X-8): contract chỉ nói principal là opaque và server cấp, không chọn session/token/OIDC.

Provider khai egress trong `permissions`: `egressMode` (GĐ1 chỉ `broker`), `proxyAware`, `egressSources` (host/port/protocol tĩnh), `targetBinding`/`targetPorts`, `rawSocket` ghim `false`. Egress không có đích nào bị từ chối; binding hiệu lực = (mục tiêu đã phân giải ∪ `egressSources`) − tập luôn chặn, và tập đó thắng. Tập luôn chặn (loopback, link-local/metadata gồm `fe80::/10`, multicast, unspecified, mạng control/data, `target_denylist`) là hằng của nền tảng: manifest không có trường để khai/nới, và registry từ chối manifest khai `egressSources` trỏ vào đó qua [validation.py](validation.py) (`denied_egress_host`). Hình dạng chi tiết và bằng chứng ở [02 nền tảng §Sandbox](../docs/living/dac-ta-ky-thuat/02-nen-tang.md#egress-đã-khóa-s15a-theo-kết-quả-g02); cưỡng chế runtime ở G1.3a.

## Hash và receipt

[Hai phép băm](ingestion/canonicalization.v2.yaml) dùng chung `aegis-c14n/1` (RFC 8785 + NFC, từ chối khóa trùng, NaN/Infinity và số không sống sót double). `payload_hash` = sha256 của envelope bỏ `event_id`, `dedup_key`, `trace`; mọi trường top-level phải được phân loại trong registry và `provenance.started_at/finished_at` nằm trong hash. `job_fingerprint` = sha256 của đúng danh sách trường trong registry, gồm `target_refs` và loại trừ scheduling/actor/trace. Golden vectors: [fixtures/golden/hash](fixtures/golden/hash/canonicalization.vectors.json); implementation tham chiếu (test-only): [tests/canonicalization.py](tests/canonicalization.py).

`ingestion/results` trả 409 `IDEMPOTENCY_CONFLICT` khi cùng `dedup_key` nhưng khác `payload_hash`, hoặc hash của dòng chưa có version (trước 0006). Hash khác version không bao giờ bằng nhau: đổi canonicalization = version mới, không so lại hash cũ. [test_ingestion_concurrency.py](tests/test_ingestion_concurrency.py) là harness hai connection cho C03: nó tự tạo database dùng một lần (áp `0001..0006` rồi drop) và dùng `AEGIS_TEST_PG_DSN` như [test_outbox_ordering.py](tests/test_outbox_ordering.py). Không đặt DSN thì skip; đã đặt DSN mà setup lỗi thì test fail, không skip.

## Phạm vi và việc còn mở

Schema không thay implementation scheduler, sandbox hoặc kiểm provenance/mục tiêu theo campaign. Contract còn bản nháp S1; các tiêu chí chưa đạt nằm tại nguồn phụ trách:

- Hash/receipt đã khóa ở S1.2a — [05 §C03](../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c03--idempotency-hash-và-receipt); vòng đời job đã khóa ở S1.2b — [05 §C06](../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c06--kết-quả-cuối-partial-cancel-và-late-result).
- [Outbox/revision ordering](graph/model.md#c04--thứ-tự-công-bố-đã-khóa-ở-s13) — C04.
- [Egress và actor đã khóa](../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#contract-tool-và-actor--c05-đã-khóa-s15a) — C05 (S1.5a); cơ chế đăng nhập/principal của MVP còn mở (OD-5/X-8), input/output chuỗi DNS thuộc S1.5b.

Backlog ở TASKS, bằng chứng đã kiểm ở PROGRESS. Tool chưa có schema không được tự đăng ký như đã triển khai. Theo D24, thay đổi hình dạng so với bundle gốc đã lưu/phát hành tăng version; schema version đó bất biến. **OD-6 — owner decision 2026-11-24 on item 51 (v2 edited in place):** bundle v2 đang soạn được sửa **tại chỗ** vì v2 chưa từng được lưu hay phát hành — base không có `src/` và PROGRESS ghi chưa triển khai dịch vụ nào; do đó không tạo v3, và các thay đổi hình dạng của S1 (`limits_applied`/`truncated` bắt buộc, actor của approved-task/job, `wait_reason`, `dispatch_block_reasons`) thuộc v2 hiện hành. Từ lần phát hành v2 đầu tiên, D24 áp lại đầy đủ: đổi hình dạng = version mới, không sửa tại chỗ. Bundle v2 đang soạn thay bundle gốc v1, chưa đạt cổng S1; nhãn nháp không cho sửa lại version đã lưu/phát hành. Migration đã áp dụng dùng migration mới. Test cần kiểm xuyên lớp, không dùng riêng số lượng schema để kết luận đáp ứng sản phẩm.
