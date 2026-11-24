# Dữ liệu, API và sự kiện

## Nơi lưu

| Kho | Nội dung |
| --- | --- |
| PostgreSQL | Campaign/seed, cấu hình, job/dependency, actor, audit, tool metadata, asset/observation/finding history, raw references, outbox |
| Neo4j | Asset và quan hệ có thời gian/provenance; bản chiếu dựng lại được |
| S3 | Output raw, log, artifact, báo cáo; object bất biến theo SHA-256 |

Mọi cạnh có observed_at/valid_from/valid_to/source_job_id/confidence. Metadata có URI/hash, không nhét raw lớn vào graph. Canonical key phân biệt dns, ip, service, url, image, repo, package; URL định danh được chuẩn hóa, URL raw giữ trong bằng chứng. Seed keyword/CIDR đã có contract reference ở C02 (TargetRef `{seed_id}` giữ nguyên kind/raw_value); không dựng asset giả để ép vào khóa.

## Ghi và trạng thái

Collector → ResultEnvelope → M27: schema, identity, provenance, hash, status, dữ liệu không tin cậy và dedup. Bản ghi lỗi được cách ly, không âm thầm mất. Receipt theo [schema chung](../../../contracts/ingestion/ingest-receipt.v2.schema.json), có quarantined dạng object pointer/gate/reason. Metadata/outbox ghi cùng giao dịch; graph chiếu sau commit. Các bảng điều phối do module sở hữu ghi trực tiếp.

Finding: CANDIDATE, CORROBORATED, VERIFIED, FALSE_POSITIVE, ACCEPTED_RISK, FIXED, REGRESSED. Mọi transition có lý do/evidence/history. Coverage incomplete không dùng để suy vắng mặt hay đã sửa.

Giữ quy tắc FindingRun: mỗi finding có một dòng cho mỗi lần chạy đã kiểm tài sản đó theo coverage, gồm scan_id, seen, status, severity/lý do, evidence và thời điểm; kể cả seen=false hoặc trạng thái không đổi. scan_id = job_id; scan_cycle phân biệt lần quét mới, không thay scan_id. Mỗi lần đánh giá severity là bản ghi mới. Sau FIXED mà thấy lại với bằng chứng thì REGRESSED; không đóng finding chỉ vì không thấy.

Job có priority 0–100 và depends_on; dependency cùng campaign, không self/cycle. Priority/dependency ghi lúc tạo và bất biến; DB giữ relation job_dependency, API thể hiện mảng depends_on. Vòng đời job (attempt/generation, cancel intent, terminal CAS, late result, lý do chờ) đã khóa ở §C06.

## API và MCP

REST `/api/v2`, danh mục operation ở [OpenAPI](../../../contracts/api/openapi.v2.yaml): campaign create/list/detail/pause/resume/cancel/policy/events/flow; capabilities; jobs submit/list/read/cancel; ingestion; assets/list/graph/history; finding/transition/history; report delta. `/campaigns/{campaign_id}/policy` vẫn là tên kỹ thuật của endpoint cập nhật snapshot cấu hình chạy, không có endpoint `/settings` riêng.

Agent dùng MCP capability/query schema, không dùng SQL/Cypher tự do. Ngữ cảnh campaign/session phải được server đối chiếu với lời gọi; ID người dùng gửi không tự tạo quyền truy cập.

## Event

`job.started.v2`, `job.completed.v2`, `policy.denied.v2`, `asset.discovered.v2`, `observation.changed.v2`, `artifact.ready.v2`, `knowledge.delta.v2`, `intel.revision.v2`, `finding.changed.v2`.

policy.denied là lỗi điều kiện thực thi/schema/budget/mục tiêu, không là phân loại quyền thao tác. Event có ID/provenance, giao at-least-once. V1 còn trong lịch sử DB, consumer v2 không tự parse như payload v2. Thuật toán watermark và content hash idempotency đã khóa (C03/C04: `aegis-c14n/1`, outbox watermark/fence ở 0008 và [graph/model.md](../../../contracts/graph/model.md#c04--thứ-tự-công-bố-đã-khóa-ở-s13)); migration kiến trúc không thay cho việc kiểm.

## Mô hình tri thức và định danh

| Khái niệm | Ý nghĩa | Nguồn hình dạng dữ liệu |
| --- | --- | --- |
| Asset/alias | Đối tượng được quan sát và các tên tham chiếu đến nó | [ID/key](../../../contracts/common/ids.v2.schema.json), DDL asset/asset_alias |
| Observation | Một giá trị được ghi nhận tại thời điểm, có nguồn và confidence | [ResultEnvelope](../../../contracts/ingestion/result-envelope.v2.schema.json), predicate registry |
| Finding | Đánh giá điểm yếu trên một asset/location; khác advisory toàn cục | [Finding](../../../contracts/finding/finding.v2.schema.json) |
| Vulnerability/intel | Dữ liệu advisory theo snapshot nguồn/version | DDL và [graph model](../../../contracts/graph/model.md) |
| Evidence/artifact | Raw bất biến cùng URI/hash và vị trí trích dẫn | ResultEnvelope, EvidenceStore |
| Hypothesis | Giả thuyết có bằng chứng ủng hộ/phản bác, chưa phải fact | [Hypothesis update](../../../contracts/agent/hypothesis-update.v2.schema.json) |
| Seed/job/campaign | Ngữ cảnh tạo ra quan sát và chuỗi phát hiện tài sản | Campaign/job schema và metadata |

Adapter trả canonical_key; M27 phân giải asset_id, không để adapter tự cấp định danh nội bộ. Chuẩn hóa domain/IDNA, IP, URL, package và snapshot đã khóa ở G0.3c tại [normalization.v2.yaml](../../../contracts/ingestion/normalization.v2.yaml): `aegis-norm/1` tất định, có golden fixture viết độc lập; đổi quy tắc là `aegis-norm/2`, key lưu với version cũ không bao giờ so hay nâng cấp chéo version. Domain viết thường, bỏ dấu chấm cuối và giữ alias raw/IDNA; IP chuẩn hóa IPv4/IPv6, service dùng IP:port/transport; package pURL giữ version/qualifiers. Image dùng digest, repo snapshot dùng commit; tag/branch mutable không làm định danh snapshot.

Metadata nghiệp vụ giữ từ mô hình gốc: Service có host/port/transport/banner/time; Endpoint có HTTP method, api_contract_id và auth_context; Package có version/ecosystem/license; Artifact có digest/kind/origin_uri/storage_uri/size/classification; alias có namespace/value/reason/validity. Trường owner chỉ ghi khi có nguồn, không tự đoán; đây là metadata người quản lý tài sản, không là bước duyệt pivot. Các thuộc tính phải được ánh xạ vào schema/predicate/attributes và khóa tại S1.5 trước khi giao adapter tương ứng, không coi object attributes tự do là đã có hợp đồng đầy đủ.

URL gốc giữ nguyên trong bằng chứng. URL định danh dùng bản chuẩn hóa theo M07, không mang token/query nhạy cảm vào canonical key. Hai raw URL khác token có thể quy về cùng endpoint nhưng phải giữ bằng chứng gốc riêng. Danh sách tham số nhạy cảm (và tiền tố/hậu tố) đã khóa chung tại mục `query_identity`/`sensitive_query_params` của [normalization.v2.yaml](../../../contracts/ingestion/normalization.v2.yaml), kiểm bằng golden fixture; adapter, M07 và M27 không tự chọn danh sách riêng. Không sửa canonical key hay observation gốc để giải quyết xung đột; giữ alias và những observation độc lập có provenance.

Định nghĩa node/cạnh và query as-of-time duy trì một lần ở [graph model](../../../contracts/graph/model.md); kiểu asset/predicate chỉ lấy từ registry hiện hành.

## Các cổng chất lượng ingestion

| Cổng | Điều kiện | Khi không đạt |
| --- | --- | --- |
| G1 Identity | Kind/key hợp lệ và chuẩn hóa tất định | Cách ly record lỗi, ghi nguyên nhân |
| G2 Provenance | Có provider/version, campaign/job, thời gian và nguồn | Ghi incomplete/unsupported, không dựng nguồn giả |
| G3 Evidence | Reference tồn tại, checksum khớp | Không VERIFIED nếu thiếu bằng chứng bắt buộc |
| G4 Schema/status | Enum, predicate, kiểu dữ liệu và trạng thái đúng contract | Quarantine/dead-letter và lỗi có next_action |
| G5 Nguồn mục tiêu | Mỗi asset/cạnh truy được seed/asset nguồn, tool và job trong campaign; không dùng allowlist phạm vi hoặc thêm bước duyệt asset mới | Cách ly phần thiếu/sai nguồn gốc, ghi audit |
| G6 Dữ liệu không tin cậy | Output chỉ là dữ liệu đã parse/gắn nguồn, không trở thành chỉ dẫn hoặc command | Cô lập raw và từ chối phần phá schema; giữ dấu vết |
| G7 Dedup | Khóa nghiệp vụ/unique transaction, không ghi đè lịch sử | Nhận duplicate hợp lệ hoặc báo conflict, giữ các observation độc lập |

Dữ liệu điều phối do module sở hữu ghi, dữ liệu quét qua M27, Neo4j chỉ do projector ghi. Metadata/outbox commit cùng transaction; graph không cập nhật trước commit. Trạng thái hiện tại đổi kèm dòng history; cạnh đóng valid_to rồi lần quan sát lại tạo khoảng hiệu lực mới.

G5 và G6 không được tắt bằng cấu hình. Tách chưa biết, vắng mặt tại lúc quan sát và bằng chứng phủ định; polarity theo schema là present/absent/negated, thiếu coverage là chưa biết. Không tự đóng valid_to hoặc đổi trạng thái chỉ vì một scanner không trả record. Xung đột ghi retry với exponential backoff có trần. Query bị cắt bởi số node/edge, bước nhảy hoặc timeout phải báo truncated/incomplete, không trình bày như toàn bộ graph.

## Correlation, xác minh và đánh giá finding

Khớp CVE ưu tiên định danh package/ecosystem/version range hoặc CPE có nguồn. Lưu phương pháp, confidence và snapshot tình báo đã dùng; tên sản phẩm do model đoán không đủ để khẳng định affected. M20 hợp nhất finding giữa provider theo fingerprint ổn định, vẫn giữ evidence từng nguồn.

Fingerprint finding dựa asset_id, rule_id, location và ngữ cảnh bằng chứng chuẩn hóa, ổn định qua phiên bản scanner; không dùng riêng ID do scanner cấp. LLM đánh giá/diễn giải finding có dữ liệu đã tiếp nhận, không tự tạo finding thiếu nguồn. Asset có owner/exposure/criticality/first_seen/last_seen và alias; cùng tài sản ở nhiều campaign vẫn là một canonical asset, truy vấn lọc membership campaign.

CVSS, EPSS, KEV, mức phơi nhiễm, criticality và hạn chế coverage là tín hiệu đầu vào để agent đánh giá kèm lý do/nguồn/uncertainty. Không dùng công thức trọng số hay hạng ưu tiên từ nghiên cứu làm severity của sản phẩm. Public PoC, version match hoặc static path không tự nâng finding thành VERIFIED. Xác minh cần bằng chứng tái lập phù hợp loại finding và đối chứng âm; không suy FIXED từ lần quét thiếu coverage.

## Các contract đã khóa (C02–C08)

Mục này liệt kê tiêu chí nghiệm thu của từng C-item. Trạng thái "đã khóa" nghĩa là schema + DDL + test của contract đã có; chưa phải runtime của dịch vụ sản phẩm.

### C02 — Seed reference xuyên hợp đồng

Đã khóa ở S1.1 (contract v2 + migration 0005). [TargetRef](../../../contracts/common/ids.v2.schema.json) là đúng một trong hai dạng: `{seed_id}` trỏ `campaign_target.target_id` (giữ nguyên kind/raw_value, kể cả keyword/CIDR không có canonical_key) hoặc `{canonical_key}` của asset đã biết. `approved-task.targets`, `job.targets` và `result-envelope.provenance.seed_targets` dùng TargetRef; `coverage.subjects`, `discovered_from` và `input.targets` vẫn là khóa asset/tham số tool, không phải chỗ thay thế seed. Không tạo asset giả cho keyword/CIDR: M05 phân giải mục tiêu trong request (job-submit, MCP capability-request) thành TargetRef; giá trị không khớp seed của campaign hoặc asset đã biết bị từ chối, không tự suy ra khóa chuẩn.

DB: `scan_job.target_refs` bắt buộc với job mới; seed phải là `campaign_target` của đúng campaign/scope (trigger `aegis.require_job_target_refs`), bất biến sau khi nhận, và `asset_provenance.from_target_id` cũng bị chặn seed khác campaign. `scan_job.targets` chỉ còn là hình chiếu canonical-key cho lịch sử/tiện đọc và có thể rỗng khi job chỉ có seed keyword/CIDR. Hàng trước 0005 giữ refs NULL, không được dispatch/replay. `job_fingerprint` băm danh sách TargetRef (không băm hình chiếu `targets text[]`, nếu không hai job keyword/CIDR khác nhau sẽ trùng fingerprint); thành phần còn lại đã khóa ở §C03.

Kiểm chứng: schema + fixture tại [test_seed_reference.py](../../../contracts/tests/test_seed_reference.py) (seed-kinds và seed-provenance hợp lệ; bị từ chối: seed_id+canonical_key cùng lúc, chuỗi khóa cũ, canonical_key giả `keyword:`); DB tại [job_target_refs.sql](../../../contracts/db/postgres/tests/job_target_refs.sql) — seed khác campaign bị chặn, replay không đổi seed đã nhận, CIDR→IP giữ seed gốc ở provenance, 5 dạng list sai bị từ chối. `policy_decision` cũng mang `target_refs` từ 0012 (bắt buộc với dòng mới, cùng luật seed với job), nên cả request bị từ chối vẫn giữ seed và một quyết định chỉ sinh ra đúng một job có cùng campaign/actor/refs; `targets` của cả hai bảng chỉ là hình chiếu canonical-key và có thể rỗng khi chỉ có seed keyword/CIDR (OI-6). Còn mở: implementation M05/M27 (G1.1c/G1.4a), kiểm `{canonical_key}` có thật là asset đã biết ở tầng DB (hiện M05/M06 chịu trách nhiệm, P3a), và capability tiêu thụ seed keyword chưa có schema.

### C03 — Idempotency, hash và receipt

Đã khóa ở S1.2a (contract v2 + migration 0006). `event_id` là ID lần nộp; `dedup_key` là ID kết quả logic ổn định. Không băm toàn envelope: `payload_hash = sha256(aegis-c14n/1(envelope bỏ event_id, dedup_key, trace))`. Mọi trường top-level của [ResultEnvelope](../../../contracts/ingestion/result-envelope.v2.schema.json) phải được phân loại include/exclude trong [canonicalization.v2.yaml](../../../contracts/ingestion/canonicalization.v2.yaml); thêm trường mà không phân loại thì test contract fail. `provenance.started_at/finished_at` nằm trong hash — collector đóng băng snapshot nghiệp vụ trước lần nộp đầu nên retry gửi lại nguyên nội dung; array giữ nguyên thứ tự.

Canonicalization `aegis-c14n/1` = RFC 8785 + NFC cho chuỗi và khóa, chối khóa trùng sau NFC, số ngoài double hoặc NaN/Infinity; có golden vectors tại [fixtures/golden/hash](../../../contracts/fixtures/golden/hash/canonicalization.vectors.json) (gồm vector RFC 8785 §3.2.3). Hash khác version không bao giờ bằng nhau: đổi quy tắc = `aegis-c14n/2`, không so lại hash cũ.

Fingerprint (X-1) có một định nghĩa duy nhất: `sha256(aegis-c14n/1({campaign_id,capability,policy_version,provider,provider_version,adapter_version,image_digest,manifest_sha256,target_refs,input,scan_cycle}))`, băm danh sách `target_refs` chứ không băm hình chiếu `targets`; loại scheduling (priority/depends_on), actor/rationale/trace và job_id/decision_id/status. 0006 đặt lại COMMENT `scan_job.job_fingerprint`; 0002/0003 không sửa.

Receipt: `ingestion_inbox` giữ đúng một dòng cho mỗi `dedup_key` — lần nộp đầu đã commit. `receipt` phải mô tả đúng dòng (event_id/payload_hash/hash_version) và chỉ ghi một lần (0006); lần nộp lại cùng `payload_hash` nhận nguyên receipt đó với `duplicate=true`, không cấp revision mới. Khác `payload_hash` — hoặc dòng có hash NULL trước 0006 — trả 409 `IDEMPOTENCY_CONFLICT` và không đổi receipt. Mỗi lần nộp ghi một dòng append-only `ingestion_attempt` (`first`/`duplicate`/`conflict` + detail) trong cùng giao dịch với quyết định, nên lần nộp lại không thể mất dấu. Đối chiếu campaign/job/provenance trước khi trả receipt vẫn là bước bắt buộc của M27.

Kiểm chứng: [test_hash_receipt.py](../../../contracts/tests/test_hash_receipt.py) (golden vectors, registry phân loại đủ trường, receipt schema, 409 code); [ingestion_hash_receipt.sql](../../../contracts/db/postgres/tests/ingestion_hash_receipt.sql) (hash_version bắt buộc/định dạng, receipt ghi một lần, dedup conflict, attempt guard, lịch sử NULL giữ nguyên khi upgrade); [test_ingestion_concurrency.py](../../../contracts/tests/test_ingestion_concurrency.py) với hai kết nối thật (cùng dedup_key chỉ một dòng, blocking trên unique index, retry sau crash nhận receipt đã commit, đổi evidence/coverage/value/status thành conflict, receipt không đổi). Còn mở: implementation M27 (G1.4a) — repo chưa có dịch vụ ingestion.

### C06 — Kết quả cuối, partial, cancel và late result

Đã khóa ở S1.2b (contract v2 + migration 0007). Một job có một `dedup_key` và một envelope reference. `partial` là kết quả thu cuối có độ phủ chưa đầy đủ — không phải chuỗi nhiều envelope thay đổi liên tục; tiến độ thể hiện qua status/event, thu thêm dữ liệu là job mới với `scan_cycle` mới.

Hai fencing token trong [job.v2](../../../contracts/capability/job.v2.schema.json): `attempt` (số lần dispatch trong cùng generation, +1 khi dispatch lại job chưa terminal) và `generation` (số lần tái thực thi; chỉ tăng khi mở lại job đã terminal, `attempt` trở về 1 và kết quả cũ được xoá khỏi hàng). Cả hai khác `scan_cycle` và khác retry truyền lại envelope.

Hủy là **ý định**: [`aegis.request_job_cancel`](../../../contracts/db/postgres/0007_job_lifecycle.sql) ghi `cancel.requested_at/requested_by`, trả `requested | already_requested | terminal`, không đổi trạng thái và không ghi đè kết quả đã nhận. Terminal hóa chỉ qua [`aegis.record_job_callback`](../../../contracts/db/postgres/0007_job_lifecycle.sql): khóa hàng rồi compare-and-set trên `(generation, attempt)`, trả `terminalized | duplicate | quarantined`. Trạng thái terminal là cuối cùng — không trạng thái terminal nào thay bằng trạng thái terminal khác; mở lại chỉ bằng `generation+1` với kết quả đã xoá (trigger `lifecycle_guard`). Callback của attempt/generation cũ, callback trái kết quả đã ghi, hoặc `CANCELLED` không có ý định hủy bị cách ly ở `job_callback_quarantine` kèm `claimed`, `payload_hash` (aegis-c14n/1 từ §C03) và `evidence_refs` — dữ liệu đã thu vẫn nằm ở S3/`evidence`, không bị xoá. Timeout có kết quả một phần giữ nguyên evidence đã thu và envelope một phần trên hàng job. Mọi thay đổi attempt/generation/cancel intent/wait reason có dòng append-only trong `job_lifecycle_change`; status có `job_status_change`.

Lý do chờ (X-4): `job.wait_reason` là `{code, detail?, blocking_job_ids?, since}` chỉ có khi `status=QUEUED`; job `QUEUED` không có nó là job sẵn sàng dispatch. Mã: `DEPENDENCY_PENDING`, `DEPENDENCY_FAILED`, `CAMPAIGN_PAUSED`, `BUDGET_EXHAUSTED`, `WINDOW_CLOSED`, `CONCURRENCY_LIMIT`, `RATE_LIMITED`, `PROVIDER_UNAVAILABLE`, `MANUAL_HOLD`; schema và DDL công bố cùng danh sách. Dispatch phải xoá reason trong cùng UPDATE (CHECK `scan_job_wait_reason_queued`), nên lý do cũ không tồn tại trên job đang chạy. Flow API `/campaigns/{id}/flow` trả `attempt`, `generation`, `cancel`, `wait_reason` cho node job.

Kiểm chứng: [test_job_lifecycle.py](../../../contracts/tests/test_job_lifecycle.py) (shape/rule schema, event mang attempt, danh sách mã schema = DDL, OpenAPI flow/cancel); [job_lifecycle.sql](../../../contracts/db/postgres/tests/job_lifecycle.sql) (cancel/complete cả hai thứ tự còn đúng một terminal, terminal bất biến, callback attempt/generation cũ bị cách ly, timeout giữ evidence một phần, duplicate callback idempotent, mở lại bằng generation+1, wait reason chỉ trong QUEUED); [test_job_lifecycle_race.py](../../../contracts/tests/test_job_lifecycle_race.py) với hai kết nối thật trên database dùng một lần do harness tự tạo và drop (chặn trên row lock, chỉ một terminal, cancel intent idempotent). Còn mở: implementation M02/M06 (G1.1d/G1.3a) — contract mô tả luồng tham chiếu, chưa có scheduler/runner.

### C08 — Kiểm biên schema và OpenAPI

Schema và kiểm conformance dùng [validator chung](../../../contracts/validation.py). Mọi consumer phải bật các format ngữ nghĩa; DTO sinh tự động phải gắn cùng kiểm tra. Quy tắc hiện hành và phép kiểm hồi quy:

| Mã | Quy tắc hiện hành | Kiểm chứng |
| --- | --- | --- |
| N01 | OpenAPI phải hợp lệ toàn bộ theo 3.1, gồm response objects và ref | Validator toàn tài liệu; test thêm thuộc tính response ngoài chuẩn phải thất bại |
| N02 | Identity kiểm IP/domain/port thực; network.discover_services cần ports không rỗng khi có IP target. Seed raw giữ nguyên, kiểm candidate IDNA/IP/CIDR hợp lệ | Ca đúng/sai IPv4/IPv6, cổng 1/65535, domain lỗi, resolver lỗi, CIDR ngoài miền và IP thiếu ports |
| N03 | Event finding dùng enum Severity chung; old/new có thể null khi chưa có mức đánh giá | Kiểm cả sáu giá trị enum, null và giá trị ngoài enum qua EventEnvelope |
| N04 | TimeWindow theo mô tả trong schema; chỉ end nhận 24:00, timezone thuộc dữ liệu IANA đã khóa | Giờ/zone đúng, giờ vượt miền, timezone không tồn tại; execution engine vẫn cần kiểm thực thi khung giờ ở G1 |
| N05 | Usage tiêu thụ không âm ở schema và DB. Lịch sử sai giữ nguyên và phải báo lỗi toàn vẹn, không giảm consumed budget | Schema từ chối âm, DB từ chối bốn cột âm và nhận zero; upgrade giữ nguyên bản ghi lịch sử sai |
| N06 | API hiện hành ở G2 xuất JSON; query và response cùng định dạng. SARIF/HTML của G4 có task khóa contract riêng, không tự bật trong API hiện tại | Kiểm enum query và response media type; G4.2 kiểm chuẩn định dạng mở rộng |

Test tại [schema boundaries](../../../contracts/tests/test_schema_boundaries.py) và SQL test trong contracts/db/postgres/tests. Kiểm conformance này không thay thế phần còn mở của GĐ1 (OD-5/X-8 cơ chế principal, OI-7 chữ ký ApprovedTask) và không thay runtime của dịch vụ.
