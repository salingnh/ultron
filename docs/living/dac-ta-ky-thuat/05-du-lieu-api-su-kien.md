# Dữ liệu, API và sự kiện

## Nơi lưu

| Kho | Nội dung |
| --- | --- |
| PostgreSQL | Campaign/seed, cấu hình, job/dependency, actor, audit, tool metadata, asset/observation/finding history, raw references, outbox |
| Neo4j | Asset và quan hệ có thời gian/provenance; bản chiếu dựng lại được |
| S3 | Output raw, log, artifact, báo cáo; object bất biến theo SHA-256 |

Mọi cạnh có observed_at/valid_from/valid_to/source_job_id/confidence. Metadata có URI/hash, không nhét raw lớn vào graph. Canonical key phân biệt dns, ip, service, url, image, repo, package; URL định danh được chuẩn hóa, URL raw giữ trong bằng chứng. Seed keyword/CIDR cần contract reference riêng đang còn backlog; không dựng asset giả để ép vào khóa.

## Ghi và trạng thái

Collector → ResultEnvelope → M27: schema, identity, provenance, hash, status, dữ liệu không tin cậy và dedup. Bản ghi lỗi được cách ly, không âm thầm mất. Receipt theo [schema chung](../../../contracts/ingestion/ingest-receipt.v2.schema.json), có quarantined dạng object pointer/gate/reason. Metadata/outbox ghi cùng giao dịch; graph chiếu sau commit. Các bảng điều phối do module sở hữu ghi trực tiếp.

Finding: CANDIDATE, CORROBORATED, VERIFIED, FALSE_POSITIVE, ACCEPTED_RISK, FIXED, REGRESSED. Mọi transition có lý do/evidence/history. Coverage incomplete không dùng để suy vắng mặt hay đã sửa.

Giữ quy tắc FindingRun: mỗi finding có một dòng cho mỗi lần chạy đã kiểm tài sản đó theo coverage, gồm scan_id, seen, status, severity/lý do, evidence và thời điểm; kể cả seen=false hoặc trạng thái không đổi. scan_id = job_id; scan_cycle phân biệt lần quét mới, không thay scan_id. Mỗi lần đánh giá severity là bản ghi mới. Sau FIXED mà thấy lại với bằng chứng thì REGRESSED; không đóng finding chỉ vì không thấy.

Job có priority 0–100 và depends_on; dependency cùng campaign, không self/cycle. Priority/dependency ghi lúc tạo và bất biến; DB giữ relation job_dependency, API thể hiện mảng depends_on. Metadata vẫn cần contract lifecycle rõ cho late result/cancel theo backlog.

## API và MCP

REST `/api/v2`, danh mục operation ở [OpenAPI](../../../contracts/api/openapi.v2.yaml): campaign create/list/detail/pause/resume/cancel/policy/events/flow; capabilities; jobs submit/list/read/cancel; ingestion; assets/list/graph/history; finding/transition/history; report delta. `/campaigns/{campaign_id}/policy` vẫn là tên kỹ thuật của endpoint cập nhật snapshot cấu hình chạy, không có endpoint `/settings` riêng.

Agent dùng MCP capability/query schema, không dùng SQL/Cypher tự do. Ngữ cảnh campaign/session phải được server đối chiếu với lời gọi; ID người dùng gửi không tự tạo quyền truy cập.

## Event

`job.started.v2`, `job.completed.v2`, `policy.denied.v2`, `asset.discovered.v2`, `observation.changed.v2`, `artifact.ready.v2`, `knowledge.delta.v2`, `intel.revision.v2`, `finding.changed.v2`.

policy.denied là lỗi điều kiện thực thi/schema/budget/mục tiêu, không là phân loại quyền thao tác. Event có ID/provenance, giao at-least-once. V1 còn trong lịch sử DB, consumer v2 không tự parse như payload v2. Thuật toán watermark và content hash idempotency còn cần khóa; không tuyên bố đã giải quyết bằng migration kiến trúc.

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

Adapter trả canonical_key; M27 phân giải asset_id, không để adapter tự cấp định danh nội bộ. Chuẩn hóa domain/IDNA, IP, URL, package và snapshot phải tất định, có fixture đối chiếu; quy tắc có version khi ảnh hưởng identity. Domain viết thường, bỏ dấu chấm cuối và giữ alias raw/IDNA; IP chuẩn hóa IPv4/IPv6, service dùng IP:port/transport; package pURL giữ version/qualifiers. Image dùng digest, repo snapshot dùng commit; tag/branch mutable không làm định danh snapshot.

Metadata nghiệp vụ giữ từ mô hình gốc: Service có host/port/transport/banner/time; Endpoint có HTTP method, api_contract_id và auth_context; Package có version/ecosystem/license; Artifact có digest/kind/origin_uri/storage_uri/size/classification; alias có namespace/value/reason/validity. Trường owner chỉ ghi khi có nguồn, không tự đoán; đây là metadata người quản lý tài sản, không là bước duyệt pivot. Các thuộc tính phải được ánh xạ vào schema/predicate/attributes và khóa tại S1.5 trước khi giao adapter tương ứng, không coi object attributes tự do là đã có hợp đồng đầy đủ.

URL gốc giữ nguyên trong bằng chứng. URL định danh dùng bản chuẩn hóa theo M07, không mang token/query nhạy cảm vào canonical key. Hai raw URL khác token có thể quy về cùng endpoint nhưng phải giữ bằng chứng gốc riêng. Danh sách tham số định danh/nhạy cảm phải được khóa chung và kiểm bằng fixture, không để mỗi adapter tự chọn. Không sửa canonical key hay observation gốc để giải quyết xung đột; giữ alias và những observation độc lập có provenance.

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

## Các phần contract còn cần khóa

### C02 — Seed reference xuyên hợp đồng

Campaign nhận keyword/CIDR nhưng targets/provenance trong task/envelope hiện đòi CanonicalKey của asset. Đây là khoảng trống hình dạng dữ liệu, không phải runtime đã hỗ trợ các seed này xuyên luồng.

Phương án cần khóa S1.1: TargetRef phân biệt seed_id và asset canonical_key; giữ loại/giá trị seed gốc tại campaign_target. Không tạo asset giả cho keyword/CIDR. M27 phải kiểm seed tồn tại và thuộc campaign/scope; coverage vẫn nói về asset thực sự đã kiểm. Test domain/IP/URL/email/keyword/CIDR từ request đến provenance, seed khác campaign, replay và CIDR mở rộng không mất nguồn gốc.

### C03 — Idempotency, hash và receipt

`event_id` là ID lần nộp; `dedup_key` là ID kết quả logic ổn định. DDL có unique dedup_key và payload_hash; canonicalization/projection của hash cùng receipt duplicate còn phải khóa ở S1.2. Không băm toàn envelope bao gồm event_id mới rồi coi retry là nội dung khác.

Phương án cần chứng minh: collector đóng băng snapshot nghiệp vụ; hash bao gồm job/campaign/config/provider, kết quả, coverage, evidence, errors, provenance và trạng thái; loại event_id/trace của lần nộp. Canonicalization có version/golden vectors cho object key, Unicode, số và array; không tùy ý bỏ timestamp thực thi hoặc đổi thứ tự array. Cùng key/hash trả receipt đã chấp nhận đầu tiên và audit lần nộp mới; cùng key khác hash trả 409, không ghi đè. Đối chiếu ngữ cảnh campaign/job và provenance trước khi trả receipt.

Test: đổi riêng event_id/trace vẫn duplicate; đổi evidence/coverage/value/status thì conflict; hai request cạnh tranh chỉ ghi một kết quả logic; retry sau crash nhận receipt đã commit. Hiện chưa có dịch vụ ingestion để chứng minh các hành vi này.

### C06 — Kết quả cuối, partial, cancel và late result

Mô hình hiện có một dedup_key và một envelope reference cho mỗi job. `partial` mô tả kết quả thu cuối có độ phủ chưa đầy đủ, không là chuỗi nhiều envelope thay đổi liên tục. Tiến độ được biểu diễn qua job status/event. Thu thêm dữ liệu là lần quét mới có scan_cycle mới.

Contract xử lý cancel/complete cạnh tranh và attempt fencing còn phải khóa ở S1.2. Phương án: cancel ghi intent; terminal hóa có compare-and-set trên attempt/generation; callback attempt cũ bị cách ly và giữ audit, không ghi đè terminal result. Generation tái thực thi khác scan_cycle và khác retry truyền lại envelope. Các field/giao dịch tương ứng chưa đủ trong schema/DDL, không được triển khai bằng giả định ngầm.

Test cần có cancel/complete đảo thứ tự, timeout có bằng chứng partial, duplicate callback, kết quả muộn từ attempt cũ và retry sau crash; chỉ một terminal result được nhận, evidence đã thu không mất.

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

Test tại [schema boundaries](../../../contracts/tests/test_schema_boundaries.py) và SQL test trong contracts/db/postgres/tests. Kiểm conformance này không thay thế các phần còn cần khóa về seed reference, hash, ordering, actor, lifecycle hay ModelClient.
