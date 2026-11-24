# Nền tảng thực thi

## Mạng

Control: API, Temporal worker, LangGraph worker, MCP, collector, ingestion. Data: PostgreSQL, Neo4j, S3, Temporal persistence. Execution: container tool theo job. UI vào private ingress/VPN. Tool không truy cập control/data network; collector tại control gửi kết quả.

Temporal UI có sẵn dùng debug nội bộ ở control plane; UI nghiệp vụ vẫn do M26 phục vụ.

## Sandbox

Podman rootless trên một máy, một invocation một container, image pin digest. Không privileged/host network/socket; drop toàn bộ Linux capability, no-new-privileges và seccomp. Filesystem read-only trừ /out; CPU/RAM/PID/timeout/output limits cụ thể. Network none hoặc egress; cấu hình egress chặn hạ tầng nội bộ của nền tảng. NET_RAW chỉ cấp khi scanner cần và có test. Timeout/cancel phải dừng container, thu output còn lại rồi remove container; không xóa evidence và không để container tự restart ngoài điều phối.

Input có kiểu, không command tùy ý. Credential vận hành được cấp riêng tới sandbox; không vào context agent. Tool output không tin cậy. Collector kiểm file thường, không symlink, áp trần; parser không mạng/credential, tiến trình riêng.

Giữ giới hạn egress theo provider: chỉ kết nối mục tiêu của job và nguồn dữ liệu provider khai báo, ngoài ra mặc định chặn. Phải kiểm cả DNS/redirect và địa chỉ IPv4/IPv6 sau phân giải; việc không dùng allowlist phạm vi không bỏ giới hạn mạng của sandbox. Hình dạng declared sources/target binding và cơ chế cưỡng chế đã khóa ở S1.5a (dưới đây); một mình `networkAccess=egress` vẫn không là bằng chứng hạn chế đích kết nối.

### Egress đã khóa (S1.5a, theo kết quả G0.2)

[Provider manifest](../../../contracts/capability/provider-manifest.v2.schema.json) khai `permissions.networkAccess` là `none` hoặc `egress`. GĐ1 chỉ có một chế độ egress (G0.2): container chỉ tới được broker L7 của job; broker phân giải ở control plane, kiểm toàn bộ đáp án A/AAAA rồi pin địa chỉ đã kiểm, nên một tên trả lẫn địa chỉ ngoài binding thì cả tên bị từ chối và redirect sang đích ngoài binding bị chặn ở hop sau. Bằng chứng đo (cgroup v2, mạng nội bộ, deny set, DNS rebinding, collector/parser) ở spike `spikes/g0.2-sandbox/` và báo cáo G0.2; mục này chỉ khóa hình dạng và luật.

- Trường bắt buộc khi `networkAccess=egress`: `egressMode: broker`, `proxyAware: true` (công cụ phải tôn trọng `HTTPS_PROXY`/`ALL_PROXY`; broker là đường ra duy nhất), `egressSources` (khai cả khi rỗng), `targetBinding: required|none`. `targetPorts: from_input` bắt buộc khi `targetBinding=required` và cấm khi `none`. `rawSocket` ghim `false`: GĐ1 không có egress L3 (Naabu tự hạ SYN xuống CONNECT dù có NET_RAW).
- Không có đích nào thì không có egress: `targetBinding=none` với `egressSources` rỗng bị từ chối. Host khai chính xác (không wildcard, không khớp hậu tố), port tĩnh, `protocol` thuộc `https|http|tls|tcp|dns` — UDP/ICMP không biểu diễn được vì broker không relay UDP.
- **Binding hiệu lực của một job = (mục tiêu đã phân giải ∪ `egressSources`) − tập luôn chặn.** Tập luôn chặn thắng, không phải "hợp rồi mới chặn một phần": một đích vừa thuộc mục tiêu vừa thuộc tập chặn thì bị từ chối, không có ngoại lệ cho `egressSources` hay cho mục tiêu campaign.
- Tập luôn chặn là hằng của nền tảng, không phải dữ liệu provider: loopback (`127.0.0.0/8`, `::1`), link-local/metadata (`169.254.0.0/16`, **`fe80::/10`**), multicast (`224.0.0.0/4`, `ff00::/8`), unspecified (`0.0.0.0/8`, `::`), reserved (`240.0.0.0/4`), mạng control/data, `target_denylist` của campaign; IPv4 nhúng IPv6 (mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`) bị chặn theo chính dạng nhúng đó nên không lách được. Manifest không có trường để khai hay nới tập này và schema từ chối trường lạ trong `permissions`.
- Registry M05 **từ chối manifest** có host trong `egressSources` thuộc tập luôn chặn (P7 của review cổng S1): cùng một danh sách hằng ở [validation.py](../../../contracts/validation.py) (`EGRESS_DENY_NETWORKS`, `EGRESS_DENY_HOSTS`, `denied_egress_host`) mà broker phải dùng, và [validate_contracts.py](../../../contracts/tests/validate_contracts.py) kiểm trên fixture âm `manifest.egress-source-in-deny-set.yaml`. Từ chối lúc nhận manifest, không đợi tới lúc kết nối.
- `networkAccess=none` thì không có cấu hình egress; runtime nhận `network=none`.

Kiểm: [test_egress_actor.py](../../../contracts/tests/test_egress_actor.py) và các fixture âm `contracts/fixtures/invalid/manifest.*.yaml`. Cưỡng chế lúc chạy (broker, ContainerSpec) thuộc G1.3a; chưa được coi schema đã là bằng chứng runtime.

## Điều phối

Temporal chứa ID/reference, không raw lớn. Activity idempotent; retry có giới hạn. Pause/resume/cancel lưu lịch sử. Scheduler lấy ready jobs (dependency thành công, đủ ngân sách/khung giờ/rate/concurrency), sắp priority DESC, created_at ASC, job_id ASC. Dependency thất bại làm job chờ có lý do; không tự bỏ dependency.

Chờ signal job/tri thức hoặc timer, không busy polling. Pause chặn dispatch mới, giữ/thu job đang chạy theo snapshot; cancel chuyển intent tới worker và đối soát kết quả theo C06. Khi kết thúc campaign phải có snapshot cuối và lý do dừng. Allowed/blackout windows là tùy chọn: không cấu hình thì không tự thêm khung giờ; đã cấu hình thì phải cưỡng chế trước dispatch.

## Model

ModelClient nhận provider/model cấu hình trực tiếp, token/time/cost limits cụ thể; kiểm policy dữ liệu trước fallback. Log model/version/token/cost và session/campaign. Cấu hình model không tạo nhóm quyền chạy tool. Chi tiết round-trip tool call, chuẩn hóa finish và fallback đã khóa ở [C07](../../../contracts/interfaces/README.md#phần-cần-khóa-của-modelclient-và-severity--c07).

Endpoint tương thích OpenAI/Anthropic có thể local hoặc cloud do vận hành cấu hình. Giữ D20: đổi model không tự tạo replay/quét lại; lịch sử assessment/FindingRun dùng để đối chiếu thay đổi đánh giá. Model lỗi không ngăn người vận hành gửi job scanner xác định qua API/MCP với các kiểm thông thường; agent có thể chờ nhưng job đã nhận và thu bằng chứng vẫn tiếp tục.

## Lưu trữ và vận hành

PostgreSQL nguồn metadata; Neo4j projection; S3 raw theo SHA-256. Giữ mục tiêu RPO PostgreSQL 15 phút, RTO 2 giờ, graph/raw RPO 1 giờ như mục tiêu kỹ thuật chưa có diễn tập chứng minh. Backup/restore kiểm checksum và số bản ghi. Outbox at-least-once, consumer idempotent; thứ tự công bố đã khóa ở C04 (allocator + watermark + fence, [graph/model.md](../../../contracts/graph/model.md#c04--thứ-tự-công-bố-đã-khóa-ở-s13)); thuật toán chọn allocator cuối cùng đang là finding mở, không dùng seq liền mạch làm bằng chứng đã đúng.

OTel: trace, log, metric; mọi job có campaign/tool/version/actor/rationale. UI cho biết lỗi và phần chưa hoàn tất. Dữ liệu lớn dùng reference và pagination.

Kế hoạch backup giữ PostgreSQL full hằng ngày/WAL liên tục, graph backup/snapshot/export, S3 versioning/replication hoặc bucket backup và Temporal persistence nhất quán theo backend. Các phương án cụ thể phải được kiểm ở môi trường vận hành; không coi một file cấu hình backup là bằng chứng đạt RPO/RTO.

### Định cỡ dung lượng và tải (G0.4d)

Mỗi số dưới đây ghi rõ **đo** (kèm cách đo/nguồn) hoặc **giả định** (tham số phải đo lại khi có tải thật). Dung lượng tính cho chính sách lưu vĩnh viễn (NFR-05): không TTL, không xóa lịch sử, nên tăng trưởng tuyến tính theo số asset/finding đã thấy và không tự giảm. Metadata PostgreSQL **không** chứa raw envelope: `ingestion_inbox` chỉ giữ `payload_hash` + receipt (677 B/envelope, đo), raw nằm ở S3 qua `evidence.storage_uri`.

**Mô hình tải.** NFR-01..04 cho biên chứ không cho tốc độ, nên các tham số nối NFR với dung lượng phải nêu rõ:

| Tham số | Giá trị dùng | Loại | Lý do/nguồn |
| --- | --- | --- | --- |
| Campaign dài | 7 ngày, ≥10.000 bước | mục tiêu | NFR-01 |
| Job đồng thời, queue delay | 50, P95 <2 phút | mục tiêu | NFR-03 |
| Envelope, artifact | <1 MB; 10 GB | mục tiêu | NFR-04, NFR-03 (G4) |
| Graph đo tải | 1 triệu node | mục tiêu | NFR-03 (G4) |
| Thời lượng job trung bình | 60 s | giả định | trần manifest `timeoutSeconds` = 900 (đo, `fixtures/valid/manifest.subfinder.yaml`); chưa có phân bố thật |
| Kết quả/job | 50 / 500 / 1.000 | giả định | 3 kịch bản demo / soak / đỉnh; OD-1 (lab) chưa có nên chưa đo |
| Observation mới/asset | 3 | giả định | A, AAAA, CNAME mỗi asset một dòng |
| Relationship + sighting/asset | 1 + 1 | giả định | mỗi asset thấy một lần bởi một job |
| Outbox event/asset | 1 | giả định | khớp G0.3b: 1.999 `asset.discovered` cho 2.465 node |
| Raw/result, log+trace/job | 120 B; 20 KiB | giả định | jsonl `subfinder`; chưa có pipeline OTel |
| Bước agent → job | 1 job/10 bước | giả định | bước không tạo job đều đặn |

**Chi phí đơn vị đo được.** Đo trên PostgreSQL 16 với chuỗi migration `0001..0010` và một mẫu ~274 nghìn dòng (2.000 job, 10.000 asset, 30.000 observation, 50.000 outbox event, 100.000 audit), `VACUUM ANALYZE`, không nén bảng, `pg_total_relation_size` chia số dòng thật:

| Đơn vị | Byte/dòng (gồm index) | Trong đó heap | Ghi chú |
| --- | --- | --- | --- |
| `asset` | 274 | 149 | |
| `observation` | 640 | 344 | index chiếm 44% |
| `relationship` | 422 | 191 | 3 index |
| `relationship_sighting` | 194 | 117 | |
| `evidence` | 885 | 391 | `storage_uri` 162 B |
| `outbox_event` | 716 | 512 | payload 296 B; giữ vĩnh viễn để rebuild graph |
| `audit_log` | 355 | 315 | |
| `ingestion_inbox` | 1.172 | 1.024 | receipt 677 B |
| `scan_job` | 1.053 | 747 | |
| `job_status_change` | 139 | 75 | |
| `graph_revision`, `model_usage` | 143, 200 | | |
| `finding`, `severity_assessment` | 503, 673 | | assessment lưu JSON đầy đủ |
| Neo4j (mỗi record): node / cạnh / property / index | 15,2 / 34,2 / 28,5 / 141,3 | | đo store sau shutdown: 20.000 node, 39.996 cạnh, 5+4 property; 12,8 MB tổng |
| WAL/outbox event | 1.030 | | cùng payload +1 KB → 2.038 B, tức ~1 B WAL/1 B payload |

Hai điểm đo cần nhớ khi đọc: (1) index là 28–45% dung lượng metadata, nên chênh lệch sau bulk load là index bloat chứ không phải dữ liệu; (2) hàng `outbox_publication` bị UPDATE một lần mỗi event — 50.000 lần cấp số làm heap của bảng 1 dòng phình lên 2,7 MB (54 B dead tuple mỗi lần, autovacuum thu hồi). Đây là chi phí ghi, không phải dung lượng lâu dài.

**Công thức tăng trưởng** (A = asset mới, J = job, E = outbox event, F = finding, N = kết quả/job):

- metadata/asset = 274 + 3×640 + 422 + 194 + 716 = **3.526 B** (3,44 KiB)
- metadata/job = 1.053 + 3×139 + 1.172 + 143 + 4×355 + 885 = **5.090 B** (4,97 KiB)
- metadata/finding = 503 + 673 + transition/run ≈ **1,4 KB**; số finding = 4% số asset (giả định)
- raw S3 = J × (N × 120 B + 5 KiB) ≤ J × `budget.maxOutputMb` (64 MiB với Subfinder, đo từ manifest)
- graph = A × (15,2 + 34,2 + 141,3 + 9×28,5) ≈ **447 B/asset** (một node, một cạnh, index + property)
- WAL = E × 1.030 B; log = J × 20 KiB; backup full/ngày ≈ kích thước PostgreSQL

**Kịch bản dung lượng** (cùng tham số ở bảng trên):

| Kịch bản | Job | Kết quả/job | Asset | Metadata PG | Raw S3 | Graph | Log | WAL |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 demo G1.5c | 2 | 50 | 100 | 0,34 MiB | 22 KiB | 44 KiB | 40 KiB | 0,1 MiB |
| P2 NFR-01 soak 7 ngày | 1.000 | 500 | 500.000 | **1,65 GiB** | 62 MiB | 213 MiB | 20 MiB | 495 MiB |
| P3 NFR-03 đỉnh 1 giờ | 3.000 | 1.000 | 3.000.000 | **9,9 GiB** | 358 MiB | 1,25 GiB | 59 MiB | 2,9 GiB |
| P4 G4 artifact 10 GB | 1 | — | — | 5 KiB + evidence | **10 GiB** | — | — | — |

**Định cỡ host và điểm nghẽn.** Host đo hôm nay: 56 thread (28 core, Xeon E5-2680 v4), 125 GiB RAM (74 GiB available), 952 GiB đĩa với **188 GiB trống**, load 8–10 do công việc khác trên cùng máy. Kết luận: CPU/RAM không phải giới hạn của GĐ1; thứ tự nghẽn đo được là:

| Điểm nghẽn | Số đo | Nguồn | Hệ quả cho NFR |
| --- | --- | --- | --- |
| Projector M23 (một consumer tuần tự) | **168–175 event/s** = 14,7 triệu event/ngày | G0.3b (14 lần rebuild 149,6–174,6) | P3 cần 833 event/s = **4,9× trần**; 3 triệu event cần 4,9 giờ mới project xong |
| Đường ghi PostgreSQL (counter 0008) | **563 event/s** tx thật, 389 tx/s allocator-only; end-to-end 163,7 event/s (blocking) / 126,7 (try-lock) | G0.3b | P3 833 event/s vượt 1,5×; allocator không phải điểm nghẽn (nextval 1.814 tx/s) |
| Watermark try-lock | 0 event được project trong 11–12 s ghi liên tục; lần đầu 1,07–1,09 s sau khi ngừng ghi | G0.3b §Reading 2 | Đã đóng: [0013](../../contracts/db/postgres/0013_outbox_watermark_blocking.sql) thay try-lock bằng khóa chờ có giới hạn, nên độ tươi graph/UI không còn tụt khi ingestion liên tục (đo lại ở G0.3b) |
| MCP handler (CPU) | 0,52 ms p50, 2,26 ms max; 250–370 `tools/call`/s mỗi process | G0.3a | NFR-04 (100 provider, P95 <300 ms) còn xa; cần ≥2 process khi >300 call/s |
| Neo4j upsert | 473 ops/s (100 key khác nhau); 100 writer cùng key 0,61–0,68 s | G0.3b | Không nghẽn ở 170 event/s |
| Ready-query scheduler | P95 1,09 ms với 5.000 job QUEUED, dùng `scan_job_ready_order` | G0.1 | Queue delay P95 <2 phút không bị query làm nghẽn |

Sandbox: 50 job đồng thời × (1 vCPU, 512 MiB) nếu không có trần manifest sẽ là 50 vCPU/25 GiB — gần hết máy. Trần manifest thực tế (đo: Subfinder `maxConcurrency` 4, DNSx 8) giới hạn GĐ1 còn 12 container, 8 vCPU/4 GiB, nên **NFR-03 50 job đồng thời không thể tạo bằng 2 tool của G1**; phải đo bằng envelope tổng hợp hoặc lùi sang G2.

Dung lượng: một asset chiếm ~8,45 KiB khi tính cả metadata, graph, raw, WAL và một bản backup full (3.526 + 447 + 120 + 1.030 + 3.526). Với 188 GiB trống hiện tại, trần là **~23 triệu asset** (không tính backup: ~39 triệu). Ở tốc độ trần của projector (170 event/s liên tục) mỗi ngày sinh 14,7 triệu asset ≈ 48 GiB metadata + 6,1 GiB graph + 14 GiB WAL, tức **khoảng 3 ngày là hết đĩa** — đĩa là giới hạn thật của chính sách không TTL, không phải RAM/CPU.

**Backlog G1 từ kế hoạch.** 14 card G1 (7 M, 7 L); ước lượng theo S=1, M=3, L=6 person-day (giả định, chưa có số thực tế): **63 person-day**. Đường găng theo đợt: W1 G1.1a (layout, codegen, fakes) → W2 G1.1b/1.1c/1.2a/1.3a/1.4a/1.5b → W3 G1.1d/1.2b/1.3b/1.4b/1.5a → W4 G1.2c → W5 G1.5c; với 2 BE + 1 FE khoảng 7 tuần lịch (giả định). Tải của G1.5c (P1) dưới 1 MB nên sizing không phải rào cản của cổng G1; bài đo tải thật thuộc G4.

**Khoảng trống phải đo trước khi chốt sizing** (chưa có bằng chứng, không suy ra từ bảng trên):

- Raw/artifact thực tế mỗi job (OD-1 lab chưa có): đang dùng trần 64 MiB và giả định 120 B/kết quả.
- Ingestion P95 <30 giây với envelope <1 MB (NFR-04) chưa đo — thuộc G1.4a.
- Graph 1 triệu node (NFR-03/G4) chưa đo; số 447 B/asset là ngoại suy tuyến tính từ 20.000 node.
- Log/trace/OTel mỗi job chưa có pipeline để đo; 20 KiB/job là giả định.
- Projector song song hoặc batch event: chưa có thiết kế; nếu muốn NFR-03 với 1.000 kết quả/job thì phải quyết định granularity event (1 event/asset so với 1 event/lô) — thay đổi contract, không thuộc G0.4d.
- Diễn tập backup/restore và WAL archive chưa chạy; RPO/RTO vẫn là mục tiêu, và archive sẽ nhân đôi phần WAL ở bảng trên.
- Các số đo chạy trên máy chia sẻ với container của worker khác (G0.3b ghi nhận), nên là biên dưới, không phải số tuyệt đối của máy rảnh.

## Phiên agent và bộ nhớ

Một phiên xử lý objective hữu hạn theo vòng BuildContext → Plan → SelectTool → Validate/Dispatch → AwaitResult → Analyze → DecideNext. Agent chỉ nhận objective, cấu hình chạy, tool schema cần thiết và delta/đoạn trích liên quan. Không giữ lịch sử toàn campaign trong prompt.

- Working context là phần dữ liệu giới hạn cho phiên hiện tại. Checkpoint LangGraph gắn session_id; replay dùng lại checkpoint và khóa idempotency.
- Campaign ledger lưu mục tiêu đã xong, giả thuyết còn mở, blocker, job đang chờ, revision/cursor và ngân sách còn lại.
- Tri thức dài hạn nằm ở metadata/graph/S3. Observation cũ vẫn giữ; query đánh dấu stale theo cấu hình trước khi agent dùng để suy luận.
- Registry đưa danh sách tool liên quan theo nhu cầu; không nạp tất cả schema/tool output vào mỗi lượt gọi model.
- Budget gồm token, chi phí model, số job/phiên, thời gian và concurrency. Mã điều phối kiểm budget trước side effect; không ủy thác việc dừng cho prompt.
- Chu kỳ không có bằng chứng mới hữu ích được ghi ledger. `idle_cycles_before_pause` lấy từ execution settings; tới ngưỡng thì pause kèm lý do. Không tự tạo seed mới để tránh điều kiện dừng.

Giữ mặc định thiết kế: khoảng 10–30 observation quan trọng mỗi context, tối đa 30 bước cho một phiên; ngưỡng idle 3–5 chu kỳ theo schema. Planner, Analyst và Verifier là ba trách nhiệm trong phiên agent, không là một hệ phân cấp tác tử. Output suy luận phải qua schema trước khi dùng; số bước/budget/điều kiện dừng do mã cưỡng chế.

Temporal lưu trạng thái điều phối dài hạn; PostgreSQL giữ metadata/query view và lịch sử cần đối soát. Không lấy model conversation làm nguồn trạng thái job. Sau worker restart, đối chiếu job/container hiện có trước dispatch; replay không đồng nghĩa chạy lại scanner. Cách lồng phiên LangGraph và xử lý hủy phải được chứng minh ở spike G0.

## Lỗi, cảnh báo và quan sát

Mỗi lỗi có code, mô tả, nguyên nhân kỹ thuật và next_action theo [error schema](../../../contracts/common/error.v2.schema.json). Không chuyển FAILED thành SUCCEEDED để tiếp tục luồng. Log/event nối campaign_id, session_id, objective_id khi có, job_id, provider/version, cấu hình và trace; evidence dùng reference/hash. Credential vận hành không ghi vào log/trace.

Provider lỗi liên tiếp phải có backoff/circuit breaker và health rõ để tránh retry vô hạn; chỉ thử lại trong giới hạn/cooldown đã cấu hình, không giấu job đang chờ dưới trạng thái thành công.

Theo dõi queue delay, job status/error/retry, ingestion/quarantine, graph lag/conflict, agent turns/tokens/cost, budget còn lại và lần delta hữu ích gần nhất. Dashboard phải drill down về job/evidence. Model lỗi có thể làm phiên suy luận chờ/thất bại; job đã dispatch và việc thu bằng chứng vẫn được điều phối, không phụ thuộc một model call đang sống.

Metric tối thiểu giữ từ thiết kế: agent_turns, tokens, cost, pending_jobs, retry_rate, normalization_errors, graph_upsert_conflicts, scanner_target_rate, policy_denials, mean_time_to_first_finding và scan_novelty. Sáu dashboard: Campaign Overview, Job Map, Knowledge Growth, kiểm đầu vào/giới hạn, AI và Findings; mỗi dashboard dẫn về trace/job/evidence.

## Ranh giới dữ liệu không tin cậy

Tool description, HTTP/README, artifact, stdout và đoạn trích từ graph đều là dữ liệu có nguồn; không được nâng thành system instruction hoặc tự đăng ký tool mới. Parser/validator kiểm hình dạng; mọi side effect vẫn qua registry và runtime. Escape/normalization khi dựng ToolMessage và nhãn UNTRUSTED chỉ hỗ trợ ranh giới này, không là bằng chứng đã ngăn được mọi prompt injection. Raw gốc giữ nguyên ở S3 để đối chiếu.

Phần văn bản không tin cậy đưa vào context được bọc bằng nhãn UNTRUSTED_TOOL_OUTPUT rõ ràng; không trộn vào system instruction. Bọc nhãn không thay parse schema, nguồn gốc hay kiểm side effect bằng mã.

## Kiểm thử, phục hồi và vận hành

Các số RPO/RTO ở trên là mục tiêu thiết kế, chưa phải SLO đã đạt. Capacity, queue delay, độ trễ API/ingestion và concurrency hiệu quả phải đo sau spike trên cấu hình phần cứng/workload xác định; không tái dùng các số benchmark ở nguồn nghiên cứu. Tồn tại schema max concurrency không chứng minh hệ thống chạy được tải đó.

| Nhóm kiểm | Kịch bản và bằng chứng nghiệm thu |
| --- | --- |
| Chuẩn hóa/parser | Fixture domain/IP/URL/pURL, Unicode, mâu thuẫn nguồn, output sai/mất trường, archive lớn; canonical ID không đổi khi replay |
| Adapter/contract | Manifest/input sai bị chặn trước chạy; repeated request chỉ một job; cancel/timeout, parser lỗi và version bump |
| Tích hợp | Seed → discovery → graph; image/SBOM → package/CVE/finding; trace ngược từng kết luận đến raw hash |
| Khôi phục | Worker chết giữa job, Temporal replay, mất graph/feed/model; đối soát container/job, không dispatch trùng hoặc mất evidence |
| Ranh giới | Tool không chạm control/data/socket; redirect, DNS rebinding, IPv4/IPv6, target exclusion, credential cấp sai job, file symlink/zip bomb |
| Agent | Nội dung web/README giả chỉ dẫn, tool metadata sai, schema output model sai; đo tool choice, nguồn trích dẫn, unsupported claims, chi phí và điều kiện dừng |
| Đồng thời | Nhiều writer upsert cùng key, giao dịch rollback/commit đảo thứ tự, duplicate ingestion và cancel/completion cạnh tranh |
| Độ bền MVP | Soak theo cổng G2; báo cáo số bước, workload, restart/lỗi tiêm vào, tài nguyên và tính toàn vẹn |
| Khôi phục dữ liệu | PostgreSQL full/WAL theo backend, Temporal persistence nhất quán; restore metadata, rebuild graph bằng consumer mới, đối soát revision/count và raw SHA-256 |

Cần lab tài sản được phép và bộ fixture cho schema/parser/adapter, có expected output độc lập với parser đang kiểm. Nghiệm thu finding theo quy tắc bằng chứng trong AGENTS. Backup phải có diễn tập restore tối thiểu mỗi quý trước khi coi là khả năng vận hành; lưu cả registry/manifest, cấu hình và secret reference cần phục hồi. Lưu lịch sử lâu dài đòi capacity estimate cho metadata, raw, artifact và log; không tự đưa TTL xóa lịch sử vào hệ thống.

| Sự cố | Hành động và kết quả phải hiển thị |
| --- | --- |
| Agent không tiến triển | Pause, xem last useful delta/ledger/budget/job chờ; ghi blocker và bước tiếp theo |
| Scanner thất bại hàng loạt | Kiểm adapter health, route và tài nguyên; thống kê theo error code, retry có trần |
| Ingestion/graph lỗi | Kiểm record bị quarantine/unique conflict và cursor; replay đúng consumer, đối soát evidence |
| Model rate limit/mất kết nối | Retry/fallback chỉ trong cấu hình dữ liệu/budget cho phép; nếu chưa thể tiếp tục thì chờ hoặc kết thúc phiên kèm lý do |
| Output nghi bị chèn chỉ dẫn | Cách ly record/artifact, audit đường output → parser → context và những job liên quan |
| Mất PostgreSQL/Temporal | Dừng dispatch mới, restore rồi reconcile job/container ngoài workflow; báo recovery point và reference thiếu |

Cổng đưa vào vận hành cần chứng minh private ingress, token dịch vụ/chữ ký task, sandbox limits, image pin và giấy phép, hash/provenance, restart không trùng, budget dừng được, backup/restore và dashboard lỗi. Chưa có các bằng chứng này thì ghi trạng thái chưa đạt; không suy từ một lần validator xanh.

## Cấu hình và bảo vệ dữ liệu vận hành

Credential scanner có thời hạn ngắn và gắn job/mục tiêu; cấp trực tiếp cho sandbox qua secret reference, không dùng secret finding làm credential vận hành ngầm. Dữ liệu lưu trữ và bản backup được mã hóa; chỉ dịch vụ cần thiết được truy cập. Kết nối dịch vụ dùng mTLS hoặc service credential; API thực hiện kiểm CORS và CSRF khi dùng cookie.

Registry/policy khai báo theo GitOps, release có chữ ký và image có SBOM theo quy tắc AGENTS. Nâng tool phải có compatibility test, canary và rollback manifest; chỉ hash file không chứng minh được nguồn phát hành. Cách triển khai các bảo vệ này phải được chứng minh trong môi trường dev/diễn tập, chưa có implementation để nghiệm thu.
