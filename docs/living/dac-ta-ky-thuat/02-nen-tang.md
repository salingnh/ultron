# Nền tảng thực thi

## Mạng

Control: API, Temporal worker, LangGraph worker, MCP, collector, ingestion. Data: PostgreSQL, Neo4j, S3, Temporal persistence. Execution: container tool theo job. UI vào private ingress/VPN. Tool không truy cập control/data network; collector tại control gửi kết quả.

Temporal UI có sẵn dùng debug nội bộ ở control plane; UI nghiệp vụ vẫn do M26 phục vụ.

## Sandbox

Podman rootless trên một máy, một invocation một container, image pin digest. Không privileged/host network/socket; drop toàn bộ Linux capability, no-new-privileges và seccomp. Filesystem read-only trừ /out; CPU/RAM/PID/timeout/output limits cụ thể. Network none hoặc egress; cấu hình egress chặn hạ tầng nội bộ của nền tảng. NET_RAW chỉ cấp khi scanner cần và có test. Timeout/cancel phải dừng container, thu output còn lại rồi remove container; không xóa evidence và không để container tự restart ngoài điều phối.

Input có kiểu, không command tùy ý. Credential vận hành được cấp riêng tới sandbox; không vào context agent. Tool output không tin cậy. Collector kiểm file thường, không symlink, áp trần; parser không mạng/credential, tiến trình riêng.

Giữ giới hạn egress theo provider: chỉ kết nối mục tiêu của job và nguồn dữ liệu provider khai báo, ngoài ra mặc định chặn. Phải kiểm cả DNS/redirect và địa chỉ IPv4/IPv6 sau phân giải; việc không dùng allowlist phạm vi không bỏ giới hạn mạng của sandbox. Hình dạng declared sources/target binding và cơ chế cưỡng chế còn cần khóa ở S1.5, chưa được coi networkAccess=egress là đã chứng minh hạn chế đích kết nối.

## Điều phối

Temporal chứa ID/reference, không raw lớn. Activity idempotent; retry có giới hạn. Pause/resume/cancel lưu lịch sử. Scheduler lấy ready jobs (dependency thành công, đủ ngân sách/khung giờ/rate/concurrency), sắp priority DESC, created_at ASC, job_id ASC. Dependency thất bại làm job chờ có lý do; không tự bỏ dependency.

Chờ signal job/tri thức hoặc timer, không busy polling. Pause chặn dispatch mới, giữ/thu job đang chạy theo snapshot; cancel chuyển intent tới worker và đối soát kết quả theo C06. Khi kết thúc campaign phải có snapshot cuối và lý do dừng. Allowed/blackout windows là tùy chọn: không cấu hình thì không tự thêm khung giờ; đã cấu hình thì phải cưỡng chế trước dispatch.

## Model

ModelClient nhận provider/model cấu hình trực tiếp, token/time/cost limits cụ thể; kiểm policy dữ liệu trước fallback. Log model/version/token/cost và session/campaign. Cấu hình model không tạo nhóm quyền chạy tool. Chi tiết round-trip tool call và xử lý lỗi còn cần khóa theo backlog.

Endpoint tương thích OpenAI/Anthropic có thể local hoặc cloud do vận hành cấu hình. Giữ D20: đổi model không tự tạo replay/quét lại; lịch sử assessment/FindingRun dùng để đối chiếu thay đổi đánh giá. Model lỗi không ngăn người vận hành gửi job scanner xác định qua API/MCP với các kiểm thông thường; agent có thể chờ nhưng job đã nhận và thu bằng chứng vẫn tiếp tục.

## Lưu trữ và vận hành

PostgreSQL nguồn metadata; Neo4j projection; S3 raw theo SHA-256. Giữ mục tiêu RPO PostgreSQL 15 phút, RTO 2 giờ, graph/raw RPO 1 giờ như mục tiêu kỹ thuật chưa có diễn tập chứng minh. Backup/restore kiểm checksum và số bản ghi. Outbox at-least-once, consumer idempotent; thuật toán thứ tự commit đang là finding mở, không dùng seq liền mạch làm bằng chứng đã đúng.

OTel: trace, log, metric; mọi job có campaign/tool/version/actor/rationale. UI cho biết lỗi và phần chưa hoàn tất. Dữ liệu lớn dùng reference và pagination.

Kế hoạch backup giữ PostgreSQL full hằng ngày/WAL liên tục, graph backup/snapshot/export, S3 versioning/replication hoặc bucket backup và Temporal persistence nhất quán theo backend. Các phương án cụ thể phải được kiểm ở môi trường vận hành; không coi một file cấu hình backup là bằng chứng đạt RPO/RTO.

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
