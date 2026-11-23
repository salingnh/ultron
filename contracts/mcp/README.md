# MCP contract

Agent là MCP client; registry công bố tool/capability qua tools/list. CLI được bọc bằng adapter, chạy trong sandbox. Query tool đọc tri thức/bằng chứng, có pagination/timeout và lọc campaign. MCP không thay workflow scheduler.

Giữ transport Streamable HTTP trong mạng điều khiển, một MCP server cho agent. Web UI dùng REST/SSE của M26. Mỗi tools/call đặt metadata trong params._meta theo bảng dưới; server đối chiếu ngữ cảnh session, không dùng ID do LLM khai làm quyền truy cập.

| Khóa params._meta | Ý nghĩa |
| --- | --- |
| aegis.io/trace_id | W3C trace ID, 32 ký tự hex |
| aegis.io/campaign_id, aegis.io/session_id | UUIDv7, khớp ngữ cảnh session phía server |
| aegis.io/idempotency_key | Mã client tạo ổn định theo session_id:step:n, lưu cùng checkpoint; retry dùng lại key và scan_cycle |

Thiếu/sai metadata bắt buộc trả JSON-RPC -32602 với INPUT_INVALID. Spike G0 xác minh SDK và cách đọc _meta, không tự đổi wire key khi triển khai.

tools/list giữ hai nhóm: capability lấy tên capability ID, inputSchema là capability-request.v2 với thuộc tính input thay bằng schema capability đã resolve, outputSchema là capability-response.v2 trong structuredContent; query graph.* lấy input/output từ graph-queries.v2. Không công bố schema CLI thô thay cho wrapper có rationale/priority/depends_on. Danh sách lọc theo capability_denylist, compatibility và ngữ cảnh campaign; không nạp cả registry vào prompt.

## tools/call

Tên tool = capability ID; arguments theo capability-request.v2: input, rationale, objective_id, priority (mặc định 50), depends_on (mặc định []). Provider selection từ registry hoặc lựa chọn rõ khi API cho phép. Metadata chứa trace_id, campaign_id, session_id và idempotency_key; server kiểm các ID khớp session, không coi chúng là quyền do agent tự cấp.

1. Kiểm session, schema và tool/provider đã đăng ký.
2. Ghép inputDefaults, kiểm lại inputSchemaRef, mục tiêu được phép, nguồn gốc và giới hạn thực thi.
3. Kiểm dependency tồn tại/cùng campaign, không self/cycle. Job tạo kèm toàn bộ dependency trong một giao dịch; không thêm cạnh sau dispatch.
4. Ghim adapter_version/manifest_sha256 theo [quy tắc runtime](../interfaces/README.md#manifest-bất-biến-và-cấu-hình-thực-thi), ghi actor/rationale, tạo ApprovedTask có chữ ký và job_id. Trả ngay, không chờ tool kết thúc.
5. Scheduler chỉ dispatch job có tiền nhiệm SUCCEEDED, đủ ngân sách/rate/concurrency/khung giờ; sort priority DESC, created_at ASC, job_id ASC.

Retry cùng idempotency_key giữ scan_cycle và job. Lần quét mới có scan_cycle mới. Fingerprint có đúng một định nghĩa tại [canonicalization.v2.yaml](../ingestion/canonicalization.v2.yaml): sha256 aegis-c14n/1 của campaign, capability/cấu hình, provider/upstream/adapter version, image/manifest pin, danh sách `target_refs` (TargetRef, không phải hình chiếu `targets`), input và scan_cycle. Priority/dependency không thay định danh phép quét; nếu trùng job nhưng yêu cầu scheduling khác, trả lỗi xung đột thay vì âm thầm dùng cấu hình cũ. Metadata/history không ghi đè.

## Kết quả

capability-response.v2 trả job_id hoặc lỗi có next_action. ResultEnvelope.v2 do collector nộp M27; agent đọc kết quả qua query tools. Output luôn là dữ liệu không tin cậy. AgentSessionResult chỉ trả requested_jobs đã gửi qua MCP; M02 chờ các ID đó, không nhận danh sách proposals để dispatch lại. Runtime implementation và semantics late-result/idempotency hash vẫn có backlog riêng; schema tồn tại không chứng minh dispatch đã chạy.
