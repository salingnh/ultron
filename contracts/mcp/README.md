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

capability-response.v2 trả job_id hoặc lỗi có next_action. ResultEnvelope.v2 do collector nộp M27; agent đọc kết quả qua query tools. Output luôn là dữ liệu không tin cậy. AgentSessionResult chỉ trả requested_jobs đã gửi qua MCP; M02 chờ các ID đó, không nhận danh sách proposals để dispatch lại. Semantics late-result/idempotency hash đã khóa ở C03/C06 (0006, 0007); runtime implementation vẫn thuộc G1.2a — schema tồn tại không chứng minh dispatch đã chạy.

## Spike G0.3a — Streamable HTTP, `_meta`, idempotency (kết quả đo)

Spike dùng Python `mcp` 2.3.0 (lowlevel `Server` + `streamable_http_app`, protocol 2025-11-25); code ở nhánh `spike/g0.3-mcp@6372e4c` và không merge. Registry giả trong bộ nhớ 100 provider, không PostgreSQL; số đo ở `spikes/g0.3-mcp/benchmarks/latency.json`, `session-concurrency.json` trên nhánh đó.

Đã xác minh trên wire:

- `_meta`: khóa `aegis.io/*` của bảng trên đọc được nguyên vẹn ở handler; không đổi wire key. Thiếu/sai key trả `error.code=-32602` với `error.data` là `error.v2` đầy đủ: `code=INPUT_INVALID`, `field` là JSON Pointer RFC 6901 (`/_meta/aegis.io~1trace_id`), `next_action=FIX_INPUT`, kèm `trace_id`. Thiếu cả `_meta` thì báo đủ bốn key thiếu. Key ngoài namespace (ví dụ `progressToken`) được bỏ qua; key lạ trong `aegis.io/` bị từ chối.
- `tools/list`: `inputSchema` phải tự chứa vì client không có bundle; `$ref` tương đối không dùng được. Server resolve mọi ref vào `$defs` của từng tool và thay `properties.input` bằng schema capability. Validator phải compile một lần cho mỗi schema: compile lại mỗi lời gọi tốn ~18 ms, sau khi cache còn 0,52 ms.
- Ngữ cảnh session: server bind `Mcp-Session-Id` với campaign/agent session phía server; `_meta` chỉ được đối chiếu với ngữ cảnh đã bind, khác campaign/session trả INPUT_INVALID. `_meta` không cấp quyền.
- `tools/call`: merge default (priority 50, depends_on [], default của capability) rồi mới validate; sai schema trả -32602 với `field` trỏ `/arguments/...`; thiếu provider hoặc quyết định registry trả kết quả `isError=true` kèm `capability-response.v2` (`decision=denied`).
- Idempotency theo `(campaign_id, idempotency_key)`; khóa coi là opaque 8..128 ký tự `[A-Za-z0-9._:-]`, quy ước `<session_id>:step:<n>` chỉ ràng buộc phía client. Cùng khóa cùng fingerprint theo [canonicalization.v2.yaml](../ingestion/canonicalization.v2.yaml) → `duplicate` kèm đúng `job_id`; cùng khóa khác fingerprint hoặc khác priority/depends_on → xung đột: `isError=true` với `capability-response.v2` (`decision=denied`) và `error.v2` `IDEMPOTENCY_CONFLICT`, không phải lỗi giao thức (`field` chỉ dành cho INPUT_INVALID nên khóa được nêu trong `message`). 100 lời gọi đồng thời cùng khóa tạo đúng 1 job; đối chứng bỏ lock tạo nhiều job nên test phát hiện được thiếu unique index.
- Latency (100 provider, loopback, 500 lượt mỗi cảnh HTTP): handler `tools/call` P95 0,62 ms; thêm 5 ms ghi registry giả → 6,14 ms; HTTP JSON P95 3,64 ms; SSE 5,54 ms; `tools/list` 4,32 ms. Mục tiêu registry P95 <300 ms đạt ở tầng MCP với registry giả, **chưa** chứng minh cho M05 thật — phải đo lại ở G1.1c/G1.2b với PostgreSQL. Đường handler nghẽn CPU (~250–370 `tools/call`/s mỗi tiến trình; 50 request đồng thời không tăng thông lượng), nên sizing dùng nhiều process.

Còn mở:

- Spike mới đo với fingerprint rút gọn; G1.2b phải băm đúng định nghĩa aegis-c14n/1 trong [canonicalization.v2.yaml](../ingestion/canonicalization.v2.yaml) (`policy_version`, `target_refs`) và trả `IDEMPOTENCY_CONFLICT` thay cho `INPUT_INVALID` mà spike tạm dùng.
- `scan_cycle` không có trong bảng `_meta`; spike lấy từ ngữ cảnh session phía server. G1.1c/G1.2b phải chốt khi nào agent bắt đầu `scan_cycle` mới (nay chỉ quy định "lần quét mới có scan_cycle mới").
- `capability-response.v2` không trả lại idempotency key/scan_cycle; agent đối chiếu qua `job_id`. Cân nhắc khi schema response được mở lại.

## G1.2b — triển khai (Streamable HTTP, session, `graph.*`)

`src/aegis/m05_registry/mcp/` hiện thực phần trên bằng `mcp` 2.3.0 (lowlevel `Server` +
`streamable_http_app`, JSON response mặc định). Entry point: `uvicorn aegis.m05_registry.mcp.main:app`.
Service tách khỏi transport (`service.py`) để test chạy đúng đường thật của handler.

- **`tools/list`**: nguồn lọc là **binding của transport**, không phải `_meta`: khi `Mcp-Session-Id`
  đã bind vào một cặp campaign/agent session thì danh sách lọc theo `capability_denylist` của campaign
  đó, kể cả khi lời gọi không gửi `_meta`. Chỉ transport chưa bind và không có khóa `aegis.io/*` nào
  mới nhận danh mục capability đã đăng ký (không lọc) — nhánh này cho chính SDK: client gọi
  `tools/list` chỉ với envelope `_meta` để đối chiếu `outputSchema` trước khi trả kết quả; nó không
  mở rộng quyền gọi. Transport chưa bind mà gửi `_meta` có namespace `aegis.io/` nhưng thiếu/sai thì
  vẫn `-32602`, không lặng lẽ bỏ lọc.
- **Session**: `Mcp-Session-Id` bind đúng một cặp `(campaign, agent_session)`; nguồn quyền là hàng
  `agent_session` (0001) và session phải `RUNNING` (đọc lại mỗi lần bind, không cache trong process
  quá một lần gọi). `objective_id` trong arguments phải trùng objective của session khi session có
  objective.
- **`scan_cycle`**: không có khóa `_meta` nên G1 lấy `scan_cycle = agent_session.session_id`: một
  session là một lần quét, retry trong session trùng đúng job cũ, restart của cùng session resume
  được; lần quét mới = session mới cho tới khi contract mở khóa riêng. (Đóng mục còn mở của spike
  cho G1; nếu G1.2c cần nhiều cycle trong một session thì phải sửa contract trước.)
- **Actor**: `requested_by` là operator đã khởi động run hiện tại của campaign (actor của lần chuyển
  `RUNNING` gần nhất, không có thì `campaign.created_by`), `proposed_by = {kind: agent, id: <session>}`
  do M05 gán từ session đã bind; cả hai nằm trong ApprovedTask đã ký. Đường MCP không có credential
  operator nên M05 tự suy `requested_by` từ dữ liệu campaign (OI-4/C05); id `module` chỉ dành cho job
  do module khởi động, agent chỉ là người đề xuất.
- **E-4 khoá idempotency theo session**: `policy_decision` ghi `session_id` của người đề xuất; một
  caller khác (session khác, hoặc REST không có session) dùng lại cùng key nhận
  `IDEMPOTENCY_CONFLICT` (`isError=true`, không có `field`) và không nhận job đó. Trùng fingerprint
  của cùng một phép quét vẫn trả `duplicate` như contract (NFR-02), kể cả khi do session khác gửi.
- **`graph.*`**: schema lấy nguyên từ `graph-queries.v2`, giới hạn do server áp (2 bước nhảy, 200 bản
  ghi, 2000 ms, 8192 byte) và `limits_applied` là trần hiệu lực của lần gọi (client xin nhỏ hơn thì
  ghi giá trị nhỏ hơn); `truncated` do M23 trả. `campaign_id` trong input phải trùng campaign đã bind.
  Chưa có M23 (G1.4b) nên provider mặc định trả `isError` `DEPENDENCY_MISSING`/`ESCALATE`, **không**
  trả trang rỗng: `truncated=false` với 0 bản ghi là khẳng định "không có gì", sai về một thành phần
  chưa tồn tại.
- **Lỗi**: `_meta`/schema sai → `-32602` + `error.v2` (HTTP 400 ở tầng transport 2.3.0); quyết định
  registry/policy và xung đột idempotency → `isError=true` + `capability-response.v2`, `field` chỉ có
  ở `INPUT_INVALID`. Xung đột giờ là `IDEMPOTENCY_CONFLICT` (đóng mục còn mở của spike).
