# Interface nội bộ giữa các module

Ngữ nghĩa không phụ thuộc ngôn ngữ; chữ ký viết bằng Python vì backend là Python 3.12. Kiểu dữ liệu sinh từ JSON Schema trong `contracts/` (Pydantic v2 qua `datamodel-code-generator`), không định nghĩa tay lần hai.

Các bản giả trong `tests/fakes/` là đầu ra cần triển khai, chưa có trong repo; dùng chúng để kiểm contract mà không gọi dịch vụ ngoài.

## 1. Adapter SDK (M08–M17)

```python
class Adapter(Protocol):
    def describe(self) -> ProviderManifest: ...                       # không tác dụng phụ
    def validate(self, ctx: TaskContext, input: dict) -> ValidationResult: ...
    def start(self, ctx: TaskContext, task: ApprovedTask, key: str) -> JobHandle: ...  # idempotent theo key
    def status(self, handle: JobHandle) -> JobState: ...              # có retry_after
    def cancel(self, handle: JobHandle) -> CancelResult: ...          # best effort, ghi audit
    def collect(self, handle: JobHandle) -> ResultEnvelope: ...
    def health(self) -> Health: ...
```

Với adapter CLI trong container, lõi sẽ cài `start/status/cancel` qua `ContainerRunner`; tác giả adapter chỉ viết **manifest** và **parser**:

```python
def parse(output_dir: Path, task: ApprovedTask, evidence: list[EvidenceObject]) -> ParsedResults:
    """Hàm thuần: đọc file trong output_dir, trả assets/observations/relationships/findings/coverage.
    Không gọi mạng, không đọc biến môi trường, không ghi DB. Phải tất định: cùng fixture → cùng output."""
```

Conformance test (`contracts/tests/` + `adapters/<m>/<tool>/fixtures/`): manifest hợp lệ, parser chạy trên fixture cho envelope hợp lệ, chạy hai lần cho kết quả giống hệt, mọi predicate có trong registry, mọi canonical_key qua cổng G1.

Bộ kiểm chạy được từ S1.5b: [test_conformance.py](../tests/test_conformance.py) + [conformance/harness.py](../tests/conformance/harness.py) trên fixture Subfinder và DNSx. Nó kiểm bảy handler: `describe` không side effect; `validate` từ chối input sai (INPUT_INVALID) và vượt trần đã pin (POLICY_DENIED) trước khi gọi OSS; `start` idempotent theo key, từ chối manifest pin thiếu (DEPENDENCY_MISSING) hoặc lệch (POLICY_DENIED) trước side effect; `status` có `retry_after` (0 khi terminal); `cancel` best effort, ghi audit, idempotent và job đã huỷ không sinh envelope (EVIDENCE_INCOMPLETE); `collect` dựng envelope đúng fixture `result-envelope.*.json` với evidence sha256 = byte raw, `seed_targets` = `task.targets`, `input_fingerprint` = `aegis-c14n/1` của input đã chấp nhận, parser chạy hai lần giống hệt và replay giữ `payload_hash`; `health` nêu provider version/ảnh đã pin và phụ thuộc, không tra mạng. Negative fixture cấp registry (capability chưa đăng ký, vượt trần manifest/campaign, target kind không nhận, `task.targets` mở rộng, target ngoài campaign, credential trong input, policy snapshot thiếu, `networkAccess` không đủ) nằm ở [conformance/fixtures/policy](../tests/conformance/fixtures/policy). Đây là kiểm contract tham chiếu, không phải runtime; adapter thật thay `FixtureAdapter` nhưng phải qua đúng bộ kiểm này.

## 2. ContainerRunner (M06)

```python
class ContainerRunner(Protocol):
    def run(self, spec: ContainerSpec) -> RunHandle: ...     # idempotent theo spec.job_id (tên container = job_id)
    def inspect(self, handle: RunHandle) -> RunState: ...    # created|running|exited|oom|timeout|missing
    def stop(self, handle: RunHandle, grace_seconds: int = 10) -> None: ...
    def output_dir(self, handle: RunHandle) -> Path: ...     # thư mục kết quả trên máy chạy
    def remove(self, handle: RunHandle) -> None: ...         # xóa container, KHÔNG xóa output (đã chuyển SeaweedFS)

@dataclass(frozen=True)
class ContainerSpec:
    job_id: str; image_digest: str; args: list[str]           # args dựng từ argsTemplate, không shell
    cpu: float; memory_mb: int; timeout_seconds: int
    max_output_bytes: int                                     # bắt buộc, resolve từ manifest đã pin
    network: Literal["exec", "none"]                           # chỉ mạng thực thi hoặc không mạng
    egress_mode: Literal["broker"] | None = None               # từ permissions.egressMode; None khi network=none
    egress_binding: tuple[str, ...] = ()                       # đọc từ task đã ký (E-1), không tính lại
    egress_proxy: str | None = None                           # broker L7 của job (HTTP CONNECT/SOCKS5), do M06 cấp
    raw_socket: bool = False                                   # GĐ1 luôn false: không có egress L3 (G0.2)
    read_only_rootfs: bool = True; user: str = "65534:65534"
    pids_limit: int = 512                                      # chống fork bomb
    max_output_files: int = 50000                              # trần số file output
    seccomp_ruleset: str = "default"                           # hồ sơ seccomp bắt buộc
```

### Manifest bất biến và cấu hình thực thi

ApprovedTask bắt buộc có `adapter_version` và `manifest_sha256`. Hash là SHA-256 của nguyên byte file manifest UTF-8 đã được registry nhận: không parse rồi serialize lại để tính hash. Registry M05 giữ bản manifest bất biến theo hash để job chờ, retry và replay dùng cùng bản, kể cả sau khi triển khai adapter mới. Từ G1.1c registry là bảng `aegis.provider_manifest`: khóa là hash, một `CHECK` chứng minh hash mô tả đúng byte đã lưu, bảng append-only, và cùng `(capability, provider, provider_version, adapter_version)` không được đăng ký hai lần với byte khác.

**Chữ ký (OI-7).** Nội dung được ký = `aegis-c14n/1` của `{"purpose": "aegis.io/approved-task/v2", "signature_key_id": <id>, "task": <task bỏ trường signature và signature_key_id>}`; `signature` = `hmac-sha256:` + hex(HMAC-SHA256(khóa[key id], utf8(nội dung đó))). `signature_key_id` nằm trong nội dung được ký nên không thể đổi khóa của task đã ký. Xoay khóa: thêm khóa mới với id mới, ký task mới bằng khóa đang hoạt động, vẫn verify task cũ bằng khóa cũ; khóa và id là cấu hình của server, không nằm trong task, log hay fixture. M06 lấy task đã ghim (`scan_job.approved_task`), verify HMAC trước khi dựng ContainerSpec, và từ chối khi khóa không có trong ring hoặc chữ ký không khớp.

**Egress binding (E-1).** `egress_binding` của task là tập đích broker được phép mở, do M05 tính và ghim **trong nội dung được ký**: `mode` (`broker|none`), `target_binding` của manifest, `entries` (host:port, đã sắp xếp, đã trừ tập luôn chặn) và `target_addresses` (IP đã phân giải khi `targetBinding=required`; rỗng khi `none`). M06 dùng đúng giá trị này và không tính lại; broker vẫn phân giải lại tên lúc kết nối và từ chối địa chỉ nằm ngoài tập đã ghim. Registry từ chối manifest khai `egressSources` thuộc tập luôn chặn, nên binding không bao giờ chứa đích bị cấm.

M05 resolve manifest, ghép inputDefaults rồi validate input, ghi pin cùng job và ký toàn bộ task trừ trường signature. `manifest_sha256` thuộc dữ liệu được ký. M06 lấy manifest theo hash, tính lại hash và đối chiếu capability/provider/adapter_version/provider_version/image_digest với task. Thiếu bản đã pin thì dừng với DEPENDENCY_MISSING; hash hoặc định danh không khớp thì POLICY_DENIED. Không thay bằng manifest latest hay defaults của bản triển khai mới. [Kiểm conformance offline](../tests/manifest_binding.py) kiểm pin/định danh; chưa phải mã executor hay kiểm HMAC runtime.

| ContainerSpec | Nguồn cấu hình |
| --- | --- |
| image_digest, args | runtime.imageDigest và argsTemplate của manifest đã pin; chỉ chèn input đã được M05 kiểm |
| args rendering | Mỗi phần tử `argsTemplate` là literal hoặc **đúng một** `${input.<field>}` chiếm trọn phần tử: không nối chuỗi, không hai placeholder trong một phần tử, không shell/quoting. Trường được chèn chỉ là `integer`/`number`/`boolean`, chuỗi có `enum`, hoặc mảng các kiểu đó — chuỗi tự do bị từ chối vì giá trị `-rf` sẽ thành cờ. Mảng render thành một argv element cho mỗi item theo thứ tự input (không join, không tách theo dấu phẩy). Literal được bắt đầu bằng `-`; giá trị được chèn không thể, vì kiểu trên không sinh ra dấu `-` đầu chuỗi. Runtime kiểm lại cùng luật trước khi chạy; sai thì POLICY_DENIED, không tự sửa argv. |
| cpu, memory_mb, timeout_seconds | budget.cpu, memoryMb, timeoutSeconds |
| max_output_bytes | budget.maxOutputMb × 1048576; thiếu maxOutputMb dùng 256 MiB theo manifest schema |
| network | permissions.networkAccess none → none; egress → exec (mạng nội bộ của job, không DNS ngoài) |
| egress_mode, egress_proxy | permissions.egressMode (GĐ1 chỉ `broker`); M06 cấp proxy/http_proxy cho container, broker là peer duy nhất trên mạng của job |
| egress_binding | Đọc từ ApprovedTask đã ký (`egress_binding`), M06 không tính lại (E-1); M05 đã phân giải target thành IP/port đã kiểm rồi hợp với permissions.egressSources và trừ tập luôn chặn. Broker chỉ mở tới tập này, đích ngoài tập bị từ chối kèm lý do |
| raw_socket | GĐ1 cố định false: manifest schema chỉ nhận `rawSocket: false` vì chưa có egress L3 (G0.2) |
| user/rootfs/PID/file/seccomp | Giới hạn cố định của ContainerSpec ở trên; runtime không đáp ứng thì không dispatch |

policy_version trỏ snapshot cấu hình campaign bất biến để kiểm budget/rate/khung giờ; pin manifest không thay kiểm đó. Job mới lưu manifest_sha256 trong PostgreSQL. Job lịch sử chưa có pin trả null ở API và không được dispatch/replay trước khi được chuyển đổi riêng; không tạo hash giả cho dữ liệu cũ. Semantics idempotency lookup phải giữ lại quyết định/task đã chấp nhận, không resolve manifest mới cho retry.

Bản cài đặt GĐ1: `PodmanRunner` (rootless, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, `--pids-limit`, seccomp, không mount socket, mỗi job một mạng riêng).

**Sandbox collector/parser.** Output của scanner là dữ liệu thù địch. Collector M06:
- Chỉ xử lý **file thường**; **không đi theo symlink**, bỏ qua FIFO/socket/thiết bị. Từ chối job nếu `output_dir` vượt `max_output_bytes`/`max_output_files`.
- Chạy `parse()` trong **tiến trình con tách biệt, không mạng, không credential, không biến môi trường kế thừa**, có trần CPU/RAM/thời gian riêng; lỗi parser không được làm sập tiến trình lõi.
- `parser.entrypoint` của manifest phải khớp mẫu `adapters.<module>.<tool>:<func>` (không import tùy ý).

## 3. Evidence collector (M06 → M28)

Container **không** chạm SeaweedFS (mạng thực thi không vào được mạng dữ liệu). Sau khi container kết thúc, collector trong mạng điều khiển:

1. Tính SHA-256 từng file thường trong `output_dir` (không theo symlink, có trần kích thước và số file — xem mục 2 sandbox), gọi `EvidenceStore.put(campaign_id, job_id, file)` → `s3://evidence/{campaign_id}/{job_id}/{sha256}` (object lock).
2. Chạy parser của adapter trong tiến trình con không mạng, không credential → `ParsedResults`.
3. Dựng `ResultEnvelope` và `POST /api/v2/ingestion/results`. `event_id` là UUIDv7 mới mỗi lần nộp; `dedup_key` = `"job:<job_id>:envelope"` (xác định từ job_id) để retry không nhân bản.

Parser thuần không đọc đồng hồ; collector gán `observed_at` theo thời điểm thu và đặt `provenance.seed_targets` bằng nguyên `targets` của ApprovedTask, `provenance.input_fingerprint` bằng sha256 `aegis-c14n/1` của input đã chấp nhận. `coverage.subjects` chỉ chứa asset thực sự được kiểm; seed chưa thành asset ở `seed_targets`. Pin provider trong envelope phải khớp task đã pin.

Object store dùng SeaweedFS qua S3. Collector có đường tải raw lên kho; scanner chỉ ghi output_dir.

## 4. EvidenceStore (M28)

```python
class EvidenceStore(Protocol):
    def put(self, campaign_id: str, job_id: str, path: Path, media_type: str,
            classification: Classification) -> EvidenceObject: ...  # idempotent theo sha256
    def signed_url(self, evidence_id: str, ttl_seconds: int = 300) -> str: ...
    def excerpt(self, evidence_id: str, offset: int, max_bytes: int) -> Excerpt: ...  # ≤ 8 KiB
    def verify(self, evidence_id: str) -> bool: ...                 # đọc lại, so sha256
```

## 5. ModelClient (M04)

Hình dạng là contract, không định nghĩa DTO tay lần hai: [message](../agent/model-message.v2.schema.json) (content block, tool call/result), [request](../agent/model-request.v2.schema.json), [response](../agent/model-response.v2.schema.json). Chữ ký Python dưới đây chỉ để đọc.

```python
class ModelClient(Protocol):
    async def complete(self, req: ModelRequest, budget: Budget) -> ModelResponse: ...
    # BudgetExceeded khi ngân sách chiến dịch hết trước lời gọi; không gọi model.

@dataclass(frozen=True)
class ModelRequest:              # model-request.v2
    provider: Literal["openai", "anthropic"]; model: str
    messages: list[Message]      # system/user/assistant/tool
    tools: list[ToolSpec] = field(default_factory=list)
    response_schema: dict | None = None   # JSON Schema đích; driver structured output rồi kiểm
    campaign_id: str; session_id: str; trace_id: str
    max_output_tokens: int; timeout_seconds: float = 120

@dataclass(frozen=True)
class ModelResponse:             # model-response.v2
    provider: Literal["openai", "anthropic"]; model: str
    message: Message | None      # assistant; vắng chỉ khi provider_error
    parsed: dict | None          # chỉ khi finish_reason=completed
    finish_reason: FinishReason  # completed|tool_calls|truncated|refused|invalid_output|provider_error
    provider_meta: ProviderMeta  # response_id/model_version/raw_finish_reason
    usage: Usage                 # input/output tokens, cost_usd, latency_ms
    error: Error | None          # bắt buộc khi provider_error
```

`Budget` là ngân sách còn lại của campaign lấy từ snapshot policy_version; không nằm trong request.

- Message giữ content block có kiểu: `text`, `tool_call` (`id`, `name`, `arguments` đã parse, `arguments_raw` nguyên văn của provider) và `tool_result` (`call_id` = `tool_call.id`; thiếu tool_call tương ứng thì từ chối). Hai driver map role/system/tool block sang dạng dây OpenAI/Anthropic nhưng gửi lại đúng id, name và arguments/arguments_raw, nên hai vòng tool call trở lên không đổi định danh hay nội dung.
- Chuẩn hóa finish: openai `stop`→completed, `tool_calls`→tool_calls, `length`→truncated, `content_filter`→refused; anthropic `end_turn`→completed, `tool_use`→tool_calls, `max_tokens`→truncated, `refusal`→refused. Output không parse hoặc không qua `response_schema` → invalid_output; lỗi transport/HTTP hoặc không có nội dung dùng được → provider_error. `tool_calls` phải có ít nhất một tool_call; `completed` không có tool_call; refused/truncated/invalid_output/provider_error không có `parsed`. Văn bản và đối số thô vẫn nằm trong message; riêng provider_error không có message nên raw provider phải giữ ở log/trace.
- Hai driver: `OpenAIChatDriver` (Chat Completions) và `AnthropicMessagesDriver` (Messages). Endpoint, base_url, bảng giá và giới hạn thực thi nằm trong cấu hình triển khai; cấu hình cũng giữ danh sách fallback có trần. Kiểm ngân sách chiến dịch trước lời gọi trong mã; vượt thì ném `BudgetExceeded`, ghi `model_usage.status=budget_denied` và không gọi provider.
- Retry/fallback: chỉ fallback khi `provider_error`, chỉ khi cấu hình có fallback và policy dữ liệu cho phép; số lần thử bị chặn bởi cấu hình. Refusal/invalid_output/truncated không được fallback để che lỗi dữ liệu, trả nguyên finish cho M03 xử lý. Mỗi lời gọi (kể cả fallback) ghi một dòng `model_usage` với trạng thái `ok|error|fallback|budget_denied` cùng provider/model/token/cost/latency/trace.

## 6. Ingestion API (M27) nội bộ

```python
class Ingestion(Protocol):
    def submit(self, envelope: ResultEnvelope) -> IngestReceipt: ...
    # IngestReceipt sinh từ ingest-receipt.v2.schema.json; không viết lại DTO thủ công.
```

Nguồn duy nhất cho receipt là [IngestReceipt](../ingestion/ingest-receipt.v2.schema.json); OpenAPI dùng cùng $ref. Mỗi phần tử quarantined có pointer, gate và reason.

Trình tự trong **một giao dịch** PostgreSQL: đối chiếu inbox theo dedup_key/payload_hash và event_id lần nộp → G1–G7 → upsert asset/alias → insert observation/relationship/finding_candidate → insert outbox_event → commit. Projector Neo4j chạy sau commit. Hash/receipt đã khóa theo [C03](../../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c03--idempotency-hash-và-receipt) (0006, `aegis-c14n/1`); vòng đời kết quả theo C06 (0007) cùng nguồn.

## 7. Temporal (M02) và Activity

| Thành phần | Tên | Đầu vào → đầu ra |
| --- | --- | --- |
| Workflow | `CampaignWorkflow` | `campaign_id` → kết thúc với `CampaignStatus` |
| Signal | `pause`, `resume`, `cancel`, `job_completed(job_id, status)`, `knowledge_delta(revision)` | |
| Query | `status() -> {state, cycle, pending_jobs, last_revision, idle_cycles}` | |
| Activity | `fetch_delta(campaign_id, cursor) -> ContextBundle` | idempotent, chỉ đọc |
| Activity | `run_agent_session(ContextBundle) -> AgentSessionResult` | idempotent theo session_id (checkpoint LangGraph) |
| Activity | `cancel_jobs(campaign_id)` | |
| Activity | `publish_snapshot(campaign_id)` | |

Workflow ID = `campaign-<campaign_id>`. Task queue: `aegis-orchestrator`, `aegis-agent`. Continue-As-New sau 500 chu kỳ hoặc khi history > 10 MB, mang theo `cursor`. Dispatcher outbox gửi signal `job_completed` khi gặp `job.completed.v2`.

`run_agent_session` phải heartbeat và phải đặt `cancellation_type=WAIT_CANCELLATION_COMPLETED` cùng `heartbeat_timeout` hữu hạn (G0.1 dùng 3 s, poll trạng thái job ≤ 1 s); mặc định `TRY_CANCEL` bỏ activity đang chờ, nên phần dọn checkpoint và lý do dừng phiên bị mất. Hủy activity trả về failure canceled, không phải `asyncio.CancelledError` (memo: `spikes/g0.1-temporal-langgraph/DECISION.md` ở nhánh `spike/g0.1-temporal-langgraph@8c20a1e`).

Phiên M03 (G1.2c) chạy vòng `BuildContext → Plan → SelectTool → Dispatch → AwaitResult → Analyze → DecideNext` trong activity, mỗi nút một checkpoint; các ràng buộc dưới đây là phần thực thi của interface, không phải lời khuyên:

- `agent_session` là authority: M03 tạo hàng `RUNNING` (objective dùng chung của chiến dịch, `revision_from = cursor`) **trước** lời gọi MCP đầu tiên; liên kết bền giữa nhãn phiên của M02 (`<campaign_id>:cycle-<n>`, không phải `Id`) và `session_id` UUIDv7 nằm ở `campaign_ledger` `cycle_started`, nên activity chạy lại không mở phiên thứ hai và `run_agent_session` idempotent theo `session_id`.
- Không có đường dispatch thứ hai: chỉ `tools/call` trên biên MCP (M05) tạo job; lựa chọn của model bị kiểm với `tools/list` của chính phiên và schema input đã công bố, `objective_id` do phiên gán, từ chối mang mã `error.v2` và không được dispatch. `requested_jobs` trong `AgentSessionResult` chỉ chứa id job đến từ MCP.
- Budget bước/chi phí/token và trần số job do mã cưỡng chế (M04 từ chối trước lời gọi provider); dừng phiên ghi `stop_reason` theo `session-result.v2` (`budget_exhausted`/`step_limit`/`objective_met`), còn "không có bằng chứng mới" trả `decision=wait` với `idle` để M02 tự pause kèm lý do theo `budget.idle_cycles_before_pause` — phiên không tự pause campaign.
- Kết quả job không đến trong cùng phiên: MCP nhận job không đồng bộ, M02 chờ `job_completed` rồi mở phiên kế tiếp; `AwaitResult` chỉ thu câu trả lời MCP (gửi lại **cùng** idempotency key nếu câu trả lời bị mất, nên vẫn một job).

## Scheduling

ApprovedTask chứa priority và depends_on do M05 chuẩn hóa. Dependency cùng campaign, không self/cycle; chỉ SUCCEEDED giải phóng job. Sort ready jobs theo priority DESC, created_at ASC, job_id ASC. M06 kiểm chữ ký task và cấu hình sandbox, không tự bỏ dependency. Priority/dependency bất biến sau acceptance.

Cách M02 ghi quyết định (G1.1d): job được dispatch bằng transition `QUEUED → VALIDATING` cùng một dòng `job_status_change`, trong giao dịch đã khóa campaign; M06 nhận job `VALIDATING`, chuyển `DISPATCHED`/`RUNNING` và là bên duy nhất terminal hóa qua `aegis.record_job_callback`. `attempt` chỉ tăng khi dispatch lại một job chưa terminal (0007). Thứ tự cổng: dependency (`DEPENDENCY_FAILED` trước `DEPENDENCY_PENDING`) → `CAMPAIGN_PAUSED` → `BUDGET_EXHAUSTED` (ngân sách thời gian `max_duration_hours`; token/chi phí là M04, số job là M05) → `WINDOW_CLOSED` → `CONCURRENCY_LIMIT` → `RATE_LIMITED`; job có `dispatch_block_reasons` bị loại khỏi hàng đợi chứ không nhận lý do. `wait_reason` giữ nguyên `since` khi lý do không đổi. Dispatcher outbox gửi signal `job_completed` khi đọc `job.completed.v2` theo C04 (0008 + 0013: lease/fence, watermark refresh trong transaction ngắn riêng); nó phải đặt `statement_timeout` và `idle_in_transaction_session_timeout` (R-6) để không giữ khóa publication sau mỗi lần refresh.

## Phần cần khóa của ModelClient và severity — C07

Đã khóa ở S1.4 bằng contract và suite offline `contracts/tests/test_model_client.py` (hành vi tham chiếu: `contracts/tests/model_client_ref.py`); chưa có LLM thật.

- Message/ToolCall/ToolResult: [model-message.v2](../agent/model-message.v2.schema.json) định nghĩa content block, liên kết tool_result → tool_call.id và round-trip `arguments_raw`; [model-request.v2](../agent/model-request.v2.schema.json) và [model-response.v2](../agent/model-response.v2.schema.json) giữ metadata provider và finish chuẩn hóa. Suite kiểm hai vòng tool call cả hai provider, output sai schema, cắt, refusal, hết ngân sách trước lời gọi, fallback trong cấu hình, và orphan/duplicate tool_result.
- Severity: mỗi bản ghi có `trigger` (`scan|intel_revision|operator_request|verification`), `input_revision` và `dedup_key = severity:<finding_id>:<input_revision>`; cùng finding và cùng revision trả bản ghi đã có, không gọi model lại, nên đánh giá lại phải có đầu vào mới. `assessed_by`/`inputs`/`trigger`/`input_revision`/`dedup_key` do mã gán; model chỉ sinh phần `$defs/ModelOutput` rồi mã kiểm nguồn trích dẫn.
- Fallback khi đánh giá thất bại: bản ghi mới `severity=UNRATED`, `failure` (mã lỗi theo error.v2, attempt, finish_reason/provider/model/session khi có lời gọi) và `raw_signals` trỏ finding/finding_source/evidence/intel đã lưu; cấm `source_refs` nên không dựng nguồn giả. Không có `failure` thì `source_refs` bắt buộc. Bảng append-only: bản ghi cũ không đổi, severity cũ không được trình bày như kết quả mới. Hết ngân sách trước lời gọi vẫn tạo UNRATED với `failure.code=POLICY_DENIED`.
- Ngoài phạm vi S1.4: streaming, content ảnh, block `thinking`/signature của extended thinking (provider trả block lạ bị đánh dấu invalid_output thay vì bỏ im lặng), bảng giá token (cấu hình triển khai) và runtime M04/M20 thật. Các test/fake này chưa phải implementation đã có trong repo.
