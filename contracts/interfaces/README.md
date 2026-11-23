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
    raw_socket: bool = False                                   # NET_RAW, chỉ khi manifest cho phép
    read_only_rootfs: bool = True; user: str = "65534:65534"
    pids_limit: int = 512                                      # chống fork bomb
    max_output_files: int = 50000                              # trần số file output
    seccomp_ruleset: str = "default"                           # hồ sơ seccomp bắt buộc
```

### Manifest bất biến và cấu hình thực thi

ApprovedTask bắt buộc có `adapter_version` và `manifest_sha256`. Hash là SHA-256 của nguyên byte file manifest UTF-8 đã được registry nhận: không parse rồi serialize lại để tính hash. Registry M05 giữ bản manifest bất biến theo hash để job chờ, retry và replay dùng cùng bản, kể cả sau khi triển khai adapter mới.

M05 resolve manifest, ghép inputDefaults rồi validate input, ghi pin cùng job và ký toàn bộ task trừ trường signature. `manifest_sha256` thuộc dữ liệu được ký. M06 lấy manifest theo hash, tính lại hash và đối chiếu capability/provider/adapter_version/provider_version/image_digest với task. Thiếu bản đã pin thì dừng với DEPENDENCY_MISSING; hash hoặc định danh không khớp thì POLICY_DENIED. Không thay bằng manifest latest hay defaults của bản triển khai mới. [Kiểm conformance offline](../tests/manifest_binding.py) kiểm pin/định danh; chưa phải mã executor hay kiểm HMAC runtime.

| ContainerSpec | Nguồn cấu hình |
| --- | --- |
| image_digest, args | runtime.imageDigest và argsTemplate của manifest đã pin; chỉ chèn input đã được M05 kiểm |
| cpu, memory_mb, timeout_seconds | budget.cpu, memoryMb, timeoutSeconds |
| max_output_bytes | budget.maxOutputMb × 1048576; thiếu maxOutputMb dùng 256 MiB theo manifest schema |
| network | permissions.networkAccess none → none; egress → exec |
| raw_socket | permissions.rawSocket, mặc định false |
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

```python
class ModelClient(Protocol):
    async def complete(self, req: ModelRequest) -> ModelResponse: ...

@dataclass(frozen=True)
class ModelRequest:
    provider: Literal["openai", "anthropic"]
    model: str
    messages: list[Message]                 # system/user/assistant/tool
    response_schema: dict | None            # JSON Schema; driver dùng structured output nếu có, nếu không thì kiểm sau
    tools: list[ToolSpec] | None
    campaign_id: str; session_id: str; trace_id: str
    max_output_tokens: int; timeout_seconds: float = 120

@dataclass(frozen=True)
class ModelResponse:
    content: str | None; parsed: dict | None; tool_calls: list[ToolCall]
    model: str; provider: Literal["openai", "anthropic"]
    input_tokens: int; output_tokens: int; cost_usd: float
    finish_reason: str
```

Hai driver: `OpenAIChatDriver` (Chat Completions) và `AnthropicMessagesDriver` (Messages). Provider, model, base_url và giới hạn thực thi nằm trong cấu hình triển khai trực tiếp. Trước mỗi lời gọi kiểm ngân sách chiến dịch trong mã; vượt thì ném `BudgetExceeded`. Mỗi lời gọi ghi một dòng `model_usage`.

## 6. Ingestion API (M27) nội bộ

```python
class Ingestion(Protocol):
    def submit(self, envelope: ResultEnvelope) -> IngestReceipt: ...
    # IngestReceipt sinh từ ingest-receipt.v2.schema.json; không viết lại DTO thủ công.
```

Nguồn duy nhất cho receipt là [IngestReceipt](../ingestion/ingest-receipt.v2.schema.json); OpenAPI dùng cùng $ref. Mỗi phần tử quarantined có pointer, gate và reason.

Trình tự trong **một giao dịch** PostgreSQL: đối chiếu inbox theo dedup_key/payload_hash và event_id lần nộp → G1–G7 → upsert asset/alias → insert observation/relationship/finding_candidate → insert outbox_event → commit. Projector Neo4j chạy sau commit. Hash/receipt còn phải khóa theo [C03](../../docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md#c03--idempotency-hash-và-receipt); vòng đời kết quả theo C06 cùng nguồn.

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

## Scheduling

ApprovedTask chứa priority và depends_on do M05 chuẩn hóa. Dependency cùng campaign, không self/cycle; chỉ SUCCEEDED giải phóng job. Sort ready jobs theo priority DESC, created_at ASC, job_id ASC. M06 kiểm chữ ký task và cấu hình sandbox, không tự bỏ dependency. Priority/dependency bất biến sau acceptance.

## Phần cần khóa của ModelClient và severity — C07

Chữ ký ModelClient ở trên còn là khung bản nháp; `Message`, `ToolCall`, `ToolResult` và finish_reason chưa đủ để sinh driver hoàn chỉnh. S1.4 phải định nghĩa content blocks, ID liên kết tool call/result, metadata provider cần round-trip; không ép toàn bộ nội dung thành string. Chuẩn hóa completed/tool_calls/truncated/refused/invalid_output/provider_error; retry/fallback có trần và tuân cấu hình dữ liệu/budget.

Severity có input snapshot, trigger (finding mới, evidence mới, intel revision hoặc yêu cầu đánh giá lại), budget và khóa chống trùng theo finding/input revision. Đánh giá thất bại phải ghi lỗi và giữ nguyên lịch sử; đánh giá cũ không được trình bày như kết quả mới. Mục tiêu là lần đánh giá hiện tại có trạng thái chưa đánh giá/UNRATED và tín hiệu thô, không dựng nguồn trích dẫn giả. Hình dạng fallback khi chưa có assessment/source_refs hợp lệ còn phải khóa cùng schema trước S1; chưa tuyên bố contract hiện có đã bao phủ trường hợp này.

Test offline bằng fake driver: ít nhất hai vòng tool call giữ ID/content, output sai schema hoặc bị cắt, refusal, hết budget, fallback provider, lỗi lần đánh giá đầu và đánh giá lại. Không mất raw alert/evidence/history khi model lỗi. Các test/fake này chưa phải implementation đã có trong repo.
