# Interface nội bộ giữa các module (v1)

Ngữ nghĩa không phụ thuộc ngôn ngữ; chữ ký viết bằng Python vì backend là Python 3.12 (đã chốt D1, 2026-11-15). Kiểu dữ liệu sinh từ JSON Schema trong `contracts/` (Pydantic v2 qua `datamodel-code-generator`), không định nghĩa tay lần hai.

Mỗi interface có một bản giả (fake) trong `tests/fakes/` để các luồng việc phát triển song song mà không chờ nhau.

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

Với adapter L1 (CLI trong container), lõi đã cài sẵn `start/status/cancel` qua `ContainerRunner`; tác giả adapter chỉ viết **manifest** và **parser**:

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
    def remove(self, handle: RunHandle) -> None: ...         # xóa container, KHÔNG xóa output (đã chuyển MinIO)

@dataclass(frozen=True)
class ContainerSpec:
    job_id: str; image_digest: str; args: list[str]           # args dựng từ argsTemplate, không shell
    cpu: float; memory_mb: int; timeout_seconds: int
    network: Literal["exec", "none"]                           # chỉ mạng thực thi hoặc không mạng
    raw_socket: bool = False                                   # NET_RAW, chỉ khi manifest cho phép
    read_only_rootfs: bool = True; user: str = "65534:65534"
```

Bản cài đặt GĐ1: `PodmanRunner` (rootless, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, không mount socket). Kubernetes sau này chỉ là `K8sJobRunner`.

## 3. Evidence collector (M06 → M28)

Container **không** chạm MinIO (mạng thực thi không vào được mạng dữ liệu). Sau khi container kết thúc, collector trong mạng điều khiển:

1. Tính SHA-256 từng file trong `output_dir`, gọi `EvidenceStore.put(campaign_id, job_id, file)` → `s3://evidence/{campaign_id}/{job_id}/{sha256}` (object lock).
2. Chạy parser của adapter → `ParsedResults`.
3. Dựng `ResultEnvelope` và `POST /api/v1/ingestion/results` với `event_id` = UUIDv5(job_id, "envelope") để retry không nhân bản.

(Đã chốt D3 ngày 2026-11-15, thay cho cách "scanner tải lên qua signed URL" trong đặc tả.)

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
    profile: Literal["LOW", "MID", "HIGH"]
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

Hai driver: `OpenAIChatDriver` (Chat Completions) và `AnthropicMessagesDriver` (Messages). Ánh xạ profile → (driver, model, base_url) nằm trong file cấu hình triển khai. Trước mỗi lời gọi kiểm ngân sách chiến dịch trong mã; vượt thì ném `BudgetExceeded`. Mỗi lời gọi ghi một dòng `model_usage`.

## 6. Ingestion API (M27) nội bộ

```python
class Ingestion(Protocol):
    def submit(self, envelope: ResultEnvelope) -> IngestReceipt: ...
    # IngestReceipt: event_id, accepted (bool), duplicate (bool), quarantined (list[str]), revision (int)
```

Trình tự trong **một giao dịch** PostgreSQL: inbox (unique event_id) → G1–G7 → upsert asset/alias → insert observation/relationship/finding_candidate → insert outbox_event → commit. Projector Neo4j chạy sau commit, đọc outbox.

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

Workflow ID = `campaign-<campaign_id>`. Task queue: `aegis-orchestrator`, `aegis-agent`. Continue-As-New sau 500 chu kỳ hoặc khi history > 10 MB, mang theo `cursor`. Dispatcher outbox gửi signal `job_completed` khi gặp `job.completed.v1`.
