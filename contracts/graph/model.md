# Mô hình đồ thị Neo4j (bản chiếu của PostgreSQL)

Neo4j là **bản chiếu dựng lại được**: projector M23 đọc `outbox_event` theo `seq` (consumer `m23-projector`) và các bảng PostgreSQL tương ứng, rồi `MERGE` bằng Cypher tham số hóa (`projector-upserts.cypher`). Không module nào khác ghi Neo4j. Projector chỉ checkpoint cursor sau khi commit Neo4j. Thuật toán publication ordering chịu rollback/commit đảo thứ tự còn mở (C04); không chờ seq liền mạch vô điều kiện.

**Dựng lại toàn bộ:** xóa database Neo4j rồi chạy projector dưới một **consumer thế hệ mới** (vd `m23-projector#g2`) bắt đầu từ `last_seq = 0`. Không tái dùng consumer cũ, vì `consumer_inbox` khử trùng vĩnh viễn (append-only, không xóa) sẽ khiến replay bỏ qua sự kiện đã xử lý. Dòng inbox/cursor cũ vẫn giữ; kết quả phải giống hệt (tiêu chí nghiệm thu replay/rebuild).

## Nút

| Nhãn | Khóa | Thuộc tính chính | Nguồn PG |
| --- | --- | --- | --- |
| `:Asset` + nhãn phụ theo kind | `canonical_key` (unique), `asset_id` (unique) | `kind`, `first_seen`, `last_seen`, `owner`, `exposure`, `criticality`, `campaign_ids[]` | `asset`, `asset_campaign` |
| `:Target` | `target_id` | `kind`, `raw_value`, `campaign_id` | `campaign_target` (từ khóa, CIDR không có asset) |
| `:Campaign` | `campaign_id` | `name`, `status` | `campaign` |
| `:Job` | `job_id` | `capability`, `provider`, `provider_version`, `policy_version`, `status` | `scan_job` |
| `:Observation` | `observation_id` | `predicate`, `value_summary`, `polarity`, `observed_at`, `confidence` | `observation` (chỉ predicate có `graph: true` trong registry, để đồ thị không phình) |
| `:Vulnerability` | `vulnerability_id` | `cvss_base`, `kev`, `epss`, `snapshot_id` | `vulnerability_current` |
| `:Finding` | `finding_id` | `fingerprint`, `rule_id`, `status`, `severity`, `secret_value` (dạng rõ) | `finding` |
| `:Evidence` | `evidence_id` | `sha256`, `storage_uri`, `source_tool` | `evidence` |
| `:Hypothesis` | `hypothesis_id` | `claim`, `status`, `confidence`, `revision` | `hypothesis_revision` mới nhất |

Bảng kind → nhãn phụ: domain `:Domain`, ip `:IP`, service `:Service`, application `:Application`, url `:Endpoint`, email `:Email`, oci_image `:Image`, repo `:Repo`, repo_snapshot `:RepoSnapshot`, artifact `:Artifact`, package `:Package`, cloud_resource `:CloudResource`, k8s_workload `:K8sWorkload`.

## Cạnh

Mọi cạnh mang `observed_at`, `valid_from`, `valid_to`, `source_job_id`, `confidence` (bắt buộc). Cạnh tài sản–tài sản mang thêm `relationship_id` (một khoảng hiệu lực trong PG = một cạnh Neo4j, nên lịch sử "mất rồi thấy lại" hiện thành nhiều cạnh song song có khoảng thời gian khác nhau).

| Cạnh | Từ → tới | Ai sinh | Ghi chú |
| --- | --- | --- | --- |
| `SUBDOMAIN_OF` | Domain → Domain | adapter (qua M27) | |
| `RESOLVES_TO` | Domain → IP | adapter | |
| `EXPOSES` | IP → Service | adapter | |
| `SERVES` | Service → Application | adapter hoặc M27 suy ra từ `web.probe` | |
| `HAS_ENDPOINT` | Application → Endpoint | adapter | |
| `HAS_ARTIFACT` | Application/Repo/RepoSnapshot → Artifact/Image | adapter, M28 | |
| `CONTAINS_PACKAGE` | Artifact/Image → Package | adapter SBOM | |
| `DISCOVERED_FROM` | Asset → Asset hoặc Target | M27 (cổng G5) | cạnh nguồn gốc bắt buộc cho mọi tài sản tìm thêm |
| `SNAPSHOT_OF` | RepoSnapshot → Repo | adapter |  |
| `ALIAS_OF` | Asset → Asset | M07 | vd domain CNAME tới domain khác |
| `AFFECTED_BY` | Package → Vulnerability | M20 | Chỉ là ứng viên (`package_vuln_match`) |
| `HAS_FINDING` | Asset → Finding | M20 | |
| `SUPPORTED_BY` | Finding → Evidence | M20, M21 | |
| `DERIVED_FROM` | Observation → Job | M27 | |

## Truy vấn theo thời gian

- "Đồ thị tại thời điểm T": lọc cạnh `r.valid_from <= T AND (r.valid_to IS NULL OR r.valid_to > T)`.
- "Đổi gì từ revision R": đọc `knowledge.delta.v2` hoặc `graph.summarize_campaign_delta`, không quét toàn đồ thị.
- Dữ liệu quá hạn (stale): `last_seen` cũ hơn ngưỡng theo kind (cấu hình M23, mặc định 7 ngày) thì truy vấn trả `stale: true`.

## C04 — Thứ tự công bố còn cần chứng minh

`bigserial` cấp số trước commit: rollback tạo khoảng trống, còn writer có seq thấp có thể commit sau writer seq cao. Vì vậy không dùng MAX(seq), chờ seq liên tiếp hoặc lấy transaction xmin làm watermark seq. Hiện chưa có allocator/dispatcher chứng minh xử lý đúng cả hai tình huống.

Giữ yêu cầu D25: một dispatcher outbox chủ động, chỉ công bố tới mốc đã xác nhận mọi giao dịch trước đó commit/rollback, áp dụng cả graph_revision; consumer vẫn idempotent. Watermark phải được chứng minh bằng cơ chế công bố thực tế, không suy từ bigserial. Failover dispatcher phải có fencing; thêm consumer không cho phép checkpoint vượt qua dữ liệu chưa công bố.

Phương án để khóa tại S1.3: các writer outbox/revision lấy chung publication lock, tăng counter transactional và ghi metadata/revision/event trong giao dịch ngắn; giữ lock tới commit/rollback. Không gọi mạng/LLM trong lock. Counter là trạng thái được UPDATE, event/revision vẫn append-only. Quyền DB/hàm ghi phải ngăn writer bypass allocator; chỉ thêm mô tả này chưa tạo implementation.

Đánh đổi là tuần tự hóa đoạn công bố; cần đo trước khi chọn làm thuật toán cuối. Test nhiều connection phải bao phủ writer chậm, rollback, commit đảo thứ tự, crash, nhiều event/giao dịch, retry consumer và rebuild. Consumer chỉ checkpoint sau xử lý thành công, không bỏ sót event commit muộn hoặc kẹt ở số không bao giờ commit. Kết quả graph rebuild phải đối soát metadata/revision/evidence, không chỉ đếm node.
