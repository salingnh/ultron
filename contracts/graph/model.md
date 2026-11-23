# Mô hình đồ thị Neo4j (bản chiếu của PostgreSQL)

Neo4j là **bản chiếu dựng lại được**: projector M23 đọc `outbox_event` theo `seq` (consumer `m23-projector`) và các bảng PostgreSQL tương ứng, rồi `MERGE` bằng Cypher tham số hóa (`projector-upserts.cypher`). Không module nào khác ghi Neo4j. Projector chỉ checkpoint cursor sau khi commit Neo4j. Thuật toán publication ordering chịu rollback/commit đảo thứ tự còn mở (C04); không chờ seq liền mạch vô điều kiện.

**Dựng lại toàn bộ:** xóa database Neo4j rồi chạy projector dưới một **consumer thế hệ mới** (vd `m23-projector#g2`) bắt đầu từ `last_seq = 0`. Không tái dùng consumer cũ, vì `consumer_inbox` khử trùng vĩnh viễn (append-only, không xóa) sẽ khiến replay bỏ qua sự kiện đã xử lý. Dòng inbox/cursor cũ vẫn giữ; kết quả phải giống hệt (tiêu chí nghiệm thu replay/rebuild).

## Nút

| Nhãn | Khóa | Thuộc tính chính | Nguồn PG |
| --- | --- | --- | --- |
| `:Asset` + nhãn phụ theo kind | `canonical_key` (unique), `asset_id` (unique) | `kind`, `first_seen`, `last_seen`, `owner`, `exposure`, `criticality`, `campaign_ids[]` | `asset`, `asset_campaign` |
| `:Target` | `target_id` | `kind`, `raw_value`, `campaign_id`, `canonical_key` (NULL cho keyword/CIDR) | `campaign_target` (seed keyword/CIDR không có asset nên không có nhãn `:Asset`) |
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
| `DISCOVERED_FROM` | Asset → Asset hoặc Target | M27 (cổng G5) | cạnh nguồn gốc bắt buộc cho mọi tài sản tìm thêm; đích là `:Target` khi nguồn gốc là seed keyword/CIDR (TargetRef `{seed_id}`), không tạo asset giả |
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

## C04 — Thứ tự công bố (đã khóa ở S1.3)

`bigserial` cấp số trước commit nên rollback để lại khoảng trống và writer có số thấp có thể commit sau writer số cao; vì vậy không dùng MAX(seq), không chờ số liền nhau và không lấy transaction xmin làm watermark. Cơ chế đã khóa ở [migration 0008](../db/postgres/0008_outbox_publication_order.sql), kiểm bằng [db test một phiên](../db/postgres/tests/outbox_ordering.sql) và [harness nhiều connection + dispatcher prototype](../tests/test_outbox_ordering.py):

- **Allocator**: writer lấy `pg_advisory_xact_lock_shared` trên khóa công bố chung rồi tăng counter một dòng `outbox_publication.next_seq` trong chính giao dịch của mình. Trigger `allocate_seq` gán `outbox_event.seq` và `graph_revision.revision` từ counter đó, nên event và revision dùng chung một thứ tự; writer không được tự đặt số (trigger từ chối). Commit order = thứ tự số, rollback trả lại số. Giao dịch phải ngắn, chỉ ghi metadata/event/revision; không gọi mạng/LLM trong khóa.
- **Watermark**: dispatcher lấy khóa công bố ở chế độ exclusive bằng `pg_try_advisory_xact_lock` trong một giao dịch ngắn; chỉ khi lấy được (không còn writer nào đang chạy) mới đẩy `outbox_watermark.published_upto` lên `next_seq - 1`. Vì vậy mọi số ≤ watermark đã commit hoặc đã rollback xong: không bỏ sót commit muộn, không kẹt ở số không bao giờ commit, và dispatcher không chặn writer chậm (try-lock thất bại thì giữ nguyên watermark và trả về ngay). Với counter transactional, MVCC cũng khiến reader không thấy số chưa commit; khóa exclusive là phần hợp đồng giữ đúng cho allocator không transactional và để watermark chứng minh được, không phải suy từ bigserial.
- **Consumer**: chỉ đọc `outbox_batch` (số > cursor và ≤ watermark, theo thứ tự công bố) và chỉ checkpoint qua `consumer_advance` kèm fence của dispatcher. Checkpoint vượt watermark bị từ chối (D25), nên thêm consumer không nhảy qua dữ liệu chưa công bố. Khoảng trống hợp lệ và không làm kẹt consumer vì consumer không chờ một số cụ thể; khử trùng bằng `consumer_inbox`, rebuild dùng consumer thế hệ mới (`m23-projector#g2`) bắt đầu từ cursor 0.
- **Fencing**: `outbox_dispatcher` giữ lease và fence, mỗi lần lấy/gia hạn lease tăng fence; `outbox_watermark_refresh` và `consumer_advance` kiểm fence nên holder cũ bị từ chối (SQLSTATE 55000) thay vì công bố/checkpoint sai.
- **Quyền**: `aegis_outbox_writer` chỉ INSERT event/revision (kèm SELECT để `RETURNING`) và EXECUTE allocator (SECURITY DEFINER); `aegis_outbox_dispatcher` chỉ đọc event/cursor và gọi các hàm có fence; cả hai không có quyền trên counter/watermark/lease nên không bypass allocator được. Batch writer dùng `outbox_publication_reserve(n)`; số đã reserve mà không dùng là khoảng trống vĩnh viễn và dispatcher vượt qua bình thường.
- **Đo được** (PostgreSQL 16.16, 8 writer × 250 event, commit từng event, fsync bật, đĩa NVMe của máy dev; máy còn chạy container của task song song nên số dao động): counter transactional ~223 event/s; cùng writer gộp 10 event mỗi commit ~1390 event/s; allocator không transactional (nextval dưới cùng khóa, chỉ có trong harness) ~1138 event/s; baseline không allocator ~1138 event/s. Trên tmpfs (fsync gần như miễn phí): ~2,8k / ~3,1k / ~4,5k event/s. Chi phí của counter transactional là tuần tự hóa **commit**, không phải từng event: gộp event mỗi giao dịch thì về sát baseline.
- **Còn lại (spike G0.3b quyết)**: chọn allocator cuối cho G1 sau khi đo 100 writer vào Neo4j và rebuild. Nếu chọn nextval thì chỉ thay `outbox_publication_alloc`, giữ nguyên watermark/fence/consumer và bỏ kỳ vọng "rollback trả lại số".
