# Mô hình đồ thị Neo4j (bản chiếu của PostgreSQL)

Neo4j là **bản chiếu dựng lại được**: projector M23 đọc `outbox_event` theo `seq` (consumer `m23-projector`) và các bảng PostgreSQL tương ứng, rồi `MERGE` bằng Cypher tham số hóa (`projector-upserts.cypher`). Không module nào khác ghi Neo4j. Projector chỉ checkpoint cursor sau khi commit Neo4j. Thuật toán publication ordering chịu rollback/commit đảo thứ tự đã khóa ở C04 (0008 + 0013); không chờ seq liền mạch vô điều kiện.

**Dựng lại toàn bộ:** xóa database Neo4j rồi chạy projector dưới một **consumer thế hệ mới** (vd `m23-projector#g2`) bắt đầu từ `last_seq = 0`. Không tái dùng consumer cũ, vì `consumer_inbox` khử trùng vĩnh viễn (append-only, không xóa) sẽ khiến replay bỏ qua sự kiện đã xử lý. Dòng inbox/cursor cũ vẫn giữ; kết quả phải giống hệt (tiêu chí nghiệm thu replay/rebuild).

Nguồn chiếu có hai: M27 (kết quả tool, revision ≥ 1) và M01 (seed của campaign, `asset.discovered.v2` với revision 0, ghi trong giao dịch tạo campaign). Cả hai đi qua outbox C04; projector không có đường backfill nào khác.

**Đo được (spike G0.3b, 2026-11-23, Neo4j 5.26.33 + PostgreSQL 16.16):** 2 799 event (1 999 `asset.discovered` + 800 `finding.changed`; 865 asset, 800 finding, 800 evidence, 1 143 cạnh `SUBDOMAIN_OF` gồm cả khoảng đã đóng) chiếu thành 2 465 nút / 2 743 cạnh. Xóa đồ thị rồi chạy `m23-projector#g2` từ cursor 0: 2 799 event trong 16,0 s (174,5 event/s); snapshot trước và sau bằng nhau từng thuộc tính (`asset_id`, `kind`, `first_seen`/`last_seen`, `campaign_ids`, `pg_revision`; `fingerprint`/`rule_id`/`status`/`severity`/`transition_seq` của finding; `sha256`/`storage_uri`/`source_tool` của evidence; `relationship_id`/`observed_at`/`valid_from`/`valid_to`/`source_job_id`/`confidence` của cạnh) và reconcile với PostgreSQL 0 lệch; cursor/inbox của `m23-projector#g1` giữ nguyên. Replay lại 67 event đã chiếu vào đồ thị đang có (consumer mới, cursor lùi 100) không đổi một thuộc tính nào, nên `MERGE` + `consumer_inbox` idempotent thật. Rollback của counter: số bị rollback được giao lại cho giao dịch sau và vẫn được chiếu; nextval để lại khoảng trống vĩnh viễn và consumer vượt qua bình thường. 100 writer đồng thời cùng `canonical_key` cho đúng 1 nút, 0 lỗi: Neo4j 5.26.33 tuần tự hóa `MERGE` trên khóa unique (100 lần ghi hết 0,68 s; 473 lần/s khi mỗi writer một khóa), nên projector vẫn nên retry lỗi transient/constraint dù chưa quan sát được lỗi nào.

## Nút

| Nhãn | Khóa | Thuộc tính chính | Nguồn PG |
| --- | --- | --- | --- |
| `:Asset` + nhãn phụ theo kind | `canonical_key` (unique), `asset_id` (unique) | `kind`, `first_seen`, `last_seen`, `owner`, `exposure`, `criticality`, `campaign_ids[]` | `asset`, `asset_campaign` |
| `:Target` | `target_id` | `kind`, `raw_value`, `campaign_id`, `canonical_key` (NULL cho keyword/CIDR) | `campaign_target` (seed keyword/CIDR không có asset nên không có nhãn `:Asset`) |
| `:Campaign` | `campaign_id` | `name`, `status` | `campaign` |
| `:Job` | `job_id` | `capability`, `provider`, `provider_version`, `policy_version`, `status` | `scan_job` |
| `:Observation` | `observation_id` | `predicate`, `value_summary`, `polarity`, `observed_at`, `confidence`, `subject` (canonical_key của tài sản) | `observation` (chỉ predicate có `graph: true` trong registry, để đồ thị không phình) |
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
| `AFFECTED_BY` | Package → Vulnerability | M20 | Chỉ là ứng viên (`package_vuln_match`); cạnh chỉ tồn tại khi quyết định mới nhất của cặp là khớp. Rút ứng viên xóa cạnh và `:Vulnerability` mồ côi, lịch sử ở PostgreSQL |
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
- **Watermark**: dispatcher **chờ** (blocking) khóa công bố ở chế độ exclusive bằng `pg_advisory_xact_lock` trong một giao dịch ngắn, rồi đẩy `outbox_watermark.published_upto` lên `next_seq - 1`. Chờ là phần hợp đồng, không phải tối ưu: yêu cầu khóa xếp hàng sau các writer đang giữ khóa shared và writer mới xếp hàng sau dispatcher, nên watermark luôn tiến được dưới tải ghi liên tục; chỉ khi lấy được khóa (không còn writer nào đang chạy) thì mọi số ≤ watermark mới chắc chắn đã commit hoặc rollback xong. Chờ bị chặn bởi `aegis.outbox_watermark_lock_timeout` (GUC session, mặc định 5s); hết hạn là SQLSTATE 55P03, watermark không đổi và dispatcher retry — không có nhánh bỏ qua im lặng; bound 0/âm/không đọc được bị từ chối thay vì thành chờ vô hạn. Giao dịch refresh phải ngắn và riêng vì khóa exclusive giữ các writer mới đến khi commit. (0008 dùng `pg_try_advisory_xact_lock`; 0013 thay bằng dạng chờ này sau khi G0.3b đo được bế tắc: 936–2 331 lần refresh bị chặn trên 1 150–2 483 lần thử, watermark chỉ tiến 1 lần, consumer không nhận event nào trong 11–12 s ghi liên tục ở 100 writer. Với counter transactional, MVCC cũng khiến reader không thấy số chưa commit; khóa exclusive vẫn là phần hợp đồng giữ đúng cho allocator không transactional và để watermark chứng minh được, không phải suy từ bigserial.) Đo 100 writer × 20 event (6 cặp run try/blocking, cùng máy và cùng cổng): p50 commit của writer 0,185 s so với 0,148 s, p99 1,30 s so với 1,21 s (một run lệch p99 2,53 s); chờ của dispatcher p99 0,13–0,19 s (max 0,25 s; run lệch 0,62 s), không lần nào chạm trần 5 s; end-to-end 167 so với 133 event/s. Harness refresh ~150–200 lần/s nên đây là cận trên của chi phí: dispatcher thật phải có nhịp refresh giới hạn, không spin.
- **Consumer**: chỉ đọc `outbox_batch` (số > cursor và ≤ watermark, theo thứ tự công bố) và chỉ checkpoint qua `consumer_advance` kèm fence của dispatcher. Checkpoint vượt watermark bị từ chối (D25), nên thêm consumer không nhảy qua dữ liệu chưa công bố. Khoảng trống hợp lệ và không làm kẹt consumer vì consumer không chờ một số cụ thể; khử trùng bằng `consumer_inbox`, rebuild dùng consumer thế hệ mới (`m23-projector#g2`) bắt đầu từ cursor 0.
- **Fencing**: `outbox_dispatcher` giữ lease và fence, mỗi lần lấy/gia hạn lease tăng fence; `outbox_watermark_refresh` và `consumer_advance` kiểm fence nên holder cũ bị từ chối (SQLSTATE 55000) thay vì công bố/checkpoint sai.
- **Quyền**: `aegis_outbox_writer` chỉ INSERT event/revision (kèm SELECT để `RETURNING`) và EXECUTE allocator (SECURITY DEFINER); `aegis_outbox_dispatcher` chỉ đọc event/cursor và gọi các hàm có fence; cả hai không có quyền trên counter/watermark/lease nên không bypass allocator được. Batch writer dùng `outbox_publication_reserve(n)`; số đã reserve mà không dùng là khoảng trống vĩnh viễn và dispatcher vượt qua bình thường.
- **Đo được** (PostgreSQL 16.16, 8 writer × 250 event, commit từng event, fsync bật, đĩa NVMe của máy dev; máy còn chạy container của task song song nên số dao động): counter transactional ~223 event/s; cùng writer gộp 10 event mỗi commit ~1390 event/s; allocator không transactional (nextval dưới cùng khóa, chỉ có trong harness) ~1138 event/s; baseline không allocator ~1138 event/s. Trên tmpfs (fsync gần như miễn phí): ~2,8k / ~3,1k / ~4,5k event/s. Chi phí của counter transactional là tuần tự hóa **commit**, không phải từng event: gộp event mỗi giao dịch thì về sát baseline.
- **Chốt allocator (spike G0.3b, 2026-11-23): giữ counter của 0008, không cần migration mới cho allocator.** Đo với 100 writer đồng thời (Neo4j 5.26.33, PostgreSQL 16.16, podman rootless, đĩa máy dev; máy còn container của task khác nên số dao động), 1 giao dịch = 1 commit: 2 lần cấp số/giao dịch (revision + event) — counter 389 tx/s (372–391) so với nextval dưới cùng khóa 1 814 tx/s (1 774–1 889); 16 writer — 570 (544–577) so với 2 200 (2 099–2 323); giao dịch writer thật (asset + relationship + revision + event, 100 writer) — 563 event/s (293–570) so với 1 127 event/s (1 056–1 154). Projector là nút cổ chai phía sau: rebuild 2 799 event đạt 149,6–174,6 event/s (trung vị 170,1 trên 14 lần chạy đủ tải); end-to-end 100 writer × 20 event đạt trung vị 127 event/s (97–134, counter + try-lock của 0008 trước 0013), 163,7 (162,9–164,3, counter + khóa chờ), 146 (141,6–154,0, nextval + try-lock), 147,7 (146,2–149,2, nextval + khóa chờ). Counter vẫn nhanh hơn trần chiếu ít nhất 2,2 lần (389 so với 175) và 3,2 lần trong giao dịch writer thật, nên đổi allocator không tăng thông lượng end-to-end; nextval chỉ có lợi khi projection được song song hóa hoặc nhu cầu ghi vượt ~500 event/s. Khi cần đổi, chỉ thay `outbox_publication_alloc`/`reserve` và cách `outbox_watermark_refresh` đọc số cuối; giữ nguyên khóa công bố, watermark, fence và consumer, nhưng mất tính chất "rollback trả lại số" (số đã cấp thành khoảng trống vĩnh viễn, consumer đã đo là vượt qua bình thường).
