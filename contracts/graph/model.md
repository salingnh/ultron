# Mô hình đồ thị Neo4j v1 (bản chiếu của PostgreSQL)

Neo4j là **bản chiếu dựng lại được**: projector M23 đọc `outbox_event` theo `seq` (consumer `m23-projector`) và các bảng PostgreSQL tương ứng, rồi `MERGE` bằng Cypher tham số hóa (`projector-upserts.cypher`). Không module nào khác ghi Neo4j. Dựng lại toàn bộ = xóa database Neo4j, đặt `consumer_cursor.last_seq = 0`, chạy lại projector; kết quả phải giống hệt (tiêu chí nghiệm thu tab Dữ liệu mục 6).

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
| `DISCOVERED_FROM` | Asset → Asset hoặc Target | M27 (cổng G5) | **Đề xuất mới**: cạnh nguồn gốc bắt buộc cho mọi tài sản tìm thêm |
| `SNAPSHOT_OF` | RepoSnapshot → Repo | adapter | **Đề xuất mới** |
| `ALIAS_OF` | Asset → Asset | M07 | **Đề xuất mới**, vd domain CNAME tới domain khác |
| `AFFECTED_BY` | Package → Vulnerability | M20 | Chỉ là ứng viên (`package_vuln_match`) |
| `HAS_FINDING` | Asset → Finding | M20 | |
| `SUPPORTED_BY` | Finding → Evidence | M20, M21 | |
| `DERIVED_FROM` | Observation → Job | M27 | |
| `TOUCHED` | Campaign → Asset | M27 | **Đề xuất mới**, thay cho lọc theo mảng `campaign_ids` nếu benchmark spike 3 cho thấy chậm |

## Truy vấn theo thời gian

- "Đồ thị tại thời điểm T": lọc cạnh `r.valid_from <= T AND (r.valid_to IS NULL OR r.valid_to > T)`.
- "Đổi gì từ revision R": đọc `knowledge.delta.v1` hoặc `graph.summarize_campaign_delta`, không quét toàn đồ thị.
- Dữ liệu quá hạn (stale): `last_seen` cũ hơn ngưỡng theo kind (cấu hình M23, mặc định 7 ngày) thì truy vấn trả `stale: true`.
