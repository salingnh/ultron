# Dữ liệu, API và sự kiện

Tab này là hợp đồng dữ liệu dùng chung giữa các module: thực thể, khóa định danh, quan hệ đồ thị, REST API và sự kiện.

## 1. Thực thể dữ liệu và nơi lưu

Mô hình tách năm khái niệm để không lẫn giữa sự thật và suy đoán: Asset là đối tượng tồn tại, Observation là điều ghi nhận được tại một thời điểm, Finding là đánh giá điểm yếu trên một tài sản cụ thể, Evidence là bằng chứng có checksum, Hypothesis là giả thuyết chưa được xác minh. CVE là định danh tình báo dùng chung; Finding mới là thể hiện của lỗ hổng gắn với tài sản, phiên bản và môi trường.

PostgreSQL là nguồn sự thật. Neo4j là bản chiếu có thể dựng lại từ PostgreSQL. MinIO giữ dữ liệu thô bất biến.

| Thực thể | Thuộc tính định danh chính | Nơi lưu | Module sở hữu |
| --- | --- | --- | --- |
| Campaign | campaign\_id, targets (IP, domain, URL, email, từ khóa), objective, budget, state, cursor | PostgreSQL, Temporal | M01, M02 |
| Policy (RoE) | policy\_version, impact\_class, windows, rate | PostgreSQL | M01 |
| ScanJob | job\_id, capability, provider, fingerprint, input\_ref, state | PostgreSQL | M06 |
| Asset | asset\_id, kind, canonical\_key, owner, exposure, criticality, first\_seen, last\_seen | PostgreSQL, chiếu sang Neo4j | M07 |
| AssetAlias | namespace, alias\_value, reason, validity | PostgreSQL | M07 |
| Service | asset\_id, host\_ip, port, protocol, banner, observed\_at | PostgreSQL, Neo4j | M07 |
| Endpoint | URL đã chuẩn hóa, HTTP method, api\_contract\_id, auth\_context | PostgreSQL, Neo4j | M07 |
| Package | purl, version, ecosystem, license | PostgreSQL, Neo4j, kèm SBOM | M07 |
| Artifact | digest, kind, origin\_uri, storage\_uri, size, classification | MinIO, metadata ở PostgreSQL | M28 |
| Evidence | evidence\_id, sha256, storage\_uri, source\_tool | MinIO, metadata ở PostgreSQL | M28 |
| Observation | observation\_id, scan\_id, subject\_id, predicate, value, time | PostgreSQL chỉ ghi thêm, chiếu sang Neo4j | M27 |
| Vulnerability | source, vulnerability\_id, cvss, references, affected ranges | Bộ đệm tình báo ở PostgreSQL | M18 |
| Finding | finding\_id, asset\_id, rule\_id, severity, severity\_reason, lifecycle; lịch sử từng lần chạy nằm ở bảng FindingRun | PostgreSQL | M20, với M21 và M24 đổi trạng thái |
| Hypothesis | hypothesis\_id, claim, bằng chứng ủng hộ và phản bác, status | PostgreSQL, Neo4j | M03 |
| Provenance | provider, version, execution, source URI, observed\_at | Gắn trên mọi bản ghi | M27 ghi khi tiếp nhận |

Vòng đời của Finding dùng bảy trạng thái: `CANDIDATE`, `CORROBORATED`, `VERIFIED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `FIXED`, `REGRESSED`. Mọi lần chuyển trạng thái được ghi lại kèm người hoặc module thực hiện, lý do và evidence\_id.

Dữ liệu được phân loại `PUBLIC`, `INTERNAL`, `RESTRICTED`. Theo quyết định ngày 12/11/2026, dữ liệu được lưu vĩnh viễn và không tự xóa. Secret phát hiện được lưu dạng rõ kèm fingerprint trong PostgreSQL và Neo4j, không che ở đâu (chốt 13/11).

**Lưu vĩnh viễn và lịch sử theo từng lần chạy (chốt 13/11).** Mọi dữ liệu quét được giữ mãi: tài liệu, tài sản, observation, quan hệ trong đồ thị, finding, bằng chứng, mức nghiêm trọng và trạng thái. Quy tắc:

- Không xóa và không ghi đè. Mọi thay đổi là một bản ghi mới có `scan_id` và thời điểm.
- Quan hệ trong đồ thị không còn thấy thì đặt `valid_to`, không xóa cạnh. Thấy lại thì mở một khoảng hiệu lực mới.
- Bảng `FindingRun` ghi một dòng cho mỗi finding ở mỗi lần chạy có kiểm tra tài sản đó: `finding_id`, `scan_id`, `seen` (có hoặc không), `status`, `severity`, `severity_reason`, `evidence_id`, `observed_at`. Lần sau không tìm thấy lỗ hổng thì vẫn ghi một dòng `seen = false`.
- Không thấy nữa chưa có nghĩa là đã sửa. Finding chỉ chuyển `FIXED` khi có bằng chứng mới; thấy lại sau `FIXED` thì chuyển `REGRESSED`.
- Mỗi lần agent đánh giá lại mức nghiêm trọng (do quét lại hoặc do KEV, EPSS đổi) là một bản ghi mới kèm lý do.
- Tài sản biết được có xuất hiện ở từng lần chạy hay không qua observation gắn `scan_id`.
- API và giao diện có dòng thời gian cho một tài sản và một finding: `GET /assets/{id}/history`, `GET /findings/{id}/history`.

## 2. Khóa định danh chuẩn và quy tắc khử trùng

Mỗi tài sản có đúng một `canonical_key`. Hai scanner nhìn thấy cùng một tài sản phải sinh ra cùng một khóa, nếu không đồ thị sẽ phân mảnh và cảnh báo bị lặp.

| Loại | Khóa chuẩn | Ghi chú |
| --- | --- | --- |
| domain | `dns:<fqdn chữ thường, bỏ dấu chấm cuối>` | Giữ alias gốc và dạng IDNA |
| ip | `ip:<ipv4 hoặc ipv6 đã chuẩn hóa>` | Không gán chủ sở hữu khi chưa có nguồn gốc |
| service | `service:<ip>:<port>/<transport>` | Giao thức tầng ứng dụng là observation riêng |
| url | `url:<scheme>://<host>:<port>/<path>?<query đã chuẩn hóa>` | Không lưu token hay tham số nhạy cảm |
| oci-image | `oci:sha256:<manifest_digest>` | Tag là alias có thể đổi, không dùng làm định danh |
| repo-snapshot | `git:<repo_identity>@<commit_sha>` | Branch là alias có thể đổi |
| package | `purl:<purl đã chuẩn hóa>` | Ghim phiên bản và qualifiers |
| finding | `hash(asset_id, rule_id, location, ngữ cảnh bằng chứng đã chuẩn hóa)` | Fingerprint phải ổn định qua các phiên bản scanner |
| cloud-resource | `cloud:<provider>:<account>:<region>:<type>/<resource_id>` | Chốt 13/11, cần cho M11 ở GĐ3 |
| k8s-workload | `k8s:<cluster_id>/<namespace>/<kind>/<name>` | Chốt 13/11, cần cho M11 ở GĐ3 |

Hai dòng cuối không có trong tài liệu nguồn, được bổ sung vì M11 (Prowler, Kubescape, kube-bench) không thể ghi kết quả nếu thiếu khóa. Theo quyết định ngày 13/11, tài sản do hai công cụ khác nhau cùng tìm thấy được gộp thành một node theo khóa chuẩn ở bảng này, và mỗi công cụ để lại một observation riêng.

Quy tắc ghi đồng thời:

- Ràng buộc duy nhất trên `Asset(canonical_key)` ở cả PostgreSQL và Neo4j.
- Ghi vào Neo4j chỉ bằng Cypher có tham số, dùng `MERGE` theo khóa chuẩn.
- Giao dịch xung đột được thử lại với backoff lũy thừa.
- Thuộc tính được gộp theo quy tắc xác định. Giá trị mâu thuẫn giữa các nguồn được giữ thành nhiều observation độc lập, không ghi đè dữ liệu gốc.

```cypher
MERGE (a:Asset {canonical_key: $canonical_key})
ON CREATE SET a.asset_id = $asset_id, a.first_seen = $observed_at
SET a.last_seen = $observed_at, a.kind = $kind
RETURN a.asset_id;
```

## 3. Quan hệ đồ thị và tính thời gian

| Quan hệ | Nguồn tới đích | Ý nghĩa | Giai đoạn |
| --- | --- | --- | --- |
| `SUBDOMAIN_OF` | Domain tới Domain | Quan hệ cha con giữa tên miền | GĐ2 |
| `RESOLVES_TO` | Domain tới IP | Phân giải DNS quan sát được, có thời hạn | GĐ2 |
| `EXPOSES` | IP tới Service | Quan sát mạng theo policy của chiến dịch | GĐ2 |
| `SERVES` | Service tới Application | Suy luận ứng dụng có bằng chứng | GĐ2 |
| `HAS_ENDPOINT` | Application tới Endpoint | Đường dẫn biết được qua crawl hoặc hợp đồng API | GĐ2 |
| `HAS_ARTIFACT` | Application hoặc Repo tới Artifact | Ảnh chụp artifact có hash | GĐ2 |
| `CONTAINS_PACKAGE` | Artifact tới Package | Kiểm kê từ SBOM | GĐ2 |
| `AFFECTED_BY` | Package tới Vulnerability | Ánh xạ ứng viên theo dải phiên bản và nguồn | GĐ2 |
| `HAS_FINDING` | Asset tới Finding | Finding cụ thể trên tài sản | GĐ2 |
| `SUPPORTED_BY` | Finding tới Evidence | Tham chiếu bằng chứng bất biến | GĐ2 |
| `DERIVED_FROM` | Observation tới Job | Nguồn gốc và truy vết | GĐ2 |

Mọi cạnh mang năm thuộc tính: `observed_at`, `valid_from`, `valid_to`, `source_job_id`, `confidence`. Nhờ đó hệ thống trả lời được câu hỏi "điều gì đã đổi kể từ lần quét trước", là nền của cảnh báo sớm.

Ba quy tắc diễn giải bắt buộc:

- "Không tìm thấy" không có nghĩa là "không tồn tại". Hệ thống phân biệt ba trạng thái: chưa biết, vắng mặt tại thời điểm quan sát, và có bằng chứng phủ định rõ ràng.
- `AFFECTED_BY` chỉ là ứng viên. Nó chỉ thành finding khi M20 đối chiếu được phiên bản và ngữ cảnh.
- Call graph tĩnh từ dịch ngược (M16) không đủ để khẳng định khả năng chạm tới lúc chạy và không được dùng một mình để đóng finding.

Agent không chạy Cypher tự do. Agent chỉ gọi sáu truy vấn đã đăng ký của M23: `get_asset_neighbors`, `get_recent_observations`, `get_unverified_hypotheses`, `get_package_cve_matches`, `summarize_campaign_delta`, `get_evidence_excerpt`. Mỗi truy vấn có giới hạn số bước nhảy, số bản ghi, thời gian chờ và điều kiện lọc theo chiến dịch.

## 4. REST API v1

Tất cả endpoint nằm dưới `/api/v1`, do M26 phục vụ, trừ endpoint ingestion do M27 phục vụ.

| Method | Path | Ý nghĩa | Idempotency | Giai đoạn |
| --- | --- | --- | --- | --- |
| POST | `/campaigns` | Tạo chiến dịch kèm ảnh chụp RoE | Bắt buộc `Idempotency-Key` | GĐ1 |
| GET | `/campaigns/{id}` | Trạng thái, ngân sách, bộ đếm | Chỉ đọc | GĐ1 |
| POST | `/campaigns/{id}/pause` | Tạm dừng | Thử lại an toàn | GĐ1 |
| POST | `/campaigns/{id}/resume` | Tiếp tục | Thử lại an toàn | GĐ1 |
| POST | `/campaigns/{id}/cancel` | Hủy và phát lệnh hủy tới job | Thử lại an toàn | GĐ1 |
| GET | `/campaigns/{id}/events` | Dòng thời gian, hỗ trợ SSE | Phân trang theo cursor | GĐ1 |
| GET | `/capabilities` | Danh sách capability và provider | Chỉ đọc | GĐ1 |
| POST | `/jobs` | Gửi job đã qua kiểm tra | Bắt buộc `Idempotency-Key` | GĐ1 |
| GET | `/jobs/{id}` | Trạng thái và tham chiếu kết quả | Chỉ đọc | GĐ1 |
| POST | `/jobs/{id}/cancel` | Hủy job con | Thử lại an toàn | GĐ1 |
| POST | `/ingestion/results` | Nhận ResultEnvelope và tham chiếu bằng chứng | `event_id` duy nhất | GĐ1 |
| GET | `/assets/{id}/graph` | Vùng lân cận đồ thị có giới hạn | Chỉ đọc | GĐ1 |
| GET | `/findings` | Lọc và xuất findings | Phân trang theo cursor | GĐ2 |

Ví dụ tạo chiến dịch:

```http
POST /api/v1/campaigns
Idempotency-Key: camp-root-2026-11-12

{
  "name": "Internal baseline",
  "targets": {"domains": ["internal.example"], "ips": ["10.20.0.0/24"],
              "urls": [], "emails": [], "keywords": []},
  "policy": {"scan_profile": "low-impact", "max_parallel_jobs": 10,
             "blackout_windows": [], "max_duration_hours": 168},
  "objective": "Inventory and identify vulnerabilities without service disruption"
}

HTTP/1.1 202 Accepted
{"campaign_id": "camp-0001", "status": "CREATED", "policy_version": "roe-12"}
```

Quy ước chung:

- Gửi lại cùng `Idempotency-Key` với cùng nội dung trả về kết quả cũ. Cùng khóa nhưng khác nội dung trả về `409`.
- Lỗi trả về theo 14 mã lỗi chuẩn ở tab Tổng quan đặc tả, kèm `trace_id`.
- Job bị policy từ chối trả về `403` với lý do có cấu trúc và sinh sự kiện `policy.denied.v1`.
- Danh sách dài dùng phân trang theo cursor, không dùng offset.
- MVP chưa có đăng nhập người dùng. API chỉ mở qua private ingress hoặc VPN, có allowlist ở tầng mạng, giới hạn CORS, kiểm tra hợp lệ đầu vào, và mTLS hoặc service credential giữa các dịch vụ.

Các nhóm endpoint dưới đây không có trong tài liệu nguồn và đã được đưa vào thiết kế của M24 và M26. Ngoài ra có nhóm lịch sử, gồm `GET /assets/{id}/history` và `GET /findings/{id}/history`, trả về trạng thái và mức nghiêm trọng theo từng lần chạy, đọc từ bảng `FindingRun`:

- `POST /findings/{id}/transitions` để đổi trạng thái finding kèm lý do, và `GET /findings/{id}` để xem chi tiết kèm bằng chứng.
- `GET /reports/delta?from=&to=` để lấy báo cáo thay đổi giữa hai thời điểm.

## 5. Danh mục sự kiện

Sự kiện là cách các module báo cho nhau mà không gọi trực tiếp. Mọi sự kiện được giao theo kiểu ít nhất một lần, nên mọi consumer phải idempotent và khử trùng theo khóa nêu trong bảng.

| Sự kiện | Payload tối thiểu | Bên phát | Bên nhận và cách xử lý | Khóa khử trùng | Giai đoạn |
| --- | --- | --- | --- | --- | --- |
| `job.started.v1` | job\_id, campaign\_id, provider, time | M06 | M26 hiển thị, M25 đo | job\_id | GĐ1 |
| `job.completed.v1` | job\_id, status, evidence\_refs, time | M06 | M02 nhận làm signal của Temporal | job\_id | GĐ1 |
| `policy.denied.v1` | job\_id, lý do theo policy | M05 | M25 ghi audit, M24 thông báo | job\_id | GĐ1 |
| `asset.discovered.v1` | asset\_id, canonical\_key, kind, causal\_job\_id | M27 | M02 xếp việc tiếp theo trong RoE, M24 cảnh báo tài sản mới | asset\_id cộng revision | GĐ2 |
| `observation.changed.v1` | subject\_id, predicate, giá trị cũ và mới, time | M27 | M23 cập nhật delta, M20 đánh giá lại | observation\_id | GĐ2 |
| `artifact.ready.v1` | artifact\_id, digest, kind, storage\_uri | M28 | M02 kích hoạt SBOM và quét artifact | digest | GĐ2 |
| `knowledge.delta.v1` | revision, changed\_entities, causal\_job\_id | M23 | M02 và M03 chọn việc tiếp theo trong RoE | revision | GĐ2 |
| `intel.revision.v1` | feed, version, impacted\_ids | M18 | M20 đánh giá lại có chọn lọc | feed cộng version | GĐ2 |
| `finding.changed.v1` | finding\_id, trạng thái cũ và mới, evidence\_ref | M20, M21, M24 | M24 tính lại báo cáo và phát cảnh báo | finding\_id cộng số thứ tự chuyển trạng thái | GĐ2 |

Hai luồng cảnh báo sớm đi qua bảng này. Luồng thứ nhất bắt đầu từ thay đổi trên hệ thống của mình: `asset.discovered.v1` hoặc `observation.changed.v1` dẫn tới đánh giá lại rồi `finding.changed.v1`. Luồng thứ hai bắt đầu từ thế giới bên ngoài: `intel.revision.v1` khi có CVE mới hoặc KEV, EPSS đổi, dẫn tới M20 đánh giá lại các tài sản bị ảnh hưởng mà không cần quét lại.

**Thống nhất tên sự kiện.** Tài liệu 01 (HLD) dùng `intel.updated.v1` và `finding.confirmed.v1`, còn tài liệu 03 dùng `intel.revision.v1` và `finding.changed.v1` cho cùng mục đích. Bộ đặc tả này chọn tên của tài liệu 03 vì `finding.changed.v1` bao được mọi lần chuyển trạng thái, kể cả `FIXED` và `REGRESSED`, chứ không chỉ lúc xác nhận. Hai tên trong HLD không còn được dùng.

Tài liệu nguồn không nêu hạ tầng truyền sự kiện. Thiết kế chọn cho MVP là bảng outbox trong PostgreSQL cộng signal của Temporal, đủ cho quy mô một tổ chức. Message broker riêng chỉ cần cân nhắc khi số consumer tăng.

## 6. Cổng chất lượng dữ liệu G1 đến G7

Mọi ResultEnvelope đi qua bảy cổng ở M27 trước khi được ghi. Bản ghi không qua cổng không bị bỏ đi mà được cách ly để xem lại.

| Cổng | Kiểm tra | Nếu không đạt |
| --- | --- | --- |
| G1 Identity | Khóa chuẩn hợp lệ theo mục 2 | Cách ly bản ghi |
| G2 Provenance | Xác định được công cụ, phiên bản, thời điểm, job và nguồn | Đánh dấu thiếu căn cứ, không dùng để kết luận |
| G3 Evidence | Checksum khớp và tham chiếu lưu trữ tồn tại | Finding không thể lên `VERIFIED` |
| G4 Status | Giá trị enum đúng schema | Đưa vào dead-letter queue và báo lỗi |
| G5 Nguồn gốc mục tiêu | Mỗi tài sản và mỗi cạnh ghi rõ được tìm ra từ mục tiêu nào, bởi công cụ nào, trong lần chạy nào | Cách ly bản ghi cho tới khi bổ sung nguồn gốc |
| G6 Safety | Nội dung lấy từ mục tiêu quét được đánh dấu là dữ liệu, không phải chỉ dẫn | Cô lập nội dung, không đưa vào prompt như chỉ dẫn |
| G7 Dedup | Khóa duy nhất trong giao dịch | Gộp bản ghi, giữ các observation độc lập |

G5 và G6 không được tắt bằng cấu hình. Theo quyết định ngày 13/11, hệ thống không giới hạn phạm vi quét, nên G5 không chặn tài sản mà bảo đảm mọi tài sản và quan hệ đều truy được nguồn gốc. G6 không che secret, vì secret được lưu và hiển thị dạng rõ; G6 chỉ chặn nội dung từ mục tiêu quét chui vào prompt của agent như một chỉ dẫn.

Tiêu chí nghiệm thu của tab này ở cuối GĐ1: ghi 1.000 envelope đồng thời không tạo tài sản trùng; gửi lại cùng một envelope không tạo bản ghi mới; dựng lại toàn bộ Neo4j từ PostgreSQL cho kết quả giống hệt bản đang chạy; chạy hai lần quét liên tiếp trên cùng mục tiêu thì dữ liệu lần đầu còn nguyên và mỗi finding có một dòng FindingRun cho từng lần chạy.
