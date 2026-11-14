# Module lõi

Mười bảy module lõi là phần dự án tự xây. Mỗi module được đặc tả theo cùng một khuôn: mục đích, trách nhiệm, đầu vào, đầu ra, giao diện, dữ liệu sở hữu, phụ thuộc, quy tắc bắt buộc, tiêu chí nghiệm thu và giai đoạn giao.

## 1. Nhóm điều phối

### M01 Campaign và RoE

M01 quản lý chiến dịch, mục tiêu đầu vào và quy tắc tham chiến (RoE), rồi phát hành bản chụp policy mà mọi job phải mang theo.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Tạo, xem, tạm dừng, tiếp tục, hủy chiến dịch. Nhận năm loại đầu vào: IP, domain, URL, email, từ khóa. Ghi nguồn gốc của từng mục tiêu (không giới hạn phạm vi). Quản lý RoE: cửa sổ được quét, khung giờ cấm, giới hạn tốc độ, scan profile, số job song song, thời lượng tối đa. Khai báo ngân sách |
| Đầu vào | Tên, mục tiêu đầu vào (IP, domain, URL, email, từ khóa), policy, mục tiêu (objective) của chiến dịch |
| Đầu ra | `campaign_id`, `scope_id`, `policy_version`; trạng thái và bộ đếm chiến dịch |
| Giao diện | `POST /api/v1/campaigns`, `GET /api/v1/campaigns/{id}`, `POST .../pause`, `.../resume`, `.../cancel` |
| Dữ liệu sở hữu | Campaign, Policy (PostgreSQL) |
| Phụ thuộc | M02 để khởi chạy workflow; M25 để ghi audit |
| Quy tắc bắt buộc | Không chặn mục tiêu theo phạm vi, vì chế độ black box không biết trước phạm vi; tài sản quét được thì coi như thuộc tổ chức và mọi mục tiêu được ghi nguồn gốc. Mỗi thay đổi RoE sinh `policy_version` mới; bản chụp cũ không bị sửa. Tạo chiến dịch bắt buộc có `Idempotency-Key` |
| Nghiệm thu | FR-001, FR-002: cho qua mọi mục tiêu và ghi nguồn gốc mục tiêu vào audit; tài sản agent lần ra được coi là thuộc tổ chức và có quan hệ nguồn gốc trong đồ thị (chốt 13/11); 100% job chủ động gắn bản chụp policy và nguồn gốc mục tiêu |
| Giai đoạn | GĐ1 |

### M02 Campaign Controller

M02 là workflow Temporal giữ vòng đời chiến dịch nhiều ngày và là nguồn sự thật về trạng thái dài hạn.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Chạy vòng lặp chiến dịch. Xử lý signal tạm dừng, tiếp tục, hủy. Timer, retry, phân nhánh job. Đánh giá ngân sách và điều kiện dừng. Continue-As-New định kỳ |
| Trạng thái | CREATED, RUNNING, WAITING, PAUSED, COMPLETED, FAILED, CANCELLED |
| Đầu vào | `campaign_id`; delta tri thức; sự kiện job; signal từ người vận hành |
| Đầu ra | Lời gọi phiên agent; yêu cầu gửi job; bản chụp cuối chiến dịch; lý do dừng |
| Giao diện | Temporal signal và query; tiêu thụ `job.completed.v1`, `knowledge.delta.v1` |
| Dữ liệu sở hữu | Temporal Event History; campaign ledger (PostgreSQL) |
| Phụ thuộc | M01, M03, M05, M06, M27 |
| Quy tắc bắt buộc | History chỉ giữ ID và URI. Mọi Activity idempotent. Không busy polling. Nếu 3 đến 5 chu kỳ liên tiếp không có bằng chứng mới hữu ích thì giảm cấp hoặc tạm dừng và ghi lý do. Pause giữ job theo policy; cancel phát tín hiệu tới worker |
| Nghiệm thu | FR-006: kill worker giữa chừng không mất tiến độ, không sinh job trùng. GĐ4: 7 ngày, từ 10.000 bước điều phối |
| Giai đoạn | GĐ1; kiểm thử độ bền ở GĐ4 |

### M03 Agent Harness

M03 là đồ thị LangGraph chạy các phiên suy luận ngắn: đọc tri thức mới, lập kế hoạch, đọc kết quả và quyết định bước tiếp theo. Agent chỉ đề xuất; M05 quyết định.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Ba vai trò: Planner lập kế hoạch, Analyst cập nhật giả thuyết từ kết quả, Verifier đối chiếu bằng chứng. Quản lý ngữ cảnh và sổ giả thuyết |
| Các nút đồ thị | BuildContext, Planner, PolicyCheck, ToolSelect, ReviewResult, DecideNext |
| Đầu vào | Mục tiêu, delta đồ thị, RoE, tóm tắt capability (ContextBundle v1) |
| Đầu ra | TaskPlan dạng JSON; HypothesisUpdates có độ tin cậy và bằng chứng; quyết định continue, wait hoặc stop |
| Giao diện | Được M02 gọi như một Temporal Activity. Gọi M04 để suy luận, M05 để tìm capability, M23 để đọc tri thức |
| Dữ liệu sở hữu | Checkpoint phiên (PostgreSQL), Hypothesis |
| Phụ thuộc | M04, M05, M23 |
| Quy tắc bắt buộc | Không shell, không Cypher tự do, không credential mục tiêu. Mỗi phiên bắt đầu với ngữ cảnh sạch, 10 đến 30 quan sát, khoảng 30 bước. Không nạp log thô vào prompt. Output được kiểm bằng JSON Schema. Output công cụ là dữ liệu không tin cậy. Điều kiện dừng nằm trong mã |
| Nghiệm thu | FR-005: resume sau restart, không mất sổ nhiệm vụ. Kiểm thử prompt injection: chỉ dẫn cài trong output công cụ không tạo ra job trái phép |
| Giai đoạn | GĐ1: khung, một đường Planner chạy trọn vẹn. GĐ2: context builder, sổ giả thuyết, bộ đánh giá delta. GĐ4: Verifier đầy đủ |

### M04 LLM Gateway

M04 là cửa duy nhất để gọi model, lo định tuyến, ghi chi phí và fallback.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Ánh xạ profile LOW, MID, HIGH sang model. Ghi token và chi phí theo chiến dịch. Fallback khi nhà cung cấp lỗi hoặc giới hạn tốc độ |
| Đầu vào | Lời gọi qua `ModelClient` kèm profile và `campaign_id` |
| Đầu ra | Kết quả model; metric lời gọi |
| Giao diện | `ModelClient` interface nội bộ tự dựng, hai driver theo chuẩn OpenAI và Anthropic; không dùng LiteLLM |
| Dữ liệu sở hữu | Bản ghi sử dụng model |
| Phụ thuộc | M25 |
| Quy tắc bắt buộc | Ngưỡng ngân sách do mã cưỡng chế. Fallback chỉ khi policy dữ liệu cho phép. Không che secret khi gửi model (chốt 13/11) |
| Nghiệm thu | Đo được token và chi phí theo từng chiến dịch. Khi nhà cung cấp trả 429, hệ thống fallback hoặc chờ và báo rõ việc còn dang dở |
| Giai đoạn | GĐ1 |

## 2. Nhóm thực thi và policy

### M05 Capability Registry và điểm kiểm trong MCP server

M05 là điểm cưỡng chế: nó biết hệ thống có năng lực gì và quyết định thao tác nào được chạy.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Lưu manifest provider và schema có phiên bản. Tìm provider theo capability và kiểu đầu vào. Theo dõi sức khỏe provider. Chạy như một lớp mỏng trong MCP server: mỗi công cụ MCP ứng với một capability. Kiểm schema đầu vào, tốc độ, tầng tác động và ghi nguồn gốc mục tiêu. Cho qua mọi mục tiêu ở mọi giai đoạn (chốt 13/11); khung giờ và yêu cầu duyệt là cấu hình tùy chọn |
| Đầu vào | Kế hoạch của agent hoặc yêu cầu job: capability, input, mục tiêu, profile |
| Đầu ra | Danh sách ApprovedTask kèm provider đã chọn và `policy_version`; hoặc từ chối kèm mã lỗi |
| Giao diện | `GET /api/v1/capabilities`; công cụ MCP cho agent (tools/list, tools/call); API validate nội bộ; phát `policy.denied.v1` |
| Dữ liệu sở hữu | Manifest (GitOps), nhật ký quyết định policy |
| Phụ thuộc | M01 để lấy bản chụp policy; M25 |
| Chọn provider | Lọc theo sức khỏe và tương thích schema, lọc theo policy, rồi xếp hạng theo độ phủ, an toàn, độ tin cậy, chi phí, độ trễ. Không còn provider thì trả BLOCKED |
| Quy tắc bắt buộc | Mặc định từ chối; capability lạ bị từ chối. LLM có thể đề xuất, policy và schema do mã quyết định. Chuẩn hóa mục tiêu trước khi kiểm (dạng IP thay thế, IDNA, redirect). Agent chỉ thấy capability cấp nghiệp vụ, không thấy toàn bộ danh mục công cụ |
| Nghiệm thu | FR-003: trả provider tương thích, từ chối capability lạ. Schema sai và vượt tốc độ đều fail-closed; khung giờ cấm, nếu được cấu hình, cũng fail-closed. Thêm Subfinder chỉ cần manifest và parser, không sửa mã lõi. Lookup P95 dưới 300 ms với 100 provider |
| Giai đoạn | GĐ1 |

### M06 Execution Gateway

M06 biến một task đã duyệt thành đúng một container Podman cô lập, gọi qua interface ContainerRunner (Kubernetes Job về sau) và theo dõi nó tới khi có kết quả.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Chống trùng job. Tạo, theo dõi, hủy container qua ContainerRunner (Podman ở GĐ1). Áp giới hạn tài nguyên và timeout. Đối soát trạng thái container trên máy chạy |
| Trạng thái job | QUEUED, VALIDATING, DISPATCHED, RUNNING, COLLECTING, SUCCEEDED, FAILED, CANCELLED |
| Đầu vào | ApprovedTask từ M05 |
| Đầu ra | `job.started.v1`, `job.completed.v1`; tham chiếu artifact thô |
| Giao diện | `POST /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel` |
| Dữ liệu sở hữu | ScanJob (PostgreSQL) |
| Phụ thuộc | M05, Podman qua ContainerRunner, M28 để cấp signed URL |
| Quy tắc bắt buộc | Unique trên `job_fingerprint`. Kiểm job đã tồn tại trước khi tạo. Chỉ chạy image trong allowlist, theo digest. Container không mount socket Podman, không privileged, không dùng host network. Không nhận lệnh CLI tùy ý, chỉ nhận tham số có cấu trúc. Timeout và cancel phải kết thúc container và báo kết quả trung thực |
| Nghiệm thu | FR-004. Gửi cùng key 100 lần chỉ tạo một job. Container công cụ chỉ ra được mạng thực thi, không chạm tới mạng điều khiển và mạng dữ liệu. Độ trễ hàng đợi P95 dưới 2 phút với 50 job đồng thời |
| Giai đoạn | GĐ1 |

## 3. Nhóm dữ liệu và tri thức

### M27 Ingestion và Normalizer

M27 là cửa ghi duy nhất vào kho tri thức: mọi kết quả scanner phải đi qua đây để được kiểm tra, chuẩn hóa và khử trùng.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Kiểm JSON Schema của ResultEnvelope. Xác thực checksum bằng chứng. Lưu inbox event với `event_id` duy nhất và dedup key. Upsert PostgreSQL trong giao dịch. Áp bảy cổng chất lượng dữ liệu |
| Đầu vào | ResultEnvelope từ scanner; file xuất sẵn JSON, SARIF, SBOM (cấp tích hợp L0) |
| Đầu ra | Asset, Observation, Finding ứng viên đã chuẩn hóa; `asset.discovered.v1`, `observation.changed.v1`, `knowledge.delta.v1` |
| Giao diện | `POST /api/v1/ingestion/results` |
| Dữ liệu sở hữu | Inbox event, dead-letter queue, vùng cách ly |
| Phụ thuộc | M28, M07, M23 |
| Quy tắc bắt buộc | Consumer idempotent, giao nhận at-least-once. Giá trị mâu thuẫn được lưu thành nhiều observation, không ghi đè. Bản ghi sai định danh bị cách ly. Không xóa, không ghi đè: mỗi lần chạy ghi thêm bản ghi mới gắn scan\_id. Secret đi qua kèm fingerprint để chống trùng |
| Nghiệm thu | Replay 1.000 sự kiện không sinh bản ghi trùng. Parse lại cùng fixture cho cùng canonical ID. P95 dưới 30 giây với output dưới 1 MB |
| Giai đoạn | GĐ1 |

### M07 Asset Inventory

M07 giữ danh mục tài sản chuẩn: mỗi tài sản thật chỉ có một bản ghi, dù được nhiều công cụ nhìn thấy dưới nhiều tên.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Sinh và kiểm khóa định danh chuẩn. Hợp nhất thực thể và quản lý bí danh. Giữ chủ sở hữu, mức phơi nhiễm, độ quan trọng, `first_seen` và `last_seen` |
| Đầu vào | Thực thể đã chuẩn hóa từ M27; khai báo chủ sở hữu và độ quan trọng từ người vận hành |
| Đầu ra | Asset với `asset_id` và `canonical_key` ổn định |
| Giao diện | Nội bộ cho M27, M20, M24; đọc qua `GET /api/v1/assets/{id}/graph` |
| Dữ liệu sở hữu | Asset, AssetAlias, Service, Endpoint, Package (PostgreSQL) |
| Phụ thuộc | M27, M23 |
| Quy tắc bắt buộc | Ràng buộc unique trên `canonical_key`. Tag image và nhánh git chỉ là bí danh. Không gán chủ sở hữu khi chưa có nguồn gốc. Không lưu token hoặc query nhạy cảm trong URL |
| Nghiệm thu | FR-010: retry không tạo thực thể trùng. FR-007: đồ thị đủ chuỗi domain, IP, dịch vụ, endpoint |
| Giai đoạn | GĐ1: định danh và hợp nhất. GĐ2: chủ sở hữu, phơi nhiễm, độ quan trọng |

### M23 Knowledge Graph và Delta

M23 chiếu dữ liệu sang Neo4j, theo dõi thay đổi tri thức theo revision và cung cấp Graph Query API chỉ đọc cho giao diện, và cho agent qua công cụ MCP truy vấn đồ thị (có từ GĐ1).

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Graph projector ghi Neo4j bằng Cypher tham số hóa. Quản lý quan hệ có thời gian. Phát delta theo revision. Phục vụ tập truy vấn đã đăng ký |
| Đầu vào | Bản ghi đã commit ở PostgreSQL |
| Đầu ra | Nút và cạnh đồ thị; `knowledge.delta.v1` gồm revision, thực thể đổi, job gây ra |
| Truy vấn đăng ký | `get_asset_neighbors`, `get_recent_observations`, `get_unverified_hypotheses`, `get_package_cve_matches`, `summarize_campaign_delta`, `get_evidence_excerpt` |
| Giao diện | Graph Query service nội bộ; `GET /api/v1/assets/{id}/graph` |
| Dữ liệu sở hữu | Đồ thị Neo4j, revision và cursor |
| Phụ thuộc | M27, M07 |
| Quy tắc bắt buộc | Mỗi truy vấn có giới hạn số bước nhảy, số bản ghi, timeout và điều kiện theo chiến dịch. Cạnh không còn thấy được đặt valid\_to, không xóa. Không Cypher tự do trong production. Xung đột ghi được retry với exponential backoff. Dữ liệu quá hạn được gắn nhãn stale trước khi dùng để suy luận. Đồ thị dựng lại được từ event log |
| Nghiệm thu | Benchmark upsert đồng thời 100 worker không sinh nút trùng. Truy vấn vượt giới hạn bị cắt và báo rõ |
| Giai đoạn | GĐ1: projector và ràng buộc. GĐ2: delta và tập truy vấn cho agent |

### M28 Evidence Store

M28 lưu bằng chứng thô bất biến để mọi finding truy được về nguồn.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Cấp signed URL để scanner tải lên. Lưu object theo SHA-256. Phân loại để phân quyền xem; dữ liệu lưu vĩnh viễn. Không che dữ liệu (chốt 13/11). Trả đoạn trích có giới hạn cho agent |
| Đầu vào | Output thô của scanner, artifact, báo cáo |
| Đầu ra | `evidence_id`, `sha256`, `storage_uri`, phân loại |
| Giao diện | Signed URL; đọc qua `get_evidence_excerpt` |
| Dữ liệu sở hữu | Object ở MinIO; metadata Evidence và Artifact ở PostgreSQL |
| Phụ thuộc | MinIO |
| Quy tắc bắt buộc | Object bất biến. Phân loại PUBLIC, INTERNAL, RESTRICTED, dùng cho quyền xem về sau; dữ liệu lưu vĩnh viễn, không che. Không chạy nhị phân hay script lấy về trong control plane. Secret lưu dạng rõ kèm fingerprint (chốt 13/11) |
| Nghiệm thu | FR-011: 100% finding có bằng chứng hoặc trạng thái unsupported. Hash khớp sau diễn tập phục hồi |
| Giai đoạn | GĐ1 |

## 4. Nhóm tình báo và đánh giá

### M18 Vuln Feed Sync

M18 đồng bộ tình báo lỗ hổng từ nguồn chính thống và là một trong hai nguồn kích hoạt cảnh báo sớm.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Đồng bộ theo delta từ NVD, OSV, CISA KEV, FIRST EPSS; GHSA là nguồn bổ sung. Chuẩn hóa thành bản ghi intel có phiên bản. Phát sự kiện khi có thay đổi |
| Đầu vào | API và file máy đọc được của các nguồn, không scrape trang web |
| Đầu ra | Vulnerability: `source`, `vulnerability_id`, CVSS, dải phiên bản ảnh hưởng, cờ KEV, điểm EPSS; `intel.revision.v1` |
| Giao diện | Worker chạy theo lịch; cache intel nội bộ |
| Dữ liệu sở hữu | Intel cache có phiên bản |
| Phụ thuộc | Truy cập mạng ra các nguồn feed; M25 |
| Quy tắc bắt buộc | Lưu thời điểm snapshot và phiên bản nguồn để tái lập được điểm rủi ro trong quá khứ. Feed lỗi không làm dừng scanner. Nội dung feed là dữ liệu không tin cậy đối với agent |
| Nghiệm thu | FR-009. Độ trễ KEV dưới 2 giờ, EPSS dưới 24 giờ. Thay đổi schema của feed được phát hiện và báo lỗi |
| Giai đoạn | GĐ2 |

### M19 PoC Availability Index

M19 ghi nhận một CVE đã có mã khai thác công khai hay chưa, chỉ ở mức metadata, để làm tín hiệu ưu tiên.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Lập chỉ mục tham chiếu và metadata về PoC cho từng CVE |
| Đầu vào | Định danh CVE; metadata từ SploitScan và GitHub |
| Đầu ra | `exploit_reference_available`, `source_type`, `source_reputation`, `published_at`, `safe_validation_available`, `review_status` |
| Giao diện | Nội bộ cho M20 |
| Dữ liệu sở hữu | Bảng metadata PoC |
| Phụ thuộc | M18 |
| Quy tắc bắt buộc | Không tải về và không chạy mã PoC. PoC từ Internet là không tin cậy. Có PoC công khai không đồng nghĩa đã xác minh khai thác được |
| Nghiệm thu | Không có job nào thực thi mã PoC. Metadata có nguồn và thời điểm |
| Giai đoạn | GĐ3 |

### M20 Correlation và Scoring

M20 khớp lỗ hổng đã biết với tài sản thật, sinh finding ứng viên và xếp ưu tiên theo bối cảnh.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Khớp CVE với package theo pURL và dải phiên bản, dùng CPE khi không có pURL. Khử trùng finding từ nhiều scanner. Xếp ưu tiên. Đánh giá lại chọn lọc khi intel hoặc tài sản thay đổi |
| Đầu vào | Package và dịch vụ trong đồ thị; bản ghi intel; `intel.revision.v1`, `observation.changed.v1` |
| Đầu ra | Finding với `match_method`, độ tin cậy; mức nghiêm trọng do agent đánh giá kèm `reasons[]`, `source_refs[]`, `uncertainty[]`, `recommended_actions[]`; `finding.changed.v1` |
| Giao diện | Nội bộ; kết quả đọc qua `GET /api/v1/findings` |
| Dữ liệu sở hữu | Finding (PostgreSQL là nguồn sự thật), mức nghiêm trọng do agent đánh giá kèm lý do |
| Phụ thuộc | M07, M23, M18, M19 |
| Luật ưu tiên | Finding chỉ được coi là lỗ hổng khi có bằng chứng xác nhận và dẫn chứng để người dùng tự kiểm lại. AI agent đánh giá mức nghiêm trọng dựa trên CVSS, KEV, EPSS, mức phơi nhiễm và bằng chứng, ghi rõ lý do; không dùng công thức trọng số (chốt 13/11) |
| Quy tắc bắt buộc | Fingerprint finding tính từ `asset_id`, `rule_id`, vị trí và ngữ cảnh bằng chứng; không dùng ID riêng của scanner. Không cộng thô EPSS với CVSS. Không trả về con số thiếu giải thích. LLM không tạo finding trực tiếp |
| Nghiệm thu | Cùng package từ Trivy, OSV, Grype cho một finding với ba tham chiếu bằng chứng. Mỗi finding có bằng chứng xác nhận, dẫn chứng và mức nghiêm trọng kèm lý do. Mỗi lần chạy ghi một dòng FindingRun, kể cả khi không còn thấy lỗ hổng. Nâng cấp ra ngoài dải ảnh hưởng thì rescan đóng finding bằng bằng chứng mới |
| Giai đoạn | GĐ2: khớp CVE, khử trùng, luật KEV, đánh giá lại theo feed. GĐ4: agent đánh giá mức nghiêm trọng kèm lý do (FR-018) |

### M21 Evidence Verification

M21 nâng một finding từ ứng viên lên đã xác minh bằng phương pháp an toàn, không khai thác.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Xác minh bằng kiểm tra xác định: so phiên bản, kiểm phản hồi HTTP, đối chiếu chéo scanner, mẫu Nuclei. Chạy đối chứng âm. Trình bày bằng chứng và dẫn chứng để người dùng tự kiểm lại. Chuyển trạng thái finding |
| Đầu vào | Finding CANDIDATE hoặc CORROBORATED đã triage |
| Đầu ra | Trạng thái VERIFIED, CORROBORATED, FALSE\_POSITIVE hoặc giữ nguyên kèm lý do; bằng chứng xác minh |
| Giao diện | Nội bộ; gửi job xác minh qua M05 và M06 |
| Dữ liệu sở hữu | Lịch sử chuyển trạng thái finding; bảng FindingRun theo từng lần chạy (cùng M20) |
| Phụ thuộc | M20, M05, M06, M28 |
| Quy tắc bắt buộc | Chỉ dùng thao tác tầng T0 đến T2. Không VERIFIED nếu thiếu bằng chứng có checksum. Verifier dùng LLM chỉ khi cần diễn giải, và phải trả khẳng định kèm tham chiếu bằng chứng và độ tin cậy. Mọi thay đổi trạng thái ghi nguồn, thời điểm, bằng chứng |
| Nghiệm thu | FR-016: tách rõ verified, corroborated, unknown. Có đối chứng âm cho finding mức cao |
| Giai đoạn | GĐ4 |

## 5. Nhóm giao diện và vận hành

### M26 Web UI và Backend API

M26 là nơi người vận hành tạo chiến dịch và thấy agent đã làm gì, lỗi ở đâu, còn gì chưa làm.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | REST API v1 và SSE. Màn hình luồng quét và đồ thị tri thức (GĐ1); chiến dịch và findings (GĐ2). Dòng sự kiện thời gian thực. Cấu hình policy |
| Đầu vào | Thao tác của người vận hành |
| Đầu ra | Trạng thái chiến dịch, timeline, danh sách findings, bản xuất |
| Giao diện | REST API v1 (xem tab Dữ liệu, API và sự kiện); `GET /api/v1/campaigns/{id}/events` qua SSE |
| Dữ liệu sở hữu | Không; stateless trên PostgreSQL |
| Phụ thuộc | M01, M06, M23, M24 |
| Quy tắc bắt buộc | Chưa có đăng nhập ở MVP; chỉ truy cập qua private ingress hoặc VPN. Phải hiển thị minh bạch trạng thái bị chặn, chưa xong và lỗi. Phân trang bằng cursor |
| Nghiệm thu | FR-012. 100% job lỗi có phân loại lỗi và bước tiếp theo trên giao diện |
| Giai đoạn | GĐ1: API, màn hình luồng quét (React Flow) và màn hình đồ thị tri thức (Cytoscape.js), cập nhật qua SSE. GĐ2: màn hình findings và quản lý chiến dịch đầy đủ |

### M24 Reporting và Remediation

M24 biến finding thành cảnh báo, báo cáo và việc cần làm, rồi theo dõi tới khi được khắc phục.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Quản lý vòng đời finding. Cảnh báo sớm qua Telegram khi finding mới hoặc đổi mức nghiêm trọng; template và group id cấu hình được, ngưỡng gửi chốt sau. Báo cáo delta giữa hai thời điểm. Xuất SARIF, JSON, HTML. Gán chủ xử lý, gợi ý khắc phục, yêu cầu rescan |
| Vòng đời finding | CANDIDATE, CORROBORATED, VERIFIED, FALSE\_POSITIVE, ACCEPTED\_RISK, FIXED, REGRESSED |
| Đầu vào | `finding.changed.v1`; thao tác triage của người dùng |
| Đầu ra | Cảnh báo, báo cáo, yêu cầu rescan |
| Giao diện | `GET /api/v1/findings` có lọc và xuất |
| Dữ liệu sở hữu | Báo cáo đã sinh; lịch sử triage |
| Phụ thuộc | M20, M21, M28 |
| Quy tắc bắt buộc | Báo cáo hiển thị đầy đủ, kể cả secret (chốt 13/11). Mỗi lỗ hổng kèm bằng chứng và dẫn chứng. Không có khẳng định thiếu bằng chứng. Không tự áp bản vá, không tự merge. PR nháp (FR-022) thuộc nhánh để sau |
| Nghiệm thu | FR-019: output hợp lệ theo chuẩn. Finding đã sửa được đóng bằng rescan có bằng chứng mới |
| Giai đoạn | GĐ2: danh sách, xuất JSON, cảnh báo cơ bản. GĐ4: SARIF, HTML, delta, quy trình khắc phục đầy đủ |

Kênh cảnh báo đã chốt ngày 12/11 là Telegram, gửi vào nhóm nội bộ qua bot. Email và hệ thống ticket có thể thêm sau. DefectDojo là lựa chọn tích hợp tùy chọn nếu muốn dùng lại quy trình quản lý lỗ hổng có sẵn.

### M25 Telemetry và Audit

M25 cho phép trả lời câu hỏi "hệ thống đã chạy gì, trên mục tiêu nào, theo policy nào" cho mọi thao tác.

| Mục | Đặc tả |
| --- | --- |
| Trách nhiệm | Thu trace, metric, log theo OpenTelemetry. Ghi audit chỉ ghi thêm cho kế hoạch, quyết định policy, lệnh gọi công cụ, duyệt, thay đổi đồ thị. Phục vụ dashboard vận hành |
| Đầu vào | Telemetry từ mọi module |
| Đầu ra | Dashboard, cảnh báo vận hành, truy vấn audit |
| Giao diện | OTel collector; truy vấn audit nội bộ |
| Dữ liệu sở hữu | Audit log (PostgreSQL), kho metric và log |
| Phụ thuộc | Không |
| Quy tắc bắt buộc | Mọi bản ghi mang đủ bộ ID truy vết. Audit không sửa, không xóa, lưu vĩnh viễn |
| Nghiệm thu | 100% tác vụ có campaign, job và trace ID. Truy vấn audit chứng minh 100% job chủ động gắn `scope_id` và `policy_version` |
| Giai đoạn | GĐ1 |
