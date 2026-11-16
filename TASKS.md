# TASKS: AEGIS–Vanguard

> Danh sách việc nhỏ, làm theo thứ tự. Nguồn: [docs/living/02-ke-hoach-trien-khai.md](docs/living/02-ke-hoach-trien-khai.md).
> Quy ước: `[ ]` chưa làm, `[~]` đang làm, `[x]` xong. Mỗi task có mã `Tx.y`, module (Mxx) và tiêu chí xong. Chỉ làm task của giai đoạn đang mở (xem PROGRESS.md). Một task nên vừa một PR.

## GĐ0 Chuẩn bị (1–2 tuần, cổng G0) — ĐANG MỞ

Không viết mã sản phẩm ở GĐ0. Đầu ra là văn bản kết luận trong `docs/spikes/` và cấu hình môi trường trong `deploy/`.

- [ ] **T0.1** Chốt ngày bắt đầu; cấu hình agent review kiến trúc và agent review bảo mật (checklist review). *Xong khi:* checklist nằm trong `docs/review-checklists.md`.
- [ ] **T0.2** Spike 1: phiên LangGraph chạy trong Temporal như Activity hay child workflow; thử replay và hủy. *Xong khi:* có kết luận + mã thử trong `docs/spikes/01-langgraph-temporal.md`.
- [ ] **T0.3** Spike 2: Naabu và Nmap trong Podman rootless; có cần cấp riêng raw socket không. *Xong khi:* kết luận + cấu hình container tối thiểu.
- [ ] **T0.4** Spike 3: benchmark upsert Neo4j đồng thời với nhiều worker, không sinh nút trùng. *Xong khi:* số liệu + cách ràng buộc unique.
- [ ] **T0.5** Spike 4: MCP server đưa capability cho agent; truyền trace ID và idempotency key qua lời gọi MCP; vị trí điểm kiểm trước khi tạo container. *Xong khi:* kết luận + mẫu schema công cụ MCP.
- [ ] **T0.6** Spike 5: BBOT thụ động, output JSON → ResultEnvelope; nghĩa vụ AGPL khi dùng nội bộ. *Xong khi:* kết luận + parser thử.
- [ ] **T0.7** Bảng pin phiên bản: phiên bản, digest image, giấy phép, định dạng output của công cụ GĐ1–GĐ2 và thư viện giao diện; áp quy tắc chờ 14 ngày. *Xong khi:* `docs/pinning.md`.
- [ ] **T0.8** Môi trường dev trên máy đã có: Podman, registry image nội bộ, compose cho Temporal, PostgreSQL, Neo4j, SeaweedFS; ba mạng điều khiển, dữ liệu, thực thi; quyền gọi model chuẩn OpenAI hoặc Anthropic. *Xong khi:* `deploy/` khởi động được bằng một lệnh.
- [ ] **T0.9** Ước lượng dung lượng cho chính sách lưu vĩnh viễn. *Xong khi:* có con số trong `docs/capacity.md`.
- [ ] **T0.10** Dựng lab mục tiêu được phép quét: vài domain, host, image có lỗ hổng đã biết. *Xong khi:* danh sách mục tiêu lab trong `docs/lab.md`.
- [ ] **T0.11** Khóa backlog GĐ1: ticket cho S1–S4, S8a, chia sẵn cho subagent. *Xong khi:* Product Team duyệt; demo kết quả spike ở cổng G0.

## GĐ1 Nền tảng (4–5 tuần, cổng G1)

Thứ tự: tuần 1 chốt S1; tuần 2–4 chạy song song S2, S3, S4, S8a; tuần cuối tích hợp và demo. **S1 là điểm nghẽn: Product Team phải duyệt trong tuần đầu.**

### S1 Hợp đồng (M01, M05, M27)

> 2026-11-15: bản nháp T1.2–T1.8 và T1.19 đã có trong `contracts/` theo chỉ đạo Product Team (kéo sớm trong GĐ0), chờ duyệt. Xem [docs/s1/00-thanh-phan-va-quyet-dinh.md](docs/s1/00-thanh-phan-va-quyet-dinh.md).
- [ ] **T1.1** Khung repo theo ARCHITECTURE.md mục 6; CI chạy lint + test.
- [~] **T1.2** JSON Schema chiến dịch + RoE với năm loại đầu vào (IP, domain, URL, email, từ khóa).
- [~] **T1.3** Schema manifest `CapabilityProvider` v1.
- [~] **T1.4** Schema `ResultEnvelope` v1 + mã lỗi chuẩn.
- [~] **T1.5** Schema chín sự kiện `.v1`.
- [~] **T1.6** Schema công cụ MCP (capability cấp nghiệp vụ + truy vấn đồ thị chỉ đọc).
- [~] **T1.7** OpenAPI v1 cho 12 endpoint REST.
- [~] **T1.8** Bộ fixture + bộ conformance test cho adapter. *Xong khi:* schema test chạy trong CI; Product Team duyệt S1.

### S2 Engine bền vững (M01–M04)
- [ ] **T1.9** Temporal worker + `CampaignWorkflow` với pause, resume, cancel; Activity idempotent; Continue-As-New.
- [ ] **T1.10** Checkpoint LangGraph trên PostgreSQL; khung agent với một đường Planner chạy trọn.
- [ ] **T1.11** `ModelClient` với hai driver OpenAI và Anthropic; profile LOW/MID/HIGH; ghi token và chi phí; retry, timeout, fallback.
- [ ] **T1.12** API chiến dịch (M01): tạo, xem, pause, resume, cancel; RoE có phiên bản. *Xong khi:* tắt worker giữa chừng, chiến dịch tự chạy tiếp.

### S3 Cổng công cụ (M05, M06)
- [ ] **T1.13** MCP server đưa capability cấp nghiệp vụ cho agent.
- [ ] **T1.14** Registry đọc manifest từ thư mục `adapters/`.
- [ ] **T1.15** Điểm kiểm duy nhất trước mỗi lệnh: kiểm schema, tốc độ, khung giờ; cho qua mọi mục tiêu; ghi mục tiêu + lý do vào audit.
- [ ] **T1.16** `ContainerRunner` cho Podman theo hợp đồng container (RULES.md mục 3); chống trùng theo `job_fingerprint`; cancel, timeout; phát `job.started.v1`, `job.completed.v1`.
- [ ] **T1.17** Adapter mẫu DNSx (M09).
- [ ] **T1.18** Adapter mẫu Subfinder (M08), thêm **chỉ bằng manifest + parser**. *Xong khi:* không sửa mã lõi; container không vào được mạng dữ liệu.

### S4 Dữ liệu và đồ thị (M07, M23, M27, M28)
- [~] **T1.19** Khóa định danh chuẩn cho domain, IP, service, URL, email, image, repo, package.
- [ ] **T1.20** Ingestion API `POST /api/v1/ingestion/results` với bảy cổng chất lượng G1–G7; inbox + dead-letter queue.
- [ ] **T1.21** Evidence Store: SHA-256, signed URL, đoạn trích có giới hạn cho agent.
- [ ] **T1.22** Projector Neo4j (`MERGE` theo khóa chuẩn, tham số hóa); dựng lại được từ PostgreSQL.
- [ ] **T1.23** Bộ truy vấn đồ thị chỉ đọc dùng chung cho agent (qua MCP) và giao diện. *Xong khi:* ghi lặp song song không sinh bản ghi trùng.

### S8a Giao diện luồng quét và đồ thị (M26)
- [ ] **T1.24** Khung web React + TS + Vite theo DESIGN.md; dòng sự kiện SSE.
- [ ] **T1.25** Màn hình tạo và quản lý chiến dịch.
- [ ] **T1.26** Màn hình luồng quét (React Flow), chi tiết từng bước.
- [ ] **T1.27** Màn hình đồ thị tri thức (Cytoscape.js), nguồn gốc từng nút. *Xong khi:* người xem thấy chiến dịch chạy và đồ thị lớn dần mà không đọc log.

### Xuyên suốt (M25, M26)
- [ ] **T1.28** OpenTelemetry trace + audit chỉ ghi thêm kèm nguồn gốc mục tiêu.
- [ ] **T1.29** Tích hợp, demo G1: tạo chiến dịch → xem luồng và đồ thị → cắm Subfinder → tắt worker giữa chừng. *Xong khi:* đạt mọi điều kiện cổng G1.

## GĐ2 MVP Khám phá (4–6 tuần, cổng G2 = MVP)

- [ ] **T2.1** S5 Khám phá (M08–M10): adapter Subfinder, asnmap, BBOT thụ động, DNSx, Naabu, Nerva, cdncheck, httpx, Katana, Nuclei (toàn bộ mẫu chính thức + mẫu tùy chỉnh), tlsx, urlfinder; Nmap chỉ nhận diện sâu; nguồn tự dựng crt.sh, dnstwist; scan profile có trần tốc độ.
- [ ] **T2.2** S6 Chuỗi cung ứng (M13, M14, M18, M20): Trivy chính, Syft và Grype đối chứng; feed NVD, OSV, KEV, EPSS; khớp CVE–package; khử trùng nhiều provider.
- [ ] **T2.3** S7 Suy luận (M02, M03, M23): context builder, sổ giả thuyết, bộ đánh giá delta, điều kiện dừng; Planner + Analyst.
- [ ] **T2.4** S8b Findings và báo cáo (M24, M26): màn hình findings và job lỗi; xuất JSON; `GET /findings`.
- [ ] **T2.5** Cảnh báo sớm (M18, M20, M24): `intel.revision.v1` → đánh giá lại → `finding.changed.v1` → Telegram theo template; cảnh báo tài sản mới.
- [ ] **T2.6** Chất lượng (M07, M20, M23): thuộc tính chủ sở hữu, phơi nhiễm, độ quan trọng; bảng `FindingRun`.
- [ ] **T2.7** Mức nghiêm trọng do agent đánh giá kèm lý do, nguồn, điểm chưa chắc; `assessed_by.kind = agent|rule|operator`, fallback `UNRATED` (M20, D18, FR-018). *Xong khi:* mỗi finding có đánh giá hoặc `UNRATED` kèm tín hiệu thô.
- [ ] **T2.8** Kiểm thử credential (M17 module mật khẩu): sinh ứng viên mật khẩu từ dữ liệu thu được (OSINT, breach_lookup, endpoint đăng nhập) + thử đăng nhập; **T3 qua policy M05 + denylist bắt buộc, ghi người kích hoạt/duyệt** (D16, D17, D19). *Xong khi:* T3 tự duyệt mà denylist trống thì từ chối chạy.
- [ ] **T2.9** Xác minh động T3 (M03, M21): khai thác/kiểm chứng có kiểm soát để nâng finding CVE/dịch vụ từ `CANDIDATE`/`CORROBORATED` lên `VERIFIED`; đối chứng âm; không chạm T4; qua policy M05 + denylist (D14, FR-016). *Xong khi:* không VERIFIED nếu thiếu bằng chứng có checksum.
- [ ] **T2.10** Gia cố mức MVP: chaos test, bộ kiểm thử prompt injection, backup/restore, **soak test 7 ngày** (chạy sau khi đóng băng tính năng, muộn nhất tuần áp chót của GĐ2), hiệu năng cơ bản (M02, M06, M25). *Xong khi:* 7 ngày liên tục từ 10.000 bước điều phối không mất trạng thái.
- [ ] **T2.11** Demo G2: domain + từ khóa → finding có bằng chứng, có finding `VERIFIED` qua M21 và mức nghiêm trọng do agent; giả lập CVE vào KEV → tin Telegram; dòng thời gian một finding qua hai lần chạy; báo cáo soak 7 ngày.

Nếu GĐ2 vượt khung thời gian, phần lùi sang GĐ3 trước là Grype, cdncheck, urlfinder (bổ sung, không mở chuỗi mới). **Soak 7 ngày và bước xác minh T3 không rút ngắn được và không được lùi khỏi cổng G2 (quyết định Product Team 2026-11-16: T3, severity, bền-7-ngày thuộc MVP).**

## GĐ3 V1 Làm giàu (6–8 tuần, cổng G3)

- [ ] **T3.1** S9 Phân tích artifact (M15, M16, M28): webcrack, jsluice; bộ giải nén tự dựng (JADX, asar, Syft/Trivy, strings, Ghidra headless); container không mạng.
- [ ] **T3.2** S9b Mã nguồn và secret (M12, M17): Opengrep, Gitleaks, TruffleHog (**bật xác minh**, D17 — bước xác minh là T3), Betterleaks; credential Git chỉ đọc. *(Module mật khẩu `cred.test` đã chuyển lên GĐ2/T2.8 theo quyết định MVP-tới-T3 2026-11-16; GĐ3 chỉ mở rộng nguồn ứng viên từ secret quét được.)*
- [ ] **T3.3** S9c Cấu hình hạ tầng (M07, M11): Prowler, Kubescape, kube-bench; khóa chuẩn cloud và Kubernetes.
- [ ] **T3.4** Nguồn OSINT mở rộng (M08): SpiderFoot-ng thụ động; tra rò rỉ theo domain (API key do người dùng cấu hình); tìm mã nguồn công khai.
- [ ] **T3.5** PoC Availability Index metadata (M19, M20).
- [ ] **T3.6** Quét lại theo delta (M02, M23), FR-017.

## GĐ4 V1.5 Bảo đảm (4–6 tuần, cổng G4)

- [ ] **T4.1** S10 Gia cố mở rộng: chaos test nâng cao, bộ prompt injection đầy đủ, diễn tập backup/restore đạt RPO/RTO, **soak 7 ngày lặp lại ở cấu hình V1.5** (bắt đầu muộn nhất tuần 3 của GĐ4), hiệu năng với artifact 10 GB và đồ thị 1 triệu nút. *(Soak 7 ngày mức MVP đã đạt ở G2/T2.10; GĐ4 là kiểm lại ở quy mô lớn hơn.)*
- [ ] **T4.2** Xác minh mở rộng (M03, M21): Verifier đầy đủ cho các họ finding của GĐ3 (mã nguồn, secret, cloud, JS, nhị phân); đối chứng âm. *(Xác minh T3 lõi cho finding CVE/dịch vụ đã đạt ở G2/T2.9, FR-016.)*
- [ ] **T4.3** Hoàn thiện đánh giá mức nghiêm trọng cho các họ finding mới của GĐ3 (M20). *(Năng lực severity-do-agent đã đạt ở G2/T2.7, FR-018.)*
- [ ] **T4.4** Báo cáo SARIF, HTML, delta, bản cho lãnh đạo; gán chủ xử lý (M24, M26), FR-019.
- [ ] **T4.5** Tích hợp CI quét image và repo khi build, FR-020.
- [ ] **T4.6** Runbook, dashboard vận hành, checklist go-live (M25).

## Để sau (chưa lập lịch, KHÔNG làm)

M22 sub-agent Strix và Decepticon; red-team, C2; PR nháp bản vá (FR-022); đăng nhập, SSO, RBAC; Kubernetes; GUAC, DefectDojo, Dependency-Track.

## Rà soát tài liệu theo yêu cầu Product Team (2026-11-16)

- [x] **DOC-R1** Review SSE: đối chiếu rule và tính năng giữa các phần; ghi cặp dẫn chứng, tác động và hướng xử lý tại [báo cáo](docs/reviews/2026-11-16-document-consistency.md). Hoàn tất review, chưa hoàn tất khắc phục.
- [~] **DOC-R2** Xử lý R01–R18 trong báo cáo; đồng bộ phạm vi, đặc tả, task, cổng nghiệm thu và bản đồ HTML. *Đã xong:* R01, R04–R07, R10–R13, R15, R16 (sửa tài liệu/đặc tả/kế hoạch); R08, R09 đã sửa trước. R02/R03/R14: Product Team chốt kéo T3/severity/soak vào G2 (2026-11-16) — đã cập nhật PRD, kế hoạch, TASKS, đặc tả. *Còn lại:* R16/R17 trong `04-ban-do-module.html` (mức trình bày, đã gắn nhãn "để sau"); R18 gỡ đặc tả FR-022/M22 khỏi spec (tùy chọn).

- [x] **DOC-R3** Kiểm sâu R05, R08, R10–R15, R17–R18 sau feedback Claude; cập nhật phán định theo source/contract tại HEAD `54f123d`. [Báo cáo](docs/reviews/2026-11-16-ten-findings-deep-review.md).
