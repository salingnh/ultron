# AEGIS–Vanguard: Tổng quan hệ thống hợp nhất

Nov 12, 2026 · @T

## 1. Tóm tắt điều hành

AEGIS–Vanguard là nền tảng **kiểm thử xâm nhập (pentest) chủ động** nội bộ kiêm quản trị bề mặt tấn công, do AI Agent điều phối trên tài sản mà tổ chức sở hữu hoặc được ủy quyền. Hệ thống hợp nhất các công cụ OSS rời rạc thành một vòng lặp liên tục: khám phá, làm giàu tri thức, đối chiếu lỗ hổng, kiểm chứng động (tới T3), cảnh báo và theo dõi khắc phục.

Ba điểm định hướng đã chốt (cập nhật D14–D16, 2026-11-16):

- **Pentest chủ động tới T3.** Giá trị cốt lõi là biết sớm tài sản nào phơi nhiễm và lỗ hổng nào **thật sự khai thác được**, kèm bằng chứng. Hệ thống chủ động khai thác và kiểm chứng động tới tầng T3 (xâm nhập), gồm kiểm thử credential (sinh ứng viên mật khẩu và thử đăng nhập). Hệ thống không tự vá production.
- **Agent harness nằm trong MVP.** Agent lập kế hoạch và điều phối ngay từ GĐ1, nhưng chỉ sinh ra "ý định thao tác". Lớp policy bằng mã mới quyết định thao tác nào được chạy; hành vi T3 **bắt buộc đối chiếu denylist** cưỡng chế bằng mã (D16).
- **T4 để sau.** Các năng lực sâu hơn T3 — C2, persistence, lateral movement, post-exploitation, sub-agent red-team của Decepticon và Strix — **cấm mặc định**, chỉ xem xét sau nghiệm thu qua threat model và phê duyệt riêng.

Tài liệu này là bản tổng quan chuẩn của dự án. Khi các tài liệu khác mâu thuẫn với nó, nội dung ở đây được ưu tiên.

## 2. Các quyết định thống nhất

Ba nguồn tài liệu hiện có lệch nhau ở tám điểm. Bảng dưới ghi quyết định chốt cho từng điểm. "Bản gốc" là đặc tả Offensive Vaccine và bản HTML v2.6. "UDEP" là báo cáo deep-research. "Bộ 00–04" là năm tài liệu thiết kế AEGIS–Vanguard v1.0.

| Điểm lệch | Bản gốc | UDEP | Bộ 00–04 | Quyết định chốt |
| --- | --- | --- | --- | --- |
| Định vị | "Vaccine tấn công": tấn công giả lập rồi phòng thủ | Nền tảng tri thức và kiểm chứng phòng thủ | Đánh giá bề mặt tấn công có kiểm soát | **Pentest chủ động nội bộ tới T3** (D14, 2026-11-16; trước đó là phòng thủ và cảnh báo sớm) |
| Agent trong MVP | Có, 16 tác tử tự hành | Không, để tới v2 | Có, harness có giới hạn | **Có.** Harness thuộc MVP, agent chỉ đề xuất, policy quyết định |
| Khai thác và chạy PoC | Tự chạy PoC trong sandbox | Cấm, chỉ kiểm chứng không phá hoại | Chỉ lập chỉ mục metadata PoC | **Khai thác/kiểm chứng động tới T3 do nền tảng kiểm soát** (D14). M19 chỉ metadata; không chạy PoC không tin cậy từ Internet (T4) |
| Red-team, C2, post-exploit | Có (Sliver, BloodHound, evil-winrm) | Loại bỏ | Cấm mặc định (T4) | Để sau. Ngoài phạm vi MVP và V1 |
| Tự vá lỗi | Tự viết bản vá và mở Pull Request | Chỉ quy trình remediation | Đề xuất PR nháp ở P2 | Chỉ gợi ý khắc phục. PR nháp để sau, không tự merge |
| Dùng 4 OSS trọng tâm | Hợp nhất trực tiếp kiến trúc của cả bốn | Không fork, chỉ hấp thụ pattern | Không fork, tích hợp qua adapter | Không fork. Tích hợp qua Capability Registry và Adapter SDK |
| Ghi vào đồ thị | Neo4j nối cả hai vùng mạng, qua Graph Conductor | Normalizer rồi mới ghi | Ingestion API trung tâm, không dual-home | Ingestion API tự xây. Graph Conductor mới là RFC, không dùng |
| Tenancy và đăng nhập | Không nêu rõ | Multi-tenant, OIDC, RBAC | Single-tenant, chưa login ở MVP | Single-tenant, chưa login ở MVP. Thiết kế sẵn chỗ để thêm SSO và RBAC |

Tên dự án giữ là **AEGIS–Vanguard**. Khái niệm UDEP của báo cáo deep-research được dùng như nguồn tham chiếu kiến trúc, không phải tên sản phẩm.

Ba dòng cuối (cách dùng OSS, ghi vào đồ thị, tenancy) và tên dự án là đề xuất theo bộ 00–04, chưa được Product Team xác nhận riêng.

**Cập nhật ngày 13/11/2026.** Bản tổng quan này đã được sửa theo các quyết định ngày 12 và 13/11: không giới hạn phạm vi quét mà ghi nguồn gốc trên từng quan hệ, secret lưu và hiển thị dạng rõ, AI agent đánh giá mức nghiêm trọng thay cho công thức trọng số, không đo precision và recall, lưu vĩnh viễn kèm lịch sử theo từng lần chạy, scanner chạy trong container Podman. Bảng quyết định đầy đủ nằm ở tab Tổng quan của [bộ đặc tả](dac-ta-ky-thuat/README.md).

## 3. Bài toán, mục tiêu và phi mục tiêu

Đội an ninh hiện phải ghép tay kết quả từ nhiều công cụ quét không chung định danh tài sản, nên findings trùng lặp, thiếu bối cảnh và đến chậm. AEGIS–Vanguard giải năm vấn đề sau.

| Hiện trạng | Hệ quả | Cách giải |
| --- | --- | --- |
| Kết quả Nmap, Nuclei, Trivy, OSINT không có định danh tài sản chung | Findings trùng lặp, mất quan hệ giữa tài sản | Ontology chuẩn, hợp nhất thực thể, ghi nguồn gốc cho mọi dữ liệu |
| Rà quét theo kế hoạch tĩnh | Bỏ sót tài sản mới và mối liên hệ mới | Agent tự sinh nhiệm vụ tiếp theo, dựa trên tri thức mới |
| Mỗi OSS một giao thức, một runtime | Chi phí tích hợp cao | Một hợp đồng capability, adapter và bộ conformance test |
| Agent chạy dài dễ lỗi, tràn ngữ cảnh, lặp vô ích | Không đủ tin cậy để vận hành | Temporal giữ vòng đời, LangGraph chạy phiên ngắn có checkpoint, ngân sách và điều kiện dừng |
| Xác minh và ưu tiên lỗ hổng thiếu bối cảnh | Tốn công SOC và AppSec, cảnh báo muộn | Đối chiếu CVE, KEV, EPSS với mức phơi nhiễm, độ quan trọng và bằng chứng |

**Mục tiêu MVP**

- Khám phá tài sản theo ba góc nhìn black-box, gray-box, white-box, xuất phát từ mục tiêu được khai báo và ghi nguồn gốc cho mọi tài sản tìm thêm.
- Chiến dịch rà quét bền vững tới 7 ngày, có tạm dừng, tiếp tục và retry an toàn.
- Agent harness lập kế hoạch nhiều vòng, có checkpoint và ngân sách.
- Đồ thị tri thức và kho bằng chứng truy vết được từ tên miền tới finding.
- Đối chiếu lỗ hổng với CVE, OSV, KEV, EPSS và cảnh báo sớm theo mức ưu tiên.
- Giao diện web nội bộ cho thấy agent đã làm gì, lỗi ở đâu, còn gì chưa làm.

**Không thuộc MVP**

- Tầng T4 (cấm mặc định): C2, persistence, lateral movement, post-exploitation, sub-agent red-team.
- Tự chạy mã PoC **không tin cậy** lấy từ Internet (T4). MVP chỉ lập chỉ mục metadata về PoC; khai thác/kiểm chứng động chỉ qua năng lực T3 do nền tảng kiểm soát.
- Tự áp bản vá hoặc tự merge thay đổi vào production.
- Multi-tenant, SSO và RBAC người dùng.
- Viết lại hoặc fork các scanner OSS.

## 4. Người dùng và kịch bản chính

Năm nhóm người dùng nội bộ dùng chung một đồ thị tri thức, mỗi nhóm với một kịch bản riêng.

| Người dùng | Kịch bản | Giá trị nhận được |
| --- | --- | --- |
| Security Analyst, SOC | Khởi chạy chiến dịch, nhận cảnh báo findings mới, truy nguyên bằng chứng | Phát hiện sớm, ít nhiễu |
| AppSec | Đi từ repo, image, SBOM tới CVE; theo dõi fix và tái phát | Rút ngắn xác minh và khắc phục |
| Hạ tầng, SRE | Đối chiếu host, IP, dịch vụ, cấu hình; đặt cửa sổ quét | Giảm rủi ro gián đoạn dịch vụ |
| Security Architect | Xem bề mặt tấn công và các quan hệ có nguy cơ | Ra quyết định dựa trên đồ thị |
| Platform Engineer | Tích hợp scanner OSS mới, giám sát workload | Mở rộng bằng hợp đồng ổn định |

Kịch bản cảnh báo sớm điển hình: một CVE mới vào danh mục KEV, hệ thống đối chiếu lại với các package đã biết trong đồ thị, xác định tài sản nào đang phơi nhiễm và báo cho SOC kèm bằng chứng, không cần chờ lần quét kế tiếp.

## 5. Kiến trúc tổng thể

Hệ thống chia thành ba mặt phẳng: điều khiển, thực thi cô lập, và dữ liệu tri thức. Scanner không bao giờ ghi thẳng vào cơ sở dữ liệu; mọi kết quả đi qua Ingestion API để được chuẩn hóa trước.

&#91;embedded content: Kiến trúc tổng thể · 3 mặt phẳng, 11 dịch vụ\]

Đọc theo chiều mũi tên: agent đề xuất kế hoạch, Policy duyệt, scanner chạy trong vùng cô lập, kết quả quay về kho tri thức qua Ingestion API, rồi agent đọc lại tri thức mới ở chế độ chỉ đọc.

| Dịch vụ | Vai trò | Trạng thái lưu ở đâu |
| --- | --- | --- |
| UI và Backend API | Tạo chiến dịch, dashboard, truy vấn đồ thị, báo cáo, cấu hình policy | PostgreSQL |
| Campaign Controller | Workflow Temporal: tạm dừng, tiếp tục, timer, phân nhánh | Temporal |
| Agent Runtime | LangGraph Planner, Analyst, Verifier; checkpoint theo phiên | PostgreSQL (checkpoint) |
| Registry và Policy Gateway | Khớp capability, safe profile, ghi nguồn gốc mục tiêu | Cấu hình có phiên bản |
| Execution Gateway | Chống trùng job, tạo container Podman, giới hạn tài nguyên | PostgreSQL và Kubernetes |
| Ingestion và Normalizer | Parse output thô, kiểm schema, hợp nhất thực thể | Consumer idempotent |
| Graph Query API | Truy vấn đồ thị chỉ đọc, có giới hạn | Neo4j |
| Intel Fetchers | Đồng bộ NVD, OSV, KEV, EPSS theo delta | Cache có phiên bản |
| Reporting | Vòng đời finding, delta, xuất SARIF, JSON, HTML | Stateless |

Công nghệ nền: LangGraph và Temporal cho điều phối; PostgreSQL là nguồn sự thật cho giao dịch, Neo4j cho quan hệ và đường đi, MinIO cho bằng chứng thô; container Podman trên một host cho scanner, Kubernetes để sau; ModelClient tự dựng nhận endpoint chuẩn OpenAI và Anthropic cho định tuyến model; OpenTelemetry cho quan sát và kiểm toán.

## 6. Agent harness trong MVP

Agent harness thuộc phạm vi MVP và được tách làm hai tầng: Temporal giữ vòng đời chiến dịch nhiều ngày, LangGraph chạy từng phiên suy luận ngắn. Không có một lượt LangGraph nào chạy liên tục nhiều ngày.

Một chu kỳ của chiến dịch gồm sáu bước lặp lại:

1. Lấy phần tri thức mới (delta) chưa xử lý từ đồ thị.
2. Chạy một phiên agent có giới hạn, khoảng 30 bước, để sinh kế hoạch dạng JSON.
3. Policy kiểm kế hoạch theo RoE (lớp tác động, tốc độ, khung giờ cấm) và ghi nguồn gốc mục tiêu.
4. Execution Gateway gửi job theo cách idempotent.
5. Chờ sự kiện job hoàn tất rồi nạp bằng chứng vào đồ thị.
6. Đánh giá tiến độ và ngân sách, quyết định tiếp tục, chờ hay dừng.

**Ba vai trò agent trong MVP.** Planner lập kế hoạch từ mục tiêu và delta. Analyst đọc kết quả đã chuẩn hóa và cập nhật giả thuyết. Verifier đối chiếu bằng chứng trước khi nâng trạng thái finding. Mô hình 16 tác tử của bản gốc không áp dụng ở MVP.

**Những gì agent không có.** Agent không có shell, không có Docker socket, không có quyền cluster, không viết Cypher tự do, không cầm credential của mục tiêu. Agent chỉ gọi capability cấp nghiệp vụ qua Registry.

**Quản lý ngữ cảnh.** Mỗi phiên bắt đầu với ngữ cảnh sạch: mục tiêu hiện tại, 10 đến 30 quan sát quan trọng nhất, các capability phù hợp và bản chụp policy. Log scanner thô nằm ở MinIO; agent chỉ nhận bản tóm tắt có URI và độ tin cậy. Trạng thái dài hạn nằm trong sổ chiến dịch và đồ thị, không nằm trong lịch sử hội thoại.

**Ngân sách và chống lặp.** Mỗi chiến dịch có ngân sách về token, chi phí, số job, thời gian và số mục tiêu chạy đồng thời. Ngưỡng dừng nằm trong mã, không chỉ trong prompt. Nếu 3 đến 5 chu kỳ liên tiếp không có bằng chứng mới hữu ích, workflow giảm cấp hoặc tạm dừng và ghi lý do. Công thức ProgressScore trong HLD là heuristic cần hiệu chỉnh, chưa phải thuật toán đã kiểm chứng.

**Định tuyến model.** Tác vụ phân loại và trích xuất dùng model nhỏ; lập kế hoạch và tương quan dùng model trung bình; suy luận mã phức tạp dùng model lớn kèm xác minh độc lập. Các scanner xác định vẫn phải chạy được khi lớp LLM không khả dụng.

## 7. Năng lực sản phẩm và cách dùng OSS

Dự án chỉ viết lớp hợp nhất; mọi scanner là OSS được gọi qua adapter. Agent yêu cầu một năng lực nghiệp vụ, ví dụ `network.discover_services`, và Registry chọn công cụ phù hợp. Agent không gọi trực tiếp binary hay CLI.

| Nhóm năng lực | Đầu vào | Đầu ra | Công cụ OSS | Giai đoạn |
| --- | --- | --- | --- | --- |
| Khám phá tài sản | IP, domain, URL, email, từ khóa | Đồ thị domain, IP, dịch vụ, endpoint | Subfinder, BBOT, asnmap, DNSx, Naabu, Nerva, Nmap, httpx, tlsx, cdncheck, Katana, urlfinder | GĐ2 |
| SBOM và lỗ hổng thành phần | Image, filesystem, repo | SBOM, pURL, ứng viên lỗ hổng | Trivy, Syft, Grype; OSV-Scanner tùy chọn | GĐ2 |
| Tình báo lỗ hổng | CVE, pURL, CPE | Bản ghi intel có phiên bản | Feed NVD, OSV, KEV, EPSS | GĐ2 |
| Tương quan và đánh giá mức nghiêm trọng | Đồ thị và intel | Finding có bằng chứng, mức nghiêm trọng kèm lý do, lịch sử từng lần chạy | Tự xây | GĐ2, hoàn thiện ở GĐ4 |
| Kiểm tra theo mẫu | Endpoint | Bằng chứng | Nuclei với toàn bộ mẫu chính thức và mẫu người dùng thêm | GĐ2 |
| OSINT và pivot | Thực thể hạt giống | Quan hệ mới có nguồn gốc | BBOT, enricher tự dựng (crt.sh, RDAP, dnstwist, tra rò rỉ theo domain); SpiderFoot-ng ở GĐ3 | GĐ2 |
| Phân tích JS và source map | Bundle, source map | Endpoint và package ẩn | webcrack, jsluice | GĐ3 |
| Phân tích nhị phân và ứng dụng | ELF, PE, APK, Electron | Tham chiếu bằng chứng | Bộ giải nén tự dựng (JADX, asar, strings, Ghidra headless); REA tùy chọn | GĐ3 |
| Phát hiện secret | Repo, cấu hình, artifact | Finding secret kèm bằng chứng | Gitleaks, Betterleaks, TruffleHog | GĐ3 |
| Mã nguồn và cấu hình hạ tầng | Repo, cloud, cluster | Finding mã và cấu hình | Opengrep, Prowler, Kubescape, kube-bench | GĐ3 |
| Đánh giá nâng cao bằng sub-agent | Mục tiêu lab hoặc staging | Báo cáo và bằng chứng | Strix, Decepticon | Để sau |

**Vai trò của bốn OSS trọng tâm**

| OSS | Dùng làm gì | Không dùng làm gì | Giấy phép |
| --- | --- | --- | --- |
| Flowsint | Không dùng (chốt 13/11); chỉ tham khảo cách trình bày đồ thị | Enricher tự dựng trong M08 thay thế; không dùng Graph Conductor | Apache-2.0 từ 25/01/2026 |
| Decepticon | Tham khảo pattern middleware, tách sandbox, ngữ cảnh sạch | Không nhập workflow red-team, C2, post-exploit | Apache-2.0 |
| REA | Adapter dịch ngược tĩnh, chạy theo yêu cầu trong sandbox | Không coi pseudocode là mã nguồn gốc; không coi call graph tĩnh là bằng chứng runtime | MIT |
| Strix | Tham khảo pattern báo cáo, ngân sách, kiểm soát phạm vi | Không chạy khai thác động trên production | Apache-2.0 |

**Năm cấp tích hợp.** L0 nhập file JSON, SARIF, SBOM xuất sẵn. L1 bọc CLI trong container. L2 gọi dịch vụ REST. L3 gọi qua MCP có whitelist. L4 chạy cả một phiên sub-agent như một job. MVP dùng L0 đến L2; L3 dành cho REA ở V1; L4 để sau.

**Giấy phép cần rà trước khi đóng gói.** Nmap dùng giấy phép NPSL có hạn chế phân phối lại. TruffleHog v3 là AGPL-3.0. Opengrep là LGPL-2.1. Ba công cụ này nên chạy như tiến trình ngoài, tách biệt, và cần được pháp chế xem xét nếu hệ thống được phân phối ra ngoài.

## 8. Tri thức và dữ liệu

Mọi kết luận trong hệ thống phải truy được về bằng chứng, nên dữ liệu được tách thành năm loại có ý nghĩa khác nhau.

| Loại | Ý nghĩa | Lưu ở đâu |
| --- | --- | --- |
| Asset | Đối tượng tồn tại: domain, IP, dịch vụ, endpoint, image, repo, package | PostgreSQL và Neo4j |
| Observation | Điều quan sát được tại một thời điểm, chỉ ghi thêm, không ghi đè | PostgreSQL, chiếu sang đồ thị |
| Hypothesis | Giả thuyết của agent, chưa được xác minh | PostgreSQL và đồ thị |
| Finding | Đánh giá điểm yếu trên một tài sản cụ thể | PostgreSQL là nguồn sự thật |
| Evidence | Bằng chứng thô có checksum SHA-256, bất biến | MinIO, metadata ở PostgreSQL |

Bốn quy tắc giữ cho tri thức đáng tin:

- **CVE khác Finding.** CVE là định danh tình báo toàn cục. Finding là một trường hợp cụ thể gắn với tài sản, phiên bản và môi trường.
- **Định danh chuẩn.** Mỗi loại tài sản có một khóa chuẩn, ví dụ `dns:<fqdn>`, `service:<ip>:<port>/<transport>`, `oci:sha256:<digest>`, `purl:<purl>`. Tag image và nhánh git chỉ là bí danh.
- **Có tính thời gian.** Mỗi quan hệ mang thời điểm quan sát, khoảng hiệu lực, job nguồn và độ tin cậy. "Không tìm thấy" được ghi là chưa rõ, không phải không tồn tại.
- **Một cửa ghi duy nhất.** Scanner tải bằng chứng lên MinIO qua signed URL rồi gửi ResultEnvelope tới Ingestion API. API kiểm schema và checksum, chống trùng, ghi PostgreSQL trong giao dịch, sau đó chiếu sang Neo4j bằng Cypher tham số hóa.

Finding đi qua bảy trạng thái: CANDIDATE, CORROBORATED, VERIFIED, FALSE\_POSITIVE, ACCEPTED\_RISK, FIXED, REGRESSED. Một finding không thể lên VERIFIED nếu thiếu bằng chứng có checksum.

Agent đọc tri thức qua một tập truy vấn đã đăng ký, có giới hạn số bước nhảy, số bản ghi, thời gian và luôn lọc theo chiến dịch.

## 9. Vòng đời nghiệp vụ và cảnh báo sớm

Một chiến dịch đi qua bảy pha, trong đó pha Phản hồi tri thức đưa phát hiện mới quay lại làm đầu vào cho vòng khám phá kế tiếp.

1. **Mục tiêu và RoE.** Khai báo IP, domain, URL, email, từ khóa, cùng repo và artifact ở GĐ3, cửa sổ được quét và khung giờ cấm.
2. **Khám phá nền.** Gieo đồ thị từ ba góc nhìn black-box, gray-box, white-box.
3. **Làm giàu từ artifact.** Phân tích image, JS bundle, package và nhị phân được phép.
4. **Phản hồi tri thức.** Hợp nhất bằng chứng, tạo giả thuyết và nhiệm vụ mới, có ghi nguồn gốc.
5. **Tương quan lỗ hổng.** Đối chiếu phiên bản, pURL, CPE với CVE, KEV, EPSS và metadata về PoC.
6. **Kiểm chứng an toàn.** Xác minh thụ động hoặc tác động thấp; kiểm chứng chủ động chỉ khi được duyệt.
7. **Cảnh báo, báo cáo và đánh giá lại.** Khử trùng, xếp ưu tiên, cảnh báo, gợi ý khắc phục, quét lại.

**Cảnh báo sớm đến từ hai nguồn kích hoạt.** Thứ nhất là thay đổi bên trong: tài sản mới, cổng mới mở, package mới trong một image. Thứ hai là thay đổi bên ngoài: CVE mới, CVE vào KEV, điểm EPSS tăng. Cả hai đều phát sự kiện để hệ thống đánh giá lại chọn lọc các finding liên quan, thay vì chờ lịch quét.

**Agent đánh giá mức nghiêm trọng, có lý do.** Một lỗ hổng có bằng chứng xác nhận và dẫn chứng thì được coi là lỗ hổng. Mức nghiêm trọng do AI agent đánh giá, dựa trên các tín hiệu KEV, EPSS, CVSS, mức phơi nhiễm và bằng chứng, và luôn kèm lý do, nguồn và phần chưa chắc chắn. Hệ thống không dùng công thức trọng số. Mỗi lần chạy ghi lại trạng thái và mức nghiêm trọng vào lịch sử, kể cả khi lần đó không còn thấy lỗ hổng.

Ba lưu ý khi đọc điểm rủi ro: EPSS là xác suất bị khai thác trong 30 ngày, không phải mức nghiêm trọng. Có PoC công khai không đồng nghĩa đã xác minh khai thác được. Phân tích reachability tĩnh chỉ hỗ trợ VEX, không chứng minh là không khai thác được.

Các mô hình chấm điểm trong tài liệu nguồn (ma trận A+ đến D của SploitScan, công thức sigmoid của UDEP) không được dùng. Agent có thể tham khảo chúng khi nêu lý do cho mức nghiêm trọng.

## 10. An toàn và guardrails

An toàn được cưỡng chế bằng mã và hạ tầng, không ủy thác cho LLM. Dù hệ thống là nội bộ và chưa có đăng nhập, ghi nguồn gốc và kiểm toán vẫn bắt buộc.

**Năm tầng tác động quyết định thao tác nào được tự động**

| Tầng | Ví dụ | Quy trình | Trong MVP |
| --- | --- | --- | --- |
| T0 Thụ động | OSINT chỉ đọc, parse artifact cục bộ | Tự động | Có |
| T1 Tác động thấp | DNS, HTTP HEAD/GET, kiểm kê | Giới hạn tốc độ, khung giờ cấm | Có |
| T2 Chủ động có giới hạn | Nmap service scan, Nuclei theo profile giới hạn tốc độ | Duyệt theo profile hoặc chiến dịch, trần tài nguyên | Có |
| T3 Xâm nhập | Khai thác có kiểm soát, kiểm thử credential (thử đăng nhập), kiểm chứng động làm thay đổi trạng thái | Policy M05 quyết định; cấu hình được: operator duyệt tay **hoặc** tự duyệt **bắt buộc đối chiếu denylist** (D16); job ghi người kích hoạt/duyệt | **Có** (D15, 2026-11-16) |
| T4 Cấm mặc định | Chạy PoC không tin cậy, lateral movement, persistence, C2, post-exploitation | Bị chặn | Không |

**Các ranh giới tin cậy**

- **Nguồn gốc theo cấu trúc.** Hệ thống không giới hạn phạm vi quét (chốt 13/11): tài sản quét được thì được coi là thuộc tổ chức và có quan hệ trong đồ thị. Mục tiêu, credential và policy vẫn được kiểm trước, trong và sau mỗi job. Mọi job gắn `campaign_id` và `policy_version`, và mọi cạnh ghi rõ nó được tìm ra từ mục tiêu nào, bởi công cụ nào.
- **Scanner cô lập.** Mỗi scanner chạy trong một container Podman rootless với image cố định theo digest, không privileged, không gắn socket của container engine, có giới hạn tài nguyên và nằm trong mạng riêng cho scanner. Kubernetes để sau.
- **Dữ liệu thu về là không tin cậy.** Nội dung web, README, output công cụ chỉ là dữ liệu, không bao giờ là chỉ dẫn cho agent. Output được parse có kiểu trước khi tới LLM.
- **Secret lưu và hiển thị dạng rõ.** Theo quyết định ngày 13/11, secret phát hiện được lưu dạng rõ kèm fingerprint trong cơ sở dữ liệu và đồ thị, và không che ở giao diện, báo cáo, prompt hay cảnh báo. Từ D17 (2026-11-16) hệ thống **có kiểm thử credential**: sinh ứng viên mật khẩu từ dữ liệu thu được và thử đăng nhập (hành vi T3, qua denylist); TruffleHog chạy với xác minh **bật**.
- **Kiểm toán đầy đủ.** Mọi kế hoạch, quyết định policy, lệnh gọi công cụ và thay đổi đồ thị có bản ghi chỉ ghi thêm, liên kết bằng campaign, session, job và evidence ID.

**Prompt injection là rủi ro đã có tiền lệ.** CVE-2026-61732 trên Decepticon cho thấy output của công cụ trinh sát có thể giả mạo ranh giới vai trò và chiếm quyền điều khiển agent. Lọc token đặc biệt và bọc thẻ `<UNTRUSTED_TOOL_OUTPUT>` chỉ là phòng thủ bổ sung. Ranh giới thật sự là agent không có công cụ đặc quyền và policy được kiểm độc lập ở tầng mã.

Truy cập UI và API chỉ qua private ingress hoặc VPN, có allowlist mức mạng và mTLS giữa các dịch vụ.

## 11. Lộ trình triển khai

Lộ trình gồm GĐ0 chuẩn bị, bốn giai đoạn giao hàng từ GĐ1 tới GĐ4, và một nhánh nâng cao để sau nghiệm thu. Tổng cộng khoảng 19 đến 27 tuần; MVP xong ở cổng G2, khoảng tuần 9 đến 13. Agent harness có mặt ngay từ GĐ1.

&#91;embedded content: Lộ trình · 4 giai đoạn giao hàng, 1 nhánh để sau\]

Các mốc thời gian là ước lượng khi mã do nhiều subagent viết và review chéo, không phải cam kết tiến độ. Mỗi giai đoạn chỉ xong khi qua cổng của nó, và Product Team ký nhận ở mọi cổng G0 đến G4. GĐ0 gồm năm spike kỹ thuật, trong đó có cách lồng phiên LangGraph trong Temporal và cách chạy scanner bằng Podman. Điều kiện chi tiết của từng cổng nằm ở [kế hoạch triển khai](02-ke-hoach-trien-khai.md).

**So với các tài liệu nguồn.** Lộ trình này theo tài liệu 00 và 04. Lộ trình của UDEP (agent chỉ xuất hiện ở v2 sau 10 đến 15 team-month) không áp dụng, vì agent harness đã được chốt trong MVP. Khuyến nghị của UDEP vẫn được giữ ở một điểm: lớp xác định (adapter, bằng chứng, đồ thị, policy) phải xong trước khi agent được trao thêm quyền.

**Một điều chỉnh đã chốt ngày 13/11.** Tài liệu 00 xếp năng lực giám sát liên tục (đánh giá lại khi feed tình báo thay đổi) ở mức P1 đến P2. Vì cảnh báo sớm là mục tiêu chính, phần đánh giá lại theo KEV và EPSS được kéo vào GĐ2 MVP Khám phá; phần theo dõi thay đổi nâng cao ở GĐ3, còn mẫu tin và group id Telegram cấu hình được làm ở giai đoạn cuối.

**Nhánh để sau (T4).** Sub-agent Strix và Decepticon, red-team, C2, persistence, lateral movement, post-exploitation, tự sinh bản vá và PR nháp. Nhánh này chỉ mở khi có threat model riêng và một đợt pilot được phê duyệt. (Khai thác và kiểm chứng động tới T3 đã thuộc MVP theo D14.)

## 12. KPI và tiêu chí nghiệm thu

Hệ thống được nghiệm thu theo chín chỉ số, mỗi chỉ số có cách đo cụ thể. Các ngưỡng là mục tiêu thiết kế, cần hiệu chỉnh với hạ tầng và dữ liệu thật.

| Chỉ số | Mục tiêu | Cách đo |
| --- | --- | --- |
| Job chạy mà không ghi nguồn gốc mục tiêu | 0 | Kiểm thử biên: redirect, DNS trỏ sang tài sản khác, dạng IP thay thế đều phải có nguồn gốc |
| Policy coverage | 100% job chủ động gắn scope\_id và policy\_version | Truy vấn audit |
| Độ bền chiến dịch | 7 ngày liên tục, từ 10.000 bước điều phối, không mất trạng thái | Chaos test: restart pod, failover DB |
| Job trùng | 0 job trùng cho cùng idempotency key | Replay 1.000 sự kiện |
| Nguồn gốc dữ liệu | 100% finding có bằng chứng hoặc trạng thái unsupported | Kiểm schema |
| Chất lượng finding | Finding có bằng chứng xác nhận và dẫn chứng | Rà bằng chứng của từng finding |
| Thời gian tích hợp scanner | Một CLI scanner đơn giản trong tối đa 2 ngày công | Diễn tập có bấm giờ |
| Độ trễ cập nhật tình báo | KEV dưới 2 giờ, EPSS dưới 24 giờ | So thời điểm công bố với thời điểm ingest |
| Khả năng quan sát | 100% job lỗi có phân loại lỗi và bước tiếp theo | Kiểm thử nghiệm thu UI |

Chỉ số độ trễ tình báo lấy từ UDEP và được thêm vào vì nó đo trực tiếp mục tiêu cảnh báo sớm. Tám chỉ số còn lại theo tài liệu 00 và 04.

Theo quyết định ngày 13/11, hệ thống không đo precision và recall và không dùng golden dataset. Thay vào đó, mỗi finding phải có bằng chứng xác nhận và dẫn chứng để người dùng tự kiểm lại.

## 13. Rủi ro và điểm còn mở

Sáu rủi ro lớn nhất đều đã có biện pháp trong thiết kế; phần chưa chắc nằm ở năm điểm cần spike kỹ thuật.

| Rủi ro | Biện pháp ưu tiên |
| --- | --- |
| Prompt injection qua output công cụ | Ranh giới dữ liệu không tin cậy, parse có kiểu, policy ở tầng mã |
| Scanner gây gián đoạn dịch vụ | Safe profile, giới hạn tốc độ, khung giờ cấm, duyệt theo tầng tác động |
| OSS upstream đổi API | Pin phiên bản và digest, ma trận tương thích, conformance test |
| Trùng thực thể hoặc tranh chấp ghi đồ thị | Khóa chuẩn, ràng buộc unique, một Ingestion API duy nhất |
| Secret và dữ liệu nhạy cảm trong artifact | Chấp nhận theo quyết định 13/11: lưu và hiển thị dạng rõ; bù bằng giới hạn truy cập ở tầng mạng và kiểm toán |
| Bùng nổ công cụ và chi phí LLM | Tìm capability theo nhu cầu, tóm tắt ngữ cảnh, ngân sách token |

**Điểm cần spike trước khi khóa thiết kế**

- [ ] Lồng phiên LangGraph trong Temporal: replay và hủy activity có an toàn không.
- [ ] Flowsint enricher: đã đóng ngày 13/11, không dùng Flowsint, enricher tự dựng trong M08.
- [ ] REA: kích thước danh mục công cụ MCP thực tế trên phiên bản đã pin.
- [ ] Đồ thị: benchmark upsert đồng thời với 100 worker.
- [ ] Scanner cần raw socket (Nmap, Naabu): chạy được không khi bỏ hết capability.

**Những khẳng định trong tài liệu nguồn chưa được kiểm chứng độc lập.** Các con số dưới đây đến từ nghiên cứu đầu vào và tài liệu của chính các dự án OSS. Chúng không được dùng làm cam kết hay tiêu chí nghiệm thu của AEGIS–Vanguard.

- Tỷ lệ 98,08% trên bộ kiểm chuẩn XBOW là kết quả Decepticon tự công bố cho kiến trúc 16 tác tử của họ.
- Mức nén danh mục công cụ REA 93% và bản tóm tắt giảm 99,9% cần đo lại trên phiên bản pin.
- Graph Conductor (Flowsint issue #133) mới là RFC nháp, chưa phải tính năng đã phát hành.
- Phiên bản, giấy phép và trạng thái hoạt động của từng OSS phải kiểm lại tại thời điểm pin release.

**Quyết định sẽ xem lại khi điều kiện thay đổi.** Đăng nhập và RBAC khi mở truy cập cho nhiều nhóm. Multi-tenant khi phục vụ đơn vị độc lập. GUAC khi cần lineage và VEX ở quy mô lớn. DefectDojo hoặc Dependency-Track khi muốn dùng lại quy trình quản lý lỗ hổng có sẵn thay vì tự xây.

## 14. Bản đồ bộ tài liệu

Bộ tài liệu thống nhất gồm bản tổng quan này và bốn tài liệu chi tiết 01–04; ba tài liệu còn lại chuyển thành nguồn tham khảo.

Hai tài liệu mới triển khai bản tổng quan này: [Đặc tả kỹ thuật](dac-ta-ky-thuat/README.md) mô tả chi tiết 28 module, nền tảng và hợp đồng dữ liệu; [Kế hoạch triển khai](02-ke-hoach-trien-khai.md) nêu đầu ra theo từng giai đoạn và từng module. Ở những chỗ hai tài liệu này khác tài liệu 01 đến 04, chúng được ưu tiên và có ghi rõ lý do.

| Tài liệu | Vai trò sau thống nhất | Việc cần làm |
| --- | --- | --- |
| Tổng quan hệ thống hợp nhất (tài liệu này) | Chuẩn, ưu tiên cao nhất | Thay thế tài liệu 00 |
| 00 Tổng quan dự án | Được thay thế | Lưu trữ |
| 01 Thiết kế kiến trúc HLD | Chuẩn chi tiết | Khớp, không cần sửa lớn |
| 02 Đặc tả chức năng và module OSS | Chuẩn chi tiết | Chuyển FR-021, FR-022 và M22 sang nhánh để sau; bổ sung ghi chú giấy phép Nmap, TruffleHog, Semgrep |
| 03 Mô hình dữ liệu, Knowledge Graph, API | Chuẩn chi tiết | Khớp, không cần sửa lớn |
| 04 Triển khai, an toàn, kiểm thử, roadmap | Chuẩn chi tiết | Đưa sprint S11 ra khỏi backlog chính; thêm KPI độ trễ KEV và EPSS; kéo đánh giá lại theo feed tình báo vào MVP nếu được xác nhận |
| Deep-research report (UDEP) | Tham khảo | Nguồn cho giấy phép OSS, feed tình báo, thiết kế multi-tenant sau này |
| Đặc tả gốc "Offensive Vaccine" | Tham khảo, tầm nhìn dài hạn | Không dùng làm yêu cầu; phần tấn công thuộc nhánh để sau |
| Bản HTML SPEC v2.6 | Tham khảo | Không còn phản ánh thiết kế; cần dựng lại nếu muốn có bản trình bày tương tác |

Khi hai tài liệu mâu thuẫn, thứ tự ưu tiên là: bản tổng quan này, rồi tài liệu 01–04, rồi các nguồn tham khảo.
