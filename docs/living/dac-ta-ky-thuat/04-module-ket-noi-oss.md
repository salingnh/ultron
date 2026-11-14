# Module kết nối OSS

Mười một module kết nối bọc các công cụ OSS sẵn có sau một hợp đồng capability chung. Dự án không fork và không viết lại công cụ nào; phần tự xây chỉ là adapter và bộ ánh xạ kết quả.

## 1. Adapter SDK

Mọi connector, dù bọc CLI, REST, MCP hay sub-agent, đều hiện thực cùng bảy thao tác của Adapter SDK.

| Thao tác | Chữ ký logic | Bảo đảm |
| --- | --- | --- |
| `describe` | `() -> Manifest` | Không có tác dụng phụ |
| `validate` | `(Context, Input) -> ValidationResult` | Kiểm schema, policy và chuẩn hóa mục tiêu |
| `start` | `(Context, Input, key) -> JobHandle` | Có idempotency key; không chạy nếu bị từ chối |
| `status` | `(JobHandle) -> JobState` | Trạng thái ổn định, có `retry_after` |
| `cancel` | `(JobHandle) -> CancelResult` | Best effort; có ghi audit |
| `collect` | `(JobHandle) -> ResultEnvelope` | URI bằng chứng thô và kết quả có cấu trúc |
| `health` | `() -> Health` | Phiên bản provider và phụ thuộc công cụ |

**Năm cấp tích hợp**

| Cấp | Cách làm | Khi nào chọn | Dùng từ |
| --- | --- | --- | --- |
| L0 Import | Đọc file JSON, SARIF, SBOM do OSS xuất thủ công | Kiểm parser trong spike | GĐ1 |
| L1 CLI Wrapper | Container chạy CLI, ánh xạ output | Scanner ổn định có CLI | GĐ2 |
| L2 REST Service | Adapter gọi dịch vụ, polling hoặc webhook | OSS có API dài hạn; feed tình báo | GĐ2 |
| L3 MCP Capability | MCP server qua bridge có whitelist | Công cụ native MCP, ví dụ REA (tùy chọn) | GĐ3 |
| L4 Sub-agent Job | Cả một phiên agent độc lập, trả báo cáo và bằng chứng | Strix, Decepticon | Để sau |

MCP chỉ là giao thức giao tiếp. Nó không thay cho job scheduler, schema chuẩn hay policy.

**Chiến lược nâng cấp.** Khóa image theo digest. Giữ ma trận tương thích giữa phiên bản adapter và phiên bản upstream. Lưu fixture kết quả cho từng phiên bản. Triển khai canary từng provider và rollback bằng manifest.

## 2. Bảng tổng hợp connector

Bảng dưới có 22 provider, gồm 21 provider cho 11 module kết nối và một provider feed cho M18; 13 provider thuộc MVP. Tên capability là đề xuất mới, trừ bốn tên đã có trong tài liệu 02: `network.discover_services`, `artifact.generate_sbom`, `vuln.scan_web`, `intel.enrich_cve`.

| Capability | Công cụ OSS | Module | Cấp | Tầng tác động | Giấy phép | Giai đoạn |
| --- | --- | --- | --- | --- | --- | --- |
| `dns.enumerate_subdomains` | Subfinder | M08 | L1 | T0 | MIT | GĐ2 |
| `osint.passive_sweep` | BBOT, chỉ chế độ thụ động | M08 | L1 | T0 | Cần rà (spike GĐ0) | GĐ2 |
| `osint.cert_transparency` | crt.sh, nguồn tự dựng | M08 | L2 | T0 | Dữ liệu công khai | GĐ2 |
| `osint.detect_lookalike` | dnstwist, nguồn tự dựng | M08 | L2 | T0 | Cần rà | GĐ2 |
| `osint.enrich_entity` | Enricher nhỏ tự dựng | M08 | L2 | T0 | Mã nội bộ | GĐ2 và GĐ3 |
| `osint.broad_sweep` | SpiderFoot-ng | M08 | L1 | T0 | Cần rà | GĐ3 |
| `osint.breach_lookup` | Tra cứu rò rỉ theo domain tổ chức, tự dựng; API key do người dùng cấu hình | M08 | L2 | T0 | Mã nội bộ | GĐ3 |
| `osint.search_public_code` | Tìm mã công khai, tự dựng | M08 | L2 | T0 | Mã nội bộ | GĐ3 |
| `dns.resolve` | DNSx | M09 | L1 | T1 | Cần rà | GĐ2 |
| `network.map_asn` | asnmap | M09 | L1 | T0 | Cần rà | GĐ2 |
| `network.classify_cdn` | cdncheck | M09 | L1 | T0 | Cần rà | GĐ2 |
| `network.discover_ports` | Naabu | M09 | L1 | T2 | MIT | GĐ2 |
| `network.discover_services` | Nmap, Nerva | M09 | L1 | T2 | NPSL; Nerva cần rà | GĐ2 |
| `tls.inspect` | tlsx | M10 | L1 | T1 | Cần rà | GĐ2 |
| `web.probe` | httpx | M10 | L1 | T1 | MIT | GĐ2 |
| `web.crawl` | Katana | M10 | L1 | T1 | Cần rà | GĐ2 |
| `web.collect_urls` | urlfinder | M10 | L1 | T0 | Cần rà | GĐ2 |
| `vuln.scan_web` | Nuclei, toàn bộ mẫu chính thức và mẫu người dùng thêm | M10 | L1 | T2 | MIT | GĐ2 |
| `artifact.generate_sbom` | Trivy (chính), Syft (đối chứng) | M13 | L1 | T0 | Apache-2.0 | GĐ2 |
| `vuln.scan_artifact` | Trivy (chính), Grype (đối chứng), OSV-Scanner (tùy chọn) | M14 | L1 | T0 | Apache-2.0 | GĐ2 |
| `intel.enrich_cve` | Feed NVD, OSV, KEV, EPSS | M18 | L2 | T0 | Dữ liệu công khai | GĐ2 |
| `cloud.audit_config` | Prowler | M11 | L1 | T1 | Apache-2.0 | GĐ3 |
| `k8s.audit_config` | Kubescape (chính), kube-bench (bổ sung) | M11 | L1 | T1 | Apache-2.0 | GĐ3 |
| `code.scan_sast` | Opengrep | M12 | L1 | T0 | LGPL-2.1 | GĐ3 |
| `secret.detect` | Gitleaks, Betterleaks | M12, M17 | L1 | T0 | Cần rà | GĐ3 |
| `secret.detect` | TruffleHog, tắt xác minh | M17 | L1 | T0 | AGPL-3.0 | GĐ3 |
| `js.analyze_bundle` | webcrack, jsluice | M15 | L1 | T0 | Cần rà | GĐ3 |
| `binary.analyze_static` | Bộ giải nén tự dựng gọi JADX, asar, Syft hoặc Trivy, strings, Ghidra headless; REA tùy chọn | M16 | L2; REA là L3 | T0 | Theo từng công cụ, cần rà | GĐ3 |
| `assess.subagent` | Strix, Decepticon | M22 | L4 | T3 | Apache-2.0 | Để sau |

Không dùng: Amass, Flowsint, Semgrep CE (thay bằng Opengrep), LiteLLM. Liệt kê tài khoản mạng xã hội tắt mặc định. Tên capability mới trong bảng là đề xuất, chốt khi viết manifest.

"Cần rà" nghĩa là giấy phép chưa được đối chiếu trong tài liệu nguồn. Mọi giấy phép phải kiểm lại tại phiên bản pin trước khi đóng gói image. Nmap (NPSL), TruffleHog (AGPL-3.0), BBOT (giấy phép kiểm ở spike GĐ0) và Opengrep (LGPL-2.1) chạy như tiến trình ngoài tách biệt và cần pháp chế xem xét nếu hệ thống được phân phối ra ngoài.

## 3. Nhóm khám phá

### M08 Domain và ASN Discovery

M08 mở rộng từ vài thực thể hạt giống thành danh sách domain và dải mạng của tổ chức, bằng nguồn thụ động. Tài sản tìm được chuyển cho M09 và M10 quét tiếp.

| Mục | Đặc tả |
| --- | --- |
| Capability | `dns.enumerate_subdomains`, `osint.enrich_entity` |
| Provider | Subfinder (chính), BBOT thụ động, crt.sh, dnstwist, enricher nhỏ tự dựng (GĐ2); SpiderFoot-ng, tra cứu rò rỉ theo domain tổ chức, tìm mã công khai (GĐ3) |
| Đầu vào | Domain gốc, tên tổ chức, ASN |
| Output thô dự kiến | JSON lines danh sách subdomain kèm nguồn |
| Ánh xạ vào tri thức | Asset loại domain với khóa `dns:<fqdn>`; observation về nguồn phát hiện; enricher tự dựng thêm chuỗi pivot có nguồn gốc |
| Profile an toàn | Chỉ nguồn thụ động; không phát sinh lưu lượng tới mục tiêu |
| Quy tắc riêng | Tài sản lần ra được coi là thuộc tổ chức và được quét tiếp (chốt 13/11); mỗi tài sản có quan hệ tới tài sản gốc và công cụ đã tìm ra nó. Khóa API của nguồn OSINT, kể cả nguồn tra rò rỉ, do người dùng cấu hình |
| Nghiệm thu | FR-007, FR-013: kết quả có provenance và chuỗi pivot |

Dự án không dùng Flowsint; enricher là mã nhỏ tự dựng, mỗi cái một manifest. Tra cứu rò rỉ chỉ theo domain của tổ chức, không tra theo cá nhân. Liệt kê tài khoản mạng xã hội tắt mặc định. BBOT chỉ chạy module thụ động.

### M09 DNS, IP và Port Discovery

M09 xác định domain trỏ về đâu và host nào đang mở dịch vụ gì.

| Mục | Đặc tả |
| --- | --- |
| Capability | `dns.resolve`, `network.discover_ports`, `network.discover_services` |
| Provider | DNSx, asnmap, cdncheck, Naabu, Nmap, Nerva |
| Đầu vào | Danh sách domain; IP hoặc CIDR của chiến dịch |
| Output thô dự kiến | JSON lines (DNSx, Naabu); XML (Nmap) |
| Ánh xạ vào tri thức | Domain `RESOLVES_TO` IP, có thời điểm. IP `EXPOSES` Service với khóa `service:<ip>:<port>/<transport>`. Observation về banner, sản phẩm và phiên bản để M20 khớp CPE |
| Profile an toàn | Giới hạn tốc độ và số mục tiêu đồng thời theo RoE; tôn trọng khung giờ cấm. Nmap mặc định chỉ nhận diện dịch vụ và phiên bản, không bật script xâm nhập (đề xuất mới) |
| Quy tắc riêng | IP phân giải ra được ghi quan hệ nguồn gốc và được quét tiếp. Chuẩn hóa IPv4, IPv6 trước khi ghi. Naabu và Nmap có thể cần raw socket; không mặc định bật privileged |
| Nghiệm thu | FR-007: đủ chuỗi domain, IP, dịch vụ. Scanner chỉ chạy trong subnet cho phép |

### M10 Web Fingerprint và Crawl

M10 nhận diện ứng dụng web, thu endpoint và chạy mẫu Nuclei: toàn bộ mẫu chính thức cùng mẫu người dùng thêm (chốt 13/11).

| Mục | Đặc tả |
| --- | --- |
| Capability | `web.probe`, `web.crawl`, `vuln.scan_web` |
| Provider | httpx, tlsx, Katana, urlfinder, Nuclei |
| Đầu vào | Host và cổng HTTP; URL gốc; thư mục mẫu chính thức và thư mục mẫu tùy chỉnh |
| Output thô dự kiến | JSON lines |
| Ánh xạ vào tri thức | Service `SERVES` Application; Application `HAS_ENDPOINT` Endpoint với khóa URL chuẩn hóa. Observation về công nghệ, TLS, mã trạng thái. File JS và source map thành Artifact và phát `artifact.ready.v1`. Kết quả Nuclei thành Finding CANDIDATE kèm bằng chứng |
| Profile an toàn | httpx và Katana chỉ dùng HEAD và GET, có trần số request và tốc độ. Nuclei chạy mọi mẫu chính thức và mẫu tùy chỉnh, có trần tốc độ |
| Quy tắc riêng | Redirect sang domain khác được ghi thành tài sản mới kèm quan hệ nguồn gốc. URL được lưu nguyên vẹn. Crawl có đăng nhập cần credential cấp riêng. Bộ mẫu Nuclei chính thức được pin phiên bản như một phụ thuộc chuỗi cung ứng |
| Nghiệm thu | FR-007: có endpoint trong đồ thị. Kiểm thử redirect sang domain khác được ghi đúng quan hệ. Demo từ domain tới finding có provenance |

## 4. Nhóm chuỗi cung ứng, mã nguồn và cấu hình

### M13 Image và Filesystem SBOM

M13 lập danh mục thành phần phần mềm của image, filesystem và repo.

| Mục | Đặc tả |
| --- | --- |
| Capability | `artifact.generate_sbom` |
| Provider | Trivy (chính), Syft (đối chứng) |
| Đầu vào | Image OCI theo digest; đường dẫn filesystem; repo snapshot theo commit |
| Output thô dự kiến | SBOM CycloneDX hoặc SPDX dạng JSON |
| Ánh xạ vào tri thức | Artifact với khóa `oci:sha256:<digest>` hoặc `git:<repo>@<sha>`; Artifact `CONTAINS_PACKAGE` Package với khóa `purl:<purl>`. SBOM lưu làm bằng chứng |
| Profile an toàn | Phân tích tĩnh, không chạy image. Credential registry chỉ đọc, cấp theo mục tiêu |
| Quy tắc riêng | Không dùng tag làm định danh. SBOM lưu kèm digest của artifact nguồn |
| Nghiệm thu | FR-008: SBOM và pURL lưu kèm digest artifact nguồn |

### M14 Image và Dependency Vulns

M14 tìm lỗ hổng đã biết trong các package của SBOM hoặc image.

| Mục | Đặc tả |
| --- | --- |
| Capability | `vuln.scan_artifact` |
| Provider | Trivy (chính), Grype (đối chứng), OSV-Scanner (tùy chọn) |
| Đầu vào | SBOM từ M13 hoặc image theo digest |
| Output thô dự kiến | JSON danh sách lỗ hổng theo package |
| Ánh xạ vào tri thức | Package `AFFECTED_BY` Vulnerability; Finding CANDIDATE gắn Artifact và phiên bản; mỗi provider là một bằng chứng độc lập |
| Profile an toàn | Phân tích tĩnh. Cơ sở dữ liệu lỗ hổng của scanner được cập nhật có kiểm soát, ghi phiên bản |
| Quy tắc riêng | Kết quả của nhiều provider do M20 khử trùng, không khử ở adapter. Ghi `match_method` và phiên bản cơ sở dữ liệu đã dùng |
| Nghiệm thu | Demo từ image tới pURL tới CVE. Cùng package từ ba provider cho một finding |

### M12 Code Repository Analysis

M12 phân tích tĩnh mã nguồn nội bộ được cấp quyền.

| Mục | Đặc tả |
| --- | --- |
| Capability | `code.scan_sast`, `secret.detect` |
| Provider | Opengrep, Gitleaks, Betterleaks |
| Đầu vào | Repo snapshot theo commit; bộ rule pin phiên bản |
| Output thô dự kiến | JSON hoặc SARIF |
| Ánh xạ vào tri thức | Finding CANDIDATE kèm vị trí file và dòng; Package từ manifest của repo |
| Profile an toàn | Credential Git chỉ đọc, cấp riêng. Không đẩy mã nguồn ra dịch vụ ngoài |
| Quy tắc riêng | Bộ rule được chọn lọc để giảm nhiễu. Mã nguồn chỉ gửi tới LLM theo chính sách dữ liệu của M04 |
| Nghiệm thu | FR-014, FR-020: trích xuất từ repo của chiến dịch; credential cấp riêng |

### M17 Secret Exposure Detection

M17 phát hiện secret bị lộ trong repo, cấu hình và artifact, và chỉ lưu dấu vết đã che.

| Mục | Đặc tả |
| --- | --- |
| Capability | `secret.detect` |
| Provider | Gitleaks (chính), Betterleaks, TruffleHog tắt xác minh |
| Đầu vào | Repo, file cấu hình, artifact đã thu |
| Output thô dự kiến | JSON danh sách phát hiện |
| Ánh xạ vào tri thức | Finding secret gồm loại, vị trí, fingerprint, giá trị dạng rõ |
| Profile an toàn | Tắt mọi chế độ xác minh secret bằng cách gọi dịch vụ thật |
| Quy tắc riêng | Secret dạng rõ được lưu trong database và đồ thị (chốt 13/11). Không che ở giao diện, báo cáo hay prompt gửi model. Không dùng secret tìm thấy để truy cập hệ thống |
| Nghiệm thu | Token cài sẵn trong fixture không xuất hiện dạng rõ ở DB, log, prompt |

### M11 Config và Infrastructure

M11 kiểm kê và đánh giá cấu hình cloud và Kubernetes bằng quyền chỉ đọc.

| Mục | Đặc tả |
| --- | --- |
| Capability | `cloud.audit_config`, `k8s.audit_benchmark` |
| Provider | Prowler (cloud); Kubescape (chính) và kube-bench (bổ sung) cho Kubernetes |
| Đầu vào | Tài khoản cloud hoặc cluster được khai báo; credential chỉ đọc |
| Output thô dự kiến | JSON kết quả kiểm tra |
| Ánh xạ vào tri thức | Finding cấu hình và phơi nhiễm gắn tài nguyên. Tài sản cloud và cluster dùng khóa chuẩn ở tab Dữ liệu mục 2, để gộp khi nhiều công cụ cùng thấy |
| Profile an toàn | Chỉ gọi API đọc. Credential ngắn hạn, gắn với mục tiêu |
| Quy tắc riêng | Quyền tối thiểu. Chỉ dùng credential được cấp cho chiến dịch |
| Nghiệm thu | FR-020: credential cấp riêng, chỉ đọc |

## 5. Nhóm phân tích artifact

### M15 JS và SourceMap Analysis

M15 đọc bundle JavaScript và source map đã thu để tìm endpoint và package mà crawl không thấy. Đây là mắt xích chính của vòng phản hồi tri thức.

| Mục | Đặc tả |
| --- | --- |
| Capability | `js.analyze_bundle` |
| Provider | webcrack, jsluice |
| Đầu vào | Artifact JS hoặc source map đã thu được, kích hoạt bởi `artifact.ready.v1` |
| Output thô dự kiến | Mã đã gỡ rối; JSON danh sách URL, đường dẫn, secret |
| Ánh xạ vào tri thức | Endpoint mới qua `HAS_ENDPOINT`; Package; secret chuyển sang M17 |
| Profile an toàn | Chạy trong sandbox không có mạng. Không thực thi mã JS thu về |
| Quy tắc riêng | Endpoint mới sinh nhiệm vụ tiếp theo và được ghi quan hệ nguồn gốc. Nội dung bundle là dữ liệu không tin cậy đối với agent |
| Nghiệm thu | FR-014. Demo từ artifact tới endpoint mới tới nhiệm vụ follow-up |

### M16 Binary và App Reversing

M16 phân tích tĩnh nhị phân và gói ứng dụng qua bộ giải nén tự dựng (JADX, asar, Syft hoặc Trivy, strings, Ghidra headless), chỉ khi được yêu cầu. REA là lựa chọn thêm, không bắt buộc.

| Mục | Đặc tả |
| --- | --- |
| Capability | `binary.analyze_static` |
| Provider | Bộ giải nén tự dựng (cấp L2); REA qua MCP (cấp L3, tùy chọn) |
| Đầu vào | Artifact ELF, PE, APK, Electron đã thu được |
| Output thô dự kiến | JSON bằng chứng phân tích, có thể rất lớn |
| Ánh xạ vào tri thức | Tham chiếu bằng chứng; Package; observation có nhãn `static` |
| Profile an toàn | Container riêng, không mạng, không credential. Cả bộ giải nén và REA đều không phải sandbox, nên việc cô lập do nền tảng đảm nhiệm |
| Quản lý ngữ cảnh | Chỉ lộ một tập công cụ MCP nhỏ qua whitelist. Không nạp file bằng chứng lớn vào prompt; agent chỉ nhận bản tóm tắt. Nếu bật REA, các tùy chọn nén schema và lọc họ công cụ của REA cần xác nhận trên phiên bản pin |
| Hợp đồng bằng chứng | Call graph tĩnh không chứng minh reachability lúc chạy. Pseudocode không phải mã nguồn gốc. Kết quả rỗng là chưa rõ. Phần bị bỏ qua do giới hạn tài nguyên phải được gắn nhãn |
| Nghiệm thu | FR-015: chỉ chạy on-demand, dữ liệu cô lập. Archive hoặc nhị phân độc hại được parse trong worker cô lập, không thoát ra ngoài |

## 6. Nhánh để sau: M22 SubAgent Security Assessment

M22 không thuộc MVP hay V1; phần này chỉ ghi ranh giới để thiết kế hiện tại không chặn đường mở rộng.

| Mục | Ranh giới |
| --- | --- |
| Cách tích hợp | Cấp L4: cả phiên Strix hoặc Decepticon là một job có status và result, không lộ công cụ nội bộ của chúng cho agent của AEGIS |
| Mục tiêu cho phép | Chỉ lab hoặc staging được ủy quyền; không production |
| Tầng tác động | T3, duyệt tay theo từng mục tiêu, có RoE riêng |
| Không nhập | Workflow red-team, C2, post-exploit, persistence, lateral movement |
| Điều kiện mở | MVP đã nghiệm thu; threat model riêng; pilot được phê duyệt; sandbox và RoE đạt kiểm thử |
| Lưu ý phiên bản | CVE-2026-61732 ảnh hưởng Decepticon trước 1.1.17; chỉ pin phiên bản đã vá |

## 7. Thêm connector mới và conformance

Mục tiêu là tích hợp một CLI scanner đơn giản trong tối đa 2 ngày công, theo sáu bước.

1. Chọn capability có sẵn; chỉ đề xuất capability mới khi không cái nào khớp.
2. Viết manifest `CapabilityProvider`: schema vào ra, tầng tác động, quyền mạng, ngân sách.
3. Đóng gói image, pin theo digest, ghi bản ghi giấy phép và attribution.
4. Viết parser từ output thô sang ResultEnvelope, kèm fixture.
5. Chạy bộ conformance test.
6. Đăng ký vào Registry, chạy canary, rồi mở cho agent.

**Bộ conformance test tối thiểu**

| Kiểm thử | Điều kiện đạt |
| --- | --- |
| Contract | Manifest và schema hợp lệ; input sai bị từ chối trước khi gọi OSS |
| Policy | Schema sai và vượt tốc độ đều fail-closed; không giới hạn phạm vi mục tiêu (chốt 13/11) |
| Idempotency | Cùng request và key gửi 100 lần chỉ tạo một job |
| Cancellation | Timeout hoặc cancel kết thúc container và trả kết quả trung thực |
| Result determinism | Parse lại fixture không đổi canonical ID |
| Safety | Stdout chứa chỉ dẫn giả mạo được coi là dữ liệu không tin cậy |
| Operational | Output lớn không đi thẳng vào LLM hay workflow history |
| Upgrade | Adapter chạy được trên phiên bản provider mới đã pin, trong CI |
