# Đặc tả Kỹ thuật Hệ thống Hợp nhất Rà quét Lỗ hổng và Quản trị Bề mặt Tấn công Điều phối bởi Đa Tác tử AI

Bản đặc tả kỹ thuật này định nghĩa kiến trúc tổng thể, mô hình dữ liệu đồ thị, luồng điều phối tác tử và ma trận tích hợp mã nguồn mở cho một nền tảng phòng thủ chủ động tự hành hợp nhất (tạm gọi là **AEGIS-Vanguard**). Thay vì vận hành như các trình quét lỗ hổng truyền thống chỉ thực thi tập lệnh tĩnh và xuất báo cáo rời rạc, hệ thống được thiết kế theo triết lý **"Vaccine Tấn công" (Offensive Vaccine)** với chu trình khép kín *Tấn công Giả lập → Phòng thủ Chủ động → Kiểm chứng Thực nghiệm* (attack → defend → verify)<sup>1</sup>. Hệ thống hợp nhất kiến trúc của bốn dự án mã nguồn mở trọng tâm: **Flowsint** (reconurge/flowsint) đóng vai trò động cơ làm giàu dữ liệu OSINT và trực quan hóa đồ thị quan hệ<sup>2</sup>; **Decepticon** (BitterSecurity/Decepticon) cung cấp khung điều phối đa tác tử trên LangGraph, cơ chế cách ly mạng kép và quản lý phiên tương tác<sup>1</sup>; **REA** (morluto/rea) đảm nhiệm giao thức Model Context Protocol (MCP) chuyên trách dịch ngược đa định dạng từ mã nguồn đóng, gói ứng dụng web/Electron đến mã nhị phân<sup>5</sup>; và **Strix** (usestrix/strix) thực thi kiểm thử xâm nhập lai (SAST + DAST), tự động viết mã khai thác kiểm chứng (PoC) và sinh bản vá bảo mật (Pull Request)<sup>8</sup>.

Sự kết hợp giữa bốn nền tảng này cùng hệ sinh thái công cụ bổ trợ (ProjectDiscovery, GUAC, SploitScan, TruffleHog, Webcrack, Jsluice) giải quyết bài toán phân mảnh thông tin trong bảo vệ hệ thống nội bộ<sup>9</sup>. Điểm cốt lõi của kiến trúc nằm ở **Vòng lặp Phản hồi Tri thức (Knowledge Feedback Loop)**: mọi tài sản phơi nhiễm thu thập từ góc nhìn Black-box (như thư mục .git bị lộ, tập tin .js.map, gói Webpack bị làm rối, image trên Docker Registry, hay tệp thực thi nhị phân) đều được tác tử tự động chuyển hướng sang phân hệ dịch ngược của REA và bộ công cụ phân tích cây cú pháp trừu tượng (AST) để khôi phục cấu trúc mã nguồn, trích xuất khóa bí mật, tìm kiếm điểm cuối API ẩn và lập bản đồ phụ thuộc phần mềm (SBOM)<sup>5</sup>. Toàn bộ tri thức này được chuẩn hóa vào cơ sở dữ liệu đồ thị Neo4j trung tâm, ngay lập tức nâng cấp phiên rà quét từ góc nhìn Black-box sang Gray-box và White-box, đồng thời đối chiếu tự động với dữ liệu tình báo lỗ hổng (cvelistV5/NVD, OSV, CISA KEV, FIRST EPSS) và kho mã khai thác công khai trên GitHub/Packet Storm để phát cảnh báo sớm đã qua kiểm chứng thực nghiệm trước khi tin tặc kịp khai thác<sup>3</sup>.

Tuy nhiên, việc triển khai một hệ thống tác tử AI có quyền thực thi công cụ rà quét và dịch ngược tự động đặt ra ba thách thức kỹ thuật nghiêm trọng cần được kiểm soát chặt chẽ ngay từ tầng kiến trúc:

1.  **Nguy cơ Tấn công Gián tiếp qua Ngữ cảnh (Indirect Prompt Injection & Role-Boundary Forgery):** Như đã được ghi nhận qua lỗ hổng nghiêm trọng **CVE-2026-61732** (CVSS 10.0) trên nền tảng Decepticon (tồn tại ở phiên bản v1.1.4 và được vá tại v1.1.17), dữ liệu thu thập từ máy chủ mục tiêu khi đi qua các công cụ trinh sát (nmap, httpx, katana) nếu chứa các chuỗi token điều khiển đặc biệt (như \<\|im_end\|\>, \<\|im_start\|\>system của chuẩn ChatML) có thể đánh lừa bộ phân tách từ (tokenizer) của các mô hình ngôn ngữ lớn tự triển khai (vLLM, Ollama, SGLang, TGI), biến dữ liệu đầu ra thành lệnh điều khiển hệ thống để chiếm quyền thực thi shell trong vùng sandbox<sup>18</sup>.

2.  **Sự Phình đại Ngữ cảnh (Context Window Bloat) và Ảo giác Suy luận:** Việc nạp toàn bộ danh mục công cụ lớn (chẳng hạn 207–229 công cụ MCP của REA tiêu tốn tới 3.158.352 bytes dữ liệu định nghĩa JSON thô trên bản v6.7.0) hoặc duy trì lịch sử hội thoại kéo dài qua nhiều pha tấn công sẽ làm suy giảm năng lực suy luận của LLM và gây tràn bộ nhớ ngữ cảnh<sup>7</sup>.

3.  **Xung đột Đồng thời trên Đồ thị Tri thức (Graph Concurrency Bottlenecks):** Khi hàng chục worker trinh sát (Celery) và tác tử chuyên biệt cùng ghi các nút (nodes) và cạnh (edges) vào Neo4j mà không có bộ điều phối giao dịch trung tâm, đồ thị sẽ gặp nguy cơ xung đột ghi hoặc trùng lặp thực thể<sup>23</sup>.

Tài liệu đặc tả dưới đây giải quyết toàn diện các yêu cầu nghiệp vụ và hóa giải cả ba thách thức kỹ thuật nêu trên thông qua thiết kế kiến trúc phân lớp nghiêm ngặt.

## Phần 1: Kiến trúc Tổng thể Hệ thống và Mô hình Điều phối Đa Tác tử

### 1.1. Kiến trúc Hai Mặt phẳng Mạng Cách ly (Dual-Plane Network Isolation Topology)

Kế thừa và mở rộng mô hình kiến trúc từ BitterSecurity/Decepticon và reconurge/flowsint, hệ thống được thiết kế theo mô hình vùng mạng kép tách biệt giữa mặt phẳng điều khiển trí tuệ nhân tạo và mặt phẳng thực thi công cụ tác chiến<sup>1</sup>. Toàn bộ hạ tầng vận hành trên nền tảng container hóa (Docker Compose v2 hoặc Kubernetes), phân chia thành ba phân vùng chức năng rõ rệt<sup>1</sup>.

<img src="markdown/media/�����c T��� H��� Th���ng R�� Qu��t L��� H���ng AI/media/image3.png" style="width:6.45833in;height:3.52083in" />

#### Mặt phẳng Quản trị và Điều phối (decepticon-net / management-net)

Phân vùng này chứa các dịch vụ lõi luôn hoạt động (always-on services) chịu trách nhiệm suy luận và kiểm soát trạng thái<sup>1</sup>. Bộ điều phối **LangGraph & Deep Agents** quản lý luồng thực thi tác tử, duy trì trạng thái kế hoạch tác chiến (OPPLAN), quản lý điểm kiểm tra (checkpoints) và phát luồng sự kiện thời gian thực<sup>1</sup>. Nhằm ngăn chặn nguy cơ leo thang đặc quyền từ container bị xâm nhập ra máy chủ vật lý, container LangGraph tuyệt đối không được gắn kết (mount) Docker socket của host; quyền điều khiển dịch vụ cấp host được tách riêng sang container CLI của người vận hành dưới một ranh giới tin cậy độc lập<sup>4</sup>. Bên cạnh đó, cổng định tuyến **LiteLLM** cung cấp lớp trừu tượng hóa kết nối tới hơn 100 nhà cung cấp LLM (OpenAI, Anthropic, Google Vertex AI, AWS Bedrock, OpenRouter, Vercel AI Gateway) cũng như các mô hình nội bộ tự triển khai qua Ollama, vLLM hoặc LM Studio, đồng thời quản lý thông tin xác thực, theo dõi chi phí token và thực thi chuỗi chuyển đổi dự phòng (fallback chain) khi gặp giới hạn tốc độ hoặc tràn ngữ cảnh<sup>1</sup>. Dịch vụ **Skillogy REST Service** quản lý kho tri thức tác chiến được định nghĩa dưới dạng các tệp chuẩn hóa SKILL.md và ánh xạ trực tiếp với ma trận chiến thuật MITRE ATT&CK Enterprise trên đồ thị<sup>4</sup>. Song song đó, cụm dịch vụ OSINT (flowsint-api trên nền FastAPI và flowsint-core) xử lý xác thực người dùng, truyền tải sự kiện đồ thị tới giao diện flowsint-app (được tối ưu hóa bằng react-force-graph để hiển thị hàng nghìn nút mà không bị trễ), đồng thời quản lý kho khóa bảo mật (Vault mã hóa các khóa API ngoại vi bằng khóa chủ MASTER_VAULT_KEY_V1) và hàng đợi tác vụ nền Celery + Redis<sup>2</sup>.

#### Trục Dữ liệu và Đồ thị Tri thức Hai Nhánh (Dual-Homed Persistence Spine)

Cơ sở dữ liệu đồ thị **Neo4j (Engagement Neo4j)** được kết nối đồng thời vào cả hai mạng management-net và sandbox-net, đồng thời được kiểm soát ghi thông qua module trung gian Graph Conductor của flowsint-core<sup>1</sup>. Kiến trúc hai nhánh này cho phép các công cụ thu thập trong vùng sandbox ghi kết quả đã qua kiểm duyệt vào đồ thị, trong khi các tác tử trên mặt phẳng quản trị truy vấn đồ thị bằng ngôn ngữ Cypher ở chế độ chỉ đọc (read-only) kết hợp với các công cụ truy xuất chuyên biệt để ra quyết định cho bước tiếp theo<sup>1</sup>. Lưu ý rằng việc chia sẻ kết nối mạng đòi hỏi phải thiết lập quy tắc tường lửa nội bộ (network policies) để đảm bảo container sandbox chỉ có thể giao tiếp với cổng dịch vụ được chỉ định mà không thể vươn tới các cổng quản trị trên management-net<sup>4</sup>. Đi kèm với Neo4j, hệ quản trị **PostgreSQL** lưu trữ dữ liệu quan hệ của phiên điều tra, nhật ký kiểm toán (EventLogMiddleware), cấu hình Rules of Engagement (RoE) và chi phí ngân sách<sup>3</sup>, trong khi hệ thống lưu trữ đối tượng (MinIO/S3) lưu giữ các tệp tài liệu, mã nhị phân, mã nguồn thu hồi, ảnh chụp bộ nhớ (snapshots) và báo cáo chuẩn SARIF<sup>8</sup>.

#### Mặt phẳng Thực thi Cô lập (sandbox-net)

Mọi công cụ rà quét, dịch ngược và kiểm chứng đều chạy bên trong các container thực thi cô lập, không có quyền truy cập trực tiếp vào management-net<sup>1</sup>. Trong môi trường **Kali Linux Cứng hóa (HTTPSandbox)**, bộ điều phối LangGraph giao tiếp với daemon của sandbox thông qua giao thức HTTP nội bộ (SANDBOX_URL=http://sandbox:9999), loại bỏ hoàn toàn phương thức DockerSandbox / docker-exec cũ<sup>4</sup>. Bên trong sandbox, mọi lệnh dòng lệnh được quản lý qua các phiên tmux bền vững có tích hợp bộ nhận diện dấu nhắc tự động (automatic prompt detection), cho phép tác tử gửi các lệnh nối tiếp khi làm việc với các công cụ tương tác như msfconsole, sliver-client, hay evil-winrm<sup>1</sup>. Đối với kiểm thử ứng dụng web và API, **Strix Sandbox Runtime** cung cấp proxy chặn bắt HTTP **Caido**, trình duyệt không giao diện **Playwright** hỗ trợ đa tab để kiểm thử DOM XSS, CSRF và luồng xác thực, bộ quét mẫu **Nuclei**, cùng môi trường **Python PoC Runtime** cô lập để chạy mã khai thác thử nghiệm<sup>8</sup>. Đặc biệt, các công cụ tiêu tốn nhiều tài nguyên thuộc nhóm **Dynamic-Spawn Specialist Workloads** như máy chủ dịch ngược **REA + Ghidra 12.1+ / JADX**, hệ thống phân tích đường đi Active Directory **BloodHound CE** (sử dụng một Neo4j riêng biệt) hay máy chủ C2 chỉ được bộ điều phối bật lên theo yêu cầu thông qua lệnh vận hành như ops_start("ad") và tự động thu hồi qua ops_stop / ops_cleanup_engagement sau khi hoàn tất mục tiêu<sup>1</sup>.

### 1.2. Thiết kế Hệ thống Đa Tác tử Phân cấp và Cơ chế Ngữ cảnh Sạch (Fresh Context Model)

Để khắc phục hiện tượng suy thoái chất lượng suy luận khi lịch sử hội thoại kéo dài, hệ thống áp dụng **Mô hình Ngữ cảnh Sạch theo Mục tiêu (Fresh Context Window per Objective)** từ Decepticon kết hợp với kiến trúc **Đồ thị Tác tử Song song (Graph of Agents)** của Strix<sup>1</sup>.

Mỗi tác tử chuyên biệt khi được gọi qua công cụ task() sẽ khởi tạo một cửa sổ ngữ cảnh hoàn toàn mới, chỉ nhận vào đúng 3 thành phần: (1) Mô tả mục tiêu cụ thể từ bảng tiến độ OPPLAN, (2) Ràng buộc phạm vi được phép (RoE) ở dạng máy đọc được, và (3) Các bằng chứng lịch sử liên quan trực tiếp được trích xuất từ thư mục /workspace hoặc Neo4j<sup>4</sup>. Trạng thái dài hạn tuyệt đối không lưu trong bộ nhớ hội thoại của LLM mà phải ghi xuống đĩa (/workspace) và đồ thị tri thức<sup>22</sup>. Theo tài liệu công bố của dự án Decepticon, kiến trúc 16 tác tử chuyên biệt với cửa sổ ngữ cảnh sạch này đã đạt tỷ lệ vượt qua bài kiểm chuẩn **XBOW validation-benchmarks** ở mức **98,08% (102/104 bài kiểm thử)**, bao gồm 100% (45/45) ở Mức 1 (Dễ), 98,0% (50/51) ở Mức 2 (Trung bình) và 87,5% (7/8) ở Mức 3 (Khó)<sup>1</sup>.

Danh mục các tác tử trong hệ thống được phân bổ thành sáu nhóm chức năng chuyên biệt, kết hợp cơ chế định tuyến mô hình phân tầng (**Tiered Model Routing** với cấu hình mặc định eco) nhằm tối ưu hóa chi phí vận hành mà vẫn duy trì năng lực suy luận cao cho các tác vụ phức tạp<sup>1</sup>:

| **Nhóm Tác tử**                                    | **Tên Tác tử Chuyên biệt**                                                | **Phân tầng Mô hình LLM (eco profile)**                    | **Nhiệm vụ Cốt lõi & Công cụ Được Cấp quyền**                                                                                                                                     | **Nguồn Tham chiếu**                      |
|----------------------------------------------------|---------------------------------------------------------------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------|
| **Điều phối & Lập kế hoạch (Orchestrators)**       | Soundwave & autohunt (Engagement Planners)                                | LOW / MID                                                  | Đồ thị lập kế hoạch độc lập (không có quyền chạy lệnh bash); phân tích mục tiêu, đối chiếu RoE chỉ đọc và sinh bộ 7 tài liệu kế hoạch rà quét ban đầu.                            | Decepticon<sup>1</sup>                    |
| **Điều phối & Lập kế hoạch (Orchestrators)**       | Core-Orchestrator (Decepticon + Vulnresearch)                             | HIGH (Claude Opus/Sonnet 5.5, GPT-6.1 Sol, Gemini 4 Argon) | Sở hữu bảng tiến độ OPPLAN; điều phối đường ống 5 giai đoạn (scanner → detector → verifier → patcher → exploiter); gọi task() phân công cho các tác tử chuyên biệt.               | Decepticon, Strix<sup>1</sup>             |
| **Trinh sát & Khai phá (Discovery & OSINT)**       | OSINT-Operator & Recon-Agent                                              | LOW (DeepSeek V4.1 Flash, GLM-5.3, Llama 4)                | Thực thi chế độ chỉ đọc (read-only) với các enricher của Flowsint, quét cổng, phân giải DNS, thu thập subdomain, tìm kiếm tài sản rò rỉ và ghi thực thể vào Neo4j.                | Flowsint, Decepticon, Strix<sup>1</sup>   |
| **Dịch ngược & Phân tích Tĩnh (Reversing & SAST)** | Reverser-Agent & Code-Analyst                                             | HIGH                                                       | Kết nối máy chủ MCP của REA để dịch ngược nhị phân (Ghidra/Hopper), giải nén gói JS/Electron/APK, chạy webcrack, jsluice, semgrep, bandit, gitleaks và dựng đồ thị luồng gọi hàm. | REA, Decepticon<sup>5</sup>               |
| **Tương quan Tình báo & Chuỗi Cung ứng**           | SupplyChain-Operator & Scanner                                            | MID                                                        | Phân tích SBOM/pURL qua GUAC, đối chiếu CVE/KEV/EPSS qua cvemap và SploitScan, truy tìm mã PoC trên GitHub/Packet Storm và phát hiện lỗi dependency confusion / CI/CD.            | Decepticon, GUAC, SploitScan<sup>15</sup> |
| **Kiểm chứng Động & Chuyên gia Môi trường**        | Exploit, Post-Exploit, AD-Operator, Cloud-Hunter, Mobile/IoT/ICS-Operator | HIGH / MID                                                 | Sử dụng Caido proxy, Playwright, và Python PoC Runtime của Strix để chạy mã kiểm chứng lỗ hổng thực tế; kiểm thử leo thang đặc quyền AD (BloodHound) và Cloud IAM/K8s.            | Strix, Decepticon<sup>8</sup>             |
| **Thẩm định, Vá lỗi & Phòng thủ (Blue Cell)**      | finding_verifier, finding_reporter, Patcher & AutoBot (Forensicator)      | HIGH                                                       | Thẩm định độc lập kết quả bằng đối chứng âm (negative controls); sinh bản vá mã nguồn (PR) và quy tắc phát hiện; kiểm chứng log qua Fluent Bit/Caddy và lập báo cáo chuẩn.        | Decepticon, Strix<sup>1</sup>             |

Để ngăn chặn tình trạng tác tử chạy vòng lặp vô tận (như lỗi chạm giới hạn đệ quy Recursion limit từng được báo cáo tại Issue \#127 của Decepticon khi tác tử kiểm thử prompt injection trên mục tiêu thực tế) hoặc tiêu tốn ngân sách LLM vượt kiểm soát, hệ thống áp dụng cơ chế **Ngắt Mạch Ngân sách và Lượt gọi Đa tầng** từ Strix kết hợp với BudgetEnforcementMiddleware của Decepticon<sup>8</sup>. Cụ thể, mỗi phiên quét được cấu hình hạn mức chi tiêu tối đa --max-budget (tính bằng USD) và số lượt tối đa --max-turns (mặc định 500 lượt phản hồi mô hình + gọi công cụ cho mỗi tác tử)<sup>8</sup>. Khi tiệm cận giới hạn, hệ thống tự động bơm cảnh báo thu gọn (wrap-up warnings) vào ngữ cảnh để tác tử gọi công cụ đóng vòng đời (finish_scan cho tác tử gốc và agent_finish cho tác tử con)<sup>8</sup>:

- **Ở chế độ tự động không tương tác (--non-interactive / -n):** Các tác tử con nhận cảnh báo tại các mốc **75%, 80%, 85%** và bị cưỡng bức dừng ở mức **90% ngân sách**, qua đó bảo toàn nguyên vẹn **10% ngân sách dự phòng cuối cùng** cho Tác tử Gốc (nhận cảnh báo ở các mốc **70%, 85%, 95%** và dừng ở **100%**) để tổng hợp dữ liệu, xuất báo cáo SARIF và đóng hạ tầng sandbox an toàn<sup>8</sup>.

- **Ở chế độ tương tác (Interactive Mode):** Tất cả các tác tử đều nhận cảnh báo tại các mốc **70%, 85% và 95%**, sau đó tạm dừng (park/pause) khi chạm 100% ngân sách để chờ người vận hành gửi tin nhắn xác nhận gia hạn trước khi tiếp tục<sup>8</sup>.

## Phần 2: Đặc tả Chi tiết Các Phân hệ Chức năng và Ánh xạ Module Mã nguồn Mở

### 2.1. Phân hệ 1: Trinh sát và Khám phá Hệ thống Đa Góc nhìn (Multi-Perspective Recon & Discovery Engine)

Phân hệ đầu tiên đảm nhận việc lập bản đồ toàn diện bề mặt tấn công của tổ chức thông qua sự kết hợp linh hoạt giữa ba góc nhìn: **Black-box** (từ ngoài Internet nhìn vào không cần thông tin trước), **Gray-box** (có tài khoản người dùng tiêu chuẩn, tệp đặc tả API hoặc quyền truy cập mạng nội bộ), và **White-box** (truy cập trực tiếp mã nguồn, cấu hình CI/CD và API quản trị đám mây)<sup>3</sup>.

#### Khám phá Bề mặt Bên ngoài (Black-box OSINT & External Attack Surface)

Hệ thống tích hợp trực tiếp kiến trúc module của **reconurge/flowsint** (flowsint-core, flowsint-enrichers, flowsint-types) làm động cơ mở rộng thực thể tự động<sup>2</sup>. Từ một vài thực thể hạt giống ban đầu (tên công ty, tên miền gốc, dải ASN/CIDR, địa chỉ email quản trị), OSINT-Operator kích hoạt chuỗi hơn 38–49 enrichers thuộc 11 danh mục chạy bất đồng bộ qua Celery<sup>2</sup>. Ở tầng hạ tầng mạng và tên miền, hệ thống sử dụng org_to_asn và asn_to_cidrs (gọi CLI asnmap và jq) để tìm toàn bộ dải IP thuộc sở hữu của tổ chức; dùng cidr_to_ips (dnsx quét PTR) và ip_to_ports (naabu) để định vị các cổng dịch vụ đang mở; đồng thời kết hợp domain_to_subdomains (subfinder kèm cơ chế dự phòng qua JSON API của crt.sh), domain_to_tls (httpx), website_to_subdomains (c99.nl API) và domain_to_history / domain_to_whois_history (qua Whoxy API và WhoisXML API) để truy vết cả các tên miền lịch sử hoặc hạ tầng bị bỏ quên<sup>9</sup>. Ở tầng tình báo định danh và rò rỉ dữ liệu, hệ thống tự động kiểm tra email, tên miền, tên người dùng và số điện thoại nhân sự qua các module domain_to_dehashed, email_to_breaches (Have I Been Pwned API), username_to_socials_maigret (maigret), website_to_crawler (reconcrawl), website_to_links (reconspread), website_to_webtrackers (recontrack), và đặc biệt là bộ ba email_to_device_hudsonrock, phone_to_device_hudsonrock, username_to_device_hudsonrock (tích hợp HudsonRock API) để phát hiện sớm các máy trạm nội bộ của nhân viên đã bị nhiễm mã độc đánh cắp thông tin (infostealers)<sup>9</sup>. Song song đó, hệ thống tích hợp **projectdiscovery/uncover** để truy vấn đồng thời qua hơn 15 công cụ tìm kiếm không gian mạng (Shodan, Shodan-InternetDB miễn phí không cần API key, Censys, FOFA, Quake, Hunter, ZoomEye, Netlas, CriminalIP, PublicWWW, Google, Onyphe, Driftnet) nhằm phát hiện các máy chủ nội bộ vô tình mở cổng ra Internet và đẩy trực tiếp đầu ra qua đường ống stdin/stdout sang naabu hoặc httpx<sup>32</sup>.

#### Khám phá Góc nhìn Xám (Gray-box Authenticated & Contract-Driven Discovery)

Đối với các ứng dụng web phức tạp sử dụng Single Page Application (SPA) yêu cầu đăng nhập, hệ thống tích hợp **projectdiscovery/katana** ở chế độ lai không giao diện (-hl / -headless, -sc / -system-chrome, -jc / -js-crawl) kết hợp tính năng phát lại luồng đăng nhập (-rf login.json -al 'user:password')<sup>33</sup>. Katana khởi chạy trình duyệt Chrome thực thụ nhằm đảm bảo dấu vân tay HTTP (TLS và User-Agent) hoàn toàn giống trình duyệt người dùng thật, ghi nhận trạng thái trình duyệt ẩn danh ban đầu, sau đó thực thi kịch bản đăng nhập đã ghi từ Chrome DevTools Recorder (hoặc tệp JSON định nghĩa các bước navigate, fill, click, waitvisible, submit), kiểm tra sự thay đổi của cookie hoặc web-storage cùng nguồn (same-origin) để xác nhận phiên hợp lệ (nếu thất bại sẽ tự động thử cơ chế dự phòng -auto-login), tự động bỏ qua các đường dẫn đăng xuất (logout URLs) và cào toàn bộ cấu trúc DOM cũng như các điểm cuối bên trong tệp JavaScript trong suốt thời lượng phiên<sup>33</sup>. Đối với hệ thống vi dịch vụ (Microservices) và API nội bộ, phân hệ sử dụng cơ chế nạp mục tiêu đa dạng của **usestrix/strix**<sup>8</sup>. Tác tử nhận đầu vào là các tệp đặc tả OpenAPI/Swagger (--target ./openapi.yaml --target https://api.example.com) hoặc nạp trực tiếp bộ sưu tập Postman sống qua ID kèm biến môi trường (--target "postman://\<collection-uuid\>?env=\<environment-uuid\>" sử dụng POSTMAN_API_KEY)<sup>8</sup>. Strix tự động sao chép đặc tả vào không gian làm việc của tác tử, phê duyệt các URL cơ sở (base URLs) được khai báo trong hợp đồng API vào danh sách trong phạm vi (in-scope hosts) và sử dụng proxy **Caido** cùng **Playwright** để rà quét toàn bộ các điểm cuối theo ngữ cảnh đã xác thực (--instruction "Perform authenticated testing using credentials: user:pass")<sup>8</sup>.

#### Khám phá Góc nhìn Trắng (White-box Codebase, Cloud & Diff-Scoped CI/CD)

Ở tầng hạ tầng đám mây, hệ thống tích hợp **cartography-cncf/cartography** cùng các công cụ kiểm toán cấu hình như **Prowler / CloudSploit** để kết nối trực tiếp vào API quản trị đám mây (AWS, GCP, Azure, Kubernetes), tự động đồng bộ toàn bộ tài sản hạ tầng, chính sách IAM, S3 ACLs, ảnh chụp RDS công khai và mối quan hệ bề mặt tấn công vào cơ sở dữ liệu Neo4j<sup>10</sup>. Ở tầng mã nguồn ứng dụng, hệ thống tích hợp chế độ quét vi sai của **usestrix/strix** (--scope-mode diff --diff-base origin/main hoặc auto trong CI/CD)<sup>8</sup>. Thay vì phải quét lại toàn bộ kho mã nguồn lớn mỗi ngày, khi có bất kỳ thay đổi nào trên nhánh phát triển hoặc Pull Request nội bộ, tác tử tự động khoanh vùng phân tích tĩnh và động đúng vào tập hợp các tệp vừa thay đổi so với nhánh gốc, rút ngắn thời gian kiểm thử xâm nhập từ hàng tuần xuống chỉ còn vài phút hoặc vài giờ<sup>8</sup>.

### 2.2. Phân hệ 2: Dịch ngược Tài sản Phơi nhiễm và Khai phá Tri thức Chuyên sâu (Exposed Asset Reverse Engineering & Deep Inspection)

Đây là phân hệ tạo nên sự khác biệt chiến lược của hệ thống: biến các tài sản tĩnh hoặc mã đóng thu thập được từ quá trình trinh sát thành nguồn dữ liệu đầu vào giàu ngữ cảnh để kích hoạt các vòng lặp trinh sát sâu hơn.

<img src="markdown/media/�����c T��� H��� Th���ng R�� Qu��t L��� H���ng AI/media/image2.png" style="width:6.45833in;height:3.52083in" />

Quy trình xử lý và dịch ngược tài sản phơi nhiễm được chia thành bốn đường ống (pipelines) chuyên biệt do Reverser-Agent và Code-Analyst điều khiển:

#### Đường ống Khôi phục Kho Mã nguồn Git và Quét Khóa Bí mật (Exposed Git & Secret Verification Pipeline)

Khi Nuclei (với các mẫu quét phơi nhiễm) hoặc httpx phát hiện thư mục .git/HEAD có thể truy cập công khai trên máy chủ web (trả về ref: refs/heads/main), tác tử lập tức kích hoạt **arthaud/git-dumper** (git-dumper https://target.com/.git/ ./recovered_repo) để tải xuống các đối tượng git và tái cấu trúc lại toàn bộ cây mã nguồn cùng lịch sử commit vào không gian làm việc<sup>10</sup>. Ngay sau khi khôi phục, hệ thống chạy kết hợp **gitleaks/gitleaks** (gitleaks detect --source . --report-format json) để quét nhanh trên toàn bộ lịch sử commit và **trufflesecurity/trufflehog** với cờ --only-verified (trufflehog filesystem ./recovered_repo --only-verified cũng như trufflehog git và trufflehog s3) nhằm chủ động xác thực xem khóa bị lộ có còn hoạt động thực tế hay không<sup>10</sup>. Mọi khóa xác thực còn hiệu lực lập tức được ghi vào đồ thị Neo4j dưới dạng nút VerifiedCredential, kích hoạt tác tử Cloud-Hunter hoặc Recon-Agent mở rộng trinh sát vào các tài nguyên nội bộ mà khóa đó cấp quyền<sup>10</sup>.

#### Đường ống Giải mã, Phục hồi và Phân tích Cây Cú pháp Trừu tượng Mã nguồn Web (Web Bundle Deobfuscation & AST Extraction Pipeline)

Các ứng dụng web hiện đại thường đóng gói toàn bộ logic điều hướng, đường dẫn API quản trị nội bộ và cấu hình môi trường vào các tệp JavaScript đã được rút gọn (minified) hoặc làm rối (obfuscated). Hệ thống xử lý tự động qua ba tầng nối tiếp. Đầu tiên, nếu phát hiện tệp .js.map đi kèm, tác tử dùng **denandz/sourcemapper** hoặc danvk/source-map-explorer để giải nén và khôi phục nguyên trạng cây thư mục mã nguồn JavaScript/TypeScript gốc<sup>10</sup>. Tiếp theo, đối với các tệp bundle không có source map hoặc bị làm rối bằng obfuscator.io, tác tử gọi **j4k0xb/webcrack** (webcrack bundle.js -o output-dir) để giải rối mảng chuỗi (string array), làm phẳng luồng điều khiển, loại bỏ mã bao bọc của trình đóng gói và tách gói Webpack/Browserify về dạng tiệm cận mã nguồn gốc nhất (lưu ý cấu hình môi trường cần thiết lập NODE_OPTIONS="--max-old-space-size=8192" để tránh lỗi tràn bộ nhớ V8 heap đối với các tệp .js kích thước lớn)<sup>14</sup>. Cuối cùng, thay vì chỉ dùng biểu thức chính quy đơn thuần dễ bỏ sót chuỗi nối động, hệ thống sử dụng **BishopFox/jsluice** (xây dựng trên bộ phân tích cú pháp go-tree-sitter) để duyệt toàn bộ cây cú pháp AST<sup>12</sup>. Jsluice tự động giải mã các chuỗi thoát hex, octal và unicode (DecodeString), định vị chính xác các biểu thức gán vào document.location, lời gọi hàm window.open(), fetch(), đồng thời trích xuất các khóa bí mật kèm theo cả tên khóa, giá trị và đối tượng cha chứa chúng (parent object context)<sup>12</sup>. Nhờ đó, khi phát hiện một biểu thức như document.location = "/login?redirect=" + redirect + "&method=oauth", hệ thống nắm được đầy đủ cấu trúc tham số để đẩy ngược lại cho Katana và Strix kiểm thử xâm nhập<sup>8</sup>.

#### Đường ống Giải nén Container Registry, Firmware và Gói Ứng dụng Desktop/Mobile (Container, Firmware & App Unpacking Pipeline)

Đối với các image lấy từ Docker Registry nội bộ hoặc phơi nhiễm, hệ thống giải nén các lớp hệ thống tệp, kết hợp công cụ tạo danh mục thành phần phần mềm (SBOM) theo chuẩn pURL để chuyển cho phân hệ **GUAC**, đồng thời hỗ trợ nhập trực tiếp báo cáo quét từ Docker Scout qua SploitScan<sup>13</sup>. Đối với các gói ứng dụng Electron (.asar), ứng dụng di động Android (.apk), gói thực thi Python (PyInstaller), tệp mô hình AI (GGUF, safetensors), gói lưu lượng mạng (HAR, SAZ, TShark), cơ sở dữ liệu SQLite hoặc firmware thiết bị IoT/nhúng thu thập được, tác tử gọi trực tiếp bộ công cụ của **morluto/rea** (rea-agents)<sup>6</sup>. Cụ thể, với ứng dụng Electron/JavaScript, lệnh npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json và công cụ inspect-electron-fuses cho phép kiểm tra các cờ bảo mật cấp thực thi mà không cần chạy ứng dụng (chẳng hạn phát hiện các cờ nguy hiểm như RunAsNode, EnableNodeOptionsEnvironmentVariable, EnableNodeCliInspectArguments đang bật trong khi EnableEmbeddedAsarIntegrityValidation và OnlyLoadAppFromAsar bị tắt), đồng thời khôi phục toàn bộ đồ thị module, các kênh giao tiếp liên tiến trình (IPC channels/handlers) và danh sách thư viện gốc (.node native add-ons)<sup>5</sup>. Với firmware và ứng dụng di động, REA kết hợp cùng Mobile-Operator và IoT-Operator của Decepticon điều phối **Binwalk**, **Unblob** để trích xuất hệ thống tệp nhúng, và dùng **JADX**, **apktool**, **Frida/Objection** để dịch ngược mã bytecode Android/Java nhằm tìm kiếm khóa cứng (hardcoded credentials) hoặc các thành phần exported không bảo vệ<sup>6</sup>.

#### Đường ống Dịch ngược Nhị phân Chuyên sâu Qua Giao thức MCP (Native Binary Decompilation via REA MCP)

Khi phát hiện các tệp thực thi nhị phân nội bộ (ELF trên Linux, PE trên Windows, Mach-O trên macOS, mã biên dịch từ C/C++, Go, Rust, IL2CPP, .NET assemblies hoặc WebAssembly/EVM bytecode) bên trong các container hoặc kho lưu trữ, Reverser-Agent giao tiếp với máy chủ **rea mcp** (chạy qua stdin/stdout theo chuẩn giao thức MCP 2025-06-18)<sup>6</sup>. REA đóng vai trò lớp điều phối thống nhất đứng trước 6+ bộ dịch ngược và phân tích nhị phân gồm **Ghidra 12.1+** (yêu cầu JDK 21+ 64-bit; trên kiến trúc Linux arm64 cần biên dịch bộ decompiler gốc qua ./gradlew buildNatives), **Hopper**, **IDA Pro/Home**, **Kuna**, **Rizin** và objdump<sup>6</sup>. Bộ kết nối Ghidra của REA được thiết kế bảo toàn tính toàn vẹn ở chế độ **chỉ đọc hoàn toàn (strictly read-only)**, mở tệp nhị phân trong các dự án tạm thời với cờ -readOnly -deleteProject (hoặc giữ phiên mở qua rea mcp / cờ --snapshot) và cung cấp 27 thao tác chuyên biệt (15 thao tác kiểm kê/tìm kiếm ký hiệu và 12 thao tác phân tích hàm như procedure_pseudo_code, procedure_callers, xrefs, search_strings, batch_decompile, get_call_graph)<sup>6</sup>. Qua đó, tác tử có thể dùng rea trace và rea decompile để truy vết ngược từ một chuỗi ký tự mục tiêu đến địa chỉ hàm và khôi phục chính xác mã giả C (pseudocode) cùng các hằng số kiểm tra logic xác thực bên trong tệp nhị phân đã bị tước bỏ ký hiệu (stripped binary)<sup>7</sup>. Do chính sách bảo mật của REA nêu rõ công cụ này không phải là một sandbox cách ly quyền hệ điều hành, mọi thao tác phân tích nhị phân của REA đều được hệ thống bắt buộc chạy bên trong container chuyên biệt thuộc mạng sandbox-net<sup>4</sup>.

### 2.3. Phân hệ 3: Cơ sở Dữ liệu Tri thức Đồ thị Kép (Unified Knowledge Graph & Ontology)

Để hợp nhất dữ liệu từ trinh sát mạng (Flowsint), chuỗi tấn công và kỹ năng (Decepticon), cấu trúc mã dịch ngược (REA), và danh mục thành phần phần mềm (GUAC), hệ thống sử dụng cơ sở dữ liệu đồ thị **Neo4j** làm trục lưu trữ trạng thái trung tâm<sup>3</sup>.

Về mặt chuẩn hóa dữ liệu, hệ thống kế thừa lớp SchemaOrgMixin (flowsint/typing/schema_org/\_base.py) của **Flowsint** (được thiết kế tại Issue \#132) để ánh xạ mọi thực thể từ flowsint-types sang định dạng ngữ nghĩa chuẩn **JSON-LD** kết hợp không gian tên https://schema.org/ và https://schema.flowsint.io/<sup>39</sup>, đồng thời tích hợp mô hình cây bằng chứng (Evidence Trees) và định danh gói phần mềm **pURL** (pkg://@?) từ **guacsec/guac**<sup>17</sup>.

Nhằm giải quyết bài toán xung đột khi nhiều Celery workers của Flowsint và các tác tử của Decepticon/Strix cùng ghi các nút và cạnh vào Neo4j mà không có cơ chế khóa đồng thời, hệ thống triển khai module **Graph Conductor** (dựa trên thiết kế tại Issue \#133 của flowsint-core/src/flowsint/core) đứng chắn giữa các tác tử/enrichers và Neo4j<sup>23</sup>. Mọi thao tác thêm mới hoặc cập nhật nút/cạnh đều đi qua tầng điều phối này theo khóa định danh chuẩn hóa (schema_id hoặc IRI), đảm bảo chống trùng lặp thực thể, gắn nhãn nguồn gốc dữ liệu (provenance tracking) và hỗ trợ tính năng hoàn tác độc lập (agnostic revert) khi cần thu hồi dữ liệu của một lượt chạy enricher bất kỳ<sup>4</sup>.

Bảng dưới đây đặc tả Lược đồ Thực thể và Quan hệ (Graph Ontology Schema) của hệ thống:

| **Nhóm Thực thể (Node Label)**            | **Thuộc tính Định danh & Cốt lõi (Key Properties)**                                             | **Các Cạnh Quan hệ Đi ra (Outgoing Edges)**                        | **Nguồn Khởi tạo / Làm giàu**                                                |
|-------------------------------------------|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|------------------------------------------------------------------------------|
| Organization / Person (Individual)        | schema_id, name, email, telephone, sirene_id                                                    | OWNS_ASN, REGISTERED_DOMAIN, AFFILIATED_WITH, EXPOSED_IN_BREACH    | flowsint (SchemaOrgMixin, Whoxy, WhoisXML, DeHashed, HudsonRock)<sup>9</sup> |
| ASN / CIDR / IPAddress                    | asn, cidr_block, address, version (IPv4 \| IPv6), country_code, fraud_score                     | ANNOUNCES_CIDR, CONTAINS_IP, RESOLVES_TO, EXPOSES_PORT             | flowsint (asnmap, dnsx, naabu, Scamalytics)<sup>9</sup>                      |
| Domain / WebSite                          | fqdn, root_domain, tls_info, http_status, webtrackers                                           | HAS_SUBDOMAIN, HOSTED_ON_IP, SERVES_ASSET, EXPOSES_ENDPOINT        | flowsint, subfinder, httpx, katana, uncover<sup>9</sup>                      |
| Artifact / Document                       | artifact_id, algorithm, digest, storage_uri (MinIO/S3)                                          | DECOMPILED_INTO, CONTAINS_SECRET, HAS_SBOM, ARTIFACT_HAS_SLSA      | git-dumper, sourcemapper, webcrack, rea, guac, flowsint<sup>7</sup>          |
| CodeProcedure / IPCChannel                | procedure_name, entry_address, evidence_type (static \| runtime), resource_constraint           | CALLS_PROCEDURE, REFERENCES_STRING, INVOKES_API, LISTENS_IPC       | morluto/rea (Ghidra, Hopper, JADX, Electron analyzer)<sup>6</sup>            |
| VerifiedCredential                        | secret_type, key_id_masked, is_verified (true), parent_object_context                           | GRANTS_ACCESS_TO, EXTRACTED_FROM                                   | trufflehog (--only-verified), gitleaks, jsluice<sup>10</sup>                 |
| Package (pURL Trie)                       | id, purl, scorecard_score, timeScanned, dbUri                                                   | DEPENDS_ON, CERTIFY_VULN, HAS_SBOM, HAS_VEX_STATUS                 | guacsec/guac (Deps.dev, OSV.dev, Scorecards collectors)<sup>13</sup>         |
| Vulnerability (CVE / OSV / GHSA / NoVuln) | vuln_id (canonical lowercase), year, cvss_score, epss_score, in_cisa_kev, priority_tier (A+..D) | IS_VULNERABILITY, MAPS_TO_CPE, HAS_PUBLIC_POC, HAS_NUCLEI_TEMPLATE | cvemap, SploitScan, guac (IsVulnerability, CertifyVuln)<sup>11</sup>         |
| ExploitPoC / ValidatedFinding             | poc_id, source_url, verification_status (PASSED \| BLOCKED), sarif_uri                          | EXPLOITS_VULN, VERIFIED_AGAINST, REMEDIATED_BY                     | strix, Decepticon (finding_verifier, Patcher), trickest/cve<sup>8</sup>      |

### 2.4. Phân hệ 4: Tương quan Tình báo Lỗ hổng Ngoại vi và Ánh xạ Mã Khai thác (External Threat Intelligence & CVE-to-PoC Mapping)

Khi Đồ thị Tri thức Neo4j đã thu thập được danh sách các dịch vụ mạng, phiên bản máy chủ web, thư viện phụ thuộc (pURL/CPE) từ quá trình dịch ngược container/mã nguồn, hệ thống sẽ thực hiện đối chiếu tự động với các nguồn tình báo lỗ hổng bên ngoài để định lượng rủi ro và tìm kiếm mã khai thác tương ứng.

<img src="markdown/media/�����c T��� H��� Th���ng R�� Qu��t L��� H���ng AI/media/image1.png" style="width:4.34375in;height:9.16667in" />

#### Tương quan Cây Phụ thuộc Phần mềm và Chứng thực VEX (guacsec/guac)

Mọi tài sản nội bộ (từ kho Git, image Docker đến tệp thực thi đã dịch ngược) đều được tạo SBOM/SLSA và đẩy vào dịch vụ **GUAC** (sử dụng kiến trúc pub/sub NATS với các bộ collector, processor, parser, assembler) thông qua giao diện GraphQL<sup>13</sup>. GUAC biểu diễn các gói phần mềm dưới dạng cấu trúc cây tiền tố (trie) theo chuẩn pURL và tự động chạy các bộ thu thập (OSV Certifier, Deps.dev collector, Scorecards collector, GitHub collector) để gắn kết các nút OSV, CVE, GHSA (hoặc nút đơn NoVuln nếu gói phần mềm sạch tại thời điểm quét) thông qua cây bằng chứng IsVulnerability và CertifyVuln<sup>13</sup>. Hệ thống kết hợp thực thể chứng thực **VexStatus (Vulnerability Exploitability eXchange)** của GUAC với đồ thị luồng gọi hàm tĩnh (get_call_graph) từ **REA**<sup>7</sup>: nếu một thư viện phụ thuộc có CVE nhưng hàm chứa lỗ hổng không xuất hiện trên đường đi thực thi của ứng dụng nội bộ, kết quả phân tích được ghi nhận vào trường vexJustification và statement để hỗ trợ lọc giảm cảnh báo giả<sup>6</sup>.

#### Làm giàu Ngữ cảnh Lỗ hổng và Ma trận Phân hạng Ưu tiên (projectdiscovery/cvemap & xaitax/SploitScan)

Với mọi định danh CVE phát hiện được (hoặc nhập trực tiếp từ tệp kết quả quét của Nessus, Nexpose, OpenVAS, Docker Scout qua tính năng --import-file của SploitScan), tác tử gọi đồng thời **cvemap** (nhận đầu vào stdin và xuất định dạng JSONL) và **SploitScan** (-e JSON)<sup>15</sup>. Hai công cụ này tổng hợp dữ liệu từ kho lưu trữ CVEProject/cvelistV5 (được SploitScan sử dụng thay thế API NVD truyền thống vốn hay gặp sự cố giới hạn tần suất), điểm xác suất bị khai thác **FIRST EPSS**, danh mục lỗ hổng đang bị khai thác tích cực **CISA KEV**, ánh xạ định danh phần mềm **CPE**, và thống kê mức độ phổ biến/phân bố mức độ nghiêm trọng từ báo cáo thực tế trên **HackerOne CVE Discovery**<sup>11</sup>. Từ dữ liệu này, hệ thống áp dụng ma trận phân hạng ưu tiên vá lỗi từ **Hạng A+ đến Hạng D** của SploitScan<sup>11</sup>:

- **Hạng A+ (Ưu tiên Cao nhất):** Gán cho mọi CVE nằm trong danh mục **CISA KEV** hoặc đã có **mã khai thác công khai (publicly available exploits)**<sup>11</sup>.

- **Hạng A:** Điểm CVSS ≥ 6.0 và xác suất EPSS ≥ 0.2 (mức độ nghiêm trọng cao đi kèm xác suất bị khai thác đáng kể)<sup>11</sup>.

- **Hạng B:** Điểm CVSS ≥ 6.0 nhưng xác suất EPSS \< 0.2 (mức độ nghiêm trọng cao nhưng xác suất bị khai thác thấp hơn)<sup>11</sup>.

- **Hạng C:** Điểm CVSS \< 6.0 và xác suất EPSS ≥ 0.2 (mức độ nghiêm trọng thấp hơn nhưng xác suất bị khai thác cao, thường bị lợi dụng làm mắt xích trong chuỗi tấn công kết hợp - exploit chaining)<sup>11</sup>.

- **Hạng D:** Điểm CVSS \< 6.0 và xác suất EPSS \< 0.2<sup>11</sup>.

#### Truy tìm, Thu thập và Kiểm duyệt An toàn Mã Khai thác (Automated PoC Harvesting & Auditing)

Khi phát hiện một thành phần yếu điểm khớp với CVE, tác tử tự động truy tìm mã khai thác qua bốn nguồn dữ liệu liên kết. Thứ nhất là kho **trickest/cve** và API **nomi-sec/PoC-in-GitHub** (tích hợp trong SploitScan và cvemap), nơi tự động thu thập chi tiết CVE từ cvelistV5, quét các đường dẫn tham chiếu bằng ffuf với biểu thức chính quy (?i)\[^a-z0-9\]+(poc\|proof of concept\|proof\[-\_\]of\[-\_\]concept)\[^a-z0-9\]+, tổng hợp PoC từ báo cáo HackerOne cùng các kho GitHub và lọc bỏ kết quả sai qua blacklist.txt<sup>11</sup>. Thứ hai là cơ sở dữ liệu **VulnCheck** và **Packet Storm** được truy xuất trực tiếp qua SploitScan<sup>16</sup>. Thứ ba là kho mẫu quét cộng đồng **projectdiscovery/nuclei-templates**, được ánh xạ trực tiếp với từng CVE qua cvemap và SploitScan để kiểm tra xem lỗ hổng đó đã có mẫu YAML tự động hóa hay chưa<sup>15</sup>. Thứ tư là tìm kiếm chủ động qua GitHub MCP server (tích hợp trong Strix qua ~/.strix/mcp-servers.json), công cụ GitDorker (org:target-company) và uncover (engine google, publicwww) để phát hiện các đoạn mã khai thác hoặc cấu hình rò rỉ mới phát sinh<sup>8</sup>. Để đảm bảo an toàn, hệ thống không chạy trực tiếp mã PoC tải từ Internet trên mạng quản trị; tác tử Analyst và Reverser sẽ đọc mã nguồn hoặc dịch ngược tệp PoC bằng REA để bóc tách phương thức tạo payload, sau đó chuyển cho môi trường sandbox cô lập của Strix thực thi kiểm chứng<sup>5</sup>.

### 2.5. Phân hệ 5: Kiểm chứng Khai thác Động, Cảnh báo Sớm và Vòng lặp "Vaccine Tấn công" (Dynamic Validation, Early Warning & Offensive Vaccine Loop)

Nhằm giảm thiểu tối đa cảnh báo giả (false positives) vốn là nhược điểm cố hữu của các công cụ phân tích tĩnh (SAST) và rút ngắn thời gian từ lúc phát hiện đến lúc khắc phục, phân hệ thứ 5 kết hợp quy trình kiểm chứng của **BitterSecurity/Decepticon** với năng lực tự động vá lỗi của **usestrix/strix**<sup>1</sup>.

#### Kiểm chứng Thực nghiệm Đa Phương pháp và Đối chứng Âm (Multi-Method Verification & Negative Controls)

Trong đường ống 5 giai đoạn của Vulnresearch (scanner → detector → verifier → patcher → exploiter), mọi phát hiện ứng viên từ giai đoạn Scanner và Detector đều phải đi qua tác tử **Verifier** và đồ thị thẩm định độc lập **finding_verifier**<sup>22</sup>. Đối với các lỗ hổng có mức độ Nghiêm trọng (CRITICAL) hoặc Cao (HIGH), Verifier bắt buộc phải xác nhận bằng **tối thiểu 2 phương pháp kiểm chứng khác nhau**, đồng thời finding_verifier phải thực hiện tái hiện lỗi kèm theo **kiểm thử đối chứng âm tương đương (equivalent negative controls)** trong môi trường Strix Python PoC Runtime hoặc Kali HTTPSandbox trước khi trả về trạng thái PASSED<sup>8</sup>. Đối với các dịch vụ nhạy cảm không được phép gửi payload khai thác trực tiếp trên môi trường Production, hệ thống có thể đối chiếu và khởi tạo các môi trường container mô phỏng lỗ hổng tương ứng từ bộ mẫu **projectdiscovery/nuclei-templates-labs** để kiểm chứng mẫu phát hiện và kịch bản khai thác một cách an toàn<sup>43</sup>. Sau khi xác nhận, đồ thị finding_reporter (được thiết kế không có công cụ thực thi shell để đảm bảo tính toàn vẹn) sẽ biên tập báo cáo chuẩn hóa cuối cùng<sup>22</sup>.

#### Tự động Sinh Bản vá Bảo mật và Kiểm tra Hồi quy (Automated Patching & Regression Verification)

Khi lỗ hổng đã được xác nhận, tác tử Patcher (trong Decepticon) kết hợp với kỹ năng fix-security-vulnerabilities-with-strix (trong Strix) truy cập vào cây mã nguồn nội bộ được gắn kết vào /workspace, tự động viết bản vá sửa lỗi ở tầng mã nguồn hoặc tệp cấu hình<sup>8</sup>. Ngay sau khi áp dụng bản vá trong không gian làm việc, Strix tự động chạy lại chính kịch bản PoC vừa khai thác thành công trước đó để xác minh lỗ hổng đã được khắc phục hoàn toàn, xuất kết quả ra định dạng chuẩn **SARIF 2.1.0 (findings.sarif)**, vulnerabilities.json, penetration_test_report.md, đồng thời tự động tạo **Pull Request (PR)** vá lỗi trên GitHub/GitLab/Bitbucket và đẩy cảnh báo tới Slack, Jira hoặc Linear<sup>8</sup>. Trong đường ống CI/CD (chạy ở chế độ headless -n kèm cờ --fail-on high hoặc critical), nếu phát hiện lỗ hổng vượt ngưỡng cho phép, Strix sẽ trả về mã thoát Exit Code 2 để chặn tự động việc hợp nhất mã nguồn không an toàn vào nhánh chính<sup>8</sup>.

#### Vòng lặp Phòng thủ Tác tử Xanh (Blue Cell / AutoBot Sensor Verification)

Hoàn thiện chu trình **"Vaccine Tấn công"**, hệ thống kích hoạt chế độ /mode blue với đồ thị tác tử **autobot** (decepticon\[blue\]) kết nối tới cụm cảm biến thu thập log cục bộ sử dụng **Caddy** và **Fluent Bit**<sup>1</sup>. Tác tử Forensicator và Detector (chạy ngăn xếp chỉ đọc không có bash execution) thực hiện phân tích dòng thời gian nhật ký (disk/memory/log/network timeline analysis), trích xuất chỉ báo thỏa hiệp (IOC) và ánh xạ hành vi tấn công sang quy tắc phát hiện (attack-to-detection mapping)<sup>22</sup>. Nếu hệ thống giám sát nội bộ bỏ lọt hành vi khai thác thử nghiệm, tác tử sẽ tự động sinh quy tắc phát hiện mới và mẫu quét **Nuclei YAML** để cập nhật phòng thủ cho toàn mạng nội bộ<sup>22</sup>.

### 2.6. Bảng Tổng hợp Ánh xạ Tính năng Hệ thống và Module Mã nguồn Mở Tham khảo

Bảng dưới đây tổng hợp toàn bộ kiến trúc module của hệ thống cùng các kho mã nguồn mở tham chiếu trực tiếp để đội ngũ kỹ thuật triển khai:

| **Phân hệ Chức năng**                    | **Tính năng Kỹ thuật Chi tiết**                                                                                                   | **Module Mã nguồn Mở Trọng tâm**                                                                              | **Module Bổ trợ trong Hệ sinh thái**                                                                                                        | **Giao thức / Định dạng Tích hợp**                                                         |
|------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| **1. Điều phối & Hạ tầng Lõi**           | Điều phối đa tác tử theo trạng thái, quản lý OPPLAN, tách biệt vùng mạng quản trị & sandbox, định tuyến LLM đa tầng.              | BitterSecurity/Decepticon (LangGraph, Deep Agents, LiteLLM)<sup>1</sup>                                       | usestrix/strix (strix/agents, strix/runtime)<sup>8</sup>                                                                                    | HTTPSandbox (:9999), tmux prompt detection, Docker Compose<sup>1</sup>                     |
| **2. Quản lý Tri thức Kỹ năng**          | Lưu trữ và truy xuất động kỹ năng tác chiến theo ngữ cảnh, ánh xạ ma trận MITRE ATT&CK Enterprise.                                | BitterSecurity/Decepticon (Skillogy, SkillsMiddleware)<sup>24</sup>                                           | usestrix/strix (9 SKILL.md), flowsint (flowsint-enricher-builder skill)<sup>8</sup>                                                         | Chuẩn SKILL.md, REST API (find_skill, load_skill, traverse), Cypher<sup>4</sup>            |
| **3. Trinh sát Black-box & OSINT**       | Khám phá tên miền, ASN, CIDR, cổng mở, lịch sử WHOIS, rò rỉ định danh (breaches) và thiết bị nhiễm infostealer.                   | reconurge/flowsint (flowsint-enrichers, flowsint-core, flowsint-types)<sup>2</sup>                            | projectdiscovery (subfinder, asnmap, dnsx, naabu, httpx, uncover), reconurge (reconcrawl, reconspread, recontrack, rangebuster)<sup>9</sup> | Celery + Redis task queue, FastAPI REST, Vault mã hóa khóa API<sup>2</sup>                 |
| **4. Khám phá Gray-box & White-box**     | Cào web SPA có đăng nhập (session replay), kiểm thử theo hợp đồng OpenAPI/Postman, kiểm kê đám mây & quét PR diff.                | usestrix/strix (Caido, Playwright, --scope-mode diff)<sup>8</sup>                                             | projectdiscovery/katana (-headless -rf), cartography-cncf/cartography, Prowler<sup>10</sup>                                                 | OpenAPI YAML/JSON, Postman UUID, Chrome DevTools JSON, Neo4j Bolt<sup>8</sup>              |
| **5. Dịch ngược & Giải mã Tài sản**      | Dịch ngược nhị phân (C/C++/Go/Rust), giải nén Electron .asar, APK, firmware, khôi phục .git, giải rối JS bundle & trích xuất AST. | morluto/rea (rea-agents MCP server & CLI, Ghidra 12.1+, Hopper, IDA, Kuna, JADX, Binwalk, Unblob)<sup>5</sup> | arthaud/git-dumper, denandz/sourcemapper, j4k0xb/webcrack, BishopFox/jsluice, trufflehog, gitleaks<sup>10</sup>                             | Giao thức MCP (stdio 2025-06-18), AST go-tree-sitter, JSON Evidence<sup>7</sup>            |
| **6. Cơ sở Dữ liệu Đồ thị Tri thức**     | Lưu trữ đồ thị tài sản, quan hệ phụ thuộc phần mềm (SBOM pURL), chứng thực VEX và kiểm soát ghi đồng thời.                        | reconurge/flowsint (Neo4j, Graph Conductor, SchemaOrgMixin)<sup>2</sup>                                       | guacsec/guac (GraphQL SBOM/SLSA/VEX, NATS pub/sub), Decepticon (Engagement Neo4j)<sup>4</sup>                                               | Neo4j Cypher, JSON-LD (schema.org / flowsint), GraphQL, chuẩn pURL<sup>17</sup>            |
| **7. Tình báo Lỗ hổng & Tìm kiếm PoC**   | Tương quan CVE/OSV/GHSA với CPE/pURL nội bộ, chấm điểm ưu tiên theo KEV & EPSS, săn tìm mã PoC công khai.                         | usestrix/strix + Decepticon (Vulnresearch)<sup>8</sup>                                                        | projectdiscovery/cvemap, xaitax/SploitScan, trickest/cve, nomi-sec/PoC-in-GitHub, GitDorker<sup>10</sup>                                    | cvelistV5 JSON, FIRST EPSS API, CISA KEV, JSONL/CSV/HTML export<sup>11</sup>               |
| **8. Kiểm chứng PoC, Cảnh báo & Vá lỗi** | Chạy PoC thực nghiệm trong sandbox, kiểm chứng đối chứng âm, tự động tạo Pull Request vá lỗi & kiểm tra log phòng thủ.            | usestrix/strix (Python PoC Runtime, strix/report) & Decepticon (finding_verifier, AutoBot)<sup>1</sup>        | projectdiscovery/nuclei (nuclei-action, nuclei-templates-labs), Caddy, Fluent Bit<sup>1</sup>                                               | Báo cáo chuẩn SARIF 2.1.0, vulnerabilities.json, GitHub/GitLab PR, Nuclei YAML<sup>8</sup> |

## Phần 3: Luồng Thực thi Nghiệp vụ Xuyên suốt (End-to-End Operational Workflow)

Để minh họa cách các phân hệ phối hợp dưới sự chỉ huy của AI Agent, quy trình vận hành chuẩn của một chiến dịch rà quét bảo vệ nội bộ diễn ra tuần tự qua 7 bước:

1.  **Khởi tạo Phạm vi và Lập Kế hoạch Tác chiến (Scope Provisioning & OPPLAN Generation):** Quản trị viên bảo mật định nghĩa phạm vi rà quét được phép (tên miền, dải IP nội bộ, đường dẫn kho Git, tài khoản đám mây, khung giờ được phép quét authorized_windows và khung giờ cấm blackout_windows) để trình khởi chạy sinh tệp cấu hình **Rules of Engagement (RoE)** ở dạng máy đọc được<sup>4</sup>. Nếu người vận hành chọn chế độ lập kế hoạch tùy chọn (/plan), tác tử Soundwave sẽ thảo luận và sinh bộ 7 tài liệu kế hoạch rà quét bên cạnh RoE chỉ đọc; sau đó bộ điều phối thực thi Core-Orchestrator khởi tạo bảng tiến độ **OPPLAN** và ghim chặt mã băm phiên bản quy trình (workflow hash) vào luồng thực thi<sup>4</sup>.

2.  **Trinh sát Mở rộng Đồ thị Đa chiều (Multi-Modal Discovery & Graph Seeding):** Bộ điều phối gọi công cụ task() khởi tạo OSINT-Operator và Recon-Agent với cửa sổ ngữ cảnh sạch<sup>22</sup>. Các tác tử này kích hoạt chuỗi enrichers của **Flowsint** (subfinder, asnmap, dnsx, naabu, httpx, uncover, HudsonRock, DeHashed) cho bề mặt bên ngoài và **Cartography** cho hạ tầng đám mây/nội bộ<sup>9</sup>. Toàn bộ nút Domain, IPAddress, WebSite và các cổng dịch vụ mở được chuẩn hóa theo SchemaOrgMixin và ghi vào **Neo4j** thông qua tầng điều phối Graph Conductor<sup>23</sup>.

3.  **Thu hoạch và Dịch ngược Tài sản Phơi nhiễm (Exposed Asset Harvesting & REA Decompilation):** Trong quá trình duyệt web bằng Katana (có nạp phiên đăng nhập Gray-box qua -rf login.json) và quét mẫu phơi nhiễm bằng Nuclei, hệ thống phát hiện một thư mục .git bị lộ trên máy chủ staging, một tệp bundle.js đã làm rối trên cổng thông tin, và một gói ứng dụng nội bộ chứa tệp thực thi nhị phân trên Docker Registry<sup>10</sup>. Ngay lập tức, Core-Orchestrator cập nhật OPPLAN và triệu tập Reverser-Agent cùng Code-Analyst: công cụ git-dumper tái tạo kho mã nguồn để TruffleHog (--only-verified) tìm ra khóa truy cập dịch vụ nội bộ còn sống<sup>10</sup>; webcrack giải rối tệp bundle.js và jsluice phân tích cây cú pháp AST bóc tách các đường dẫn API quản trị ẩn kèm cấu trúc tham số<sup>12</sup>; đồng thời máy chủ MCP của **REA** (rea mcp) kết nối với **Ghidra 12.1+** ở chế độ chỉ đọc để dịch ngược tệp nhị phân, dùng procedure_pseudo_code và search_strings khôi phục logic kiểm tra xác thực và trích xuất danh sách gói phần mềm pURL đẩy vào **GUAC**<sup>6</sup>.

4.  **Phản hồi Tri thức và Tái Định hướng Trinh sát (Knowledge Graph Pivot & Secondary Recon):** Các nút VerifiedCredential, ExposedEndpoint và CodeProcedure mới được ghi vào Neo4j lập tức kích hoạt sự kiện cập nhật trên Core-Orchestrator. Bộ điều phối tự động sinh mục tiêu mới trong OPPLAN: dùng khóa xác thực vừa tìm được và danh sách đường dẫn API ẩn làm đầu vào (--target và --instruction) cho một lượt trinh sát sâu vòng hai bằng **Strix** và **Katana**, chuyển hóa góc nhìn kiểm thử từ Black-box sang Gray-box và White-box<sup>8</sup>.

5.  **Tương quan Tình báo Lỗ hổng và Truy tìm Mã Khai thác (Threat Intel Correlation & PoC Matching):** Tác tử phân tích truy vấn đồ thị Neo4j và GUAC (CertifyVuln, IsVulnerability), phát hiện một dịch vụ nội bộ đang sử dụng phiên bản thành phần phần mềm dính CVE<sup>17</sup>. Công cụ cvemap và SploitScan được gọi tự động để đối chiếu dữ liệu cvelistV5, điểm xác suất EPSS, danh mục CISA KEV và tìm kiếm mã khai thác trên nomi-sec/PoC-in-GitHub, trickest/cve cùng Packet Storm, từ đó phân loại lỗ hổng vào **Hạng A+** trong ma trận ưu tiên<sup>11</sup>.

6.  **Kiểm chứng Động trong Sandbox và Thẩm định Đối chứng Âm (Sandboxed PoC Execution & Verification):** Thay vì phát cảnh báo chỉ dựa trên số hiệu phiên bản, tác tử khai thác trong **Strix** sử dụng proxy **Caido**, trình duyệt **Playwright** và môi trường **Python PoC Runtime** cô lập trên mạng sandbox-net để thực thi kịch bản PoC kiểm chứng lỗ hổng (bao gồm cả các lỗi logic nghiệp vụ, IDOR hoặc race condition trên các API ẩn vừa dịch ngược)<sup>4</sup>. Tiếp đó, tác tử Verifier và đồ thị finding_verifier của **Decepticon** thực hiện kiểm tra độc lập bằng phương pháp thứ hai kèm đối chứng âm (negative control) để xác nhận lỗ hổng có thể khai thác thực sự (PASSED)<sup>22</sup>.

7.  **Cảnh báo Sớm, Tự động Vá lỗi và Cập nhật Phòng thủ (Early Warning, Auto-PR & Blue Cell Vaccine):** Ngay khi trạng thái chuyển sang PASSED, hệ thống xuất báo cáo chuẩn SARIF 2.1.0 (findings.sarif) và kích hoạt cảnh báo khẩn cấp tới đội ngũ SOC/DevSecOps<sup>8</sup>. Đồng thời, tác tử Patcher / Strix tự động tạo bản vá trong mã nguồn, chạy lại PoC để xác nhận bản vá đã khắc phục hoàn toàn lỗ hổng, mở Pull Request trên GitHub/GitLab, trong khi AutoBot (Blue Cell) kiểm tra nhật ký trên Fluent Bit/Caddy và xuất mẫu Nuclei YAML / quy tắc phát hiện mới để củng cố hệ thống phòng thủ<sup>1</sup>.

## Phần 4: Cơ chế An toàn, Chống Prompt Injection và Quản trị Rủi ro

Khi xây dựng một hệ thống AI Agent có khả năng tự động tương tác với các dịch vụ mạng, dịch ngược tệp tin và chạy công cụ kiểm thử, sự an toàn của chính nền tảng rà quét là yếu tố bắt buộc. Hệ thống phải triển khai 3 lớp phòng vệ kỹ thuật trọng tâm sau đây:

### 4.1. Phòng chống Tấn công Giả mạo Ranh giới Vai trò và Prompt Injection Gián tiếp (Bài học từ CVE-2026-61732)

Trong quá trình quét các máy chủ web hoặc dịch ngược mã nguồn/nhị phân, dữ liệu thu về (HTTP headers, nội dung trang HTML, chuỗi ký tự trong tệp thực thi, lịch sử commit Git) hoàn toàn có thể bị kẻ tấn công cài cắm mã độc ngữ nghĩa. Lỗ hổng **CVE-2026-61732** (CVSS 10.0) được nhóm nghiên cứu tại Viện Kỹ thuật Thông tin thuộc Viện Hàn lâm Khoa học Trung Quốc (CAS) phát hiện trên PurpleAILAB/Decepticon v1.1.4 (đã được vá trong bản v1.1.17 tại commit 79ee2aaf22f4c36a5b1968f6ca3f8086b6e35b67) là bài học kiến trúc điển hình<sup>18</sup>. Trong lỗ hổng này, khi các công cụ trinh sát (nmap, httpx, dnsx, masscan, katana, ffuf) trong agents/standard/recon.py thu thập phản hồi HTTP từ máy chủ mục tiêu có cài cắm các chuỗi token phân tách cấu trúc hội thoại như \<\|im_end\|\> và \<\|im_start\|\>system, đầu ra thô được đóng gói trực tiếp vào đối tượng ToolMessage của LangChain (llm/factory.py) mà không qua bước lọc ký tự đặc biệt<sup>18</sup>. Khi triển khai theo mô hình tự cung cấp khóa (BYOK) kết nối tới các máy chủ LLM mã nguồn mở tự vận hành (như vLLM, SGLang, TGI, Ollama, LM Studio chạy các mô hình như Qwen2.5/Qwen3.5), bộ phân tách từ (tokenizer) chuyển đổi các chuỗi văn bản này thành ID token điều khiển thực sự (ví dụ token ID 151643, 151644, 151645), đánh lừa LLM coi văn bản của kẻ tấn công là mệnh lệnh từ Hệ thống/Người vận hành và lập tức gọi phương thức execute() trong backends/http_sandbox.py để thực thi lệnh shell tùy ý trong container Kali Linux<sup>18</sup>.

Để khóa chặt bề mặt tấn công này trên cả các API đám mây lẫn mô hình tự triển khai nội bộ, hệ thống áp dụng kiến trúc lọc kép tại tầng ứng dụng trước khi bất kỳ dữ liệu nào từ công cụ được phép đi vào lịch sử hội thoại của LLM:

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Lớp Phòng vệ</strong></th>
<th><strong>Cơ chế Kỹ thuật Chi tiết</strong></th>
<th><strong>Danh sách Token / Đối tượng Áp dụng</strong></th>
<th><strong>Tham chiếu Triển khai</strong></th>
</tr>
<tr class="odd">
<th><strong>1. Bộ lọc Token Đặc biệt Đa Họ Mô hình (Special-Token Literal Filtering)</strong></th>
<th>Tước bỏ hoặc mã hóa (escape) toàn bộ các chuỗi ký tự phân tách vai trò (role-delimiter literals) trên mọi đầu ra thu thập từ mạng, tệp tin và stdout của sandbox trước khi khởi tạo ToolMessage.</th>
<th><p>• <strong>ChatML / Qwen / DeepSeek:</strong> &lt;|im_start|&gt;, &lt;|im_end|&gt;, &lt;|endoftext|&gt;</p>
<p>• <strong>Llama-3.x / Llama-4:</strong> &lt;|begin_of_text|&gt;, &lt;|end_of_text|&gt;, &lt;|start_header_id|&gt;, &lt;|end_header_id|&gt;, &lt;|eot_id|&gt;</p>
<p>• <strong>Gemma 2/3:</strong> &lt;start_of_turn&gt;, &lt;end_of_turn&gt;</p>
<p>• <strong>Mistral / Mixtral:</strong> [INST], [/INST], &lt;&lt;SYS&gt;&gt;, &lt;&lt;/SYS&gt;&gt;</p></th>
<th>Bản vá CVE-2026-61732 (Decepticon v1.1.17+)<sup>8</sup></th>
</tr>
<tr class="header">
<th><strong>2. Chống Vượt rào Mã hóa Unicode (Unicode Bypass Normalization)</strong></th>
<th>Chuẩn hóa chuỗi Unicode và chặn các biến thể ký tự đồng hình (homoglyphs), đặc biệt là ký tự dấu gạch đứng toàn độ rộng (fullwidth vertical bar) thường dùng để lách bộ lọc ASCII.</th>
<th>Biến thể &lt;｜ sử dụng mã Unicode U+FF5C và các chuỗi thoát hex/unicode tương đương.</th>
<th>Bản vá CVE-2026-61732<sup>18</sup></th>
</tr>
<tr class="odd">
<th><strong>3. Đóng gói Cô lập Đầu ra (UntrustedOutputMiddleware)</strong></th>
<th>Bọc toàn bộ dữ liệu có thể bị tác động bởi mục tiêu bên ngoài (bash stdout, đọc tệp tin, kết quả truy vấn Knowledge Graph) vào trong thẻ XML cách ly ngữ cảnh.</th>
<th>Thẻ &lt;UNTRUSTED_TOOL_OUTPUT&gt; ... &lt;/UNTRUSTED_TOOL_OUTPUT&gt;</th>
<th>Decepticon Safety Middleware Stack<sup>22</sup></th>
</tr>
<tr class="header">
<th><strong>4. Khiên Chắn Prompt Injection (PromptInjectionShieldMiddleware)</strong></th>
<th>Áp dụng bộ lọc danh sách từ chối (deny-list) và kiểm tra ngữ nghĩa đối với các đầu ra công cụ chứa mẫu câu lệnh cưỡng bức thay đổi mục tiêu hoặc vượt quyền RoE.</th>
<th>Toàn bộ phản hồi từ recon, katana, httpx, rea và strix trước khi nạp vào LLM.</th>
<th>Decepticon Safety Middleware Stack<sup>22</sup></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

### 4.2. Quản trị Ngân sách Ngữ cảnh MCP và Kỷ luật Bằng chứng (MCP Context Governance & Evidence Discipline)

Khi tích hợp máy chủ dịch ngược **REA** (morluto/rea) vào hệ thống đa tác tử, nếu giữ cấu hình mặc định, REA sẽ quảng bá toàn bộ danh mục 207–229 công cụ MCP tới mỗi tác tử khách<sup>7</sup>. Theo số liệu kiểm thử thực tế trên phiên bản rea-agents v6.7.0, định nghĩa JSON thô của danh sách 207 công cụ này chiếm tới **3.158.352 bytes (~3,08 MB)** (và trên bản v6.8.0 với 229 công cụ, ngay cả cấu hình thu gọn cũng chiếm 281 KiB), khiến các tác tử nhanh chóng bị tràn cửa sổ ngữ cảnh hoặc tốn chi phí token khổng lồ ở mỗi lượt gọi<sup>7</sup>. Tương tự, khi REA phân tích tĩnh một gói ứng dụng Electron thực tế như Hyper 3.4.1 (tệp app.asar nặng 14 MB gồm 2.236 tệp nguồn), nó sinh ra tệp bằng chứng JSON nặng tới **253 MB** chứa đồ thị 10.552 nút và 14.909 mối quan hệ<sup>7</sup>.

Do đó, cấu hình kết nối MCP của hệ thống bắt buộc thiết lập ba cơ chế kiểm soát dung lượng và tính xác thực:

1.  **Nén Lược đồ Đầu vào/Đầu ra (Compact Schema Profiles):** Thiết lập mặc định cấu hình lược đồ đầu vào thu gọn và đặt biến môi trường REA_MCP_OUTPUT_SCHEMA_PROFILE=compact (hoặc off đối với các tác tử có khung ngữ cảnh nhỏ), giúp giảm kích thước định nghĩa 207 công cụ từ **3.158.352 bytes xuống chỉ còn 219.211 bytes (~214 KB — giảm hơn 93% dung lượng)** mà vẫn bảo toàn cơ chế kiểm tra tính hợp lệ (canonical server-side validation) và kết quả có cấu trúc đầy đủ ở phía máy chủ REA<sup>5</sup>.

2.  **Phân mảnh Danh mục Nóng/Lạnh và Truy vấn Tóm tắt Đồ thị (Hot/Cold Catalog & Summary Views):** Kích hoạt chế độ REA_MCP_TOOL_CATALOG_PROFILE=hot-cold (để REA chỉ khởi động với một số ít công cụ thiết yếu và nạp động các công cụ chuyên sâu khi cần) kết hợp lọc theo họ công cụ REA_MCP_TOOL_FAMILIES<sup>48</sup>. Khi xử lý các tệp bằng chứng lớn (như tệp JSON 253 MB của ứng dụng Electron), tác tử tuyệt đối không đọc trực tiếp toàn bộ tệp vào ngữ cảnh mà bắt buộc gọi công cụ inspect-analysis-view kết hợp jq để trích xuất bản tóm tắt (summary view) dung lượng chỉ **22.843 bytes (~22,3 KB — giảm hơn 99,9% dung lượng)** chứa danh sách cửa sổ, các thao tác IPC và kênh giao tiếp xác định trước khi đưa vào LLM suy luận<sup>7</sup>.

3.  **Kỷ luật Hợp đồng Bằng chứng (Evidence Contracts):** Hệ thống buộc các tác tử tuân thủ nghiêm ngặt hợp đồng dữ liệu của REA nhằm chống ảo giác LLM: mọi đường đi lời gọi hàm tĩnh đều được gắn nhãn rõ ràng là static (tác tử không được phép suy diễn thành khả năng tiếp cận lúc chạy thực tế nếu chưa qua kiểm chứng động của Strix); mã giả dịch ngược từ Ghidra/Hopper không bao giờ được coi là mã nguồn gốc; các tệp vượt quá giới hạn bộ nhớ phân tích (như 1.994 tệp trong node_modules của Hyper) được gắn thẻ resource_constraint thay vì âm thầm loại bỏ; và một kết quả truy vấn rỗng phải được diễn giải là unknown (chưa rõ) chứ không phải "không tồn tại"<sup>6</sup>.

### 4.3. Cưỡng bức Thực thi Phạm vi bằng Máy (Machine-Readable RoE) và Khóa Bảo vệ Middleware

Để đảm bảo hệ thống AI Agent không bao giờ quét nhầm ra ngoài phạm vi nội bộ được cấp phép hoặc gây gián đoạn dịch vụ vào giờ cao điểm kinh doanh, nền tảng áp dụng cơ chế khóa bảo vệ đối với ngăn xếp Middleware (MiddlewareSlot) từ BitterSecurity/Decepticon kết hợp cùng cơ chế kiểm soát con người trong vòng lặp của usestrix/strix<sup>4</sup>.

Trong kiến trúc này, mỗi tác tử lắp ráp ngăn xếp middleware từ trên xuống dưới theo bảng phân quyền vai trò (SLOTS_PER_ROLE), trong đó 7 khe an toàn cốt lõi — bao gồm engagement-context (bơm siêu dữ liệu phiên và kiểm tra phạm vi RoE trên từng lệnh gọi mô hình/công cụ), time-window (kiểm tra trước khi chạy và trước mỗi lượt gọi LLM để đảm bảo tác tử chỉ hoạt động trong khung giờ authorized_windows và dừng ngay lập tức nếu rơi vào blackout_windows), untrusted-output, prompt-injection-shield, sandbox-notification, opscontrol-notification, và hitl-approval — được bảo vệ cứng chống lại mọi sự can thiệp trái phép<sup>22</sup>. Bất kỳ plugin hoặc cấu hình mở rộng nào cố tình chỉnh sửa hoặc vô hiệu hóa các khe an toàn này khi biến môi trường DECEPTICON_ALLOW_SAFETY_OVERRIDES=1 chưa được bật tường minh bởi quản trị viên hệ thống sẽ lập tức bị chặn đứng bởi ngoại lệ SafetyOverrideViolation<sup>22</sup>. Đồng thời, hệ thống kích hoạt cổng phê duyệt con người (DECEPTICON_HITL\_\_ENABLED=1 trên HITLApprovalMiddleware) đối với mọi tác vụ có tác động nhạy cảm lên môi trường thực tế, kết hợp cùng quy tắc bảo vệ của Strix (luôn yêu cầu con người xác nhận thủ công hoặc kiểm tra mã băm --approve-sha256 đối với các bản chụp mã nguồn trước khi đẩy lên phân tích đám mây và không bao giờ tự động thực hiện thay đổi DNS hay cài đặt tích hợp kho mã nguồn mà không có sự phê duyệt trực tiếp của kỹ sư bảo mật)<sup>8</sup>.

#### Nguồn trích dẫn

1.  BitterSecurity/Decepticon: Autonomous Hacking Agent for Red Team, [<u>https://github.com/BitterSecurity/Decepticon</u>](https://github.com/BitterSecurity/Decepticon)

2.  GitHub - reconurge/flowsint: A modern platform for visual, flexible, [<u>https://github.com/reconurge/flowsint</u>](https://github.com/reconurge/flowsint)

3.  Self-Hosted OSINT Graph Tool for Ethical Investigations - Prompts, [<u>https://prompts.brightcoding.dev/blog/reconurgeflowsint-self-hosted-osint-graph-tool-for-ethical-investigations</u>](https://prompts.brightcoding.dev/blog/reconurgeflowsint-self-hosted-osint-graph-tool-for-ethical-investigations)

4.  [<u>https://github.com/PurpleAILAB/Decepticon/blob/main/docs/architecture.md</u>](https://github.com/PurpleAILAB/Decepticon/blob/main/docs/architecture.md)

5.  GitHub - morluto/rea: Reverse engineer anything with agents, from, [<u>https://github.com/morluto/rea</u>](https://github.com/morluto/rea)

6.  Ghidra MCP vs REA: AI Reverse Engineering Compared, [<u>https://www.alekseialeinikov.com/en/blog/topics/security/ghidra-mcp-vs-rea-ai-reverse-engineering</u>](https://www.alekseialeinikov.com/en/blog/topics/security/ghidra-mcp-vs-rea-ai-reverse-engineering)

7.  REA: reverse engineering MCP for agents, tested - Jacar, [<u>https://jacar.es/en/rea-reverse-engineering-mcp-coding-agents/</u>](https://jacar.es/en/rea-reverse-engineering-mcp-coding-agents/)

8.  [<u>https://github.com/usestrix/strix</u>](https://github.com/usestrix/strix)

9.  [<u>https://github.com/reconurge/flowsint/blob/main/docs/sources/available-enrichers.mdx</u>](https://github.com/reconurge/flowsint/blob/main/docs/sources/available-enrichers.mdx)

10. Sensitive Data Exposure - Cyber Security Wiki by Payatu, [<u>https://cyber-security.wiki/docs/application-security/web/Sensitive-Data-Exposure/</u>](https://cyber-security.wiki/docs/application-security/web/Sensitive-Data-Exposure/)

11. SploitScan \| A Sophisticated Cybersecurity Utility - OneHack, [<u>https://onehack.us/t/sploitscan-a-sophisticated-cybersecurity-utility/276694</u>](https://onehack.us/t/sploitscan-a-sophisticated-cybersecurity-utility/276694)

12. GitHub - BishopFox/jsluice: Extract URLs, paths, secrets, and other, [<u>https://github.com/BishopFox/jsluice</u>](https://github.com/BishopFox/jsluice)

13. GUAC Beta v0.1 \#251 - GitHub, [<u>https://github.com/guacsec/guac/issues/251</u>](https://github.com/guacsec/guac/issues/251)

14. GitHub - j4k0xb/webcrack: Deobfuscate obfuscator.io, unminify and, [<u>https://github.com/j4k0xb/webcrack</u>](https://github.com/j4k0xb/webcrack)

15. cvemap overview - ProjectDiscovery Documentation, [<u>https://docs.projectdiscovery.io/opensource/cvemap/overview</u>](https://docs.projectdiscovery.io/opensource/cvemap/overview)

16. sploitscan — Debian testing, [<u>https://manpages.debian.org/testing/sploitscan/sploitscan.1</u>](https://manpages.debian.org/testing/sploitscan/sploitscan.1)

17. GraphQL - GUAC Project Docs, [<u>https://docs.guac.sh/guac/graphql/</u>](https://docs.guac.sh/guac/graphql/)

18. CVE-2026-61732, Decepticon - Endor Labs, [<u>https://www.endorlabs.com/vulnerability/cve-2026-61732</u>](https://www.endorlabs.com/vulnerability/cve-2026-61732)

19. EUVD-2026-86329 - European Union, [<u>https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-86329</u>](https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-86329)

20. \[Feature\] Scope advertised MCP tools by family through ... - GitHub, [<u>https://github.com/morluto/rea/issues/3246</u>](https://github.com/morluto/rea/issues/3246)

21. \[Feature\] Discover project-scoped MCP registrations in doctor and, [<u>https://github.com/morluto/rea/issues/7181</u>](https://github.com/morluto/rea/issues/7181)

22. [<u>https://github.com/BitterSecurity/Decepticon/blob/main/docs/agents.md</u>](https://github.com/BitterSecurity/Decepticon/blob/main/docs/agents.md)

23. \[DRAFT\] RFC: Graph Conductor - Concurrency, Locking, and, [<u>https://github.com/reconurge/flowsint/issues/133</u>](https://github.com/reconurge/flowsint/issues/133)

24. Decepticon/docs/design/skillogy.md at main · BitterSecurity ... - GitHub, [<u>https://github.com/BitterSecurity/Decepticon/blob/main/docs/design/skillogy.md</u>](https://github.com/BitterSecurity/Decepticon/blob/main/docs/design/skillogy.md)

25. Decepticon/docs/skills.md at main - GitHub, [<u>https://github.com/BitterSecurity/Decepticon/blob/main/docs/skills.md</u>](https://github.com/BitterSecurity/Decepticon/blob/main/docs/skills.md)

26. flowsint/CHANGELOG.md at main - GitHub, [<u>https://github.com/reconurge/flowsint/blob/main/CHANGELOG.md</u>](https://github.com/reconurge/flowsint/blob/main/CHANGELOG.md)

27. \[Feature Request\] File Upload Flowsint Type · Issue \#137 - GitHub, [<u>https://github.com/reconurge/flowsint/issues/137</u>](https://github.com/reconurge/flowsint/issues/137)

28. Bug: Recursion limit of 400 reached during LLM prompt injection, [<u>https://github.com/BitterSecurity/Decepticon/issues/127</u>](https://github.com/BitterSecurity/Decepticon/issues/127)

29. cartography/docs/root/usage/rules.md at master - GitHub, [<u>https://github.com/cartography-cncf/cartography/blob/master/docs/root/usage/rules.md</u>](https://github.com/cartography-cncf/cartography/blob/master/docs/root/usage/rules.md)

30. Flowsint — GitHub repository - Codearia Academy, [<u>https://academy.codearia.com/en/tools/flowsint</u>](https://academy.codearia.com/en/tools/flowsint)

31. flowsint - GitHub, [<u>https://github.com/reconurge</u>](https://github.com/reconurge)

32. GitHub - projectdiscovery/uncover: Quickly discover exposed hosts, [<u>https://github.com/projectdiscovery/uncover</u>](https://github.com/projectdiscovery/uncover)

33. GitHub - projectdiscovery/katana: A next-generation crawling and, [<u>https://github.com/projectdiscovery/katana</u>](https://github.com/projectdiscovery/katana)

34. performing-cloud-asset-inventory-wit... · LobeHub, [<u>https://lobehub.com/fr/skills/oyi77-1ai-skills-performing-cloud-asset-inventory-with-cartography</u>](https://lobehub.com/fr/skills/oyi77-1ai-skills-performing-cloud-asset-inventory-with-cartography)

35. denandz/sourcemapper: Extract JavaScript source trees ... - GitHub, [<u>https://github.com/denandz/sourcemapper</u>](https://github.com/denandz/sourcemapper)

36. Issues · j4k0xb/webcrack - GitHub, [<u>https://github.com/j4k0xb/webcrack/issues</u>](https://github.com/j4k0xb/webcrack/issues)

37. jsluice package - github.com/BishopFox/jsluice - Go Packages, [<u>https://pkg.go.dev/github.com/BishopFox/jsluice</u>](https://pkg.go.dev/github.com/BishopFox/jsluice)

38. waybill/CHANGELOG.md at main - GitHub, [<u>https://github.com/kusari-oss/waybill/blob/main/CHANGELOG.md</u>](https://github.com/kusari-oss/waybill/blob/main/CHANGELOG.md)

39. Schema.org as the Core Semantic Type System for Flowsint \#132, [<u>https://github.com/reconurge/flowsint/issues/132</u>](https://github.com/reconurge/flowsint/issues/132)

40. GitHub - trickest/cve: Gather and update all available and newest, [<u>https://github.com/trickest/cve</u>](https://github.com/trickest/cve)

41. SploitScan - Ubuntu Manpages, [<u>https://manpages.ubuntu.com/manpages/stonking/man1/sploitscan.1.html</u>](https://manpages.ubuntu.com/manpages/stonking/man1/sploitscan.1.html)

42. Community curated list of templates for the nuclei engine to ... - GitHub, [<u>https://github.com/projectdiscovery/nuclei-templates</u>](https://github.com/projectdiscovery/nuclei-templates)

43. GitHub - projectdiscovery/nuclei-templates-labs, [<u>https://github.com/projectdiscovery/nuclei-templates-labs</u>](https://github.com/projectdiscovery/nuclei-templates-labs)

44. projectdiscovery/nuclei-action: Vulnerability Scan with Nuclei - GitHub, [<u>https://github.com/projectdiscovery/nuclei-action</u>](https://github.com/projectdiscovery/nuclei-action)

45. Nuclei is a fast, customizable vulnerability scanner ... - GitHub, [<u>https://github.com/projectdiscovery/nuclei</u>](https://github.com/projectdiscovery/nuclei)

46. pentesting-cloud-methodology.md - GitHub, [<u>https://github.com/timb-machine-mirrors/carlospolop-hacktricks-cloud/blob/master/pentesting-cloud/pentesting-cloud-methodology.md</u>](https://github.com/timb-machine-mirrors/carlospolop-hacktricks-cloud/blob/master/pentesting-cloud/pentesting-cloud-methodology.md)

47. Decepticon/docs/getting-started.md at main - GitHub, [<u>https://github.com/BitterSecurity/Decepticon/blob/main/docs/getting-started.md</u>](https://github.com/BitterSecurity/Decepticon/blob/main/docs/getting-started.md)

48. Local models can drive REA over MCP when they see about 10 tools, [<u>https://github.com/morluto/rea/discussions/3098</u>](https://github.com/morluto/rea/discussions/3098)

49. docs: REA_MCP_TOOL_FAMILIES is documented as current, [<u>https://github.com/morluto/rea/issues/8254</u>](https://github.com/morluto/rea/issues/8254)
