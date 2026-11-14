# AEGIS–Vanguard: Kế hoạch triển khai

Nov 12, 2026 · @T

Kế hoạch chia việc xây AEGIS–Vanguard thành năm giai đoạn nối tiếp, mỗi giai đoạn kết thúc bằng một buổi demo và một cổng nghiệm thu đo được. MVP hoàn thành ở cuối GĐ2, khoảng 9 đến 13 tuần kể từ khi bắt đầu chuẩn bị. Toàn bộ lộ trình đến V1.5 mất khoảng 19 đến 27 tuần.

**Bản chốt ngày 13/11/2026.** Kế hoạch này đã gồm mọi quyết định của Product Team ngày 12 và 13/11, kể cả mười hai điểm trong [bản đánh giá OSS](03-danh-gia-oss.md). Danh sách quyết định ở mục 10. Bốn thay đổi lớn so với bản trước: giao diện luồng quét và đồ thị tri thức có ngay ở GĐ1; agent gọi công cụ qua MCP; mỗi công cụ chạy trong một container trên một máy, chưa cần Kubernetes; không giới hạn phạm vi quét. Chiều 13/11 chốt thêm: không che secret, không đo precision và recall mà yêu cầu mỗi finding có bằng chứng, AI agent đánh giá mức nghiêm trọng, và mọi dữ liệu lưu vĩnh viễn kèm lịch sử theo từng lần chạy.

## 1. Tóm tắt kế hoạch

Kế hoạch này triển khai [bản tổng quan hệ thống hợp nhất](00-tong-quan-he-thong-hop-nhat.md) và [bộ đặc tả kỹ thuật](dac-ta-ky-thuat/README.md). Mã module M01 đến M28, tên giai đoạn và tên sự kiện dùng đúng như trong bộ đặc tả.

| Giai đoạn | Thời lượng | Kết thúc vào | Kết quả chính | Module có phần giao |
| --- | --- | --- | --- | --- |
| GĐ0 Chuẩn bị | 1 đến 2 tuần | Tuần 1 đến 2 | Năm spike có kết luận, máy chạy và kho dữ liệu sẵn sàng, backlog GĐ1 được khóa | Chưa có |
| GĐ1 Nền tảng | 4 đến 5 tuần | Tuần 5 đến 7 | Bộ khung chạy trọn vòng nhìn thấy được trên giao diện: luồng quét, đồ thị tri thức; cắm thêm công cụ không sửa mã lõi | 12 module lõi, hai adapter mẫu |
| GĐ2 MVP Khám phá | 4 đến 6 tuần | Tuần 9 đến 13 | Từ IP, domain, URL, email hoặc từ khóa tới finding có bằng chứng; cảnh báo sớm theo KEV và EPSS qua Telegram | 15 module lõi, 5 module kết nối |
| GĐ3 V1 Làm giàu | 6 đến 8 tuần | Tuần 15 đến 21 | Thêm mã nguồn, secret, cloud, Kubernetes, JS và nhị phân; tri thức mới tự sinh việc tiếp theo | Thêm 1 module lõi, 5 module kết nối |
| GĐ4 V1.5 Bảo đảm | 4 đến 6 tuần | Tuần 19 đến 27 | Xác minh finding, agent đánh giá mức nghiêm trọng, báo cáo đầy đủ, chạy bền 7 ngày | Thêm 1 module lõi, hoàn thiện 4 module |
| Để sau | Chưa lập lịch | Sau nghiệm thu | Sub-agent Strix và Decepticon, red-team, C2, PR nháp | M22 |

Ba điều cần biết trước khi đọc tiếp:

- **Thời lượng là ước lượng, chưa phải cam kết.** Phần lớn mã do nhiều subagent viết song song, nên nút thắt nằm ở review, tích hợp và cổng nghiệm thu, không nằm ở số người viết mã. GĐ1 dài hơn bản trước khoảng một tuần vì có thêm giao diện; con số này là ước tính của mình. Chưa có ngày bắt đầu, nên mọi mốc tính theo tuần tương đối, với tuần 1 là tuần đầu của GĐ0. Tổng cộng 19 đến 27 tuần.
- **Bộ khung là trọng tâm của GĐ1.** Mọi chuẩn (hợp đồng dữ liệu, mô tả công cụ, công cụ MCP, sự kiện) được chốt ở GĐ1 để các giai đoạn sau chỉ cắm thêm, không sửa lõi.
- **Phạm vi không đổi.** Hệ thống nội bộ, thiên về phòng thủ và cảnh báo sớm. Agent harness có mặt từ GĐ1. Red-team, C2 và chạy PoC khai thác nằm ngoài kế hoạch này.

## 2. Lộ trình và cổng nghiệm thu

Mỗi giai đoạn chỉ được coi là xong khi qua cổng của nó. Cổng là một danh sách điều kiện đo được, không phải một ngày trên lịch.

&#91;embedded content: Lộ trình · 5 giai đoạn, 5 cổng nghiệm thu\]

Các dải có bề rộng bằng nhau và không theo tỷ lệ thời gian. Mỗi cổng là điều kiện để bước sang giai đoạn kế tiếp; cổng G2 là mốc MVP.

| Cổng | Điều kiện đạt | Buổi demo | Người ký nhận |
| --- | --- | --- | --- |
| G0, cuối GĐ0 | Năm spike có kết luận bằng văn bản. Có máy chạy container, registry image nội bộ, PostgreSQL, Neo4j, MinIO, Temporal và quyền gọi model. Bảng pin phiên bản và giấy phép cho công cụ của GĐ1, GĐ2. Backlog GĐ1 được khóa | Trình bày kết quả spike | Product Team |
| G1, cuối GĐ1 | Một chiến dịch chạy trọn vòng với công cụ mẫu và hiện trên màn hình luồng quét theo thời gian thực. Kết quả hiện trên màn hình đồ thị và agent truy vấn được đồ thị qua MCP. Thêm một công cụ thật chỉ bằng tệp mô tả và bộ đọc kết quả, không sửa mã lõi. Tắt worker giữa chừng không mất tiến độ và không sinh job trùng. 100% lệnh đi qua điểm kiểm duy nhất và có audit kèm nguồn gốc mục tiêu. Container không vào được mạng dữ liệu | Tạo chiến dịch, xem luồng chạy và đồ thị lớn dần, cắm thêm Subfinder, tắt worker giữa chừng | Product Team |
| G2, cuối GĐ2, mốc MVP | Đủ chuỗi domain, IP, dịch vụ, endpoint, package, CVE, finding; không trùng; mỗi finding có bằng chứng. KEV vào hệ thống dưới 2 giờ, EPSS dưới 24 giờ. Feed đổi thì agent đánh giá lại finding và có tin Telegram mà không cần quét lại. Mỗi lần chạy đều ghi lịch sử trạng thái của finding, kể cả khi không còn thấy. Giao diện hiện 100% job lỗi kèm phân loại. Agent tự dừng khi hết ngân sách hoặc hết tri thức mới. Đủ năm loại đầu vào | Từ một domain và một từ khóa tới danh sách finding có bằng chứng; giả lập một CVE vừa vào KEV và nhận tin Telegram | Product Team |
| G3, cuối GĐ3 | Từ một artifact JS tìm ra endpoint mới và hệ thống tự lên lịch việc tiếp theo. Token cài sẵn trong fixture được phát hiện, lưu kèm vị trí và bằng chứng. Bộ giải nén nhị phân chạy trong container không mạng. Thêm một công cụ CLI mới trong tối đa 2 ngày công | Từ artifact tới endpoint mới tới việc tiếp theo; diễn tập thêm công cụ có bấm giờ | Product Team |
| G4, cuối GĐ4 | Chạy 7 ngày liên tục, từ 10.000 bước điều phối, từ 50 job đồng thời, không mất trạng thái. Diễn tập phục hồi đạt RPO và RTO. Kiểm thử prompt injection không sinh job trái phép. Mọi finding đã xác nhận có bằng chứng và dẫn chứng để người dùng tự kiểm lại. Báo cáo SARIF, JSON, HTML hợp lệ | Báo cáo soak test, buổi diễn tập phục hồi, báo cáo delta giữa hai thời điểm | Product Team |

Khi một điều kiện chưa đạt, giai đoạn kế tiếp chưa mở. Việc được phép mang sang chỉ là việc không nằm trong cổng, và phải có người nhận cùng hạn xử lý.

## 3. GĐ0 Chuẩn bị và GĐ1 Nền tảng

### GĐ0 Chuẩn bị (1 đến 2 tuần)

Mục tiêu của GĐ0 là loại bỏ những điểm chưa chắc về kỹ thuật và dựng môi trường trước khi viết mã sản phẩm. GĐ0 không giao module nào.

| Đầu ra | Nội dung |
| --- | --- |
| Kết luận spike 1 | Phiên LangGraph chạy trong Temporal như Activity hay child workflow; replay và hủy có an toàn không |
| Kết luận spike 2 | Naabu và Nmap chạy được trong container Podman không cần root không, hay cần cấp riêng quyền raw socket |
| Kết luận spike 3 | Benchmark upsert đồ thị đồng thời với nhiều worker, không sinh nút trùng |
| Kết luận spike 4 | MCP server đưa năng lực ra cho agent: cách truyền trace ID và khóa chống trùng qua lời gọi MCP, cách gắn điểm kiểm trước khi mở container |
| Kết luận spike 5 | BBOT ở chế độ thụ động: output JSON chuyển được sang ResultEnvelope không; nghĩa vụ của giấy phép AGPL khi dùng nội bộ |
| Bảng pin phiên bản | Phiên bản, digest image, giấy phép và định dạng output của công cụ GĐ1 và GĐ2; áp quy tắc chờ 14 ngày với bản phát hành mới |
| Môi trường dev | Một máy chạy Podman, registry image nội bộ, tệp compose cho Temporal, PostgreSQL, Neo4j, MinIO; ba mạng tách riêng cho điều khiển, dữ liệu và thực thi; quyền gọi model theo chuẩn OpenAI hoặc Anthropic |
| Ước lượng dung lượng | Dung lượng lưu trữ cho chính sách lưu vĩnh viễn |
| Lab mục tiêu | Một môi trường thử được phép quét: vài domain, host và image có lỗ hổng đã biết, dùng để demo và kiểm thử hồi quy |
| Backlog GĐ1 đã khóa | Ticket cho các epic S1 đến S4 và S8a, chia sẵn thành phần việc cho subagent |

Spike về Flowsint và REA của bản trước đã bỏ, vì cả hai không còn được triển khai nguyên khối.

### GĐ1 Nền tảng (4 đến 5 tuần)

Mục tiêu của GĐ1 là dựng bộ khung mà mọi thứ về sau cắm vào, và nhìn thấy được nó chạy. Mọi chuẩn được chốt ở đây để GĐ2 trở đi chỉ thêm công cụ và luật, không sửa lõi.

| Epic | Đầu ra bàn giao | Module | Tiêu chí hoàn thành |
| --- | --- | --- | --- |
| S1 Hợp đồng | Schema chiến dịch và RoE với năm loại đầu vào; manifest CapabilityProvider v1; ResultEnvelope; schema chín sự kiện; schema công cụ MCP; OpenAPI v1; bộ fixture và bộ conformance test | M01, M05, M27 | Schema test chạy trong CI |
| S2 Engine bền vững | Temporal và worker; CampaignWorkflow với pause, resume, cancel; checkpoint LangGraph trên PostgreSQL; khung agent với một đường Planner chạy trọn vẹn; ModelClient tự dựng với hai driver OpenAI và Anthropic | M01, M02, M03, M04 | Tắt worker giữa chừng, chiến dịch tự chạy tiếp |
| S3 Cổng công cụ | MCP server đưa năng lực cấp nghiệp vụ cho agent; Registry đọc manifest; điểm kiểm duy nhất trước mỗi lệnh, hiện cho qua tất cả và ghi audit; bộ chạy container Podman sau một giao diện chung; chống chạy trùng; hai adapter mẫu DNSx và Subfinder | M05, M06 | Thêm Subfinder không sửa mã lõi; container không vào được mạng dữ liệu |
| S4 Dữ liệu và đồ thị | Khóa định danh chuẩn; Ingestion API với bảy cổng chất lượng; Evidence Store có SHA-256 và signed URL; projector Neo4j; bộ truy vấn đồ thị chỉ đọc dùng chung cho agent và giao diện | M07, M23, M27, M28 | Ghi lặp song song không sinh bản ghi trùng |
| S8a Giao diện luồng quét và đồ thị | Màn hình luồng quét theo thời gian thực bằng React Flow; màn hình đồ thị tri thức bằng Cytoscape.js; xem chi tiết từng bước và nguồn gốc từng nút; dòng sự kiện qua SSE | M26 | Người xem thấy chiến dịch chạy và đồ thị lớn dần mà không đọc log |
| Xuyên suốt | Trace và audit theo OpenTelemetry; 12 endpoint REST; CI/CD; giao diện có sẵn của Temporal để debug | M25, M26 | 100% job có trace ID và nguồn gốc mục tiêu |

**Ghi chú về điểm kiểm.** Ở GĐ1, M05 và M06 là một lớp mỏng nằm trong MCP server, không phải hai dịch vụ riêng. Điểm kiểm chưa giới hạn phạm vi vì chế độ black box không biết trước phạm vi; nó cho qua mọi lệnh nhưng ghi lại mục tiêu cùng lý do mục tiêu được chọn. Theo quyết định 13/11, các giai đoạn sau cũng không giới hạn phạm vi: tài sản quét được thì coi như thuộc tổ chức. Nếu sau này cần luật giới hạn thì cắm vào điểm này mà không viết lại.

**Ghi chú về container.** Bộ chạy dùng Podman không cần root nếu spike 2 cho phép, không mount docker socket, không chạy privileged, không dùng mạng của máy chủ. Mỗi container chỉ ghi vào một thư mục kết quả và tự hủy khi xong hoặc hết giờ. Chuyển sang Kubernetes sau này là thay bộ chạy, không đổi giao diện.

**Demo cuối GĐ1.** Tạo một chiến dịch từ giao diện. Màn hình luồng quét hiện agent lập kế hoạch, lệnh đi qua điểm kiểm, container DNSx chạy và kết quả vào kho. Màn hình đồ thị hiện tài sản mới kèm bằng chứng. Sau đó cắm thêm Subfinder chỉ bằng tệp mô tả và bộ đọc kết quả, chạy lại và thấy công cụ mới trên cả hai màn hình. Cuối cùng tắt worker giữa chừng và xem chiến dịch tự chạy tiếp.

**Chưa có sau GĐ1.** Chưa có bộ công cụ quét đầy đủ, chưa có feed tình báo, chưa có cảnh báo Telegram, agent mới có một đường Planner.

## 4. GĐ2 MVP Khám phá

GĐ2 kéo dài 4 đến 6 tuần và kết thúc bằng mốc MVP. Mục tiêu là hệ thống tự đi từ đầu vào tới danh sách finding có bằng chứng, và cảnh báo khi tình hình thay đổi. Bộ công cụ ProjectDiscovery được làm trước vì đã được kiểm chứng rộng rãi.

| Epic | Đầu ra bàn giao | Module | Tiêu chí hoàn thành |
| --- | --- | --- | --- |
| S5 Khám phá | Adapter Subfinder, asnmap, BBOT thụ động, DNSx, Naabu, Nerva, cdncheck, httpx, Katana, Nuclei với toàn bộ mẫu chính thức và mẫu người dùng thêm, tlsx, urlfinder; Nmap chỉ cho nhận diện sâu; hai nguồn tự dựng crt.sh và dnstwist cho từ khóa; scan profile có trần tốc độ | M08, M09, M10 | Demo từ domain và từ khóa tới finding có nguồn gốc |
| S6 Chuỗi cung ứng | Trivy là một provider nhiều năng lực; Syft và Grype đối chứng; feed NVD, OSV, KEV, EPSS; khớp CVE với package; khử trùng nhiều provider; tín hiệu KEV và EPSS để agent đánh giá | M13, M14, M18, M20 | Demo từ image tới pURL tới CVE |
| S7 Suy luận | Context builder; sổ giả thuyết; bộ đánh giá delta; điều kiện dừng theo ngân sách và tri thức mới; vai trò Planner và Analyst; mở rộng bộ truy vấn đồ thị cho agent | M02, M03, M23 | Agent không lặp vô ích; ngân sách có trần |
| S8b Findings và báo cáo | Màn hình findings và job lỗi; xuất JSON; endpoint GET /findings | M24, M26 | Người vận hành thấy lỗi và việc còn dang dở |
| Cảnh báo sớm | Chuỗi intel.revision.v1 tới đánh giá lại có chọn lọc tới finding.changed.v1 tới tin Telegram; cảnh báo khi có tài sản mới; template và group id cấu hình được, ngưỡng gửi chốt ở giai đoạn sau | M18, M20, M24 | KEV dưới 2 giờ, EPSS dưới 24 giờ; finding được đánh giá lại mà không quét lại |
| Chất lượng | Lab thử bản đầu; thuộc tính chủ sở hữu, phơi nhiễm, độ quan trọng của tài sản; bảng FindingRun và lịch sử theo từng lần chạy | M07, M20, M23 | Mỗi finding xác nhận có bằng chứng và dẫn chứng |

Nếu GĐ2 vượt 6 tuần, phần lùi sang GĐ3 trước tiên là Grype, cdncheck và urlfinder, vì chúng bổ sung chứ không mở chuỗi mới.

**Demo cuối GĐ2.** Khai báo một domain gốc và một từ khóa thương hiệu trong lab. Agent điều phối khám phá, quét dịch vụ và image, rồi trình bày danh sách finding, mỗi finding mở được bằng chứng và dẫn chứng để tự kiểm lại. Sau đó giả lập một CVE vừa được thêm vào KEV, xem agent đánh giá lại finding cùng tin Telegram. Cuối cùng chạy lại chiến dịch và xem dòng thời gian của một finding qua hai lần chạy.

**Sau GĐ2, đội vận hành làm được:**

- Khai báo đầu vào là IP, domain, URL, email hoặc từ khóa, rồi chạy chiến dịch nhiều ngày có tạm dừng và tiếp tục.
- Xem luồng quét và đồ thị tài sản theo thời gian thực.
- Nhận danh sách finding có bằng chứng, ưu tiên theo KEV và EPSS.
- Nhận tin Telegram khi xuất hiện tài sản mới hoặc khi một CVE mới ảnh hưởng tài sản đã biết.

**Chưa có sau GĐ2.** Chưa phân tích mã nguồn, secret, cloud, Kubernetes và nhị phân. Finding chưa qua bước xác minh của M21 nên mới dừng ở `CANDIDATE` hoặc `CORROBORATED`. Agent chưa đánh giá mức nghiêm trọng. Chưa xuất SARIF và HTML.

## 5. GĐ3 V1 Làm giàu, GĐ4 V1.5 Bảo đảm và nhánh để sau

### GĐ3 V1 Làm giàu (6 đến 8 tuần)

Mục tiêu của GĐ3 là mở rộng nguồn tri thức và khép vòng phản hồi: thứ hệ thống vừa tìm thấy tự sinh ra việc tiếp theo.

| Epic | Đầu ra bàn giao | Module | Tiêu chí hoàn thành |
| --- | --- | --- | --- |
| S9 Phân tích artifact | Adapter webcrack và jsluice; bộ giải nén tự dựng cho APK, Electron, image và nhị phân (JADX, asar, Syft hoặc Trivy, strings, Ghidra headless); REA là tùy chọn; chuỗi artifact.ready.v1 tới phân tích tới endpoint mới tới việc tiếp theo | M15, M16, M28 | Demo từ artifact tới endpoint mới tới việc tiếp theo |
| S9b Mã nguồn và secret | Adapter Opengrep, Gitleaks, TruffleHog tắt xác minh, Betterleaks; so sánh ba công cụ secret sau GĐ3; credential Git chỉ đọc | M12, M17 | Token cài sẵn được phát hiện và lưu kèm vị trí, bằng chứng |
| S9c Cấu hình hạ tầng | Adapter Prowler, Kubescape là chính, kube-bench bổ sung; khóa chuẩn cho tài nguyên cloud và workload Kubernetes; credential chỉ đọc, ngắn hạn | M07, M11 | Finding cấu hình gắn đúng tài nguyên |
| Nguồn OSINT mở rộng | SpiderFoot-ng thụ động; hai nguồn tự dựng tra rò rỉ theo domain tổ chức và tìm mã nguồn công khai; dò tài khoản mạng xã hội theo email tắt mặc định | M08 | Mỗi tài sản mới có nguồn gốc |
| Tín hiệu ưu tiên | PoC Availability Index ở mức metadata | M19, M20 | Không có job nào thực thi mã PoC |
| Quét lại theo delta | Không quét lại tài sản không đổi khi còn trong TTL của policy (FR-017) | M02, M23 | Đo được số job tiết kiệm giữa hai lần chạy |

**Demo cuối GĐ3.** Crawl một ứng dụng web trong lab, hệ thống thu bundle JS, tìm ra một endpoint chưa từng thấy và tự xếp việc kiểm tra endpoint đó. Quét một repo có token cài sẵn và chứng minh token không lộ ở đồ thị, log, prompt hay tin Telegram.

### GĐ4 V1.5 Bảo đảm (4 đến 6 tuần)

Mục tiêu của GĐ4 là làm cho kết quả đáng tin và hệ thống đủ bền để chạy thường xuyên.

| Epic | Đầu ra bàn giao | Module | Tiêu chí hoàn thành |
| --- | --- | --- | --- |
| S10 Gia cố | Chaos test; bộ kiểm thử prompt injection; diễn tập backup và restore; soak test 7 ngày; kiểm thử hiệu năng với artifact 10 GB và đồ thị 1 triệu nút; quyết định chuyển sang Kubernetes nếu một máy không đủ | M02, M06, M25, nền tảng | Ký nhận bảo mật; SLO đạt |
| Xác minh | Kiểm tra xác định không khai thác: so phiên bản, kiểm phản hồi HTTP, đối chiếu chéo công cụ; đối chứng âm; vai trò Verifier đầy đủ | M03, M21 | FR-016 |
| Mức nghiêm trọng | AI agent đánh giá mức nghiêm trọng, kèm lý do, nguồn và điểm chưa chắc; không dùng công thức trọng số | M20 | FR-018 |
| Báo cáo và khắc phục | Xuất SARIF và HTML; báo cáo delta giữa hai thời điểm và bản cho lãnh đạo lấy từ đồ thị; gán chủ xử lý; rescan đóng finding | M24, M26 | FR-019: output hợp lệ |
| Tích hợp CI | Pipeline gọi API để quét image và repo khi build | M12, M13, M26 | FR-020 |
| Vận hành | Runbook đã diễn tập; dashboard vận hành; checklist go-live | M25 | Checklist go-live đạt |

Soak test 7 ngày chiếm ít nhất một tuần lịch và không rút ngắn được, nên phải bắt đầu muộn nhất ở tuần thứ ba của GĐ4.

**Demo cuối GĐ4.** Trình bày báo cáo soak test, một buổi phục hồi từ backup có đối soát số finding và hash bằng chứng, và một finding đi trọn vòng đời từ `CANDIDATE` tới `VERIFIED` tới `FIXED` sau rescan.

### Nhánh để sau

| Hạng mục | Điều kiện để mở |
| --- | --- |
| M22 sub-agent Strix và Decepticon (S11) | MVP đã nghiệm thu; threat model riêng; pilot được phê duyệt; chỉ lab hoặc staging |
| Red-team, C2, post-exploit | Quyết định riêng của Product Team |
| PR nháp cho bản vá (FR-022) | Quy trình khắc phục của GĐ4 đã chạy ổn định |
| Đăng nhập, SSO và RBAC | Khi mở truy cập cho nhiều nhóm; điểm tích hợp đã để sẵn ở API |
| Kubernetes | Khi một máy không đủ tải hoặc cần tách vùng mạnh hơn; chỉ thay bộ chạy container |
| GUAC, DefectDojo, Dependency-Track | Khi cần lineage và VEX ở quy mô lớn, hoặc muốn dùng lại quy trình quản lý lỗ hổng có sẵn |

## 6. Đầu ra theo module lõi

Bảng dưới cho biết mỗi module lõi giao gì ở cuối từng giai đoạn. “Chưa có” nghĩa là chưa bắt đầu; “Không đổi” nghĩa là chỉ bảo trì.

**Nhóm điều phối**

| Module | GĐ1 Nền tảng | GĐ2 MVP | GĐ3 V1 | GĐ4 V1.5 |
| --- | --- | --- | --- | --- |
| M01 Campaign và RoE | Tạo, xem, pause, resume, cancel; năm loại đầu vào; RoE có phiên bản | Scan profile; ngân sách chiến dịch | Đầu vào là repo, tài khoản cloud và cluster | Không đổi |
| M02 Campaign Controller | CampaignWorkflow bền vững; Activity idempotent | Vòng lặp theo knowledge.delta.v1; dừng theo ngân sách | Quét lại theo delta; kích hoạt từ artifact.ready.v1 | Soak test 7 ngày đạt |
| M03 Agent Harness | Khung LangGraph; một đường Planner; gọi công cụ và truy vấn đồ thị qua MCP | Context builder; sổ giả thuyết; Planner và Analyst | Lập kế hoạch với năng lực mới | Verifier; kiểm thử prompt injection đạt |
| M04 LLM Gateway | ModelClient tự dựng, hai driver OpenAI và Anthropic; ghi chi phí; fallback | Trần ngân sách token theo chiến dịch | Không che dữ liệu gửi model | Không đổi |

**Nhóm thực thi và kiểm soát**

| Module | GĐ1 Nền tảng | GĐ2 MVP | GĐ3 V1 | GĐ4 V1.5 |
| --- | --- | --- | --- | --- |
| M05 Capability Registry và điểm kiểm | Registry đọc manifest; công cụ MCP cấp nghiệp vụ; điểm kiểm cho qua tất cả và ghi audit | Đăng ký provider GĐ2 | Đăng ký provider GĐ3 | Ma trận tương thích với upstream; canary và rollback |
| M06 Execution Gateway | Bộ chạy Podman sau giao diện chung; chống trùng theo job\_fingerprint; cancel, timeout; job.started.v1, job.completed.v1 | 50 job đồng thời, độ trễ hàng đợi P95 dưới 2 phút | Container không mạng cho M15, M16 | Chaos và hiệu năng đạt; Kubernetes nếu cần |

**Nhóm dữ liệu và tri thức**

| Module | GĐ1 Nền tảng | GĐ2 MVP | GĐ3 V1 | GĐ4 V1.5 |
| --- | --- | --- | --- | --- |
| M27 Ingestion và Normalizer | Ingestion API; bảy cổng chất lượng; dead-letter queue | Parser cho provider GĐ2; asset.discovered.v1, observation.changed.v1 | Parser cho provider GĐ3 | Không đổi |
| M07 Asset Inventory | Khóa chuẩn cho domain, IP, service, URL, email, image, repo, package | Chủ sở hữu, phơi nhiễm, độ quan trọng | Khóa chuẩn cloud và Kubernetes | Không đổi |
| M23 Knowledge Graph và Delta | Projector; dựng lại được từ PostgreSQL; bộ truy vấn chỉ đọc cho agent và giao diện | knowledge.delta.v1; mở rộng truy vấn | Nhãn stale; quét lại theo delta | Đồ thị 1 triệu nút đạt SLO |
| M28 Evidence Store | SHA-256; signed URL; đoạn trích có giới hạn cho agent; lưu vĩnh viễn | artifact.ready.v1 cho image và JS | Artifact lớn và tóm tắt dịch ngược | Hash khớp sau phục hồi |

**Nhóm tình báo và đánh giá**

| Module | GĐ1 Nền tảng | GĐ2 MVP | GĐ3 V1 | GĐ4 V1.5 |
| --- | --- | --- | --- | --- |
| M18 Vuln Feed Sync | Chưa có | Feed NVD, OSV, KEV, EPSS có phiên bản; intel.revision.v1 | Không đổi | Không đổi |
| M19 PoC Availability Index | Chưa có | Chưa có | Metadata PoC công khai | Không đổi |
| M20 Correlation và Scoring | Chưa có | Khớp CVE; khử trùng; tín hiệu KEV và EPSS; đánh giá lại theo feed; lịch sử theo từng lần chạy | Finding từ mã nguồn, secret, cấu hình; tín hiệu PoC | Agent đánh giá mức nghiêm trọng kèm giải thích |
| M21 Evidence Verification | Chưa có | Chưa có | Chưa có | Xác minh an toàn; đối chứng âm |

**Nhóm giao diện và vận hành**

| Module | GĐ1 Nền tảng | GĐ2 MVP | GĐ3 V1 | GĐ4 V1.5 |
| --- | --- | --- | --- | --- |
| M26 Web UI và Backend API | 12 endpoint REST; SSE; màn hình luồng quét và đồ thị tri thức | Màn hình findings, job lỗi; GET /findings | Bộ lọc theo nguồn mới | Đổi trạng thái finding; báo cáo delta; API cho CI |
| M24 Reporting và Remediation | Chưa có | Danh sách finding; xuất JSON; tin Telegram theo template cấu hình được | Không đổi | SARIF, HTML, báo cáo delta và bản cho lãnh đạo; gán chủ xử lý |
| M25 Telemetry và Audit | OpenTelemetry; audit chỉ ghi thêm kèm nguồn gốc mục tiêu | Dashboard chiến dịch, job, AI | Dashboard tăng trưởng tri thức | Runbook đã diễn tập |

## 7. Đầu ra theo module kết nối

Mỗi provider khi giao luôn gồm: manifest đã đăng ký, image pin theo digest, bộ đọc kết quả sang ResultEnvelope kèm fixture, scan profile an toàn mặc định, bản ghi giấy phép, và kết quả đạt của bộ conformance test. Công cụ chỉ dùng một phần nhỏ thì tự dựng thay vì bọc nguyên khối.

| Module | Công cụ | GĐ1 | GĐ2 MVP | GĐ3 V1 |
| --- | --- | --- | --- | --- |
| M08 Domain và ASN Discovery | Subfinder, asnmap, BBOT, SpiderFoot-ng; nguồn tự dựng crt.sh, dnstwist, tra rò rỉ, mã nguồn công khai | Adapter Subfinder mẫu | Subfinder, asnmap, BBOT thụ động, crt.sh, dnstwist; tài sản lần ra được ghi quan hệ nguồn gốc | SpiderFoot-ng; tra rò rỉ theo domain tổ chức; tìm mã nguồn công khai |
| M09 DNS, IP và Port | DNSx, Naabu, Nerva, cdncheck, Nmap | Adapter DNSx mẫu | Naabu và Nerva mặc định; cdncheck; Nmap chỉ khi cần nhận diện sâu | Không đổi |
| M10 Web Fingerprint và Crawl | httpx, Katana, Nuclei, tlsx, urlfinder | Chưa có | Năm adapter; toàn bộ mẫu Nuclei và mẫu tùy chỉnh; file JS thành artifact | Crawl tiếp endpoint mới do M15 tìm ra |
| M13 Image và Filesystem SBOM | Trivy, Syft | Chưa có | Trivy chính, Syft đối chứng | SBOM cho repo theo commit |
| M14 Image và Dependency Vulns | Trivy, Grype, OSV-Scanner | Chưa có | Trivy chính, Grype đối chứng | OSV-Scanner tùy chọn |
| M15 JS và SourceMap | webcrack, jsluice | Chưa có | Chưa có | Hai adapter, container không mạng |
| M16 Binary và App Reversing | Bộ giải nén tự dựng; REA tùy chọn | Chưa có | Chưa có | Bộ giải nén chạy theo yêu cầu, container không mạng |
| M12 Code Repository | Opengrep, Gitleaks | Chưa có | Chưa có | Opengrep với bộ rule chọn lọc |
| M17 Secret Exposure | Gitleaks, TruffleHog, Betterleaks | Chưa có | Chưa có | Ba adapter; secret lưu dạng rõ kèm fingerprint |
| M11 Config và Infrastructure | Prowler, Kubescape, kube-bench | Chưa có | Chưa có | Ba adapter, credential chỉ đọc |
| M22 SubAgent | Strix, Decepticon | Chưa có | Chưa có | Chưa có, thuộc nhánh để sau |

Đã loại khỏi danh sách: Amass (trùng vai trò với Subfinder, BBOT và kho tài sản riêng), Flowsint (chỉ giữ ý tưởng enricher nhỏ), LiteLLM (thay bằng ModelClient tự dựng), Semgrep CE (thay bằng Opengrep).

## 8. Epic, thứ tự thực hiện và đường găng

| Epic | Giai đoạn | Cần xong trước |
| --- | --- | --- |
| S1 Hợp đồng | GĐ1 | Kết luận spike ở GĐ0 |
| S2 Engine bền vững | GĐ1 | S1 |
| S3 Cổng công cụ | GĐ1 | S1, spike 2 và 4 |
| S4 Dữ liệu và đồ thị | GĐ1 | S1 |
| S8a Giao diện luồng quét và đồ thị | GĐ1 | S1; dữ liệu thật từ S3 và S4 ở tuần cuối |
| S5 Khám phá | GĐ2 | S3, S4, spike 5 |
| S6 Chuỗi cung ứng | GĐ2 | S3, S4 |
| S7 Suy luận | GĐ2 | S2, S4, dữ liệu thật từ S5 |
| S8b Findings và báo cáo | GĐ2 | S8a |
| Cảnh báo sớm | GĐ2 | S6 |
| S9, S9b, S9c, Nguồn OSINT mở rộng | GĐ3 | S3 |
| S10 Gia cố; Xác minh, đánh giá mức nghiêm trọng, báo cáo | GĐ4 | Toàn bộ GĐ1 đến GĐ3; lab thử |
| S11 Nâng cao | Để sau | MVP nghiệm thu, threat model riêng |

**Đường găng tới MVP:** spike 1, 2 và 4 ở GĐ0, rồi S1, rồi S3 và S4, rồi S5, rồi S7. S1 là điểm nghẽn lớn nhất: mọi subagent chờ schema, nên cả tuần đầu GĐ1 dành để chốt nó và agent review kiến trúc và Product Team phải duyệt ngay trong tuần.

**Thứ tự gợi ý trong GĐ1:** tuần 1 chốt S1; tuần 2 đến 4 chạy song song S2, S3, S4 và S8a (giao diện dựng trên dữ liệu fixture trước); tuần cuối tích hợp, cắm thêm Subfinder, demo và cổng G1. Lịch chi tiết nên lập ở cuối GĐ0.

## 9. Vai trò và trách nhiệm

Mã do nhiều subagent viết song song. Theo quyết định 13/11, AI agent viết mã và review chéo lẫn nhau; Product Team là bên duy nhất ký cổng nghiệm thu:

| Vai trò | Trách nhiệm | Ký cổng |
| --- | --- | --- |
| Product Team | Ưu tiên use case, quyết định policy, nghiệm thu nghiệp vụ, duyệt schema S1 | G0 đến G4 |
| Agent review kiến trúc | Review chéo schema S1, ranh giới module và mọi thay đổi vào mã lõi theo checklist | Không ký; báo cáo cho Product Team trước mỗi cổng |
| Agent review bảo mật | Review công cụ và phiên bản pin, scan profile, cấu hình container, lab thử | Không ký; báo cáo cho Product Team trước mỗi cổng |

Subagent được chia theo năm luồng việc, mỗi luồng ứng với một nhóm module: điều phối và agent (M01 đến M04), cổng công cụ và adapter (M05, M06, M08 đến M17), dữ liệu và đồ thị (M07, M23, M27, M28), tình báo và đánh giá (M18 đến M21, M24), giao diện và vận hành (M25, M26). Mỗi luồng chỉ được sửa mã ngoài nhóm mình khi agent review kiến trúc đồng ý. Cần thêm một đầu mối pháp chế không toàn thời gian cho giấy phép AGPL của BBOT và TruffleHog, và cho dữ liệu cá nhân.

## 10. Quyết định và rủi ro tiến độ

**Đã chốt ngày 12 và 13/11/2026**

| Điểm | Kết quả | Ảnh hưởng tới kế hoạch |
| --- | --- | --- |
| Đội thực hiện | Nhiều subagent viết mã | Nút thắt chuyển sang review và tích hợp; mục 9 |
| LLM | Hỗ trợ chuẩn OpenAI và Anthropic; local hay cloud do vận hành chọn, thiên về local | M04 là ModelClient tự dựng hai driver; không che dữ liệu |
| Đăng nhập | Chưa có ở MVP | Không đổi |
| OSS | Đồng ý cả mười hai điểm của bản đánh giá OSS | Mục 7; bỏ Amass, Flowsint, LiteLLM, Semgrep CE; REA thành tùy chọn |
| GĐ0 | Tách riêng 1 đến 2 tuần | Không đổi |
| Đánh giá lại theo KEV và EPSS | Có trong MVP | Epic Cảnh báo sớm ở GĐ2 |
| Kênh cảnh báo | Bot Telegram | M24 gửi tin theo template từ GĐ2 |
| Đầu vào | IP, domain, URL, email, từ khóa | M01 và M07 từ GĐ1; nguồn cho email và từ khóa ở M08 |
| Lưu dữ liệu | Vĩnh viễn | Ước lượng dung lượng ở GĐ0 |
| Phạm vi GĐ3 | Đủ mã nguồn, secret, cloud, Kubernetes; giữ TruffleHog; làm nguồn dữ liệu cá nhân | S9b, S9c và Nguồn OSINT mở rộng đều chắc chắn có |
| Giao tiếp agent với công cụ | Chuẩn hóa qua MCP | S3 dựng MCP server; M05 và M06 thành lớp mỏng trong đó |
| Hạ tầng chạy | Chưa có Kubernetes; mỗi công cụ chạy trong container trên một máy | Podman ở GĐ1; Kubernetes để sau |
| Phạm vi quét ở GĐ1 | Không giới hạn, vì có chế độ black box | Điểm kiểm cho qua tất cả, ghi nguồn gốc mục tiêu |
| Giao diện ở GĐ1 | Có màn hình luồng quét và đồ thị tri thức; agent khai phá được đồ thị | Epic S8a; GĐ1 thêm khoảng một tuần |
| Thư viện giao diện | Cytoscape.js cho đồ thị, React Flow cho luồng quét, React và TypeScript | Xác minh giấy phép và phiên bản ở GĐ0 |

**Đã chốt chiều 13/11/2026**

| Điểm | Kết quả | Ảnh hưởng tới kế hoạch |
| --- | --- | --- |
| Ngày bắt đầu và người review | Lập kế hoạch trước; AI agent viết mã; chưa cố định ngày | Mốc vẫn tính theo tuần tương đối; agent review chéo, Product Team duyệt ở mỗi cổng |
| Máy chạy và vận hành | Đã có sẵn | Bỏ việc chuẩn bị máy khỏi GĐ0 |
| Phần cứng LLM | Chỉ cần nhận endpoint tương thích OpenAI hoặc Anthropic; dev cấu hình khi chạy | M04 không phụ thuộc phần cứng |
| Tài sản agent lần ra | Quét được thì coi như thuộc chủ sở hữu, có quan hệ trong đồ thị | Điểm kiểm cho qua tất cả cả ở GĐ2; mỗi cạnh ghi nguồn gốc (công cụ, tài sản gốc) |
| Mẫu Nuclei | Dùng toàn bộ mẫu chính thức và mẫu người dùng thêm | M10 nhận thư mục mẫu tùy chỉnh; pin phiên bản bộ mẫu chính thức |
| Ngưỡng cảnh báo Telegram | Để giai đoạn sau; có template và group id cấu hình được | M24 ở GĐ2 gửi theo cấu hình; ngưỡng chưa cố định |
| Secret dạng rõ | Lưu trong database và đồ thị, hiển thị đầy đủ, không che | M28, M23, M26, M24 không có lớp che |
| Tra cứu rò rỉ theo domain | Hỗ trợ; người dùng tự cấu hình API key | M08 ở GĐ3 |
| Đo chất lượng finding | Không đo precision, recall. Mỗi finding phải có bằng chứng xác nhận và dẫn chứng để người dùng tự kiểm lại | Cổng G2, G4 kiểm bằng chứng thay cho ngưỡng; bỏ golden dataset |
| Gộp tài sản | Tài sản do hai công cụ cùng tìm thấy được gộp thành một nút, giữ quan hệ với cả hai nguồn | M07, M23 dùng khóa chuẩn; cloud và Kubernetes theo dạng `cloud:<provider>:<account>:<region>:<loại>:<id>`, `k8s:<cluster-uid>:<namespace>:<kind>:<tên>` |
| Mức nghiêm trọng | Không dùng công thức trọng số. Có lỗ hổng, có xác nhận và dẫn chứng thì là lỗ hổng; AI agent đánh giá mức nghiêm trọng | M20 đơn giản hóa; agent ghi lý do đánh giá (CVSS, KEV, EPSS, mức lộ ra) |

**Còn mở**

Không còn quyết định mở. Chốt thêm chiều 13/11: mọi dữ liệu quét được lưu vĩnh viễn kèm lịch sử trạng thái và mức nghiêm trọng theo từng lần chạy, kể cả lần không còn thấy lỗ hổng (đặc tả tab Dữ liệu mục 1, bảng `FindingRun`; làm từ GĐ2 cùng S7 Suy luận). Vì dữ liệu không được mất, giữ RPO và RTO của tài liệu nguồn: PostgreSQL RPO 15 phút, RTO 2 giờ; Neo4j và MinIO RPO 1 giờ.

**Rủi ro tiến độ**

| Rủi ro | Ảnh hưởng | Cách giảm |
| --- | --- | --- |
| Agent review chéo bỏ sót lỗi thiết kế, vì không có người duyệt chuyên trách | Mã tích hợp kém, GĐ1 trễ | Agent review chéo theo checklist; Product Team duyệt S1 trong tuần đầu và duyệt ở mỗi cổng |
| Spike 1 cho thấy LangGraph không lồng an toàn trong Temporal | Thiết kế lại S2 | Không bắt đầu S2 khi chưa có kết luận |
| Container không root không chạy được Naabu hoặc Nmap | Cần profile quyền riêng | Spike 2; chỉ cấp quyền raw socket, không privileged |
| Một máy không đủ tải ở GĐ3, GĐ4 | Job xếp hàng lâu, soak test hỏng | Theo dõi tải từ GĐ2; chuyển sang Kubernetes là thay bộ chạy |
| Không giới hạn phạm vi khi công cụ thật chạy ở GĐ2 | Quét nhầm tài sản bên thứ ba | Chấp nhận theo quyết định 13/11; mỗi quan hệ trong đồ thị có nguồn gốc để lọc lại, audit đầy đủ |
| OSS đổi output hoặc bị tấn công chuỗi cung ứng | Parser hỏng hoặc image độc | Pin theo digest, chờ 14 ngày với bản mới, fixture và conformance test trong CI |
| Soak test 7 ngày thất bại | Mỗi lần chạy lại trễ ít nhất một tuần | Soak rút gọn 24 đến 48 giờ ở cuối GĐ2 và GĐ3 |

## 11. Việc cần làm ngay

- [ ] Chốt ngày bắt đầu và cấu hình agent review kiến trúc, agent review bảo mật.
- [ ] Cài Podman, registry image nội bộ và quyền gọi model trên máy đã có.
- [ ] Chạy năm spike của GĐ0.
- [ ] Lập bảng pin phiên bản và giấy phép cho công cụ GĐ1, GĐ2 và thư viện giao diện.
- [ ] Dựng lab mục tiêu được phép quét.
- [ ] Khóa backlog GĐ1 và chia thành phần việc cho subagent.
