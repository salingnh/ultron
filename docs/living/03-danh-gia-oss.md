# AEGIS–Vanguard: Đánh giá OSS, bọc nguyên hay tự dựng

Nov 12, 2026 · @T

**Đã chốt ngày 13/11/2026.** Product Team đồng ý cả mười hai điểm dưới đây. Các chữ "Đề xuất" trong bài giờ là quyết định, và đã được đưa vào [bộ đặc tả](dac-ta-ky-thuat/README.md) (tab Module kết nối OSS) cùng [kế hoạch triển khai](02-ke-hoach-trien-khai.md). Giấy phép đánh dấu "cần rà" vẫn phải kiểm ở GĐ0.

**Cập nhật chiều 13/11/2026.** Bài đã được sửa theo các quyết định sau đó: hệ thống không giới hạn phạm vi quét mà ghi nguồn gốc trên từng quan hệ; Nuclei dùng toàn bộ mẫu chính thức cùng mẫu người dùng thêm; secret được lưu và hiển thị dạng rõ; tài sản do hai công cụ cùng tìm thấy được gộp thành một node.

Trong bộ OSS đang có trong đặc tả, bốn thành phần là cả một nền tảng lớn mà hệ thống chỉ dùng một phần nhỏ: Flowsint, LiteLLM, REA và Amass. Cả bốn được thay bằng module tự dựng mỏng hoặc công cụ gọn hơn. Phần còn lại đều là CLI được dùng gần trọn vẹn nên vẫn bọc bằng adapter, nhưng có năm chỗ nên đổi hoặc thêm ứng viên tốt hơn.

## 1. Danh sách đã chốt

Mười hai quyết định dưới đây xếp theo mức ảnh hưởng tới kiến trúc. Bạn có thể trả lời "đồng ý hết" hoặc nêu số muốn đổi.

| # | Thành phần | Hệ thống dùng bao nhiêu | Đề xuất | Ưu | Nhược |
| --- | --- | --- | --- | --- | --- |
| 1 | Flowsint | Rất ít: chỉ cần vài enricher trong một nền tảng sáu dịch vụ | Không triển khai; tự dựng enricher mỏng gọi thẳng nguồn dữ liệu | Bỏ được sáu dịch vụ phải vận hành; không trùng đồ thị và hàng đợi | Tự bảo trì từng enricher khi API nguồn đổi |
| 2 | Engine OSINT rộng | Chưa có | Thêm BBOT làm nguồn chính, SpiderFoot-ng làm nguồn bổ sung | Nhận được domain, IP, URL, email, tên tổ chức; hàng trăm module có sẵn | BBOT giấy phép AGPL-3.0; trùng một phần với ProjectDiscovery |
| 3 | LiteLLM | Ít: chỉ cần hai chuẩn endpoint | Tự dựng `ModelClient` mỏng cho chuẩn OpenAI và Anthropic | Ít phụ thuộc; không thêm proxy giữ toàn bộ khóa | Tự viết fallback, đếm chi phí, retry |
| 4 | REA | Ít: cần endpoint, secret, phiên bản thư viện từ artifact; REA có 207 công cụ | Tự dựng bộ giải nén artifact từ công cụ nhỏ; REA là tùy chọn khi cần đào sâu | Nhẹ, dễ cô lập, không phụ thuộc dự án mới 7 tháng tuổi | Mất khả năng dịch ngược tương tác qua MCP ở mặc định |
| 5 | Amass | Ít: chỉ làm đối chứng cho Subfinder | Bỏ; BBOT thay vai trò đối chứng | Bớt một framework có engine và cơ sở dữ liệu riêng | Mất vài nguồn dữ liệu riêng của Amass |
| 6 | Nmap | Một phần: chỉ nhận diện dịch vụ, không dùng script | Naabu cộng Nerva làm mặc định; Nmap chỉ gọi khi cần nhận diện sâu | JSON sẵn, nhanh, tránh giấy phép NPSL ở đường chính | Nerva mới ra tháng 2/2026; giấy phép cần rà |
| 7 | Bộ ProjectDiscovery | Gần trọn vẹn | Giữ sáu công cụ, thêm tlsx, asnmap, cdncheck, urlfinder | Cùng một họ, JSON thống nhất, adapter gần giống nhau | Phụ thuộc nhiều vào một nhà phát triển |
| 8 | Trivy, Syft, Grype, OSV-Scanner | Gần trọn vẹn, nhưng trùng nhau | Trivy là một provider phục vụ nhiều capability; Syft cộng Grype đối chứng; OSV-Scanner tùy chọn | Bớt image phải bảo trì mà vẫn có hai nguồn độc lập | Trivy từng bị xâm nhập chuỗi cung ứng tháng 3/2026, phải pin chặt |
| 9 | kube-bench | Một phần: chỉ có CIS benchmark | Kubescape làm chính, kube-bench bổ sung | Phủ cả manifest lẫn cluster, nhiều khung chuẩn | Thêm một adapter |
| 10 | Semgrep CE | Trọn vẹn | Đổi sang Opengrep | Có lại taint xuyên hàm và fingerprint kết quả, giúp khử trùng finding | Dự án trẻ hơn Semgrep |
| 11 | Gitleaks, TruffleHog | Trọn vẹn | Giữ cả hai, thêm Betterleaks | Ba nguồn đối chứng; Betterleaks do chính tác giả Gitleaks viết | Betterleaks mới ra tháng 3/2026 |
| 12 | Nguồn cho email và từ khóa | Chưa có | Tự dựng bốn nguồn nhỏ; không bật mặc định việc dò tài khoản mạng xã hội theo email | Phủ được rò rỉ, giả mạo tên miền, mã nguồn lộ | Dò tài khoản cá nhân là chỗ duy nhất mình khuyên chưa bật |

Những thành phần giữ nguyên: Subfinder, DNSx, Naabu, httpx, Katana, Nuclei, Prowler, webcrack, jsluice, Temporal, Neo4j, SeaweedFS. LangGraph giữ nguyên nếu spike 1 đạt. Strix và Decepticon vẫn thuộc nhánh để sau và không triển khai.

Với cả mười hai điểm đã chốt, số nền tảng lớn phải vận hành giảm đi bốn, còn số nguồn thông tin thì tăng lên. Điều này khớp với hướng bạn nêu: bộ công cụ phải đủ rộng để agent có nhiều dữ liệu mà điều phối.

## 2. Cách đánh giá

Mỗi thành phần OSS được xét theo năm câu hỏi. Câu đầu tiên quyết định nhiều nhất, đúng theo tiêu chí bạn nêu.

1. **Hệ thống dùng bao nhiêu phần của nó?** Một CLI dùng gần hết chức năng thì bọc adapter là hợp lý. Một nền tảng nhiều dịch vụ mà chỉ dùng một góc thì không.
2. **Phải vận hành thêm những gì?** Số dịch vụ, cơ sở dữ liệu, runtime và dung lượng đi kèm.
3. **Phần cần dùng có dễ tự dựng không?** Với đội thợ code là subagent, một module vài trăm dòng có hợp đồng rõ là việc rẻ. Một engine quét có hàng nghìn mẫu thì không.
4. **Dự án có chín và an toàn không?** Tuổi dự án, ai bảo trì, lịch sử sự cố chuỗi cung ứng.
5. **Giấy phép có vướng không?** Bạn đã chấp nhận AGPL cho công cụ chạy tách tiến trình, nên giấy phép chỉ được ghi chú, không dùng để loại.

Số liệu trong tài liệu này lấy từ các trang nguồn ở mục 6, tra ngày 12/11/2026. Chỗ nào mình dựa vào kiến thức nền mà chưa đối chiếu lại hôm nay đều có ghi rõ. Tất cả cần kiểm lại tại phiên bản pin ở GĐ0.

## 3. Nhóm nên thay hoặc tự dựng

### Flowsint (quyết định 1)

Flowsint là một nền tảng điều tra OSINT hoàn chỉnh, không phải một thư viện enricher. Theo trang phân tích kho mã, nó gồm sáu dịch vụ: giao diện React, API FastAPI, worker Celery, Redis, Neo4j và PostgreSQL. Phần hệ thống cần là khoảng 29 transform, mỗi cái chủ yếu là một lời gọi tới nguồn ngoài như crt.sh, Have I Been Pwned, Whoxy, Gravatar, Maigret.

Ba lý do không nên bọc:

- AEGIS đã có đồ thị, hàng đợi, giao diện và kho khóa riêng. Dựng Flowsint nghĩa là vận hành thêm một bộ y hệt chỉ để lấy vài lời gọi API.
- Transform của Flowsint tự ghi thẳng vào Neo4j của nó ở bước `postprocess()`. Điều này đi ngược quy tắc chỉ có một cửa ghi là Ingestion API.
- Import riêng gói transform vẫn kéo theo gói lõi cùng connector cơ sở dữ liệu và Celery của nó.

**Đề xuất.** Tự dựng trong M08 một nhóm enricher mỏng, mỗi enricher là một adapter gọi thẳng nguồn: nhật ký chứng chỉ (crt.sh), RDAP và WHOIS, DNS ngược, ASN, và tra rò rỉ theo domain. Mỗi cái là một lời gọi HTTP cộng một parser, hợp với thợ code subagent. Spike 4 về Flowsint được hủy.

### LiteLLM (quyết định 3)

Bạn đã chốt hệ thống chỉ cần hỗ trợ hai chuẩn endpoint là OpenAI và Anthropic, còn chọn model local hay cloud là việc của vận hành. LiteLLM là một proxy hỗ trợ rất nhiều nhà cung cấp, nên hệ thống chỉ dùng một phần nhỏ của nó.

Có thêm một lý do bảo mật. Ngày 24/3/2026, hai bản LiteLLM 1.82.7 và 1.82.8 trên PyPI bị cài mã độc đánh cắp khóa SSH, credential cloud và secret Kubernetes, đồng thời tìm cách cài pod đặc quyền lên mọi node của cluster. LLM gateway là nơi giữ toàn bộ khóa model và nằm ngay trong cluster, nên càng ít phụ thuộc càng tốt.

**Đề xuất.** M04 là một `ModelClient` tự dựng với hai driver: chuẩn OpenAI Chat Completions và chuẩn Anthropic Messages. Mỗi profile LOW, MID, HIGH khai báo `base_url`, tên model và khóa. Phần tự viết gồm retry, timeout, thứ tự fallback và ghi token theo chiến dịch. Nếu sau này vận hành vẫn muốn dùng LiteLLM thì nó chỉ là một endpoint chuẩn OpenAI nữa, không cần sửa mã.

### REA (quyết định 4)

REA mạnh nhưng rất rộng so với nhu cầu phòng thủ. Bản 6.7.0 có 207 công cụ MCP, cài đặt khoảng 222 MB với 158 phụ thuộc gồm cả Playwright, và cần Ghidra 12.1 cùng JDK 21 cho nhị phân native. Kho mã mới tạo ngày 14/4/2026 dưới một tài khoản cá nhân và đã ra 33 phiên bản npm trong ba tháng. Tài liệu của chính nó nói rõ REA không phải sandbox.

Thứ hệ thống thực sự cần từ một artifact là endpoint, secret và phiên bản thư viện. Phần lớn lấy được bằng công cụ nhỏ đã có sẵn trong bộ công cụ:

| Loại artifact | Cách xử lý đề xuất | Thu được |
| --- | --- | --- |
| APK Android | JADX giải mã, rồi jsluice, bộ quét secret và Trivy | Endpoint, secret, thư viện |
| Ứng dụng Electron | Giải nén gói asar, rồi đi đường ống JS của M15 | Endpoint, secret, package |
| Image, filesystem, nhị phân Go, Rust, Java | Syft và Trivy | Package và phiên bản |
| Nhị phân ELF, PE khác | Trích chuỗi và khớp rule; Ghidra headless khi cần decompile | URL, chuỗi nhạy cảm, hàm import |

Việc Syft đọc được thông tin build trong nhị phân Go, Rust và Java là kiến thức nền của mình, cần kiểm lại ở phiên bản pin.

**Đề xuất.** M16 trở thành một bộ giải nén artifact tự dựng, điều phối các công cụ nhỏ ở bảng trên trong sandbox không mạng. REA được giữ làm provider tùy chọn, chỉ bật khi một chuyên viên cần đào sâu một nhị phân cụ thể. Spike 5 về REA chuyển thành không bắt buộc.

### Amass (quyết định 5)

Amass hiện là một framework có engine thu thập và cơ sở dữ liệu tài sản riêng, trong khi đặc tả chỉ dùng nó làm nguồn đối chứng tùy chọn cho Subfinder. Khi đã thêm BBOT ở quyết định 2, vai trò đối chứng đã có người đảm nhận.

**Đề xuất.** Bỏ Amass khỏi danh mục.

## 4. Nhóm nên giữ và bọc nguyên

Các công cụ dưới đây là CLI gọn, hệ thống dùng gần hết chức năng, nên bọc bằng adapter vẫn là cách rẻ nhất. Tự dựng lại chúng là lãng phí, vì giá trị nằm ở hàng nghìn mẫu, rule và dấu nhận diện do cộng đồng bảo trì.

### Bộ ProjectDiscovery (quyết định 7)

Bạn muốn ưu tiên bộ này, và mình đồng ý: các công cụ cùng họ xuất JSON theo cùng phong cách, nên adapter gần như sao chép được cho nhau. Sáu công cụ đã có trong đặc tả được giữ, và mình đề xuất thêm bốn.

| Công cụ | Vai trò | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| Subfinder | Liệt kê subdomain thụ động | Đã có | Làm đầu tiên |
| DNSx | Phân giải DNS | Đã có | Adapter mẫu của GĐ1 |
| Naabu | Phát hiện cổng mở | Đã có | Cần kết luận spike 2 về raw socket |
| httpx | Thăm dò web, nhận diện công nghệ | Đã có |  |
| Katana | Crawl | Đã có |  |
| Nuclei | Kiểm tra theo toàn bộ mẫu chính thức và mẫu người dùng thêm | Đã có |  |
| tlsx | Đọc chứng chỉ TLS | Thêm mới | Tên miền trong chứng chỉ là nguồn tìm thêm domain |
| asnmap | Từ ASN ra dải mạng | Thêm mới | Phục vụ đầu vào là tên tổ chức |
| cdncheck | Nhận biết IP thuộc CDN hoặc cloud | Thêm mới | Giúp policy tránh quét nhầm hạ tầng của bên thứ ba |
| urlfinder | Thu URL thụ động | Thêm mới | Không chạm vào mục tiêu |

Giấy phép MIT đã đối chiếu được cho nuclei, subfinder, httpx, tlsx và urlfinder trên trang tổ chức của ProjectDiscovery. Các công cụ còn lại cần rà khi lập bảng pin. Vai trò của asnmap và cdncheck là kiến thức nền của mình.

Hai công cụ cùng họ mình không đề xuất bọc. `vulnx` tra dữ liệu lỗ hổng, nhưng M18 đã tự đồng bộ feed nên không cần. `notify` gửi thông báo, nhưng gửi qua bot Telegram chỉ là một lời gọi HTTPS nên M24 tự làm.

### Nhận diện dịch vụ (quyết định 6)

Đặc tả hiện dùng Nmap chỉ để nhận diện dịch vụ và phiên bản, tắt hết script. Nerva của Praetorian làm đúng một việc đó: nó kế thừa fingerprintx, nhận hơn 120 giao thức, xuất JSON và được thiết kế để chạy ngay sau Naabu. Nhà phát triển tự công bố nó nhanh hơn Nmap khoảng bốn lần với độ chính xác 99%; con số này chưa được kiểm chứng độc lập.

**Đề xuất.** Naabu cộng Nerva là đường mặc định. Nmap vẫn có adapter nhưng chỉ được gọi khi Nerva không nhận ra dịch vụ. Giấy phép của Nerva chưa đối chiếu được hôm nay.

### Quét thành phần phần mềm (quyết định 8)

Trivy một mình làm được SBOM, quét lỗ hổng, secret và cấu hình sai. Đặc tả đang đặt nó cạnh Syft, Grype và OSV-Scanner, tức bốn image cho hai capability.

**Đề xuất.** Trivy là một image phục vụ nhiều capability. Cặp Syft và Grype của Anchore là nguồn đối chứng độc lập. OSV-Scanner là tùy chọn vì M18 đã đồng bộ dữ liệu OSV. Vẫn có hai nguồn độc lập cho mọi finding, và bớt được một image.

### Kubernetes (quyết định 9)

kube-bench chỉ kiểm CIS benchmark ở mức node. Kubescape phủ cả manifest lẫn cluster đang chạy, theo nhiều khung chuẩn. Đây là kiến thức nền của mình và chưa đối chiếu lại hôm nay.

**Đề xuất.** Kubescape làm chính, kube-bench bổ sung cho phần node. Prowler giữ nguyên cho cloud.

### Phân tích mã nguồn (quyết định 10)

Cuối 2024, Semgrep chuyển một số tính năng của bản cộng đồng sang bản thương mại, gồm phân tích taint xuyên hàm và fingerprint kết quả. Opengrep là nhánh fork từ tháng 1/2025, cùng giấy phép LGPL-2.1, được hơn mười công ty AppSec hậu thuẫn, và khôi phục các tính năng đó. Nó dùng chung định dạng rule, JSON và SARIF với Semgrep.

**Đề xuất.** Dùng Opengrep cho M12. Fingerprint kết quả là thứ M20 cần để khử trùng finding qua các lần quét. Vì chung định dạng, đổi lại Semgrep sau này chỉ là đổi image.

### Phát hiện secret (quyết định 11)

Bạn đã chốt giữ TruffleHog. Tháng 3/2026, tác giả Gitleaks phát hành Betterleaks (giấy phép MIT) và gọi nó là bản kế nhiệm, với cách phát hiện dựa trên tokenization thay cho entropy. Con số recall 98,6% so với 70,4% là do chính dự án công bố.

**Đề xuất.** Chạy cả ba: Gitleaks vì đã chín, Betterleaks vì hướng đi mới, TruffleHog để đối chứng. Sau GĐ3, so ba công cụ trên cùng bộ fixture rồi bỏ cái kém nhất.

## 5. Ứng viên mới cho đầu vào đa dạng

Bạn đã chốt hệ thống nhận năm loại đầu vào: IP, domain, URL, email và từ khóa. Ba loại đầu đã được bộ ProjectDiscovery phủ tốt. Email và từ khóa thì chưa có công cụ nào trong đặc tả xử lý.

| Đầu vào | Hệ thống tìm gì | Công cụ đề xuất |
| --- | --- | --- |
| Domain | Subdomain, bản ghi DNS, chứng chỉ, ứng dụng web | Subfinder, tlsx, DNSx, httpx, Katana, BBOT |
| IP hoặc dải mạng | Cổng mở, dịch vụ, ASN, có thuộc CDN không | Naabu, Nerva, asnmap, cdncheck |
| URL | Công nghệ, endpoint, bundle JS, lỗi theo mẫu | httpx, Katana, urlfinder, Nuclei, đường ống JS của M15 |
| Email | Domain của email thành hạt giống mới; email của tổ chức có nằm trong vụ rò rỉ nào không | BBOT, enricher tra rò rỉ tự dựng, SpiderFoot-ng |
| Từ khóa | Tên miền giả mạo thương hiệu, chứng chỉ chứa từ khóa, mã nguồn công khai lộ thông tin, bucket cloud mang tên tổ chức | dnstwist, enricher crt.sh và tìm mã công khai tự dựng, BBOT |

### BBOT và SpiderFoot-ng (quyết định 2)

BBOT của Black Lantern Security nhận đúng các loại đầu vào bạn cần: tên DNS, IP, dải IP, URL, email và tên tổ chức. Nó có sẵn các preset liệt kê subdomain, liệt kê email, liệt kê cloud và liệt kê kho mã, xuất JSON, và có cờ giới hạn chỉ dùng nguồn thụ động. Giấy phép là AGPL-3.0.

SpiderFoot-ng là nhánh fork do cộng đồng bảo trì của SpiderFoot, giấy phép MIT, hơn 200 module, bản 4.4.10 ra ngày 3/6/2026. Nó nhận thêm số điện thoại, username và tên người.

**Đề xuất.** BBOT là provider OSINT chính từ GĐ2, SpiderFoot-ng là provider bổ sung ở GĐ3. Cả hai chỉ chạy ở chế độ thụ động.

Lý do để hai công cụ này ở chế độ thụ động: chúng tự đệ quy, tức là tự lần theo tài sản mới tìm thấy, và hệ thống không nhìn được vào từng module bên trong chúng. Nếu để chúng tự quét cổng hay chạy mẫu kiểm tra, các thao tác đó sẽ không được ghi theo từng mục tiêu, không theo giới hạn tốc độ và khung giờ cấm của RoE. Mọi thao tác chủ động vẫn đi qua adapter ProjectDiscovery, nơi mỗi mục tiêu được ghi nguồn gốc và bằng chứng.

### Nguồn cho email và từ khóa (quyết định 12)

Bốn nguồn dưới đây nhỏ đến mức tự dựng rẻ hơn là bọc một nền tảng.

| Nguồn | Trả lời câu hỏi | Cách làm |
| --- | --- | --- |
| Tra rò rỉ theo domain | Email nào của tổ chức đã nằm trong vụ lộ dữ liệu | Enricher gọi API của dịch vụ tra rò rỉ; cần khóa API và xác minh quyền sở hữu domain |
| Nhật ký chứng chỉ | Có chứng chỉ nào mới cấp chứa tên thương hiệu không | Enricher gọi crt.sh |
| Tên miền giả mạo | Có ai đăng ký domain gần giống domain của tổ chức không | Adapter cho dnstwist |
| Mã nguồn công khai | Từ khóa hoặc domain nội bộ có xuất hiện trong kho mã công khai không | Enricher gọi API tìm kiếm của nền tảng mã nguồn, rồi đưa kết quả qua bộ quét secret |

Có hai điểm mình khuyên với tư cách người làm bảo mật, và bạn có thể bác:

- **Tài sản tìm được từ từ khóa được đưa vào đồ thị kèm nguồn gốc.** Theo quyết định chiều 13/11, tài sản quét được thì được coi là thuộc tổ chức và hệ thống không giới hạn phạm vi quét. Mỗi quan hệ ghi rõ tài sản được tìm ra từ từ khóa nào và bởi công cụ nào, để người dùng tự xét một domain giống thương hiệu có thật sự là của mình hay không.
- **Chưa bật mặc định việc dò tài khoản mạng xã hội theo email hoặc username.** Các công cụ kiểu Maigret gửi định danh cá nhân của nhân viên tới hàng trăm trang bên thứ ba. Kết quả là tài khoản cá nhân, ít giá trị phòng thủ, mà dữ liệu lại được lưu vĩnh viễn theo quyết định của bạn. Nó là tùy chọn bật theo từng chiến dịch. Tra rò rỉ theo domain của tổ chức thì vẫn làm mặc định.

Giấy phép của dnstwist và điều kiện dùng API của từng nguồn chưa được đối chiếu hôm nay.

## 6. An toàn chuỗi cung ứng của chính bộ công cụ

Khi bộ công cụ càng rộng, rủi ro một công cụ bị cài mã độc càng lớn. Hai sự cố trong năm nay rơi đúng vào hai thành phần có trong đặc tả.

| Sự cố | Diễn biến | Bài học cho AEGIS |
| --- | --- | --- |
| Trivy, 19 đến 22/3/2026 | Bản nhị phân v0.69.4 bị cài mã độc; gần hết tag của trivy-action bị trỏ sang commit độc; image 0.69.5 và 0.69.6 trên Docker Hub cũng độc. Mã độc đánh cắp credential cloud, khóa SSH, token Kubernetes | Tag và số phiên bản không đủ tin; chỉ digest và commit SHA là bất biến |
| LiteLLM, 24/3/2026 | Hai bản 1.82.7 và 1.82.8 trên PyPI đánh cắp secret và tìm cách cài pod đặc quyền lên mọi node | Một phụ thuộc trong control plane có thể chiếm cả cluster |

Đặc tả đã có sẵn pin image theo digest, scanner không có quyền gọi API của cluster, và NetworkPolicy giữa các namespace. Bốn quy tắc được thêm:

1. **Thời gian chờ trước khi nhận bản mới.** Không đưa vào registry nội bộ bản phát hành chưa đủ 14 ngày tuổi, trừ bản vá bảo mật đã được rà. Cả hai sự cố trên đều bị phát hiện trong vài giờ tới vài ngày.
2. **Giới hạn lưu lượng ra theo từng provider.** Job scanner chỉ được kết nối tới mục tiêu của job và nguồn dữ liệu mà provider đó khai báo. Mã độc có lọt vào cũng không gửi dữ liệu ra ngoài được.
3. **Pin theo commit SHA trong CI.** Mọi action và bước build dùng SHA đầy đủ, không dùng tag.
4. **Khóa riêng cho từng provider.** Mỗi provider chỉ nhận khóa API của riêng nó, nên một công cụ bị chiếm không lộ khóa của công cụ khác.

Con số 14 ngày là đề xuất của mình, không lấy từ nguồn nào.

### Nguồn tham khảo

Tất cả tra ngày 12/11/2026.

- Flowsint: [phân tích kho mã trên DeepWiki](https://deepwiki.com/reconurge/flowsint)
- BBOT: [kho mã chính thức](https://github.com/blacklanternsecurity/bbot/)
- SpiderFoot-ng: [trang PyPI](https://pypi.org/project/spiderfoot-ng/)
- REA: [bài thử nghiệm với Ghidra và Electron](https://jacar.es/en/rea-reverse-engineering-mcp-coding-agents/)
- LiteLLM: [BleepingComputer về vụ xâm nhập PyPI](https://bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack)
- Trivy: [thông báo của Aqua Security](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- Nerva: [bài giới thiệu của Praetorian](https://www.praetorian.com/blog/whats-running-on-that-port-introducing-nerva-for-service-fingerprinting/)
- Amass: [trang dự án OWASP](https://owasp.org/projects/amass)
- ProjectDiscovery: [trang tổ chức trên GitHub](https://github.com/projectdiscovery)
- Opengrep: [so sánh Opengrep và Semgrep](https://appsecsanta.com/sast-tools/opengrep-vs-semgrep)
- Betterleaks: [BleepingComputer](https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/amp/)
