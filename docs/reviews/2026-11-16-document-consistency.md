# Rà soát tính nhất quán tài liệu — 2026-11-16

## Kết luận và phạm vi

**Đã hoàn thành rà soát; bộ tài liệu CHƯA đạt điều kiện nhất quán để giao triển khai.** Có 18 nhóm phát hiện dưới đây. Đây là review tĩnh nội dung hiện tại, không phải xác nhận code đã sửa hay hệ thống chạy đúng.

Phạm vi: hướng dẫn ở gốc repo, `docs/README.md`, tài liệu Markdown và bản đồ HTML trong `docs/living/`, quyết định S1 và quy tắc đổi hợp đồng trong `contracts/README.md`. `docs/source/` là lịch sử, không dùng làm yêu cầu triển khai. Không kiểm chứng thông tin OSS/CVE bên ngoài, không chạy scanner, build hay runtime test.

Mốc Git khi bắt đầu: nhánh `redesign/pentest-repositioning-s1`, HEAD `8be1b5de851704603fd748312b2c056a447cafc9`. Worktree đã có thay đổi hợp đồng chưa commit; review không sửa các thay đổi đó. Các số dòng dưới là tại thời điểm review.

Căn cứ xử lý: quyết định Product Team mới nhất, đặc biệt D14–D28 ngày 16/11, thắng nội dung cũ. Không tự suy ra rằng cho phép một năng lực đồng nghĩa năng lực đó đã được lập lịch và có tiêu chí nghiệm thu.

## A. Xung đột phải xử lý trước khi khóa S1/backlog

### R01 — P1: M05 “cho qua mọi mục tiêu” phủ định denylist bắt buộc

- `docs/living/dac-ta-ky-thuat/03-module-loi.md:81`: M05 cho qua mọi mục tiêu ở mọi giai đoạn; yêu cầu duyệt tùy chọn.
- `docs/living/02-ke-hoach-trien-khai.md:82,176` và task T1.15 vẫn yêu cầu điểm kiểm cho qua tất cả.
- `PRD.md:55-56`, RULES mục 2 và D15–D16 bắt buộc policy/denylist cho T3.
- **Hệ quả:** implement theo module hoặc task sẽ thiếu ràng buộc đã chốt ở phần đầu.
- **Hướng sửa:** đồng bộ đặc tả M05, bảng mạng, task và tiêu chí nghiệm thu theo D15–D16; bỏ câu tuyệt đối “cho qua mọi mục tiêu”. Việc không dùng allowlist phạm vi không loại bỏ denylist.

### R02 — P1: T3 thuộc MVP nhưng các năng lực thực hiện nằm sau MVP

- `docs/living/dac-ta-ky-thuat/01-tong-quan-dac-ta.md:52,55`: khai thác và kiểm thử credential thuộc MVP.
- `docs/living/02-ke-hoach-trien-khai.md:123,138`: credential ở GĐ3, xác minh T3 ở GĐ4; TASKS T3.2/T4.2 tương ứng.
- **Hệ quả:** giao đúng backlog vẫn không đáp ứng định vị MVP mới.
- **Hướng sửa:** lập ma trận năng lực tối thiểu T3 cần giao tại G2 theo D15, cập nhật task và cổng G2 tương ứng. Product Team cần xác nhận lại lịch/khối lượng; không chỉ sửa một câu “MVP” cho hết lỗi.

### R03 — P1: Agent đánh giá severity ở G2 nhưng phần sau nói chưa có

- `docs/living/02-ke-hoach-trien-khai.md:103`: demo G2 yêu cầu agent đánh giá lại finding và gửi Telegram.
- Cùng file dòng 112: “Agent chưa đánh giá mức nghiêm trọng”; dòng 139 và `03-module-loi.md:225` để việc này ở GĐ4.
- PRD mục 3/6 cam kết severity do agent đánh giá; D18 đã chốt trigger, ngân sách và fallback `UNRATED`.
- **Hệ quả:** luồng KEV → đánh giá → cảnh báo thiếu năng lực nền ở chính mốc nghiệm thu.
- **Hướng sửa:** đặc tả phần severity tối thiểu tại G2 theo D18; G4 chỉ là hoàn thiện. Nêu rõ nguồn `agent | rule | operator` và fallback, tránh yêu cầu mọi kết quả luôn do agent đánh giá thành công.

### R04 — P1: TruffleHog bật xác minh vừa là T0 vừa là T3

- `docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md:64`: hàng TruffleHog bật xác minh có tầng T0.
- Cùng file dòng 181: xác minh credential là T3, phải qua policy/denylist và audit actor.
- **Hệ quả:** bảng connector có thể tạo manifest cho phép bỏ qua kiểm soát T3.
- **Hướng sửa:** đồng bộ phân loại của provider bật xác minh với quy tắc M17/D17; phân biệt rõ phân tích tĩnh với bước xác minh chủ động.

### R05 — P1: Nuclei “mọi mẫu” nhưng cố định T2 và vẫn cấm T4

- `docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md:56` gắn toàn bộ mẫu chính thức/tùy chỉnh vào T2; phần M10 tiếp tục yêu cầu chạy mọi mẫu.
- RULES mục 2/D15 quy định quyết định theo tầng tác động và chặn T4.
- **Hệ quả:** tài liệu thiếu điều kiện để suy ra mọi mẫu, kể cả mẫu tùy chỉnh, đều hợp lệ T2. Đây là lỗ hổng đặc tả, không phải kết luận đã kiểm tra nội dung template thực tế.
- **Hướng sửa:** làm rõ danh mục mẫu được hỗ trợ khác quyền thực thi từng mẫu; ràng buộc policy thắng lựa chọn bộ mẫu. Không gán T2 vô điều kiện cho toàn bộ tập mẫu.

### R06 — P1: Scanner bị cách ly nhưng lại phải gọi kho dữ liệu

- `docs/living/dac-ta-ky-thuat/02-nen-tang.md:99` cho scanner tải bằng chứng và gọi Ingestion.
- `03-module-loi.md:107` cấm container tới cả mạng điều khiển và dữ liệu; dòng 166 lại cấp signed URL cho scanner tải lên.
- D3 đã chốt collector M06 ở mạng điều khiển tải bằng chứng; D27 thêm cách ly collector/parser.
- **Hướng sửa:** một luồng thống nhất: scanner ghi `/out` → collector kiểm file/băm/tải qua M28 → parser cô lập → ResultEnvelope → M27. Sửa cả sơ đồ, ARCHITECTURE và bảng quyền mạng. Signed URL không tự vượt qua hạn chế mạng.

### R07 — P1: Contract v1 chỉ container nhưng SDK vẫn hứa L0–L3

- D22: ApprovedTask v1 chỉ hỗ trợ runtime container.
- `ARCHITECTURE.md:82`, `docs/living/00-tong-quan-he-thong-hop-nhat.md:153`, `04-module-ket-noi-oss.md:19-27`: MVP hỗ trợ import/REST; về sau còn MCP bridge.
- Bảng connector tiếp tục gắn nhiều capability với L2, REA L3; M27 nhận import L0.
- **Hệ quả:** adapter writer có hai hợp đồng triển khai không tương thích.
- **Hướng sửa:** đặc tả runtime v1 chỉ container; nếu adapter container gọi HTTP tới nguồn ngoài thì mô tả đó là hành vi trong container, không phải runtime REST riêng. Bỏ hợp đồng import/REST/MCP bridge chưa triển khai khỏi hướng dẫn v1; không nhầm REST API của sản phẩm hoặc MCP M03→M05 với runtime provider.

### R08 — P1: Chính sách version tự mâu thuẫn — đã được cập nhật đồng thời

- RULES mục 3 và D24: mọi thay đổi schema tăng version; schema theo version bất biến.
- `contracts/README.md:38-41`: thêm field tùy chọn/enum vẫn giữ file v1.
- **Hệ quả:** consumer `additionalProperties:false` có thể từ chối payload mới dù cùng version.
- **Hướng sửa:** đồng bộ README theo D24. Tách rõ việc sửa bản nháp chưa phát hành S1 với tính bất biến của version đã công bố; không dùng ngoại lệ bản nháp làm quy tắc nâng cấp production.

**Kiểm tra lại trước khi kết thúc:** luồng công việc khác đã sửa `contracts/README.md:38` trong worktree: thêm field/enum đều tăng version, khớp D24. Xung đột chính của R08 đã được xử lý ở nội dung hiện tại; review này không thực hiện thay đổi đó. Phân biệt bản nháp và bản đã phát hành vẫn cần được giải thích nhất quán.

### R09 — P1: Công nghệ kho bằng chứng đã đổi nhưng đặc tả vẫn dùng MinIO

- D28 đã chọn SeaweedFS qua chuẩn S3, giữ EvidenceStore/collector.
- `ARCHITECTURE.md:13,122`, các tab nền tảng/dữ liệu, T0.8 và HTML dòng 225/274 còn dùng MinIO như thành phần được chọn.
- **Hệ quả:** dev có thể dựng sai hạ tầng ngay tại G0.
- **Hướng sửa:** thay công nghệ đang dùng trong tài liệu hiện hành; giữ quyết định cũ chỉ trong lịch sử. Không tự coi khả năng object lock/backup của hai sản phẩm là tương đương; tiêu chí cần được xác nhận ở spike/pinning. Review này không xác nhận nhận định “MinIO ngừng bảo trì”.

## B. Các rule và lịch giao chưa thống nhất

### R10 — P2: Cấm agent cầm credential nhưng prompt được chứa secret rõ

- `RULES.md:26` và M03 cấm agent cầm credential mục tiêu.
- PRD D17, M04/M17 cho secret dạng rõ trong prompt; D17 cho sinh ứng viên và thử credential.
- **Vấn đề:** chưa phân biệt credential vận hành được cấp cho scanner với secret thu thập được dùng làm dữ liệu. Chưa đủ căn cứ kết luận đây chỉ là lỗi câu chữ.
- **Hướng sửa:** Product Team xác nhận ranh giới dữ liệu và quyền sử dụng; đặc tả ai được nhận giá trị nào, ai được thực thi. Không tự che secret để “sửa” vì sẽ đổi D17.

### R11 — P2: URL vừa phải nguyên vẹn vừa phải loại token/query nhạy cảm

- M10 (`04-module-ket-noi-oss.md:120`) yêu cầu URL lưu nguyên vẹn.
- M07 (`03-module-loi.md:139`) và bảng khóa URL (`05-du-lieu-api-su-kien.md:52`) cấm lưu token/tham số nhạy cảm.
- **Hướng sửa:** phân biệt URL bằng chứng gốc với canonical key dùng khử trùng, xác nhận quy tắc cho từng nơi. Không áp quy tắc chuẩn hóa định danh thành lệnh xóa nội dung bằng chứng.

### R12 — P2: “Mọi ghi qua M27”, “chỉ ghi thêm” đang quá rộng

- AGENTS điều 3 nói mọi ghi dữ liệu đi qua M27; ARCHITECTURE mục 7 nói mọi dữ liệu chỉ ghi thêm.
- S1 mục 3 chia module trực tiếp sở hữu/ghi bảng campaign, session, job, audit; M23 chiếu Neo4j; D13/D26 cho cập nhật một số cột trạng thái có lịch sử.
- **Hướng sửa:** định nghĩa phạm vi M27 là ingestion dữ liệu quét/tri thức theo thiết kế, phân biệt lịch sử bất biến với projection/trạng thái hiện tại. Cần một ma trận quyền ghi thống nhất; không thể giữ nghĩa đen của cả hai mô tả.

### R13 — P2: Truy vấn graph vừa giao G1 vừa giao G2

- T1.23 và cổng G1 yêu cầu agent truy vấn graph qua MCP.
- `03-module-loi.md:158`: tập truy vấn cho agent tới GĐ2 mới giao, dù phần mở đầu M23 nói từ GĐ1.
- **Hướng sửa:** ghi tập truy vấn tối thiểu G1, delta/mở rộng G2; tiêu chí G1 chỉ dùng phần thực sự giao tại G1.

### R14 — P2: MVP hứa bền 7 ngày nhưng kiểm chứng ở G4

- PRD mục 4 đặt chiến dịch 7 ngày trong mục tiêu MVP.
- M02 và T4.1/cổng G4 mới làm soak 7 ngày; kế hoạch chỉ làm soak rút gọn cuối G2/G3.
- **Hệ quả:** thiếu bằng chứng để nghiệm thu lời hứa MVP. Chưa có test không chứng minh hệ thống không làm được, nhưng không thể tuyên bố đã đạt.
- **Hướng sửa:** đặt kiểm chứng tương ứng tại G2 hoặc điều chỉnh cam kết sau quyết định sản phẩm; ghi rõ G4 là kiểm tra lại nếu đã nghiệm thu ở G2.

### R15 — P2: Nguồn ưu tiên và trạng thái quyết định không phản ánh hiện tại

- AGENTS nói `docs/living/` thắng bản gốc; RULES ưu tiên chỉ đạo mới nhất nhưng không chỉ thẳng tới các quyết định đã chốt nằm trong file S1 mang nhãn “bản nháp”.
- PROGRESS còn nói AGENTS/PRD/RULES đang mang định vị chỉ phòng thủ, trong khi các file đã có T3.
- Kế hoạch dòng 299 nói “Không còn quyết định mở”; PROGRESS/S1 còn D5–D13 chờ duyệt.
- RULES mục 1 vẫn nói phần tấn công của tài liệu nguồn đã bị loại chung chung.
- **Hướng sửa:** chỉ rõ quyết định đã chốt nào có hiệu lực, phần nào là đề xuất và phần nào đã bị thay thế. Giữ lịch sử nhưng không dùng lịch sử làm trạng thái hiện tại. Đồng bộ thứ tự đọc PRD → RULES → ARCHITECTURE giữa AGENTS và RULES.

## C. Tính năng đã bỏ nhưng vẫn xuất hiện như thành phần thiết kế

### R16 — P1: M22 vừa ngoài phạm vi/T4 vừa có thiết kế triển khai T3

- `04-module-ket-noi-oss.md:68` xếp `assess.subagent` vào T4; dòng 233-244 lại đặc tả M22, T3, cách tích hợp, điều kiện chạy và phiên bản.
- ARCHITECTURE đếm M22 trong 11 connector; HTML hiển thị card M22.
- **Hệ quả:** agent có thể tưởng M22 là phần phải làm chỉ cần bật duyệt tay.
- **Hướng sửa theo yêu cầu lần này:** bỏ M22/`assess.subagent` khỏi danh mục tính năng, sơ đồ triển khai, bảng provider và đặc tả đang dùng. Giữ mã M22 đã cấp trong lịch sử, không đánh lại mã module còn lại. Không cần mô tả cách triển khai một module không giao.

### R17 — P2: OSS đã loại vẫn nằm trong bản đồ và tài liệu hướng dẫn hiện hành

- HTML dòng 127/157 có LiteLLM/Flowsint/Amass; dòng 259 trở đi còn nguyên khu “lấy cảm hứng”.
- Tổng quan mục 7 còn bảng Flowsint/Strix/Decepticon; đánh giá OSS nói bỏ LiteLLM/Semgrep nhưng lại mô tả cách quay lại dùng chúng.
- Đây phần lớn là lịch sử lựa chọn, không tự thân là mâu thuẫn runtime, nhưng trái mục tiêu tài liệu gọn, chỉ mô tả cái đang dùng.
- **Hướng sửa:** tài liệu hiện hành chỉ ghi ModelClient tự dựng, enricher tự dựng, Subfinder/BBOT và Opengrep. Đưa phân tích phương án đã loại về hồ sơ quyết định/lịch sử, bỏ khỏi luồng đọc triển khai. REA đang là tùy chọn, không được tự coi như đã bị loại; phải ghi rõ điều kiện và runtime nếu giữ.

### R18 — P2: Nhánh “để sau” bị trình bày như backlog đã cam kết

- TASKS cuối file, kế hoạch mục 5 và tổng quan mục 11 vẫn liệt kê PR nháp, C2, sub-agent, các nền tảng chưa dùng.
- RULES cấm tự mở PR vào mã mục tiêu; M24 vẫn mô tả PR nháp FR-022 ở nhánh sau.
- **Hướng sửa theo yêu cầu lần này:** bỏ đặc tả/đầu ra/task triển khai của tính năng chưa làm khỏi tài liệu hiện hành. Giữ một ranh giới cấm ngắn trong RULES để agent không tự bổ sung; không lặp cả danh sách công cụ và thiết kế “để sau” trong từng chương.

## Cách chuẩn hóa đề xuất

1. Một bảng phạm vi hiện hành: năng lực được giao, module, giai đoạn và tiêu chí nghiệm thu. Các phần còn lại dẫn tới bảng này.
2. Mỗi quyết định có trạng thái rõ: đã chốt, đề xuất, đã thay thế. Chỉ quyết định đã chốt áp dụng cho triển khai.
3. Tài liệu vận hành/thiết kế chỉ mô tả công nghệ đang dùng. Hồ sơ lịch sử chứa lý do bỏ phương án; không đưa phương án đã bỏ vào sơ đồ hiện hành.
4. Giữ các lệnh cấm cần thiết tập trung tại RULES. “Không mô tả tính năng không dùng” không có nghĩa xóa ranh giới an toàn khiến agent hiểu là được phép.
5. Cập nhật đồng thời PRD, đặc tả, TASKS, cổng nghiệm thu và HTML; không chỉ sửa phần giới thiệu.

## Kiểm chứng và việc còn lại

- Mỗi phát hiện ở trên có cặp nội dung đối chiếu từ file hiện tại; các đề xuất chưa được coi là quyết định sản phẩm mới.
- Chưa sửa nội dung thiết kế, chính sách, lịch giao hoặc contracts trong lượt review này. Chỉ thêm báo cáo và cập nhật trạng thái công việc.
- Cần xử lý R01–R07, R09/R16; R08 đã có cập nhật đồng thời như ghi chú trên. Cần hoàn tất các mục này trước khi khóa S1 và backlog; chốt ranh giới/lịch giao tại R02, R10–R12, R14 trước khi viết lại các cam kết liên quan.
- Sau khi sửa: rà lại từng R01–R18, kiểm link và đối chiếu ma trận năng lực với task/cổng nghiệm thu; nếu đổi contract thì chạy validator và kiểm tra DDL phù hợp. Không lấy kiểm tra Markdown thay cho bằng chứng runtime.

**Biến động workspace khi review:** HEAD cuối lượt là `2e6100b26fc91f2d8d3cf16ea37af0aa2cb0f874`, khác HEAD ban đầu do luồng khác commit contract. Báo cáo tập trung nội dung tài liệu; không kết luận các lỗi contract lịch sử trong PROGRESS vẫn còn sau commit này.
