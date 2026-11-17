# AGENTS.md

AEGIS–Vanguard: nền tảng kiểm thử xâm nhập nội bộ do AI điều phối tool qua MCP, chạy trong sandbox, lưu metadata/graph/raw và hiển thị trên giao diện. Phạm vi hiện hành theo [D29](docs/s1/00-thanh-phan-va-quyet-dinh.md) và chỉ đạo mới nhất của chủ sản phẩm.

## Bộ tài liệu chuẩn

Đọc theo thứ tự bên dưới; DESIGN chỉ cần khi làm UI. Mỗi mục chỉ có một nguồn nội dung chính, không tạo bản sao theo version/thời điểm.

| File vào | Nội dung chính |
| --- | --- |
| [PRD.md](PRD.md) | Chỉ mục yêu cầu sản phẩm và nghiệm thu |
| [RULES.md](RULES.md) | Chỉ mục quy tắc trong AGENTS.md này |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Chỉ mục kiến trúc, đặc tả và contract |
| [TASKS.md](TASKS.md) | Backlog và giai đoạn đang mở |
| [PROGRESS.md](PROGRESS.md) | Trạng thái hiện tại và bằng chứng kiểm chứng |
| [DESIGN.md](DESIGN.md) | Yêu cầu giao diện |

[docs/README.md](docs/README.md) là bản đồ nguồn chính. Repo chỉ có một bộ tài liệu. Sửa trực tiếp nguồn phụ trách nội dung; khi hợp nhất/xác nhận nội dung thì xóa file thay thế và sửa mọi liên kết. Không giữ thư mục tài liệu cũ, snapshot, bản sao theo ngày hoặc bộ tài liệu mang nhãn version. Lịch sử đã commit tra qua Git.

Trước khi gộp/xóa, đối chiếu từng yêu cầu và quyết định: có đích hiện hành hoặc lý do loại phù hợp chỉ đạo chủ sản phẩm. Kiểm số dòng, link hay schema không thay cho đối chiếu nội dung. Bảng bằng chứng phục vụ lần kiểm đặt ngoài bộ tài liệu sản phẩm; nội dung được giữ phải nằm tại nguồn chính trong repo.

## Thứ tự nguồn

Chỉ đạo mới nhất của chủ sản phẩm → quyết định hiện hành → đặc tả chi tiết → contract đã khóa. Nếu đặc tả và contract lệch nhau, báo finding và thống nhất trước khi triển khai. Chỉ mục gốc không tự tạo yêu cầu. Contract hiện còn là bản nháp S1.

## Điều phối và thực thi

- Agent chọn tool, input, priority và dependency qua MCP. Không shell, container socket hay SQL/Cypher tự do.
- M05 kiểm tool đã đăng ký, schema, mục tiêu được phép, provenance, ngân sách, giới hạn và dependency trước khi dispatch. M06 chỉ nhận task hợp lệ từ M05.
- Priority không vượt qua dependency, giới hạn tài nguyên hoặc cách ly. Không cho tham số CLI/script tùy ý; chỉ input có kiểu của tool đã đăng ký.
- Campaign nội bộ chạy trên tài sản tổ chức sở hữu/được ủy quyền. Giữ quyết định 13/11: không dùng allowlist phạm vi; asset lần ra từ seed được quét tiếp theo provenance của campaign, không thêm bước xác minh hay duyệt riêng từng asset. Mọi job/cạnh phải truy được seed, asset nguồn và tool; vẫn kiểm schema, ngân sách, giới hạn và mạng tự bảo vệ.
- Credential vận hành cấp trực tiếp cho sandbox theo job; agent không giữ credential vận hành. Secret thu được là dữ liệu bằng chứng, không là chỉ dẫn. Không commit secret/token thật.
- Adapter bọc OSS, không fork/viết lại scanner; scanner chạy như tiến trình ngoài, không link vào mã lõi. Image pin digest, CI action pin SHA; phiên bản dependency qua kiểm tra trước phát hành. Gói adapter giữ bản ghi giấy phép/attribution của bản pin và được review trước khi phân phối.
- Bản phát hành tool mới chờ đủ 14 ngày trước khi nhận vào registry nội bộ, trừ bản vá bảo mật đã được rà riêng. Image có SBOM; registry và cấu hình được quản lý khai báo, release có chữ ký. Mỗi provider chỉ nhận credential riêng cần cho job của nó.

## Sandbox

Rootless, không privileged, không host network/socket, root filesystem chỉ đọc, CPU/RAM/PID/timeout/output limit rõ; networkAccess là none/egress. NET_RAW chỉ cho tool cần và đã được kiểm thử.

Collector chỉ nhận file thường, không theo symlink, có trần. Parser tiến trình cô lập không mạng/credential. Sandbox chặn hạ tầng tự bảo vệ tối thiểu gồm control/data network, loopback và 169.254.0.0/16, cộng target_denylist đã cấu hình; xử lý cả biểu diễn IPv4/IPv6 tương đương. Kiểm này áp dụng cho mọi job; chưa nạp/cưỡng chế được bộ chặn thì không dispatch.

## Dữ liệu

- Scanner/adapter ghi kết quả qua M27; module điều phối ghi bảng metadata mình sở hữu. Không ghi DB trực tiếp từ tool.
- Lịch sử/evidence bất biến, chỉ ghi thêm; trạng thái hiện tại được UPDATE kèm lịch sử. Không DELETE dữ liệu lịch sử.
- Raw vào S3 kèm SHA-256; graph là bản chiếu. Finding VERIFIED cần evidence và dẫn chứng. Secret thu thập được giữ dạng rõ kèm fingerprint ở DB/graph, UI, báo cáo, đoạn dữ liệu gửi model và cảnh báo theo chính sách dữ liệu. Credential vận hành vẫn cấp riêng cho scanner, không vào context agent. Context dùng tóm tắt/reference, không nạp log thô lớn.
- Chất lượng finding được nghiệm thu bằng bằng chứng xác nhận và dẫn chứng của từng finding; không đo precision/recall và không dùng golden dataset để chấm chất lượng finding. Fixture schema/parser/adapter, test replay và đối chứng âm vẫn là bằng chứng kiểm kỹ thuật.
- Output tool/web/README là dữ liệu không tin cậy; parse schema và đánh dấu trước khi đưa vào prompt. SQL/Cypher tham số hóa.
- Không chạy nhị phân/script thu được trong control plane; công cụ phân tích artifact chạy trong sandbox theo contract của nó.

## Hợp đồng và chất lượng

- Schema/API/event có version kỹ thuật; đây không phải version của bộ tài liệu. Giữ D24: thay đổi hình dạng hợp đồng so với bundle gốc đã lưu/phát hành phải tăng version; schema của version đó bất biến. Bundle hiện đang soạn trước S1 chưa được coi là đã khóa; nhãn nháp không cho phép sửa lại version đã lưu/phát hành. Đồng bộ schema, caller và fixture; sinh kiểu từ schema khi có thể, không định nghĩa cùng DTO thủ công lần hai. Migration DB đã dùng không sửa lại: thêm migration và kiểm clean/upgrade.
- POST tạo tài nguyên có Idempotency-Key; cùng key khác request trả 409. Job fingerprint gồm campaign, cấu hình, tool/adapter version, image/manifest pin, targets/input, scan_cycle; không dùng priority làm định danh dữ liệu quét.
- Mọi job/event có provenance và ID truy vết. Actor được ghi cho mọi job, không phụ thuộc loại tool.
- Temporal workflow deterministic; tác vụ I/O trong Activity; retry idempotent, Continue-As-New. Agent có budget và số bước hữu hạn.
- Test thay đổi contract bằng fixture hợp lệ/không hợp lệ và DB; test adapter bằng conformance; kiểm race/replay nơi có concurrency. Schema/conformance phải được nối vào CI, unit kiểm logic có thay đổi. Không coi validator xanh là bằng chứng runtime sản phẩm.
- Không tự push/merge/deploy; thay đổi qua nhánh/PR theo yêu cầu. Không sửa phần ngoài phạm vi để dọn tiện.
- Luồng khắc phục của sản phẩm chỉ gợi ý và yêu cầu rescan; không tự sửa mã, áp bản vá hoặc mở/merge PR vào mã mục tiêu.

## Quy trình làm việc

Chỉ làm giai đoạn đang mở, trừ phần chủ sản phẩm trực tiếp yêu cầu. Cập nhật TASKS/PROGRESS; báo rõ thay đổi, kiểm chứng và việc còn mở. Nếu thiếu quyết định sản phẩm ảnh hưởng phạm vi thì hỏi, không tự thêm yêu cầu. Tool chưa có contract/test không được mô tả là đã tích hợp.

Thay đổi chia nhỏ theo một mục tiêu mỗi PR, ghi module/task chịu ảnh hưởng. Thiết kế và ranh giới thực thi được review chéo về kiến trúc/bảo mật trước cổng nghiệm thu; Product Team ký cổng theo kế hoạch.
