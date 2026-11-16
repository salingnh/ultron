# PRD: AEGIS–Vanguard

> Tài liệu yêu cầu sản phẩm rút gọn cho AI agent. Nguồn chuẩn: [docs/living/00-tong-quan-he-thong-hop-nhat.md](docs/living/00-tong-quan-he-thong-hop-nhat.md). Khi file này mâu thuẫn với tài liệu nguồn, tài liệu nguồn thắng.
> Cập nhật theo các quyết định ngày 12 và 13/11/2026.

## 1. Đang xây cái gì

AEGIS–Vanguard là nền tảng **kiểm thử xâm nhập (pentest) chủ động nội bộ** kiêm quản trị bề mặt tấn công, do AI agent điều phối, chạy trên tài sản tổ chức sở hữu hoặc được ủy quyền. Ngoài rà quét và cảnh báo sớm, hệ thống còn **chủ động khai thác và kiểm chứng động tới tầng T3 (xâm nhập)** — gồm kiểm thử credential (sinh ứng viên mật khẩu và thử đăng nhập) — để xác nhận lỗ hổng thật sự khai thác được (quyết định D14, 2026-11-16). Hệ thống gom các công cụ OSS rời rạc thành một vòng lặp liên tục:

khám phá tài sản → làm giàu tri thức → đối chiếu lỗ hổng → kiểm chứng động (tới T3) → cảnh báo → theo dõi khắc phục.

Một câu: **biết sớm tài sản nào đang phơi nhiễm, lỗ hổng nào thật sự khai thác được, kèm bằng chứng.**

## 2. Dành cho ai

Hệ thống nội bộ, single-tenant, chưa có đăng nhập ở MVP. Năm nhóm người dùng dùng chung một đồ thị tri thức:

| Người dùng | Việc họ làm | Giá trị |
| --- | --- | --- |
| Security Analyst, SOC | Tạo chiến dịch, nhận cảnh báo finding mới, truy nguyên bằng chứng | Phát hiện sớm, ít nhiễu |
| AppSec | Đi từ repo, image, SBOM tới CVE; theo dõi fix và tái phát | Rút ngắn xác minh và khắc phục |
| Hạ tầng, SRE | Đối chiếu host, IP, dịch vụ, cấu hình; đặt cửa sổ quét | Giảm rủi ro gián đoạn |
| Security Architect | Xem bề mặt tấn công và quan hệ có nguy cơ | Quyết định dựa trên đồ thị |
| Platform Engineer | Tích hợp scanner OSS mới, giám sát workload | Mở rộng bằng hợp đồng ổn định |

Kịch bản điển hình: một CVE mới vào danh mục KEV → hệ thống đối chiếu lại với package đã biết trong đồ thị → xác định tài sản đang phơi nhiễm → gửi tin Telegram cho SOC kèm bằng chứng, **không cần chờ lần quét kế tiếp**.

## 3. Đầu vào và đầu ra

- **Đầu vào chiến dịch:** IP, domain, URL, email, từ khóa (GĐ3 thêm repo, tài khoản cloud, cluster). Kèm quy tắc tham chiến (RoE): scan profile, số job song song, khung giờ cấm, thời lượng tối đa.
- **Đầu ra:** đồ thị tài sản (domain, IP, dịch vụ, endpoint, image, repo, package), danh sách finding có bằng chứng, mức nghiêm trọng do agent đánh giá kèm lý do, cảnh báo Telegram, báo cáo JSON (GĐ2), SARIF và HTML (GĐ4).

## 4. Mục tiêu MVP (cổng G2, khoảng tuần 9 đến 13)

1. Khám phá tài sản theo black-box, gray-box, white-box, xuất phát từ mục tiêu khai báo, ghi nguồn gốc cho mọi tài sản tìm thêm.
2. Chiến dịch chạy bền tới 7 ngày, có tạm dừng, tiếp tục, retry an toàn.
3. Agent harness lập kế hoạch nhiều vòng, có checkpoint và ngân sách.
4. Đồ thị tri thức và kho bằng chứng truy vết được từ domain tới finding.
5. Đối chiếu lỗ hổng với CVE, OSV, KEV, EPSS; đánh giá lại khi feed đổi; cảnh báo sớm qua Telegram.
6. Giao diện web nội bộ cho thấy agent đã làm gì, lỗi ở đâu, còn gì chưa làm.

## 5. Không làm (phi mục tiêu)

- Tầng T4 (cấm mặc định): C2, persistence, lateral movement, post-exploitation, sub-agent red-team (Strix, Decepticon).
- Chạy mã PoC **không tin cậy** lấy từ Internet (T4). M19 chỉ lập chỉ mục metadata PoC; khai thác/kiểm chứng động chỉ dùng năng lực T3 do nền tảng kiểm soát.
- Tự áp bản vá hay tự merge vào production. Chỉ gợi ý khắc phục.
- Multi-tenant, SSO, RBAC (để sẵn chỗ cắm, chưa làm).
- Fork hay viết lại scanner OSS.

## 6. Quyết định đã chốt (không được tự ý đổi)

| Chủ đề | Quyết định |
| --- | --- |
| Định vị (D14, 2026-11-16) | **Pentest chủ động** nội bộ, do agent điều phối. Khai thác và kiểm chứng động tới T3; T4 cấm mặc định |
| Tầng tác động (D15) | MVP dùng T0–T3. T3 (xâm nhập) duyệt theo cấu hình: operator duyệt tay, hoặc policy/agent tự duyệt **bắt buộc đối chiếu denylist**. T4 cấm mặc định |
| Denylist (D16) | **Bắt buộc, cưỡng chế bằng mã**: hạ tầng của chính nền tảng và các dải cấu hình. T3 tự duyệt không có denylist → từ chối chạy |
| Agent | Có trong MVP từ GĐ1. Agent chỉ **đề xuất**; mã policy quyết định |
| Phạm vi quét | **Không giới hạn** phạm vi (gồm cả T3). Tài sản quét được coi là thuộc tổ chức. Bù lại: mọi cạnh ghi nguồn gốc, mọi job có audit, job T3 ghi người kích hoạt/duyệt (D19) |
| Secret (D17) | Lưu và hiển thị **dạng rõ** kèm fingerprint; không che ở UI, báo cáo, prompt, cảnh báo. Có kiểm thử credential: sinh ứng viên mật khẩu và thử đăng nhập (TruffleHog bật xác minh) |
| Mức nghiêm trọng | AI agent đánh giá, kèm lý do, nguồn, điểm chưa chắc. **Không dùng công thức trọng số** |
| Chất lượng finding | **Không đo precision/recall**, không golden dataset. Mỗi finding phải có bằng chứng xác nhận và dẫn chứng |
| Lưu trữ | **Vĩnh viễn**, không xóa, không ghi đè; lịch sử theo từng lần chạy (`FindingRun`) |
| Hạ tầng chạy công cụ | Mỗi lần gọi công cụ = một container **Podman** trên một máy. Kubernetes để sau |
| Giao tiếp agent–công cụ | Qua **MCP** |
| LLM | `ModelClient` tự dựng, hai driver chuẩn OpenAI và Anthropic. Không dùng LiteLLM |
| Cảnh báo | Bot Telegram, template và group id cấu hình được; ngưỡng gửi chốt sau |
| OSS bỏ | Amass, Flowsint, LiteLLM, Semgrep CE (thay bằng Opengrep). REA là tùy chọn |

## 7. KPI nghiệm thu

| Chỉ số | Mục tiêu |
| --- | --- |
| Job chạy không ghi nguồn gốc mục tiêu | 0 |
| Job chủ động gắn `scope_id` và `policy_version` | 100% |
| Độ bền chiến dịch | 7 ngày, từ 10.000 bước điều phối, không mất trạng thái |
| Job trùng cho cùng idempotency key | 0 |
| Finding có bằng chứng hoặc trạng thái unsupported | 100% |
| Thời gian tích hợp một CLI scanner đơn giản | ≤ 2 ngày công |
| Độ trễ tình báo | KEV < 2 giờ, EPSS < 24 giờ |
| Job lỗi có phân loại lỗi và bước tiếp theo | 100% |

## 8. Đọc thêm

- Đặc tả 28 module: [docs/living/dac-ta-ky-thuat/](docs/living/dac-ta-ky-thuat/README.md)
- Kế hoạch theo giai đoạn: [docs/living/02-ke-hoach-trien-khai.md](docs/living/02-ke-hoach-trien-khai.md)
- Đánh giá OSS: [docs/living/03-danh-gia-oss.md](docs/living/03-danh-gia-oss.md)
