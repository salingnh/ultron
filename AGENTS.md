# AGENTS.md

Hướng dẫn cho mọi AI agent (Claude Code, Codex, Cursor, subagent…) làm việc trong repo này.

**Dự án:** AEGIS–Vanguard, nền tảng **kiểm thử xâm nhập (pentest) chủ động** nội bộ, do AI agent điều phối, chạy trên tài sản tổ chức sở hữu hoặc được ủy quyền. Từ 2026-11-16 (D14) sản phẩm cho phép khai thác và kiểm chứng động tới **tầng tác động T3 (xâm nhập)**, gồm kiểm thử credential (sinh ứng viên mật khẩu và thử đăng nhập). **T4 vẫn cấm mặc định** (PoC không tin cậy từ Internet, C2, persistence, lateral movement, post-exploitation). Chi tiết quyết định ở [docs/s1/00-thanh-phan-va-quyet-dinh.md](docs/s1/00-thanh-phan-va-quyet-dinh.md) mục 7.

## Đọc theo thứ tự này trước khi làm bất cứ việc gì

1. [PRD.md](PRD.md): đang xây gì, cho ai, quyết định đã chốt, phi mục tiêu.
2. [RULES.md](RULES.md): quy tắc viết mã và những điều AI **tuyệt đối không được làm**.
3. [ARCHITECTURE.md](ARCHITECTURE.md): công nghệ, module M01–M28, luồng dữ liệu, cấu trúc thư mục.
4. [TASKS.md](TASKS.md): việc nhỏ theo thứ tự; chỉ làm task của giai đoạn đang mở.
5. [PROGRESS.md](PROGRESS.md): đang ở đâu, cái gì hỏng, bước tiếp theo.
6. [DESIGN.md](DESIGN.md): khi làm giao diện (M26).

Chi tiết đầy đủ nằm ở [docs/living/](docs/README.md). Khi có mâu thuẫn, `docs/living/` thắng các file tóm tắt ở gốc repo.

## Năm điều không bao giờ được quên

1. Agent trong sản phẩm chỉ **đề xuất**; mã policy quyết định. Không shell, không socket, không Cypher tự do.
2. Khai thác và kiểm thử credential (gồm thử đăng nhập) được phép tới **T3**, do mã policy (M05) quyết định và **bắt buộc đối chiếu denylist** (D16); chế độ tự duyệt T3 không có denylist thì không chạy, job T3 ghi người kích hoạt/duyệt. **Vẫn cấm:** T4 (PoC không tin cậy từ Internet, C2, persistence, lateral movement, post-exploitation), tự vá, tự merge PR vào mã mục tiêu.
3. Mọi ghi dữ liệu đi qua Ingestion API (M27); lưu vĩnh viễn, chỉ ghi thêm; mọi thứ ghi nguồn gốc.
4. Finding phải có bằng chứng (SHA-256) và dẫn chứng; mức nghiêm trọng do agent đánh giá kèm lý do.
5. Không chắc thì dừng và hỏi Product Team. Xong việc thì cập nhật TASKS.md và PROGRESS.md.
