# AEGIS–Vanguard

Nền tảng AI điều phối tool qua MCP, thực thi trong sandbox, lưu metadata ở PostgreSQL, tri thức asset/quan hệ ở Neo4j và dữ liệu raw trên S3. Giao diện cho thấy kế hoạch, thứ tự job, trạng thái và bằng chứng.

Bắt đầu từ [PRD](PRD.md), [kiến trúc](ARCHITECTURE.md), [thiết kế hiện hành](docs/living/00-tong-quan-he-thong-hop-nhat.md) và [contract](contracts/README.md). [Tiến độ](PROGRESS.md) phân biệt contract đã kiểm với dịch vụ chưa triển khai.

[Chỉ mục tài liệu](docs/README.md) dẫn tới bộ duy nhất ở đường dẫn chính. Tài liệu cũ đã được đối chiếu và xóa; lịch sử đã commit tra qua Git.

## Chạy local (một lệnh)

`make run-local` dựng đủ thứ để mở giao diện với API thật và để chạy demo G1.5c:

1. `make dev-up` — PostgreSQL 16, Neo4j, SeaweedFS, Temporal (idempotent; thêm `LAB=1` để dựng luôn lab DNS có uỷ quyền cho Subfinder/DNSx);
2. `python -m aegis.migrations` — áp chuỗi migration theo `contracts/README.md` (một sổ ghi duy nhất, cùng lệnh với `make migrate`);
3. sinh operator token cho dev, **in một lần**, chỉ lưu sha256 trong `.local/operators.json` (git-ignored);
4. chạy `uvicorn aegis.m26_api.main:app` trên `127.0.0.1:8000` với CORS cho origin của Vite;
5. in base URL, token, và đúng biến môi trường để UI gọi API thật.

```bash
make run-local                  # API + token; in ra lệnh chạy UI
make run-local LAB=1 SEED=1     # kèm lab DNS và một campaign demo qua POST /campaigns
make run-local NEW_TOKEN=1      # xoay token dev và in lại
make stop-local                 # dừng đúng những gì run-local đã bật
```

UI (terminal khác):

```bash
cd ui
VITE_USE_MOCK=false VITE_API_BASE=http://127.0.0.1:8000/api/v2 \
  VITE_BEARER_TOKEN=<token run-local in ra> npm run dev
```

Ghi chú:

- `make stop-local` chỉ dừng API do `run-local` bật và chỉ gỡ dev stack/lab **nếu chính `run-local` đã dựng chúng** (marker trong `.local/`); stack có sẵn từ trước được giữ nguyên — gỡ bằng `make dev-down` / `make lab-down`.
- Token chỉ in một lần vì trên đĩa chỉ có sha256; mất token thì `make run-local NEW_TOKEN=1`.
- `make seed-demo AEGIS_DEV_TOKEN=<token>` tạo thêm campaign demo qua `POST /campaigns` (body lấy từ fixture hợp lệ của contract), in ra `campaign_id`, URL flow và events.
- `AEGIS_CORS_ORIGINS` đổi danh sách origin được phép (mặc định `http://127.0.0.1:5173,http://localhost:5173`); không đặt thì API không mở CORS.
- Log và pid: `.local/api.log`, `.local/api.pid`. Trạng thái stack: `make dev-status`.
