# Ultron Foundation UI (G1.5b)

Operations console for Ultron security orchestration, implementing Item #51 (Card G1.5b). Built with React 18, TypeScript, and Vite under `ui/`.

## Features & Screens

1. **Campaign Management (`/`, `/campaigns/:id`)**
   - Filterable campaigns table with status chips (CHỜ CHẠY, ĐANG CHẠY, TẠM DỪNG, HOÀN THÀNH, THẤT BẠI, ĐÃ HỦY).
   - Campaign detail view with target seeds (domains, IPs), RoE policy rules, budget, and live counters.
   - Operations controls: Tạm dừng (Pause), Tiếp tục (Resume), Hủy (Cancel) with confirmation modal and idempotent requests.

2. **Job Table & Flow Graph (`/jobs`)**
   - Dual-view toggle between tabular list and React Flow interactive dependency graph.
   - Visualizes job wait reasons (`DEPENDENCY_PENDING`, `DEPENDENCY_FAILED`).
   - Displays retry attempts, generations, and capability references.

3. **Asset Graph & Provenance Panel (`/assets`)**
   - SVG topology graph displaying assets (domains, IPs, services) and relationships.
   - Truncated banner notification when query limits cap result sets (`truncated: true`).
   - Slide-over Provenance Panel displaying tool name, tool version, job ID, observation timestamps, confidence bar, and full unmasked 64-character SHA-256 evidence digests.

4. **Tool Catalogue (`/capabilities`)**
   - Operations catalogue listing all registered execution tools and adapters.
   - Entrypoint functions, health check statuses, and Podman OCI sandbox isolation specifications.

## Design System & UX Standards

- Adheres to `DESIGN.md` tokens: `--bg`, `--surface`, `--ink`, `--muted`, `--line`, `--subtle`, `--accent`, `--success`, `--warning`, `--neutral`.
- Dense operations console layout with high-contrast typography (`IBM Plex Sans` + `JetBrains Mono`).
- Theme support: Light and Dark mode with live switching.
- Vietnamese labels for operational statuses and user interfaces.
- Zero hard-coded mock data in components; data is strictly loaded via the typed API client (`src/api/client.ts`).

## Environment Configuration

Configuration is managed via environment variables (create `.env` in `ui/` if overriding):

| Variable | Description | Default |
|---|---|---|
| `VITE_API_BASE` | Base URL of Ultron backend API | `/api/v2` (or `http://127.0.0.1:8000/api/v2`) |
| `VITE_USE_MOCK` | Enable contract fixture mock handlers (`true`/`false`) | `true` |
| `VITE_BEARER_TOKEN` | Bearer token for authenticated requests | (empty) |

When `VITE_USE_MOCK=false`, requests are sent directly to `VITE_API_BASE` using `fetch` with `Idempotency-Key` and `Authorization: Bearer <token>` headers.

## Getting Started

### Hướng dẫn Chạy thử (Walkthrough Guide)

Dành cho người vận hành khảo sát toàn diện giao diện Ultron Operations Console trên môi trường cục bộ:

#### 1. Khởi động Backend API & Ngăn xếp dịch vụ phụ trợ

```bash
# Khởi động toàn bộ hệ G1 (PostgreSQL 16, Neo4j, SeaweedFS, Temporal, lab DNS và uvicorn M26 API)
make run-local

# Chạy demo G1 để sinh dữ liệu thật (campaigns, jobs, assets, graph, provenance)
make demo-g1
```

#### 2. Cấu hình Operator Token (Xác thực Người vận hành)

1. Khi `make run-local` hoàn tất, token người vận hành (Bearer token) sẽ được in ra terminal (và lưu trong `.local/operator-token`).
2. Mở giao diện Ultron tại `http://localhost:3100`.
3. Nhấp vào nút **Token: Chưa cấu hình** (hoặc **Cấu hình Token**) ở góc trên bên phải thanh tiêu đề.
4. Dán mã Bearer token và nhấn **Lưu Token**. Trạng thái sẽ chuyển sang **Token: Đã cấu hình** (lưu an toàn trong `localStorage`).
*(Hoặc có thể truyền trực tiếp qua biến môi trường `VITE_BEARER_TOKEN` khi khởi chạy lệnh `npm run dev`)*.

#### 3. Khởi chạy Giao diện Frontend

```bash
cd ui
npm install

# Chế độ Real API (kết nối trực tiếp backend http://127.0.0.1:8000/api/v2)
VITE_USE_MOCK=false VITE_API_BASE=http://127.0.0.1:8000/api/v2 \
  VITE_BEARER_TOKEN=$(cat ../.local/operator-token) npm run dev

# Hoặc chế độ Mock Mode (dữ liệu mẫu hợp đồng OpenAPI v2)
VITE_USE_MOCK=true npm run dev
```

#### 4. Khảo sát các màn hình chính

- **Quản lý Chiến dịch (`/campaigns`)**: Xem danh sách chiến dịch, trạng thái, tạo mới, tạm dừng, tiếp tục hoặc hủy chiến dịch.
- **Kế hoạch & Luồng Job (`/jobs`)**: Chuyển đổi giữa bảng Job chi tiết và Đồ thị Luồng tương tác (React Flow).
- **Đồ thị Tri thức & Nguồn gốc Tài sản (`/assets`)**:
  - Khảo sát các đỉnh (Node: tên miền, IP) và cạnh quan hệ (Edge: SUBDOMAIN_OF, RESOLVES_TO).
  - Nhấp vào bất kỳ Node hoặc Edge để mở **Bảng điều khiển Nguồn gốc (Provenance Panel)** ở cạnh phải, hiển thị đầy đủ công cụ trinh sát, phiên bản, Job ID, thời điểm quan sát, độ tin cậy và mã băm bằng chứng SHA-256 không bị che giấu.
  - Chuyển sang **Bảng Tài sản** để xem dưới dạng bảng mật độ cao kèm bộ lọc theo loại tài sản (`domain`, `ip`) và tìm kiếm canonical key.
- **Danh mục Công cụ (`/tools`)**: Xem trạng thái đăng ký M05, phiên bản OCI container sandbox và sức khỏe các công cụ trinh sát.

### Prerequisites

- Node.js >= 20.x
- npm >= 10.x

### Installation

```bash
cd ui
npm install
```

### Development Server

Runs Vite development server on port 3100:

```bash
npm run dev
```

### Build

Compiles TypeScript and bundles production assets into `dist/`:

```bash
npm run build
```

### Verification & Testing

- **Lint**: Run ESLint across all source files:
  ```bash
  npm run lint
  ```
- **Typecheck**: Verify TypeScript types with `--noEmit`:
  ```bash
  npm run typecheck
  ```
- **Unit Tests**: Run Vitest component and API client test suites:
  ```bash
  npm test
  ```
- **OpenAPI Codegen Check**: Verify generated TypeScript schema matches `contracts/api/openapi.v2.yaml`:
  ```bash
  npm run codegen:check
  ```
- **Re-generate Schema**:
  ```bash
  npm run codegen
  ```
- **End-to-End Tests & Screenshots**: Run Playwright suite to verify routes and generate 1440px light and dark mode screenshots:
  ```bash
  npm run test:e2e
  ```
