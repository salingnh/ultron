# Ultron Operations UI (G1.5b–G1.6)

Operations console for Ultron security orchestration, implementing Item #51 (Card G1.5b). Built with React 18, TypeScript, and Vite under `ui/`.

## Features & Screens

1. **Campaign Management (`/`, `/campaigns/new`, `/campaigns/:id`)**
   - Filterable campaigns table (CREATED, RUNNING, WAITING, PAUSED, COMPLETED, FAILED, CANCELLED) with budget (`budget.limits/used/remaining`) and counters (`counters.jobs_by_status`, `counters.assets_by_kind`) from the API; absent fields are shown as absent, never fabricated.
   - Create form (`/campaigns/new`, `POST /campaigns` + `Idempotency-Key`): targets, RoE (`network_profile` lab|internet, rate/connection caps, budget), structured authorization (owner, reference, date, authorized suffixes) required for internet, confirmation before an internet campaign. `max_agent_sessions` is omitted unless the operator sets it (API default); the form shows the minimum for the chosen capabilities.
   - Campaign detail: target seeds, RoE policy panel with snapshot adoption (`POST /campaigns/{id}/policy`, non-terminal campaigns only), budget/counter panel, links to jobs, activity and asset graph.
   - Operations controls: Tạm dừng (Pause), Tiếp tục (Resume), Hủy (Cancel) with confirmation modal and idempotent requests.
   - First-run help when no operator token is configured; the token modal closes on Escape and traps focus.

2. **Job Table & Flow Graph (`/jobs`)**
   - Dual-view toggle between tabular list and React Flow interactive dependency graph.
   - Visualizes job wait reasons (`DEPENDENCY_PENDING`, `DEPENDENCY_FAILED`).
   - Displays retry attempts, generations, and capability references.

3. **Asset Graph & Provenance Panel (`/assets`)**
   - SVG topology graph displaying assets (domains, IPs, services) and relationships.
   - Truncated banner notification when query limits cap result sets (`truncated: true`).
   - Slide-over Provenance Panel displaying tool name, tool version, job ID, observation timestamps, confidence bar, and full unmasked 64-character SHA-256 evidence digests.

4. **Tool Catalogue (`/tools`)**
   - Operations catalogue listing all registered execution tools and adapters.
   - Entrypoint functions, health check statuses, and Podman OCI sandbox isolation specifications.

5. **Agent Activity (`/activity`)**
   - `GET /campaigns/{campaign_id}/activity`: agent sessions (start/finish, stop reason), policy decisions (approved/denied, reason code, targets, linked job), blockers, budget per session, idle cycles; kind/decision filters, keyset pagination with a truncated banner.
   - Live refresh: SSE resumes from the last known event (`Last-Event-ID`), subscribes only to event types the screen needs, and coalesces refetches (O(1) requests when opening a campaign).

Errors show a short operator message (code, HTTP status, path, next action) with technical details collapsed; an error belongs to the view that failed (a graph error does not cover the service/asset tables).

### Discovery & CVE (G1.6)

- **Đồ thị tài sản:** IP → Service (port/protocol) → Application/công nghệ (product, version, CPE) → Vulnerability (CVE, CVSS, KEV, EPSS); cạnh có nhãn.
- **Bảng dịch vụ** (`ServiceTable`): host, port, protocol, product, version, CPE, số ứng viên CVE (số KEV).
- **Panel CVE** (`VulnerabilityPanel`): luôn ghi "Ứng viên (chưa xác minh)" — kết quả khớp CPE, không phải finding. Bấm dòng dịch vụ hoặc badge ứng viên/KEV đều mở panel.
- Đồ thị chỉ có node tài sản và cạnh tài sản↔tài sản (`GET /assets/{id}/graph`); ứng viên CVE đọc qua `GET /assets/{id}/vulnerabilities`.
- Ảnh chụp review chạy trên API thật, theme sáng và tối, 1440px và 390px.

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
| `VITE_API_BASE` | Base URL of Ultron backend API | `http://127.0.0.1:8000/api/v2` |
| `VITE_USE_MOCK` | Enable contract fixture mock handlers (`true`/`false`) | `true` |
| `VITE_BEARER_TOKEN` | Bearer token for authenticated requests | (empty) |

When `VITE_USE_MOCK=false`, requests are sent directly to `VITE_API_BASE` using `fetch` with `Idempotency-Key` and `Authorization: Bearer <token>` headers.

## Getting Started

### Hướng dẫn Chạy thử (Walkthrough Guide)

Dành cho người vận hành khảo sát toàn diện giao diện Ultron Operations Console trên môi trường cục bộ:

#### 1. Khởi động Backend API & Ngăn xếp dịch vụ phụ trợ

```bash
# Khởi động PostgreSQL 16, Neo4j 5.26, SeaweedFS, Temporal và uvicorn M26 API
make run-local

# (Tùy chọn) Dữ liệu mẫu chạy thật trên lab
make demo-g1        # chuỗi Subfinder → DNSx
make demo-g16c      # chuỗi port → service/version → ứng viên CVE (KEV/EPSS)
```

#### 2. Cấu hình Operator Token (Xác thực Người vận hành)

1. Khi `make run-local` hoàn tất, token người vận hành (Bearer token) sẽ được in ra terminal.
2. Mở giao diện Ultron tại `http://localhost:5173`.
3. Nhấp vào nút **Token: Chưa cấu hình** (hoặc **Cấu hình Token**) ở góc trên bên phải thanh tiêu đề.
4. Dán mã Bearer token và nhấn **Lưu Token**. Trạng thái sẽ chuyển sang **Token: Đã cấu hình** (lưu an toàn trong `localStorage`).

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
- **End-to-End Tests & Screenshots**: Run Playwright suite to verify routes (incl. `/campaigns/new`, `/activity`) and generate screenshots at 1440px and 390px in light and dark mode (mock by default; `VITE_USE_MOCK=false` + a real backend for real-API shots):
  ```bash
  npm run test:e2e
  ```
