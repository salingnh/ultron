# Ultron Foundation UI (G1.5b)

Operations console for Ultron security orchestration, implementing Item #51 (Card G1.5b). Built with React 18, TypeScript, and Vite under `ui/`.

## Features & Screens

1. **Campaign Management (`/`, `/campaigns/:id`)**
   - Filterable campaigns table with status chips (CHỜ CHẠY, ĐANG CHẠY, TẠM DỪNG, HOÀN THÀNH, THẤT BẠI, ĐÃ HỦY).
   - Campaign detail view with target seeds (domains, IPs), RoE policy rules, budget, and live counters.
   - Operations controls: Tạm dừng (Pause), Tiếp tục (Resume), Hủy (Cancel) with confirmation modal and idempotent requests.

2. **Job Table & Flow Graph (`/jobs`)**
   - Dual-view toggle between tabular list and React Flow interactive dependency graph.
   - Visualizes job wait reasons (`DEPENDENCY_PENDING`, `WINDOW_CLOSED`, `DEPENDENCY_FAILED`) and dispatch block reasons (`LEGACY_POLICY_V1`, `LEGACY_MISSING_TARGET_REFS`).
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
| `VITE_API_BASE` | Base URL of Ultron backend API | `http://localhost:8000` |
| `VITE_USE_MOCK` | Enable contract fixture mock handlers (`true`/`false`) | `true` |
| `VITE_BEARER_TOKEN` | Bearer token for authenticated requests | (empty) |

When `VITE_USE_MOCK=false`, requests are sent directly to `VITE_API_BASE` using `fetch` with `Idempotency-Key` and `Authorization: Bearer <token>` headers.

## Getting Started

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
