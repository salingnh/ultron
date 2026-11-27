# AEGIS–Vanguard

Nền tảng AI điều phối tool qua MCP, thực thi trong sandbox, lưu metadata ở PostgreSQL, tri thức asset/quan hệ ở Neo4j và dữ liệu raw trên S3. Giao diện cho thấy kế hoạch, thứ tự job, trạng thái và bằng chứng.

Bắt đầu từ [PRD](PRD.md), [kiến trúc](ARCHITECTURE.md), [thiết kế hiện hành](docs/living/00-tong-quan-he-thong-hop-nhat.md) và [contract](contracts/README.md). [Tiến độ](PROGRESS.md) phân biệt contract đã kiểm với dịch vụ chưa triển khai.

[Chỉ mục tài liệu](docs/README.md) dẫn tới bộ duy nhất ở đường dẫn chính. Tài liệu cũ đã được đối chiếu và xóa; lịch sử đã commit tra qua Git.

## Chạy local (một lệnh)

`make run-local` dựng **toàn bộ** hệ G1 trên máy này và in ra đúng những gì cần để mở giao diện hoặc chạy demo:

1. `make dev-up` — PostgreSQL 16, Neo4j, SeaweedFS, Temporal (idempotent); `LAB=1` (mặc định) dựng luôn lab DNS có uỷ quyền cho Subfinder/DNSx;
2. `python -m aegis.migrations` — áp chuỗi migration theo `contracts/README.md`;
3. sinh operator token (in **một lần**, chỉ lưu sha256 trong `.local/operators.json`) và internal service token cho endpoint ingestion (`.local/service-token`); cả hai để trong `.local/run-local.env` (mode 600) cho các script demo;
4. `uvicorn aegis.m26_api.main:app` — API (campaigns, jobs, flow, events, assets, `POST /ingestion/results`);
5. `WORKERS=1` (mặc định): `uvicorn aegis.m05_registry.mcp.main:app` (MCP), M02 worker + dispatcher, M23 projector loop, M06 runner loop (`python -m aegis.m06_runner`);
6. in URL, token và biến môi trường cho UI.

```bash
make run-local                  # toàn bộ hệ, có lab DNS
make run-local WORKERS=0        # chỉ API + MCP (làm UI, không chạy job)
make llm-smoke                  # một lần gọi LLM thật bằng key trong .env (không chạy trong CI; tên biến ở .env.example)
make run-local LAB=0            # không dựng lab (job DNS không có endpoint để chạy)
make run-local NEW_TOKEN=1      # xoay operator token và in lại
make stop-local                 # dừng đúng những process/stack mà run-local đã bật
```

Mọi thứ `run-local` bật được ghi trong `.local/` (`<tên>.pid`, `<tên>.log`) và `stop-local` chỉ dừng đúng những process đó; dev stack/lab chỉ bị gỡ khi chính `run-local` đã dựng chúng (marker `.local/stack.started`, `.local/lab.started`). Stack có sẵn từ trước được giữ nguyên — gỡ bằng `make dev-down` / `make lab-down`.

UI (terminal khác):

```bash
cd ui
npm ci
VITE_USE_MOCK=false VITE_API_BASE=http://127.0.0.1:8000/api/v2 \
  VITE_BEARER_TOKEN=$(cat ../.local/operator-token) npm run dev
```

## LLM gateway (bạn quản lý endpoint, key nằm trong .env)

ultron chỉ gọi model qua LLM gateway của bạn: một LiteLLM proxy chạy local (`deploy/llm-gateway`,
pin digest, lõi MIT) tự chuyển sang endpoint kế tiếp khi một endpoint hết quota (429), lỗi 5xx hoặc
timeout, và cho endpoint lỗi nghỉ `cooldown_time` giây. Bạn sửa đúng hai chỗ:

- `~/.config/ultron/llm-gateway/config.yaml` (ngoài checkout): danh sách endpoint + thứ tự ưu tiên;
  key chỉ ghi dạng `os.environ/LLM_KEY_A`.
- `.env` của checkout (mode 600): mọi key và setting, gồm `AEGIS_MODEL_API_KEY` - cũng là master key
  của gateway - và `LLM_KEY_A/B/C...`.

Những giá trị không được đổi (không log nội dung request/response, không retry, cooldown, `/metrics`
sau master key, không spend log) nằm ở `deploy/llm-gateway/base.yaml`; `make llm-gateway-up` trộn file
đó với `config.yaml` của bạn, và từ chối nếu bạn đặt lại một trong các khoá đó (không bỏ qua im lặng).

```bash
mkdir -p ~/.config/ultron/llm-gateway
cp deploy/llm-gateway/config.example.yaml ~/.config/ultron/llm-gateway/config.yaml
$EDITOR ~/.config/ultron/llm-gateway/config.yaml   # endpoint + thứ tự; không có key ở đây
cp .env.example .env && chmod 600 .env             # nếu chưa có: nơi DUY NHẤT giữ key
$EDITOR .env                                       # LLM_KEY_A=..., AEGIS_MODEL_NAME=<group>
make llm-gateway-up        # trộn base.yaml + config.yaml, kiểm tra, rồi chạy chỉ trên 127.0.0.1
make llm-gateway-status    # từng endpoint: healthy / cooling down / no traffic yet
make llm-gateway-reload    # áp cấu hình đã sửa (endpoint hoặc key); ultron vẫn chạy
make llm-gateway-down      # gỡ gateway của checkout này
make llm-gateway-test      # image đã pin với 2 endpoint giả (một cái hết quota), không cần key
```

`AEGIS_MODEL_API_KEY` để trống thì `make llm-gateway-up` tự sinh một key và ghi vào `.env` (mode 600,
không in ra); ultron gửi đúng key đó nên không có key thứ hai phải đồng bộ. Gateway chỉ nhận những
biến mà `config.yaml` tham chiếu, không bao giờ cả file `.env`.

Trỏ ultron vào gateway trong `.env` (xem `.env.example`): `AEGIS_SESSION_LIVE_MODEL=1`, `AEGIS_MODEL_GATEWAY=1`, `AEGIS_MODEL_BASE_URL=http://127.0.0.1:4000/v1`, `AEGIS_MODEL_NAME=aegis-smart` (tên nhóm định tuyến, không phải model upstream), `AEGIS_MODEL_API_KEY=<key trong .env, cũng là master key của gateway>`, `AEGIS_MODEL_PROVIDER=openai|anthropic` (upstream chỉ có chat-completions thì dùng `openai`), cùng hai giá (chỉ dùng khi gateway không báo chi phí). `make llm-smoke` gửi một lời gọi thật qua gateway. Xoay vòng chỉ nằm ở gateway: `AEGIS_MODEL_GATEWAY=1` từ chối fallback trong app. Nội dung request/response không bao giờ bị log; metadata (model, endpoint, status, token, chi phí, độ trễ) nằm ở `aegis.model_usage` và `/metrics` của proxy (sau master key).

## Chạy G1 một mình

Ba lệnh dưới đây là bằng chứng của cổng G1 (`docs/living/02-ke-hoach-trien-khai.md` dòng 28 và 33). Chúng cần một checkout sạch, rootless Podman và image đã có trên máy (`make lab-up` dùng image Subfinder/DNSx đã pin).

Nếu máy đã có stack `aegis-dev` từ bản trước khi gộp migration (chuỗi 0001–0017): chạy `make dev-reset` trước (xóa volume của `aegis-dev` rồi dựng lại bằng `0001_baseline.sql`); DB theo chuỗi cũ không được nâng cấp tại chỗ.

```bash
make run-local      # 1. dựng toàn bộ hệ + lab, in token; để nguyên terminal này
make demo-g1        # 2. campaign thật -> agent/MCP -> Subfinder -> DNSx -> raw/metadata/graph
make demo-g16c      #    G1.6: ... -> Naabu -> fingerprintx/httpx -> ứng viên CVE (KEV/EPSS) trên lab
make demo-recovery  # 3. SIGKILL runner giữa job: chạy tiếp, không trùng container/job/envelope
make soak-start     # 4. soak rút gọn 24 h (SOAK_HOURS=... để đổi), chạy nền
```

Ứng viên CVE thật cần intel: trên stack mới chạy `make intel-sync` (NVD đủ mọi năm lần đầu ~30 phút, sau đó tăng dần; KEV từ `cisagov/kev-data`; EPSS khi đặt `AEGIS_EPSS_SOURCE`) trước `make vulnlab-test PROFILE=lab`. Lệnh thoát khác 0 nghĩa là intel chưa mới, không có nguồn dự phòng. Demo và CI dùng fixture đã commit, không gọi mạng.

Tạo thêm một campaign mẫu qua API: `make seed-demo AEGIS_DEV_TOKEN=$(cat .local/operator-token)`. Campaign này dùng target của fixture contract (`internal.example`, `10.20.0.0/24`), lab không trả lời các tên đó, nên nó chạy một lượt enumerate, không có tên mới và tự tạm dừng với lý do "no progress for 3 session(s)" — đó là hành vi đúng. Campaign chạy trọn vòng trên lab là `make demo-g1`.

### `make demo-g1` — bằng chứng cổng G1

Tạo campaign qua `POST /campaigns` (seed duy nhất `lab.aegis.test`, policy lab, model giả theo script), rồi in từng mục bằng chứng:

| Mục | Nội dung phải thấy |
| --- | --- |
| 3. job history | `dns.enumerate_subdomains` (subfinder) và `dns.resolve` (dnsx) đều `SUCCEEDED`, kèm chuỗi `QUEUED→VALIDATING→DISPATCHED→RUNNING→COLLECTING→SUCCEEDED` |
| 4. dependency | đúng một cạnh: `dns.resolve depends_on dns.enumerate_subdomains` |
| 5. raw + ingestion | mỗi job một evidence object (`s3://evidence/...`, sha256, `verified`), mỗi job một envelope `accepted`, `quarantined 0` |
| 6. metadata + graph | asset/observation/relationship trong PostgreSQL và số node/edge trong Neo4j (≥ 4 asset, ≥ 6 observation, ≥ 3 quan hệ) |
| 7. provenance | `seed → asset` (`asset_provenance`, kèm provider version) và `observation → evidence` (sha256) |
| 8. audit | `audit_log` theo `action` + actor (`operator`/`module`/`agent`) |
| 9. network isolation | probe container trên cùng network lab: `internal true`, không published port, `1.1.1.1:443` và control plane **không** kết nối được |
| 10. no duplicates | job theo `job_fingerprint`, asset theo `canonical_key`, observation, outbox `(type, dedup_key)`, `ingestion_inbox.dedup_key`, evidence — tất cả 0 nhóm trùng |
| 11. events + flow | event đã publish (nguồn của SSE) gồm `job.completed.v2`; flow read model có node/edge |

Kết thúc bằng `PASS - every G1 evidence check passed` và một file `.local/demo/g1-<UTC>.json` chứa toàn bộ bằng chứng (job, evidence, counts, provenance, audit, isolation, duplicates, event, flow). Thời gian chạy khoảng 30–60 s; `DEMO_TIMEOUT_SECONDS` đổi hạn chờ, lỗi in ra kèm đường dẫn log.

Lưới an toàn: campaign chỉ dùng zone lab `lab.aegis.test`; job container chạy trên network `aegis-lab-lab` (internal, không gateway) theo `deploy/lab/runner-profile.json`, nên nó chỉ tới được lab và không có đường ra ngoài.

### `make demo-recovery` — tắt worker giữa job rồi tiếp tục, không trùng

1. tạo campaign, đợi job đầu tiên `RUNNING` **và** container của nó đang chạy;
2. `kill -9` runner (M06) — tool vẫn chạy trong container, job vẫn `RUNNING`, chưa có envelope;
3. bật lại runner trên cùng base directory (đúng lệnh `run-local` dùng);
4. yêu cầu: log có `resume: job ... adopting the container this runner already started`, job `SUCCEEDED`, **một** container (đúng id trước khi kill), **một** envelope, không trùng job/fingerprint/asset/outbox.

Bằng chứng: `.local/demo/recovery-<UTC>.json`.

### `make soak-start` — soak rút gọn 24–48 h

Chạy nền, mỗi `SOAK_INTERVAL_SECONDS` (mặc định 180 s) tạo một campaign lab, giữ tối đa `SOAK_MAX_ACTIVE` (mặc định 2) campaign mở; campaign quá `SOAK_CAMPAIGN_TIMEOUT_SECONDS` (mặc định 900 s) bị **cancel qua API** và ghi là lỗi. Mỗi `SOAK_REPORT_SECONDS` (mặc định 300 s) ghi một dòng JSON vào `.local/soak/report.jsonl` và bản đọc được vào `.local/soak/report.txt`: campaign/job theo trạng thái, lỗi tool/ingestion (mã lỗi đầu tiên), dung lượng evidence, số asset/observation/relationship, độ trễ projection (outbox head vs cursor), **các truy vấn chống trùng**, RSS của từng process và bộ nhớ container.

```bash
make soak-start                      # 24 h, report .local/soak/report.txt
SOAK_HOURS=1 make soak-start         # 1 h (thử nhanh)
SOAK_HOURS=48 make soak-start        # bản đầy đủ của khung 24–48 h
make soak-stop                       # dừng, ghi report cuối
cat .local/soak/report.txt
```

Dừng hết: `make stop-local` (hoặc `make soak-stop` trước nếu muốn dừng soak sạch).

### Ghi chú

- Log: `.local/api.log`, `.local/mcp.log`, `.local/m02-worker.log`, `.local/m02-dispatcher.log`, `.local/m23.log`, `.local/m06.log`; trạng thái stack: `make dev-status`; lab: `make lab-status`.
- Token chỉ in một lần vì trên đĩa chỉ có sha256; mất token thì `make run-local NEW_TOKEN=1`. `.local/operator-token` và `.local/service-token` là tiện ích dev (mode 600, đã git-ignore) để script demo dùng.
- `make seed-demo AEGIS_DEV_TOKEN=<token>` tạo thêm một campaign demo qua `POST /campaigns`.
- `AEGIS_CORS_ORIGINS` đổi danh sách origin được phép (mặc định `http://127.0.0.1:5173,http://localhost:5173`).
- M06 chạy image đã pin theo digest; runner không pull. `make run-local` dựng broker image (`deploy/broker/Containerfile`), đặt `AEGIS_M06_INTERNET_PROFILE`, `AEGIS_L3_HOOK` và tạo uplink riêng `aegis-uplink`; job internet phân giải DNS qua broker, không cần cấu hình thêm. Campaign demo/CI khai `network_profile: lab`; campaign của người vận hành mặc định `internet`. Chạy thử internet (chỉ trên tài sản bạn sở hữu, thụ động trước): `make internet-smoke DOMAIN=<domain>`. Campaign internet bắt buộc có `authorization` có cấu trúc (owner, reference, date, `authorized_suffixes`) và trần tốc độ/kết nối; dải IP nội bộ luôn bị chặn trừ CIDR seed khai rõ; zone có wildcard DNS (vd icomm.vn) chỉ quét chủ động được qua seed IP. Luật đầy đủ: `docs/living/dac-ta-ky-thuat/02-nen-tang.md` §Profile mạng của job.
- Một máy chỉ có một lab (subnet lab cố định `10.114.53.0/24`): checkout sau dùng chung lab đang chạy; muốn lab riêng phải gỡ lab cũ trước.
- Mỗi checkout chạy stack riêng: đặt `AEGIS_DEV_PROJECT`/`AEGIS_LAB_PROJECT`/`AEGIS_VULNLAB_PROJECT` và port riêng trong `.env`; `dev-up`/`dev-down`/`lab-down`/`vulnlab-*` từ chối đụng stack do checkout khác tạo.
- `make ci-local` và `make ci-python` là đúng hai job CI; `make demo-g15a` là bằng chứng flow/SSE riêng của G1.5a.
