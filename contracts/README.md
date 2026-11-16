# contracts/: hợp đồng ghép nối giữa các module (v1, bản nháp S1)

Thư mục này là **nguồn sự thật duy nhất** cho mọi kiểu dữ liệu đi qua ranh giới module. Mã của từng module sinh kiểu từ đây (Pydantic cho Python, `json-schema-to-typescript` cho web), không định nghĩa tay lần hai. Bản giải thích, phân việc và các quyết định chờ duyệt: [docs/s1/00-thanh-phan-va-quyet-dinh.md](../docs/s1/00-thanh-phan-va-quyet-dinh.md).

**Trạng thái:** bản nháp, chờ Product Team duyệt (cổng S1). Sau khi duyệt, mọi thay đổi phải tăng phiên bản.

## Bản đồ file

| Thư mục | Nội dung | Module sở hữu | Bên dùng |
| --- | --- | --- | --- |
| `common/` | ID, khóa định danh chuẩn, TraceContext, Actor, EvidenceRef; lỗi chuẩn 14 mã + `next_action` | M25 (kiến trúc) | Tất cả |
| `campaign/` | Tạo chiến dịch, RoE, chiến dịch (đọc) | M01 | M02, M05, M26, web |
| `capability/` | Manifest `CapabilityProvider`, `ApprovedTask`, ScanJob, yêu cầu gửi job | M05, M06 | adapter, M03, M26 |
| `capabilities/` | Schema đầu vào từng capability (`schema://<nhóm>/<tên>/v<n>`) | tác giả adapter | M05, M03 |
| `ingestion/` | `ResultEnvelope v1`, danh mục predicate | M27 | M06 collector, adapter |
| `events/` | Phong bì sự kiện + 9 payload `.v1` | bên phát từng sự kiện | consumer |
| `mcp/` | Công cụ MCP: capability (đối số, kết quả) và 6 truy vấn đồ thị | M05, M23 | M03 |
| `agent/` | `ContextBundle`, `HypothesisUpdate`, `AgentSessionResult` | M03 | M02 |
| `finding/` | Trạng thái, bảng chuyển trạng thái, đánh giá mức nghiêm trọng, finding (đọc) | M20 | M21, M24, M26 |
| `api/` | OpenAPI 3.1 cho REST `/api/v1` | M26, M27 | web, dịch vụ |
| `db/postgres/` | DDL PostgreSQL (migration 0001) + smoke test | M27 (người giữ migration) | mọi module lõi |
| `graph/` | Mô hình Neo4j, ràng buộc, mẫu Cypher của projector | M23 | M23, M26 |
| `interfaces/` | Interface nội bộ: Adapter SDK, ContainerRunner, EvidenceStore, ModelClient, Ingestion, Temporal | từng module | module gọi |
| `fixtures/` | Mẫu hợp lệ và không hợp lệ | | CI, conformance test |
| `tests/` | `validate_contracts.py` | | CI |

## Kiểm tra

```bash
python3 -I contracts/tests/validate_contracts.py          # schema, $ref, fixture, OpenAPI, kiểm chéo DDL
psql -v ON_ERROR_STOP=1 -f contracts/db/postgres/0001_init.sql -f contracts/db/postgres/tests/smoke.sql
```

Cần Python 3.11+ với `jsonschema>=4.23`, `referencing`, `PyYAML`; PostgreSQL 16.

## Quy tắc đổi hợp đồng

1. **Schema theo version là bất biến (D24, 2026-11-16, khớp RULES.md).** Schema dùng `additionalProperties: false`, nên thêm bất kỳ trường nào cũng phá bên nhận cũ. Vì vậy **mọi thay đổi nội dung schema — kể cả thêm trường tùy chọn hay thêm giá trị enum — đều tạo file version mới** (`.v1` → `.v2`), không sửa file version đang có (trừ sửa lỗi chính tả/`description` không đổi hình dạng dữ liệu). `.v1` và `.v2` chạy song song tới khi mọi bên chuyển xong; ma trận tương thích producer/consumer ghi trong PR. Mọi thay đổi đi qua PR có agent review kiến trúc.
2. Tên module, sự kiện, endpoint, trạng thái finding, mã lỗi giữ đúng đặc tả (RULES mục 2).
3. Thêm predicate, capability, loại cạnh: thêm vào registry tương ứng trong cùng PR với adapter dùng nó.
4. DDL: chỉ thêm migration mới (`0002_...sql`), không sửa migration đã chạy.
