# Hợp đồng MCP giữa agent (M03) và MCP server (M05 + M06 + M23)

Một MCP server duy nhất, transport Streamable HTTP trong mạng điều khiển. Agent là MCP client duy nhất; Web UI không dùng MCP.

## tools/list

Server chỉ trả hai nhóm công cụ, lọc theo chiến dịch (capability_denylist, tầng tác động tối đa của RoE):

| Nhóm | Tên công cụ | inputSchema | outputSchema (structuredContent) |
| --- | --- | --- | --- |
| Capability | đúng capability id, vd `dns.enumerate_subdomains` | `capability-request.v1` với `input` thay bằng schema của capability | `capability-response.v1` |
| Truy vấn đồ thị | `graph.get_asset_neighbors`, `graph.get_recent_observations`, `graph.get_unverified_hypotheses`, `graph.get_package_cve_matches`, `graph.summarize_campaign_delta`, `graph.get_evidence_excerpt` | `graph-queries.v1#/$defs/<name>/properties/input` | `.../output` |

Không có công cụ nào nhận tên binary, dòng lệnh, Cypher hay SQL. Không có `resources` hay `prompts` ở MVP.

## params._meta bắt buộc trên mọi tools/call

| Khóa | Giá trị | Dùng để |
| --- | --- | --- |
| `aegis.io/trace_id` | W3C trace-id 32 hex | Nối trace agent → M05 → M06 → container → M27 |
| `aegis.io/campaign_id`, `aegis.io/session_id` | UUIDv7 | Lọc theo chiến dịch, ghi audit |
| `aegis.io/idempotency_key` | `<session_id>:<step>:<n>` | Activity retry không sinh job mới. M05 lưu khóa và ánh xạ sang `scan_cycle` (cùng khóa → cùng `scan_cycle`); M06 còn chặn thêm bằng `job_fingerprint` |

Thiếu `_meta` thì server trả lỗi JSON-RPC `-32602` kèm `INPUT_INVALID`.

## Luồng một lời gọi capability

1. M05 kiểm `input` theo schema capability (fail-closed `INPUT_INVALID`).
2. Chuẩn hóa mục tiêu (IDNA, dạng IP thay thế), kiểm tầng tác động, tốc độ, khung giờ nếu có, `approval_required_tiers` nếu có. **Với job T3 (D15/D16):** đối chiếu `target_denylist` của RoE và denylist tự bảo vệ cố định trong mã (hạ tầng nền tảng, loopback, `169.254.0.0/16`) — trúng denylist thì từ chối `POLICY_DENIED`; chế độ `t3_approval_mode=operator` cần duyệt tay, `auto` mà denylist rỗng thì fail-closed; ghi người kích hoạt/duyệt vào audit (D19).
3. Ghi `policy_decision` (mục tiêu, lý do `rationale`, `policy_version`) vào audit; từ chối thì phát `policy.denied.v1` và trả `decision=denied`.
4. Chọn provider (sức khỏe, tương thích, xếp hạng) → gọi M06 `submit(ApprovedTask)`; M06 tính `job_fingerprint = sha256(campaign, policy_version, provider, targets, input, profile, scan_cycle)`, trùng thì trả job cũ với `decision=duplicate`. Lần quét mới (scan_cycle mới) không trùng job cũ dù input giống hệt (D21).
5. Trả ngay `job_id`. Agent không chờ; kết quả về sau qua `knowledge.delta.v1` ở chu kỳ kế.

Điểm còn chờ spike T0.5: SDK MCP Python cụ thể, cách đọc `_meta` ở phía server, và đo P95 của bước 1 đến 4.
