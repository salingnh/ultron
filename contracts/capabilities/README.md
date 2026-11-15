# Schema đầu vào của capability

Mỗi capability có một schema đầu vào, đặt theo quy ước `schema://<nhóm>/<tên>/v<n>` ↔ `contracts/capabilities/<nhóm>/<tên>.v<n>.schema.json`. Đầu ra luôn là `ResultEnvelope v1`.

Quy tắc chung:

- Tham số có cấu trúc, `additionalProperties: false`. Không có trường "args" hay "command" tự do.
- `targets` là danh sách khóa định danh chuẩn hoặc giá trị thô (domain, IP, CIDR, URL) mà M05 chuẩn hóa trước khi kiểm.
- Trường tốc độ và độ sâu bị kẹp bởi RoE và safety profile của manifest; giá trị agent đưa vượt trần thì M05 trả `POLICY_DENIED`, không tự hạ.

Đã có (mẫu cho S1): `dns/enumerate-subdomains`, `dns/resolve`, `network/discover-services`. Các capability còn lại trong tab Module kết nối OSS mục 2 thêm khi viết adapter tương ứng.
