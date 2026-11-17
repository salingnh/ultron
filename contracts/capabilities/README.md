# Input schema của tool

Mỗi capability có một schema `schema://<nhóm>/<tên>/v2` ánh xạ tới file trong thư mục này; output là ResultEnvelope v2. M05 ghép inputDefaults từ manifest, validate input, kiểm mục tiêu và giới hạn trước dispatch. Không nhận args/command tự do.

Bộ mẫu: dns/enumerate-subdomains, dns/resolve, network/discover-services. Tool mới phải thêm schema/parser/fixture trước khi đăng ký; không coi danh mục OSS là adapter đã triển khai. Priority/dependency nằm ở request chung, không trộn vào tham số CLI.

Giữ quy tắc trần tham số: rate/depth/concurrency trong input không được vượt cấu hình campaign/manifest đã pin. Vượt trần trả POLICY_DENIED, không tự hạ giá trị rồi chạy một yêu cầu khác. InputDefaults chỉ bù trường chưa có và phải validate lại toàn bộ input cuối trước dispatch.
