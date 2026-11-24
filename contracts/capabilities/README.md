# Input schema của tool

Mỗi capability có một schema `schema://<nhóm>/<tên>/v2` ánh xạ tới file trong thư mục này; output là ResultEnvelope v2. M05 ghép inputDefaults từ manifest, validate input, kiểm mục tiêu và giới hạn trước dispatch. Không nhận args/command tự do.

Bộ mẫu: dns/enumerate-subdomains, dns/resolve, network/discover-services. Tool mới phải thêm schema/parser/fixture trước khi đăng ký; không coi danh mục OSS là adapter đã triển khai. Priority/dependency nằm ở request chung, không trộn vào tham số CLI.

Giữ quy tắc trần tham số: rate/depth/concurrency trong input không được vượt cấu hình campaign/manifest đã pin. Vượt trần trả POLICY_DENIED, không tự hạ giá trị rồi chạy một yêu cầu khác. InputDefaults chỉ bù trường chưa có và phải validate lại toàn bộ input cuối trước dispatch.

## Hai cách viết tên capability (không suy ra nhau)

Cùng một capability xuất hiện dưới hai dạng, cả hai đều cố ý (G0.2 finding 8 — envelope nháp đầu tiên bị từ chối vì dùng lẫn):

| Dạng | Ví dụ | Dùng ở | Kiểu |
| --- | --- | --- | --- |
| `CapabilityId` | `dns.enumerate_subdomains` | `ApprovedTask.capability`, `job.capability`, ResultEnvelope `capability`, `params._meta`/tên MCP tool, `policy_denied`, `acceptableTargetKinds` của campaign | [ids.v2 `CapabilityId`](../common/ids.v2.schema.json): `<nhóm>.<động_từ_danh_từ>`, chấm, gạch dưới |
| `schema://` ref | `schema://dns/enumerate-subdomains/v2` | `provider-manifest.spec.inputSchemaRef` (và `outputSchemaRef`) | `<nhóm>/<tên>/v<n>`, gạch chéo, gạch nối |

Không chuyển dạng này sang dạng kia bằng cách thay ký tự: `enumerate_subdomains` ≠ `enumerate-subdomains` theo quy tắc máy móc, và tên riêng có thể khác nhau. Muốn biết schema của một capability thì đọc manifest của provider (Regexp/Pattern không phải nguồn duy nhất). Envelope, task, job và event luôn dùng `CapabilityId`; chỉ manifest dùng `schema://`. Validator `validate_contracts.py` kiểm `inputSchemaRef` phân giải được tới file schema, và test conformance kiểm manifest đã pin phục vụ đúng `capability` của task.

`network/discover-services` chưa có provider/manifest: schema tồn tại không có nghĩa capability đã đăng ký.

## Chuỗi DNS đầu tiên: dns.enumerate_subdomains và dns.resolve

Hai capability này là chuỗi G1 (Subfinder v2.17.0, DNSx v1.2.2 — bảng pin ở [04 §Chọn provider](../../docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md#chọn-provider-và-quản-lý-phiên-bản)). Chúng khóa bốn điểm trước khi viết adapter:

**1. Kiểu target.** `input.targets` là giá trị thô: domain ASCII/IDNA đã chuẩn hóa ([`DomainTarget`](../common/ids.v2.schema.json)), tùy chọn tiền tố `dns:`. M05 phân giải từng giá trị thành `TargetRef` ([`ids.v2`](../common/ids.v2.schema.json)) cho `ApprovedTask.targets`/job: khớp seed của `campaign_target` cùng scope → `{seed_id}` (giữ nguyên kind/raw_value, keyword/CIDR không thành asset giả), khớp asset đã biết → `{canonical_key}`, còn lại là INPUT_INVALID. `task.targets` phải bằng đúng phân giải đó — không mở rộng, không đổi seed thành khóa chuẩn, không thêm seed thứ hai. Provider chỉ nhận kind trong `spec.acceptsTargetKinds` (`domain` với hai tool DNS), nên task trỏ seed CIDR/keyword bị từ chối trước khi chạy. Collector chép nguyên `task.targets` vào `provenance.seed_targets`.

**2. Trần tham số.** Input có tham số điều khiển tài nguyên; trần đến từ manifest đã pin và snapshot campaign, không phải từ input:

| Trường input | Tool | Trần / nguồn |
| --- | --- | --- |
| `concurrency` | Subfinder `-t`, DNSx `-t` | `spec.budget.maxConcurrency` của manifest đã pin |
| `rate_limit` | Subfinder `-rl` (request/giây tới nguồn thụ động) | `rate_limits.requests_per_second_per_host` của snapshot `policy_version` |
| `max_results` (chỉ enumerate) | adapter cắt sau thu thập | giới hạn của chính schema; vượt là INPUT_INVALID |
| `timeoutSeconds`, `cpu`, `memoryMb`, `maxOutputMb` | mọi tool | `spec.budget` của manifest; M06 cưỡng chế trong ContainerSpec |

Vượt trần là POLICY_DENIED kèm giá trị vi phạm; adapter không tự hạ xuống rồi chạy một yêu cầu khác. Snapshot thiếu trường trần (ví dụ không có `requests_per_second_per_host` mà input lại đặt `rate_limit`) cũng là POLICY_DENIED: không cưỡng chế được thì không chạy. `rate_limit` không có ở `dns.resolve` vì DNSx v1.2.2 không có trần theo host tương ứng trong snapshot campaign.

**3. Mạng và credential.** Hai tool cần mạng ra ngoài: `networkAccess: egress`, `rawSocket: false`, không credential. Subfinder gửi tên miền tới nguồn thụ động bên thứ ba (điều kiện OD-1); DNSx hỏi resolver. Input không có trường secret nào — `additionalProperties: false` nên `api_key`/`token` bị INPUT_INVALID; credential vận hành (nếu có về sau) do manifest/cấu hình cấp thẳng tới sandbox, không đi qua input hay prompt. Manifest khai báo `networkAccess: none` mà input lại cần `sources`/`resolvers` thì M05 từ chối (POLICY_DENIED). Hình dạng `permissions` đầy đủ đã khóa ở S1.5a: `egressMode: broker`, `proxyAware: true`, `egressSources` (host/port/protocol tĩnh), `targetBinding: required|none` + `targetPorts: from_input` cho tool nối tới mục tiêu, `rawSocket: false`; tập luôn chặn là hằng của nền tảng. `sources` của Subfinder và `resolvers` của DNSx phải nằm trong `egressSources` của manifest đã pin — kiểm ở [test_conformance.py](../tests/test_conformance.py) (`policy/source-not-declared`, `policy/resolver-not-declared`) và [test_egress_actor.py](../tests/test_egress_actor.py); cưỡng chế runtime thuộc G1.3a.

**4. Provenance.** Envelope do collector nộp phải mang: `provider` (name/version/adapter_version/image_digest) khớp pin của task, `policy_version`, `provenance.seed_targets` = `task.targets`, `provenance.input_fingerprint` = sha256 `aegis-c14n/1` của input đã chấp nhận, evidence raw kèm `sha256`/`size_bytes`/`uri`, `coverage.subjects` là những gì job thực sự kiểm (seed chưa thành asset nằm ở `seed_targets`, không ở coverage), `observed_at` do collector gán (parser thuần không đọc đồng hồ). Sai lệch pin là POLICY_DENIED, thiếu bằng chứng là EVIDENCE_INCOMPLETE.

## INPUT_INVALID và POLICY_DENIED

| Tình huống | Mã | Ghi chú |
| --- | --- | --- |
| Kiểu/format/enum sai, thừa trường (secret, tham số lạ) | INPUT_INVALID | schema input quyết định |
| Target không khớp seed/asset của campaign | INPUT_INVALID | `capability-request.input` mô tả cùng quy tắc |
| Capability/provider chưa đăng ký, trần manifest/campaign bị vượt, target kind không được nhận, `task.targets` không khớp input, manifest pin lệch | POLICY_DENIED | cấu hình đã pin quyết định, không phải hình dạng input |
| Manifest đã pin không còn trong registry | DEPENDENCY_MISSING | không resolve latest |
| Job bị huỷ trước khi có envelope | EVIDENCE_INCOMPLETE | không dựng envelope từ bằng chứng dở dang |

## Kiểm conformance

[test_conformance.py](../tests/test_conformance.py) chạy [harness.py](../tests/conformance/harness.py) trên fixture Subfinder và DNSx: bảy handler (describe không side effect, validate từ chối trước khi chạy, start idempotent theo key, status có `retry_after`, cancel có audit, collect raw/hash/coverage/provenance, health nêu tool version/phụ thuộc), envelope dựng lại đúng fixture `result-envelope.*.json`, parser tất định và replay giữ `payload_hash`, cộng các negative fixture cấp registry trong [conformance/fixtures/policy](../tests/conformance/fixtures/policy). Adapter mới phải qua cùng bộ kiểm này; đây là kiểm contract tham chiếu, chưa phải runtime sản phẩm.
