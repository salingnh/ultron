# MCP và adapter tool

## Giao thức

Agent gọi MCP tools/list để lấy capability/schema, tools/call để đề xuất job. M05 kiểm tool, input và cấu hình chạy, trả job_id; M02/M06 điều phối sandbox. Query tools đọc graph/evidence có giới hạn. CLI không cần tự nói MCP: adapter bọc CLI theo manifest.

## Manifest

`CapabilityProvider`: tên/provider/version, capability, inputSchemaRef, outputSchemaRef, inputDefaults, runtime container/image digest/argsTemplate, permissions, budget, parser và conformance tests. inputDefaults là giá trị cụ thể; ghép rồi validate. Không có chuỗi command tùy ý. Network none/egress mô tả quyền kết nối thực tế của sandbox.

## Adapter SDK

`describe`, `validate`, `start`, `status`, `cancel`, `collect`, `health`. CLI adapter dùng ContainerRunner chung; tác giả viết manifest, parser thuần, fixture, input schema và giấy phép. Parser không gọi mạng, không credential, không ghi DB. Output thành ResultEnvelope có raw reference/hash.

## Danh mục tích hợp

| Nhóm | Tool dự kiến | Dữ liệu tạo ra |
| --- | --- | --- |
| DNS/discovery (M08/M09) | Subfinder, DNSx, BBOT, asnmap; nguồn crt.sh/RDAP/dnstwist; SpiderFoot-ng ở G3 | Domain/IP, ASN, lookalike và nguồn phát hiện |
| Network (M09) | Naabu, Nmap, Nerva, cdncheck | Service/banner |
| Web (M10) | httpx, Katana, Nuclei, tlsx, urlfinder | Endpoint, công nghệ, evidence/finding |
| Artifact/package (M13/M14) | Trivy, Syft, Grype | SBOM, package, CVE evidence |
| Source/secret (M12/M17) | Opengrep, Gitleaks, TruffleHog, Betterleaks | Finding kèm vị trí và bằng chứng |
| Config (M11) | Prowler, Kubescape, kube-bench | Observation cấu hình |
| JS/binary (M15/M16) | webcrack, jsluice, JADX, asar, strings, Ghidra headless | Endpoint/package/quan sát tĩnh |

Danh mục không phải cam kết có sẵn adapter. Triển khai theo thứ tự giá trị và dependency dữ liệu. Mỗi tool cần schema tham số cụ thể và test trước khi đăng ký. Template hay nội dung từ mục tiêu không tự biến thành chỉ dẫn/thực thi mã mới. Các yêu cầu mạng/credential phải thể hiện trong contract tool và sandbox, không suy từ tên tool.

Giữ thứ tự lựa chọn đã chốt: DNSx/Subfinder chứng minh G1; bộ ProjectDiscovery được ưu tiên ở G2; Trivy là provider chính cho SBOM/vulnerability, Syft/Grype đối chứng, Nmap dùng khi cần nhận diện sâu. Grype/cdncheck/urlfinder có thể giao G3 nếu cần; không lùi kiểm chứng động, credential, severity hoặc soak khỏi G2. Provider đủ schema/health mới được xét; khi có nhiều provider phù hợp, cân nhắc coverage, độ tin cậy, chi phí và độ trễ, không tự đổi input/hành vi đã yêu cầu.

## Tiêu chí thêm tool

1. Schema input/output và capability ổn định.
2. Image pin digest, parser cô lập, giới hạn thực thi rõ.
3. Fixture parse đúng, replay không đổi kết quả, evidence có checksum/provenance.
4. MCP discovery/call hoạt động; job hiện đúng dependency/priority trên UI.
5. Không sửa mã lõi chỉ để thêm scanner cùng kiểu runtime.

## Chọn provider và quản lý phiên bản

Registry lọc theo capability, schema input/output tương thích, health, phiên bản/digest và yêu cầu mạng/credential/tài nguyên. Agent có thể đề xuất provider trong tập hợp đó; M05 kiểm lại trước khi phát task. Nếu không có provider phù hợp thì trả lỗi kèm next_action, không âm thầm dùng tool khác với hình dạng input khác.

Mỗi adapter có ma trận adapter version ↔ tool version ↔ schema, golden fixtures và thông tin giấy phép của bản pin. Task ghim manifest_sha256 theo [quy tắc runtime](../../../contracts/interfaces/README.md#manifest-bất-biến-và-cấu-hình-thực-thi); registry giữ nguyên bản đã pin cho job còn chờ/retry. Nâng tool phải chạy lại parser/conformance, canary trên lab đã được phép và có đường rollback manifest. Không mang các claim release/giấy phép hoặc benchmark trong tài liệu nghiên cứu thành dữ kiện của bản đang tích hợp.

### Pin table đã kiểm (spike G0.2, 2026-11-24)

Kiểm trên máy dev (Fedora 44, rootless Podman 5.8.9): digest lấy bằng `skopeo inspect` cho `linux/amd64`, ngày phát hành lấy từ GitHub release, giấy phép từ repo/label của image, SBOM SPDX 2.3 sinh bằng `trivy` từ `podman save` của đúng digest. Toàn bộ ở `spikes/g0.2-sandbox/pins/` và `spikes/g0.2-sandbox/sbom/`.

| Tool | Bản pin | Ngày phát hành | Tuổi (ngày) | Digest | Giấy phép | SBOM (số package) |
| --- | --- | --- | --- | --- | --- | --- |
| subfinder | v2.17.0 | 2026-10-08 | 47 | `sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf` | MIT | SPDX (134) |
| dnsx | v1.2.2 | 2025-02-01 | 661 | `sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec` | MIT | SPDX (138) |
| bbot | v3.0.2 | 2026-08-24 | 92 | `sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e` | AGPL-3.0 | SPDX (277) |
| naabu | v2.7.0 | 2026-10-28 | 27 | `sha256:67c120a669954b768354197fc04328e08027898dc821bc8f276b3e26cd21f6aa` | MIT | SPDX (146) |

Ghi chú bắt buộc khi lập manifest:

- **dnsx**: upstream đã có v1.3.0/v1.3.1 nhưng Docker Hub không có image tương ứng (tag mới nhất là v1.2.2), nên pin là v1.2.2. `provider_version`/`adapter_version` phải ghi đúng khoảng lệch; không mô tả hành vi v1.3 khi chưa có image.
- **bbot**: AGPL-3.0, chỉ chạy như container riêng, không link vào mã lõi, giữ attribution. Bản 3.1.0 (2026-11-12) mới 12 ngày tuổi nên chưa được nhận theo luật 14 ngày (đủ điều kiện từ 2026-11-26), và các tag 3.1.x trên Docker Hub hiện là `rc`.
- **naabu**: chỉ dùng cho kiểm raw socket. Trong rootless Podman, `-s syn` tự hạ xuống CONNECT dù `NET_RAW` hiệu lực (xem §Sandbox ở [Nền tảng](02-nen-tang.md)); `-proxy` nhận `host:port` không kèm scheme. Chưa đăng ký egress nếu chưa chứng minh được chế độ quét thực tế.
- Mọi lần nâng pin phải chạy lại parser/conformance, ghi ngày phát hành và kiểm lại 14 ngày; SBOM phải sinh lại từ digest mới.

Conformance giữ đủ: describe không side effect; validate từ chối input sai trước khi gọi OSS; start idempotent; status có retry_after; cancel/timeout dừng container và audit; collect có raw/hash/coverage; health nêu tool version/phụ thuộc. Parser tất định, không mạng/credential/biến môi trường kế thừa/DB; cùng fixture giữ canonical ID và predicate hợp lệ. Kiểm output giả chỉ dẫn, output lớn, upgrade và canary theo nền tảng.

## Chuỗi xử lý artifact và phản hồi tri thức

| Đầu vào | Chuỗi xử lý khi adapter tương ứng được giao | Đầu ra được giữ |
| --- | --- | --- |
| Repo snapshot | Định danh repo/commit → tool source/secret → parser | Finding có path/line/commit, package và evidence |
| JavaScript/source map | Raw digest → giải nén/giải rối → trích AST/chuỗi có nguồn | Endpoint/secret candidate và vị trí trong artifact |
| OCI image/filesystem | Digest cố định → inventory/SBOM → đối chiếu package/version | Package/pURL và snapshot nguồn khớp CVE |
| APK/Electron/binary | Raw digest → unpack/phân tích tĩnh trong sandbox | Symbol/chuỗi/package/endpoint có nguồn và giới hạn phân tích |

Đây là các chuỗi adapter theo giai đoạn ở TASKS, không phải bốn dịch vụ nền tảng bắt buộc. Package và endpoint mới chỉ trở thành đầu vào của job tiếp theo sau khi ingestion kiểm nguồn gốc và điều kiện mục tiêu.

Pseudocode không phải mã nguồn gốc; static call graph không chứng minh runtime reachability. File không phân tích được vì tài nguyên phải ghi resource constraint và coverage incomplete. Kết quả rỗng là chưa đủ thông tin, không tự thành bằng chứng không tồn tại. Template/phiên bản/tập rule được chọn phải nằm trong input hoặc cấu hình có snapshot để tái lập, không suy hành vi từ tên scanner.

## Contract tool và actor — C05 đã khóa (S1.5a)

Catalogue chưa phải registry đã triển khai: bộ schema hiện chỉ có ba input DNS/network mẫu. Mỗi tool tiếp theo phải khóa input/output, target reference, budget, mạng/credential và provenance trước khi implement adapter (input/output của chuỗi DNS ở S1.5b; output query bắt buộc `truncated`/`limits_applied` từ S1.5b). Hai phần C05 đã khóa:

- **Egress:** `permissions` của [manifest](../../../contracts/capability/provider-manifest.v2.schema.json) khai `egressMode` (GĐ1 chỉ `broker`), `proxyAware`, `egressSources` (host/port/protocol tĩnh), `targetBinding`/`targetPorts`; `rawSocket` ghim `false`. Egress không có đích nào bị từ chối; tập luôn chặn là hằng của nền tảng (loopback, link-local/metadata gồm `fe80::/10`, multicast, unspecified, mạng control/data, `target_denylist`) và manifest không có trường để khai/nới nó. Binding hiệu lực = (mục tiêu đã phân giải ∪ `egressSources`) − tập luôn chặn, và registry M05 từ chối manifest khai `egressSources` trỏ vào tập đó (cùng danh sách ở [validation.py](../../../contracts/validation.py)). Hình dạng và cưỡng chế: [02 nền tảng §Sandbox](02-nen-tang.md#egress-đã-khóa-s15a-theo-kết-quả-g02). `egressSources` là tập nguồn duy nhất mà S1.5b tham chiếu: `sources` của Subfinder và `resolvers` của DNSx phải nằm trong đó, nên trần tham số (`concurrency` theo `budget.maxConcurrency`, `rate_limit` theo snapshot) và binding đích được kiểm cùng một chỗ.
- **Actor:** `requested_by` là người/kênh khởi động, do server gán từ principal đã xác minh (`RequestedBy`: `operator|module`); `proposed_by` là phiên agent đề xuất (`ProposedBy`: `agent` + session id), cũng do server gán từ ngữ cảnh phiên. Cả hai thuộc nội dung ApprovedTask được ký và được ghi bất biến khi job đã nhận ([0010](../../../contracts/db/postgres/0010_job_actor_attribution.sql)); hàng trước 0010 giữ actor cũ và không được gán người thay thế. Hàng có `requested_by` mà 0010 không thể chấp nhận (kind `agent` hoặc sai shape) được giữ bằng `dispatch_block_reasons = {LEGACY_ACTOR}` nên không dispatch/replay và cũng không mở lại được ([0011](../../../contracts/db/postgres/0011_dispatch_hold_and_search_path.sql)); hàng cũ có actor tự khai trùng shape `operator` không phân biệt được với hàng sau 0010, nên contract chỉ khẳng định phần cưỡng chế được. Đường MCP không có trường danh tính trong `capability-request.v2`: identity do LLM khai không tạo quyền thực thi và không bao giờ trở thành `requested_by`/`proposed_by`.

Đã khóa ở S1.5b cho chuỗi DNS đầu tiên (dns.enumerate_subdomains + dns.resolve, Subfinder và DNSx): kiểu target ref và binding seed, trần tham số theo manifest/campaign (`concurrency`, `rate_limit`), mạng/credential, provenance bắt buộc của envelope, và bộ conformance registry/adapter chạy được — xem [capabilities/README.md](../../../contracts/capabilities/README.md) và [test_conformance.py](../../../contracts/tests/test_conformance.py); mọi output graph-queries bắt buộc `truncated` + `limits_applied` ([graph-queries.v2](../../../contracts/mcp/graph-queries.v2.schema.json)). Runtime M05–M06/M23 chưa tồn tại nên đây vẫn là contract và kiểm tham chiếu.

**Còn mở (X-8/OD-5):** cơ chế xác minh principal cho operator (chưa có đăng nhập ở MVP: session/ký nội bộ/OIDC/mTLS) do chủ dự án quyết. Contract chỉ khẳng định principal là opaque và do server cấp, không chọn cơ chế. Body REST không mang actor nữa (OI-10): `job-submit.v2`, `campaign-create.v2`, body đổi policy và chuyển trạng thái finding không có trường `actor`, server gán `requested_by` từ principal đã xác minh và REST **không bao giờ** đặt `proposed_by` (không có phiên agent sau một lời gọi REST).

Tiêu chí kiểm: input sai, actor không hợp lệ hoặc nguồn mục tiêu không thuộc campaign bị từ chối; job hợp lệ truy được người kích hoạt và nguồn đề xuất; credential vận hành cấp trực tiếp tới sandbox. Thiếu contract thì tool chưa được đăng ký. Kiểm của phần này: [test_egress_actor.py](../../../contracts/tests/test_egress_actor.py), [tests/job_actor.sql](../../../contracts/db/postgres/tests/job_actor.sql), [test_conformance.py](../../../contracts/tests/test_conformance.py) và fixture âm trong `contracts/fixtures/invalid/`.

## Hành vi nghiệp vụ của các chuỗi tool

| Chuỗi | Dữ liệu và hành vi phải giữ |
| --- | --- |
| Discovery/DNS/network | Domain → RESOLVES_TO → IP → EXPOSES → Service; Naabu phát hiện cổng, Nerva nhận diện mặc định, Nmap nhận diện sâu khi cần và không bật script mặc định. Banner/version và nguồn phát hiện đi vào observation. IPv4/IPv6 được chuẩn hóa trước khi ghi |
| Web/Nuclei | Service → Application → Endpoint; JS/source map thu được thành artifact. Hỗ trợ bộ mẫu chính thức và mẫu người vận hành thêm; snapshot/pin bộ mẫu như một dependency, có input schema và giới hạn request/rate |
| SBOM/vulnerability | Image theo digest hoặc repo theo commit; SBOM CycloneDX/SPDX cùng digest nguồn; package dùng pURL. Lưu phiên bản DB/rule của scanner; M20 hợp nhất finding giữa provider, adapter giữ từng nguồn bằng chứng |
| Source/secret | Finding giữ path/line/commit hoặc vị trí trong artifact và fingerprint. Secret thu được là bằng chứng; quy tắc hiển thị ở AGENTS |
| Credential | TruffleHog bật xác minh credential. Sinh ứng viên từ dữ liệu OSINT/breach/secret đã thu và thử đăng nhập endpoint là lời gọi tool có input riêng, actor, ngân sách, kết quả và bằng chứng; credential vận hành vẫn cấp theo job. Mỗi adapter phải khóa các trường này trước khi đăng ký |
| Enrichment | API nguồn cho domain/email/keyword do người vận hành cấu hình key và hoàn tất yêu cầu xác minh domain của dịch vụ nguồn khi có. Tra cứu rò rỉ theo domain tổ chức, có provenance/pivot chain; không mở rộng sang tra cứu cá nhân ngầm |

Giới hạn riêng của tool là input/permissions cụ thể: BBOT và SpiderFoot-ng dùng module thụ động; httpx/Katana mặc định HEAD/GET với request/rate cap, crawl đăng nhập dùng credential cấp riêng. Phân tích SBOM không chạy image; quét repo dùng credential Git chỉ đọc và chỉ gửi mã tới model theo cấu hình dữ liệu. Prowler/Kubescape/kube-bench kiểm cấu hình bằng API/quyền chỉ đọc, credential ngắn hạn; cluster mục tiêu không phải hạ tầng chạy scanner. Phân tích JS/source map và binary chỉ đọc/giải nén tĩnh trong sandbox không mạng/credential, không thực thi artifact thu về; binary chỉ chạy khi có job yêu cầu.

Parser theo output của bản pin: JSONL cho discovery/web, XML khi Nmap dùng XML, JSON/SARIF cho source, CycloneDX/SPDX cho SBOM. M08 giữ nguồn domain/ASN/tổ chức và khả năng tìm mã nguồn công khai ở G3. JS mới sinh endpoint/package và chuyển secret candidate cho M17; observation binary có nhãn static và giới hạn coverage. Các hành vi này đều qua container/ResultEnvelope, không thêm runtime import/REST riêng.

Đường vào M08 giữ hành vi riêng: email tổ chức dẫn tới domain và lookup rò rỉ domain; keyword/brand tìm chứng chỉ, lookalike domain, mã công khai và bucket mang tên tổ chức. Tên miền trong chứng chỉ TLS cũng là nguồn pivot. Mỗi kết quả giữ seed gốc và nguồn tìm ra nó; BBOT/SpiderFoot không tự chạy các kiểm chủ động bên trong ngoài đường job/audit của nền tảng.

Kiểm thử credential và xác minh động là năng lực nghiệp vụ được giữ từ quyết định trước; chúng dùng tool/input và thứ tự chạy thông thường. Chưa có adapter/schema tương ứng trong bộ mẫu hiện tại thì vẫn là việc phải giao, không được báo đã hỗ trợ runtime.

Mỗi chuỗi có ca kiểm độc lập: redirect tạo quan hệ nguồn gốc đúng; image → pURL → CVE giữ digest/snapshot; ba provider báo cùng package cho một finding với ba nguồn; artifact JS sinh endpoint rồi tạo job tiếp theo; secret cài sẵn trong fixture giữ nguyên giá trị và fingerprint.
