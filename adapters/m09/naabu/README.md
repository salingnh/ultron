# Adapter M09 — Naabu (`network.discover_services`)

- Capability: [`capabilities/network/discover-services.v2`](../../../contracts/capabilities/network/discover-services.v2.schema.json).
- Tool: Naabu v2.7.0 (ProjectDiscovery, MIT), image pin theo digest trong `manifest.yaml`; manifest trùng từng byte với `contracts/fixtures/valid/manifest.naabu.yaml`.
- Chạy: CONNECT scan (`-s connect`, `rawSocket: false` — G0.2: SYN bị hạ xuống CONNECT khi rootless), `targetBinding: required` (chỉ IP đã ký), port set qua `/in/ports.txt`, `version_intensity` cố định 0.
- Parser: `adapters.m09.naabu.parser` → Service asset (`service:<ip>:<port>/tcp`), cạnh `EXPOSES` (IP → Service), `net.port_state`, `service.protocol` khi biết.
- Không phát: `SERVES`, Application, product/version — thuộc `service/fingerprint` và `web/probe-http`.
- Fixture conformance lấy từ lần chạy lab thật (`fixtures/lab/`).
