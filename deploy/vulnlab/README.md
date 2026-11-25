# CVE test lab (G1.6)

Known-vulnerable HTTP services for the discovery chain (port → service/product/version/CPE → CVE
candidates), plus the optional Cloudflare Tunnel the owner publishes them through. Detection only:
nothing here sends a payload (dynamic verification is G2).

```sh
make vulnlab-up      # origins + lab network; auto-stops after VULNLAB_TTL_MINUTES (default 120)
make vulnlab-check   # every origin serves the page its catalog entry documents
make vulnlab-status  # boundary, TTL armed/remaining, tunnel state (non-zero if not healthy)
make vulnlab-down    # remove only the aegis-vulnlab project and its two networks
make vulnlab-test PROFILE=lab|internet   # one campaign per catalog case, assert the detections
```

## Authorization

| | |
| --- | --- |
| Decision | Owner decision on item 61 (2026-11-25): a CVE lab on `salingnh.com`, only through a Cloudflare Tunnel, with Cloudflare Access restricted to this machine's egress IP, isolated containers and a TTL. Tunnel, DNS and Access are created by the leader through the Cloudflare MCP after the owner signs in (owner decision, item 61). |
| Scope | Compose project `aegis-vulnlab`; networks `aegis-vulnlab-net` (internal), `aegis-vulnlab-egress` (cloudflared only) and the existing `aegis-lab-lab`. No published host port, no host mount. |
| Record | Item 61; report `/orca/bots/ultron-lead/memory/reports/g16-e-vulnlab.md`. |

## Topology

| Case | Image | Origin port | Lab address | Product / version |
| --- | --- | --- | --- | --- |
| httpd-2.4.49 | httpd:2.4.49 | 80 | 10.114.53.61 | Apache httpd 2.4.49 |
| nginx-1.16.0 | nginx:1.16.0 | 80 | 10.114.53.62 | nginx 1.16.0 |
| tomcat-8.5.19 | vulhub/tomcat:8.5.19 | 8080 | 10.114.53.63 | Apache Tomcat 8.5.19 |
| spring-webmvc-5.3.17 | vulhub/spring-webmvc:5.3.17 | 8080 | 10.114.53.64 | Tomcat 8.5.77 (Spring 5.3.17 not disclosed) |
| jenkins-2.138 | jenkins/jenkins:2.138 | 8080 | 10.114.53.65 | Jenkins 2.138 |
| jetty-9.4.40 | jetty:9.4.40-jre11-slim | 8080 | 10.114.53.66 | Jetty 9.4.40.v20210413 |
| struts2-2.3.30 | vulhub/struts2:2.3.30 | 8080 | 10.114.53.67 | Jetty 9.2.11 (Struts version not disclosed) |

`tests/vulnlab/cases.yaml` is the source of truth: pins, licenses, expected ports/products/CPEs and
the CVE candidates (with KEV flags and forbidden ids), per profile.

## Isolation and auto-stop

Origins run rootless on `aegis-vulnlab-net` (internal, only peer cloudflared) and on the authorized
lab network; no `ports:`, no host mount, tmpfs only for the directories the server writes,
`cap_drop: ALL` (httpd/nginx keep the caps they need to bind 80 and drop privileges), no-new-privileges,
memory/CPU/PID caps, read-only rootfs except the two images that unpack/compile at start. Every
container is created with `podman --timeout` = `VULNLAB_TTL_MINUTES` (1–1440, default 120): podman
stops the stack by itself, and `make vulnlab-status` fails when a container has no/other TTL or was
created outside `make vulnlab-up`.

## Tunnel

Created by the leader through the Cloudflare MCP: remote-managed tunnel `ultron-vulnlab` (ingress lives in the Cloudflare dashboard and mirrors `cloudflared/config.yml.template`), proxied `vl-*` hostnames on the authorized domain, and a Cloudflare Access app that bypasses only the scanner's egress IP (everyone else is blocked). Hostnames go in `deploy/vulnlab/.env` (git-ignored; only names in `.env.example`). The token is read from `AEGIS_VULNLAB_TUNNEL_TOKEN_FILE` (default `/home/admin/.config/ultron/vulnlab-tunnel.token`, must be 0600) and is never printed.

Publishing is an explicit opt-in: `make vulnlab-up` is lab-only even when the token file exists; `VULNLAB_TUNNEL=1 make vulnlab-up` (or `make vulnlab-test PROFILE=internet`) starts `cloudflared`. Only one tunnel-enabled stack per host; another checkout's `aegis-vulnlab` is never touched (`AEGIS_VULNLAB_PROJECT` per checkout). If the scanner's egress IP changes, the Access policy must be updated (until then the scanner is blocked — fail closed).

## Tests

`make vulnlab-check` proves what each service reveals (status, Server, title, body) through a
one-shot probe on the lab network. `make vulnlab-test PROFILE=lab` creates one campaign per case and
asserts the recorded ports/product/version/CPE and CVE candidates (KEV flags included; forbidden ids
must be absent). `BLOCKED` means the chain only has DNS capabilities — the port/fingerprint/CVE
providers are slices A/B/C. `PROFILE=internet` needs the live tunnel and refuses placeholder names.
