# fingerprintx for the authorized lab (G1.6b), built from the pinned upstream module version.
#
# Upstream publishes no container image (only the Dockerfile in its repository), so the pin is:
# the source tag below (`go install ...@v1.1.19`), the digest of each base image, and the digest
# of the built image recorded in `deploy/lab/images.env`. Changing any of the three is a pin
# bump: `make lab-build-fingerprintx`, then update `deploy/lab/images.env`, the adapter manifest
# and `contracts/fixtures/valid/manifest.fingerprintx.yaml` in the same commit, and re-record the
# lab fixture (`adapters/m08/fingerprintx/fixtures/lab`).
#
# No shell in the runtime image: the entrypoint is the static binary, and the runner supplies
# argv. `CGO_ENABLED=0` keeps it a single static binary on a minimal base.
FROM docker.io/library/golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

RUN apk add --no-cache git ca-certificates
RUN CGO_ENABLED=0 GOFLAGS=-trimpath \
    go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1.1.19

FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 65532 scanner
COPY --from=build /go/bin/fingerprintx /usr/local/bin/fingerprintx
USER 65532:65532
ENTRYPOINT ["fingerprintx"]
