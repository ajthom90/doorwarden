# syntax=docker/dockerfile:1
# Multi-stage build. Pure Go (CGO off) so the same Dockerfile builds for any
# platform under buildx; the builder runs on the build platform and
# cross-compiles via TARGETOS/TARGETARCH.
# Base images are pinned by version tag; pin by digest for stricter
# reproducibility (e.g. golang:1.26@sha256:...).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/doorwarden ./cmd/doorwarden
# Pre-create the state directories (distroless has no shell to mkdir/chown).
RUN mkdir -p /out/rootfs/data /out/rootfs/config

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/doorwarden /doorwarden
# License of Doorwarden and of every Go module compiled into the binary.
COPY --from=build /src/LICENSE /src/THIRD_PARTY_NOTICES.md /usr/share/doc/doorwarden/
# /data holds SQLite state and certificates, /config the config file; both
# are pre-created owned by 65532 (the distroless nonroot user). No VOLUME
# directive: it would create root-owned anonymous volumes; bind mount your
# own (chown 65532:65532).
COPY --from=build --chown=65532:65532 /out/rootfs/data /data
COPY --from=build --chown=65532:65532 /out/rootfs/config /config
EXPOSE 8080
USER 65532:65532
# The /healthz endpoint is served by the control plane; DOORWARDEN_HEALTH_URL
# overrides the target.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/doorwarden", "healthcheck"]
ENTRYPOINT ["/doorwarden"]
