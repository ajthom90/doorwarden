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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/doorwarden /doorwarden
# /data holds SQLite state and certificates, /config the config file. Mount
# volumes owned by uid 65532 (the distroless nonroot user).
VOLUME ["/data", "/config"]
EXPOSE 8080
USER 65532:65532
# The /healthz endpoint is served by the control plane; DOORWARDEN_HEALTH_URL
# overrides the target.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/doorwarden", "healthcheck"]
ENTRYPOINT ["/doorwarden"]
