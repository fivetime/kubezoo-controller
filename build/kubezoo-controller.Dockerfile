# syntax=docker/dockerfile:1.7

FROM --platform=${BUILDPLATFORM} golang:1.26-alpine3.24 AS builder
RUN apk add --no-cache bash git
WORKDIR /build

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG TARGETOS TARGETARCH
# ⚠️ No GIT_VERSION build-arg, unlike the two images in kubezoo-gateway. Those
# stamp it into pkg/projectinfo; this repository has no version variable to
# stamp, and accepting an argument that goes nowhere would read as if it did.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -o /out/kubezoo-controller ./cmd/kubezoo-controller

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 nonroot \
    && adduser -S -D -H -u 65532 -G nonroot nonroot
COPY --from=builder /out/kubezoo-controller /usr/local/bin/kubezoo-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kubezoo-controller"]
