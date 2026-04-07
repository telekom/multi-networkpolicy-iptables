# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.25 AS build

WORKDIR /usr/src/multi-networkpolicy-nftables

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./
COPY vendor/ vendor/

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/bin/multi-networkpolicy-nftables ./cmd/multi-networkpolicy-nftables/

FROM docker.io/debian:stable-slim

LABEL org.opencontainers.image.source="https://github.com/telekom/multi-networkpolicy-nftables"
LABEL org.opencontainers.image.description="Multi-NetworkPolicy enforcement using nftables"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    nftables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/doc /usr/share/man

COPY --from=build /usr/bin/multi-networkpolicy-nftables /usr/bin/multi-networkpolicy-nftables

ENTRYPOINT ["multi-networkpolicy-nftables"]
