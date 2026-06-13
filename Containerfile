# Kraken — multi-stage Docker build
#
# Usage:
#   docker build -t kraken -f Containerfile .
#   docker run --rm -it kraken
#
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
#     -t ghcr.io/rooselvelt6/kraken:latest \
#     -f Containerfile --push .

FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_TERM_COLOR=always

WORKDIR /build
COPY rust/ .

RUN cargo build --release -p rusty-claude-cli

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/kraken /usr/local/bin/kraken

RUN kraken --version

WORKDIR /workspace
ENTRYPOINT ["kraken"]
CMD ["--help"]
