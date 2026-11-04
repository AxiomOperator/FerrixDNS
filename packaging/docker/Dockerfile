# Build from the repository root:
#   docker build -f packaging/docker/Dockerfile -t ferrixdns .

FROM node:24-bookworm-slim AS ui
WORKDIR /src/frontend
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM rust:1.99.1-slim-bookworm AS node
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml ./
COPY crates/ crates/
COPY tests/ tests/
COPY migrations/ migrations/
COPY --from=ui /src/frontend/dist frontend/dist
RUN cargo build --release --locked --package node-bin
RUN mkdir -p /data && chown 65532:65532 /data

# Distroless has no shell or package manager, so there's little for an attacker to use.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=node /src/target/release/fx /usr/bin/fx
COPY --from=node --chown=65532:65532 /data /data
ENV FX_STATE_DIR=/data
ENV FX_LISTEN=0.0.0.0:53
ENV FX_UPSTREAM=1.1.1.1,9.9.9.9
ENV FX_WEB_LISTEN=0.0.0.0:8443
ENV FX_WEB_TLS_SELF_SIGNED=true
# Containers see traffic from their network's gateway unless they use host networking.
ENV FX_HEALTH_ADDRESS=127.0.0.1:53
VOLUME /data
EXPOSE 53/udp 53/tcp 8443/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/usr/bin/fx", "health"]
ENTRYPOINT ["/usr/bin/fx"]
CMD ["serve"]
