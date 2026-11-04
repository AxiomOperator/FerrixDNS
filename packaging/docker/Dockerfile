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
# Docker doesn't pass --cap-add on to a non-root process, so the binary carries the capability itself.
# It's what lets the node answer on ports 53 and 123. Starting the image requires NET_BIND_SERVICE
# to be allowed, which it is by default, and no-new-privileges would make the kernel ignore it.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_bind_service=+ep target/release/ferrixdns
RUN mkdir -p /data && chown 65532:65532 /data

# Distroless has no shell or package manager, so there's little for an attacker to use.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=node /src/target/release/ferrixdns /usr/bin/ferrixdns
COPY --from=node --chown=65532:65532 /data /data
ENV FERRIXDNS_STATE_DIR=/data
ENV FERRIXDNS_LISTEN=0.0.0.0:53
ENV FERRIXDNS_UPSTREAM=1.1.1.1,9.9.9.9
ENV FERRIXDNS_WEB_LISTEN=0.0.0.0:8443
ENV FERRIXDNS_WEB_TLS_SELF_SIGNED=true
# Containers see traffic from their network's gateway unless they use host networking.
ENV FERRIXDNS_HEALTH_ADDRESS=127.0.0.1:53
VOLUME /data
EXPOSE 53/udp 53/tcp 123/udp 8443/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/usr/bin/ferrixdns", "health"]
ENTRYPOINT ["/usr/bin/ferrixdns"]
CMD ["serve"]
