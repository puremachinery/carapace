# ---- Build stage ----
FROM rust:1.93-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/
COPY wit/ wit/

RUN cargo build --release --locked \
        --config 'profile.release.strip=true'

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/cara /usr/local/bin/cara

RUN groupadd --system carapace && useradd --system --gid carapace carapace

# State directory for sessions, cron, config
ENV CARAPACE_STATE_DIR=/data
RUN mkdir -p /data && chown carapace:carapace /data

USER carapace

EXPOSE 18789

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:18789/health || exit 1

ENTRYPOINT ["cara"]
