# ---- Build stage ----
FROM rust:1.94.1-slim AS builder

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

# Pin the runtime user/group to a fixed, numeric uid/gid (satisfies
# hadolint DL3066 and keeps the runtime identity deterministic instead of
# relying on whatever `useradd --system` happens to allocate). 10001 sits
# above the system range (<1000) where apt-installed accounts live, so it
# will not collide with the ca-certificates/curl packages this stage adds.
# UPGRADE NOTE: this differs from the previously auto-allocated uid. The
# daemon refuses to start if its state dir (/data) is owned by another uid
# (see src/server/startup.rs), so a persistent /data volume created by an
# older image must be chowned once: `chown -R 10001:10001 /data`.
RUN groupadd --system --gid 10001 carapace \
    && useradd --system --uid 10001 --gid carapace carapace

# State directory for sessions, cron, config
ENV CARAPACE_STATE_DIR=/data
RUN mkdir -p /data && chown carapace:carapace /data

USER 10001:10001

EXPOSE 18789

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:18789/health"]

ENTRYPOINT ["cara"]
