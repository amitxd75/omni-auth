# ── Stage 1: Build ───────────────────────────────────────────
FROM rust:1.96-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/omni-auth

# Copy Cargo workspace configuration and manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml ./crates/core/
COPY crates/api/Cargo.toml ./crates/api/
COPY crates/verify/Cargo.toml ./crates/verify/

# Create dummy source tree to cache dependencies compilation step
RUN mkdir -p crates/core/src crates/api/src crates/verify/src \
    && echo "pub fn dummy() {}" > crates/core/src/lib.rs \
    && echo "pub fn dummy() {}" > crates/verify/src/lib.rs \
    && echo "fn main() {}" > crates/api/src/main.rs \
    && cargo build --release --bin omni-auth-api

# Remove dummy code and copy actual project sources
RUN rm -rf crates/core/src crates/api/src crates/verify/src
COPY crates/core/src ./crates/core/src
COPY crates/verify/src ./crates/verify/src
COPY crates/api/src ./crates/api/src
COPY crates/migrations ./crates/migrations

# Touch files to force rebuild of project binaries
RUN touch crates/core/src/lib.rs \
    && touch crates/verify/src/lib.rs \
    && touch crates/api/src/main.rs

# Build the release binary
RUN cargo build --release --bin omni-auth-api

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS runner

# Install runtime dependencies (OpenSSL 3, CA Certificates, Curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /usr/src/omni-auth/target/release/omni-auth-api ./omni-auth-api

# Copy database migrations since they are run at startup
COPY --from=builder /usr/src/omni-auth/crates/migrations ./crates/migrations

# Expose API port
EXPOSE 8080

# Run binary
CMD ["./omni-auth-api"]
