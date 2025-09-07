# Multi-stage Dockerfile for rust-bitcoin-core

# Stage 1: Builder
FROM nixos/nix:latest AS builder

# Copy source code
WORKDIR /build
COPY . .

# Build static binary using Nix
RUN nix develop -c cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime
FROM scratch

# Copy the static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/bitcoin-node /bitcoin-node

# Create data directory
VOLUME ["/data"]

# Expose ports
# 8332: RPC
# 8333: P2P
EXPOSE 8332 8333

# Set the entrypoint
ENTRYPOINT ["/bitcoin-node"]
CMD ["--datadir", "/data", "--network", "mainnet"]