# Aegis eBPF Firewall - Multi-stage Build
#
# Build: docker build --output=dist .
# This produces three portable binaries:
#   - aegis-cli (userspace controller with embedded eBPF)
#   - aegis.o (XDP eBPF object, optional)
#   - aegis-tc.o (TC eBPF object, optional)

# =============================================================================
# STAGE 1: Build Environment
# =============================================================================
FROM rust:latest AS builder

# Install required system tools
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    libelf-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install nightly Rust (required for eBPF cross-compilation)
RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly

# Create non-root builder user FIRST, then install bpf-linker as that user
RUN useradd -m builder
USER builder

# Install bpf-linker as builder user so it's in builder's PATH
RUN cargo install bpf-linker

WORKDIR /home/builder/build

# Copy source
COPY --chown=builder . .

# Build eBPF programs first (XDP + TC) — must use release profile
RUN cargo run -p xtask -- build-all --profile release

# Build aegis-cli (with embedded eBPF bytecode)
RUN cargo build --release -p aegis-cli

# Verify outputs
RUN ls -la target/release/aegis-cli && \
    ls -la target/bpfel-unknown-none/release/aegis && \
    ls -la target/bpfel-unknown-none/release/aegis-tc

# =============================================================================
# STAGE 2: Export Binaries
# =============================================================================
FROM scratch AS export

# The main binary (contains embedded eBPF)
COPY --from=builder /home/builder/build/target/release/aegis-cli /aegis-cli

# eBPF objects (for advanced users who want external files)
COPY --from=builder /home/builder/build/target/bpfel-unknown-none/release/aegis /aegis.o
COPY --from=builder /home/builder/build/target/bpfel-unknown-none/release/aegis-tc /aegis-tc.o

# Install script
COPY --from=builder /home/builder/build/install.sh /install.sh
