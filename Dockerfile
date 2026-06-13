# Aegis eBPF Firewall - Multi-stage Build (musl static binary)
#
# Build: docker build --output=dist .
# This produces a statically linked x86_64 userspace artifact:
#   - aegis-cli (userspace controller with embedded eBPF, statically linked)
#   - aegis.o (XDP eBPF object, optional)
#   - aegis-tc.o (TC eBPF object, optional)
#
# The aegis-cli binary is statically linked for x86_64 Linux; runtime support
# still depends on the kernel, XDP/TC attach mode, and the release evidence matrix.

# =============================================================================
# STAGE 1: Build Environment (musl for static linking)
# =============================================================================
FROM rust:1.96.0-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS builder

# Install required system tools + musl cross-compilation support
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    libelf-dev \
    pkg-config \
    musl-tools \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Create non-root builder user FIRST, then install bpf-linker as that user
RUN useradd -m builder
USER builder

# Install bpf-linker as builder user so it's in builder's PATH
RUN cargo install bpf-linker --version 0.10.1 --locked

WORKDIR /home/builder/build

# Copy source
COPY --chown=builder . .

# Initialize the correct toolchain from rust-toolchain.toml and add targets
RUN rustup show && \
    rustup component add rust-src && \
    rustup target add x86_64-unknown-linux-musl

# Archive the exact toolchain used by the release container.
RUN { \
      rustc --version --verbose; \
      cargo --version --verbose; \
      rustup show active-toolchain; \
      bpf-linker --version; \
    } > toolchain.txt

# Build eBPF programs first (XDP + TC) — must use release profile
RUN cargo run --locked -p xtask -- build-all --profile release

# Build aegis-cli as fully static musl binary (with embedded eBPF bytecode)
RUN cargo build --locked --release --target x86_64-unknown-linux-musl -p aegis-cli

# Verify outputs
RUN ls -la target/x86_64-unknown-linux-musl/release/aegis-cli && \
    file target/x86_64-unknown-linux-musl/release/aegis-cli && \
    ls -la target/bpfel-unknown-none/release/aegis && \
    ls -la target/bpfel-unknown-none/release/aegis-tc

# =============================================================================
# STAGE 2: Export Binaries
# =============================================================================
FROM scratch AS export

# The main binary (fully static, contains embedded eBPF)
COPY --from=builder /home/builder/build/target/x86_64-unknown-linux-musl/release/aegis-cli /aegis-cli

# eBPF objects (for advanced users who want external files)
COPY --from=builder /home/builder/build/target/bpfel-unknown-none/release/aegis /aegis.o
COPY --from=builder /home/builder/build/target/bpfel-unknown-none/release/aegis-tc /aegis-tc.o

# Install script
COPY --from=builder /home/builder/build/install.sh /install.sh

# Release build environment metadata
COPY --from=builder /home/builder/build/toolchain.txt /toolchain.txt
