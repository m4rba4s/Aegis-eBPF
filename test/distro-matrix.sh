#!/bin/bash
# Aegis Cross-Distro Build Test Matrix
#
# Tests the full build pipeline (install deps → install rust → build eBPF → build CLI)
# inside Docker containers for each supported distro.
#
# Usage:
#   ./test/distro-matrix.sh          # Run all distros
#   ./test/distro-matrix.sh ubuntu   # Run single distro
#
# NOTE: Docker containers cannot load eBPF programs (no kernel access).
# This script validates: compilation, binary creation, install paths.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Distro definitions ────────────────────────────────────────────
# Format: name|image|pkg_cmd
DISTROS=(
    "ubuntu|ubuntu:22.04|apt-get"
    "debian|debian:12|apt-get"
    "fedora|fedora:40|dnf"
    "arch|archlinux:latest|pacman"
    "alpine|alpine:3.19|apk"
    "rocky|rockylinux:9|dnf"
)

# ─── Generate Dockerfile for each distro ───────────────────────────
generate_dockerfile() {
    local name="$1"
    local image="$2"

    cat <<DOCKERFILE
FROM ${image}

# Install system deps based on distro
$(case "$name" in
    ubuntu|debian)
        echo 'RUN apt-get update && apt-get install -y \'
        echo '    build-essential pkg-config curl git \'
        echo '    llvm clang libelf-dev \'
        echo '    && rm -rf /var/lib/apt/lists/*'
        ;;
    fedora|rocky)
        echo 'RUN dnf install -y \'
        echo '    gcc make pkg-config curl git \'
        echo '    llvm clang llvm-devel elfutils-libelf-devel \'
        echo '    && dnf clean all'
        ;;
    arch)
        echo 'RUN pacman -Sy --noconfirm \'
        echo '    base-devel llvm clang libelf curl git'
        ;;
    alpine)
        echo 'RUN apk add --no-cache \'
        echo '    build-base musl-dev linux-headers \'
        echo '    llvm clang libelf-dev curl git'
        ;;
esac)

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:\${PATH}"

# Install nightly + bpf-linker
RUN rustup install nightly && \\
    rustup component add rust-src --toolchain nightly
RUN cargo install bpf-linker

# Copy source
WORKDIR /build
COPY . .

# Build eBPF (release profile — debug panics bpf-linker)
RUN cargo run -p xtask -- build-all --profile release

# Build CLI (eBPF bytecode embedded by build.rs)
RUN cargo build --release -p aegis-cli

# Verify outputs exist and binary runs
RUN test -f target/release/aegis-cli && echo "✅ Binary exists"
RUN test -f target/bpfel-unknown-none/release/aegis && echo "✅ XDP object exists"
RUN test -f target/bpfel-unknown-none/release/aegis-tc && echo "✅ TC object exists"
RUN target/release/aegis-cli --version && echo "✅ Binary runs"
RUN target/release/aegis-cli --help > /dev/null && echo "✅ Help works"
DOCKERFILE
}

# ─── Run test for a single distro ──────────────────────────────────
run_test() {
    local entry="$1"
    local name image pkg_cmd
    IFS='|' read -r name image pkg_cmd <<< "$entry"

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Testing: ${name} (${image})${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo ""

    local tmpdir
    tmpdir=$(mktemp -d)
    local dockerfile="$tmpdir/Dockerfile"
    local tag="aegis-test-${name}"

    generate_dockerfile "$name" "$image" > "$dockerfile"

    local start_time
    start_time=$(date +%s)

    if docker build \
        -t "$tag" \
        -f "$dockerfile" \
        "$SCRIPT_DIR" \
        2>&1 | tee "$tmpdir/build.log"; then

        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo ""
        echo -e "${GREEN}✅ ${name}: PASSED (${duration}s)${NC}"
        RESULTS+=("${GREEN}✅ ${name} (${image}): PASSED in ${duration}s${NC}")
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo ""
        echo -e "${RED}❌ ${name}: FAILED (${duration}s)${NC}"
        echo -e "${YELLOW}   Log: ${tmpdir}/build.log${NC}"
        RESULTS+=("${RED}❌ ${name} (${image}): FAILED after ${duration}s${NC}")
        FAILURES=$((FAILURES + 1))
    fi

    # Cleanup image (keep disk space)
    docker rmi "$tag" 2>/dev/null || true
    rm -rf "$tmpdir"
}

# ─── Main ──────────────────────────────────────────────────────────
main() {
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}❌ Docker is required to run the test matrix${NC}"
        exit 1
    fi

    local filter="${1:-}"
    declare -a RESULTS=()
    FAILURES=0

    echo ""
    echo -e "${BOLD}🛡️  Aegis Cross-Distro Build Test Matrix${NC}"
    echo ""

    for entry in "${DISTROS[@]}"; do
        local name
        IFS='|' read -r name _ _ <<< "$entry"

        # Filter by name if specified
        if [[ -n "$filter" ]] && [[ "$name" != "$filter" ]]; then
            continue
        fi

        run_test "$entry"
    done

    # Summary
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  RESULTS SUMMARY${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    for r in "${RESULTS[@]}"; do
        echo -e "  $r"
    done
    echo ""

    if [[ $FAILURES -eq 0 ]]; then
        echo -e "${GREEN}  All distros passed! 🎉${NC}"
    else
        echo -e "${RED}  ${FAILURES} distro(s) failed.${NC}"
    fi
    echo ""

    exit $FAILURES
}

main "$@"
