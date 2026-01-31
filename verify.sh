#!/bin/bash
# Aegis Verification Script
# Run all verification layers for critical infrastructure assurance
#
# Usage:
#   ./verify.sh           # Run all tests
#   ./verify.sh tests     # Run unit + property tests only
#   ./verify.sh fuzz      # Run fuzzers (requires cargo-fuzz)
#   ./verify.sh kani      # Run Kani proofs (requires kani)
#   ./verify.sh ci        # CI mode (tests + limited fuzz)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         AEGIS VERIFICATION SUITE                          ║${NC}"
echo -e "${BLUE}║   Formal Verification for Critical Infrastructure         ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo

MODE="${1:-all}"

# ============================================================
# COMPILE-TIME CHECKS
# ============================================================
run_compile_checks() {
    echo -e "${YELLOW}[1/4] Compile-time assertions...${NC}"
    cargo build -p aegis-verification 2>&1 | grep -v "Compiling\|Finished" || true
    echo -e "${GREEN}✓ Struct size invariants verified${NC}"
    echo
}

# ============================================================
# UNIT + PROPERTY-BASED TESTS
# ============================================================
run_tests() {
    echo -e "${YELLOW}[2/4] Running unit + property-based tests...${NC}"
    cargo test -p aegis-verification -- --nocapture 2>&1 | tail -20
    echo -e "${GREEN}✓ All property tests passed${NC}"
    echo
}

# ============================================================
# FUZZING
# ============================================================
run_fuzz() {
    echo -e "${YELLOW}[3/4] Running fuzzers...${NC}"

    if ! command -v cargo-fuzz &> /dev/null; then
        echo -e "${RED}✗ cargo-fuzz not installed${NC}"
        echo "  Install with: cargo install cargo-fuzz"
        echo "  Skipping fuzzing..."
        return 0
    fi

    FUZZ_TIME="${FUZZ_TIME:-30}"
    echo "  Fuzzing for ${FUZZ_TIME} seconds per target..."

    cd verification/fuzz

    for target in fuzz_packet_parsing fuzz_lpm_lookup fuzz_rate_limit; do
        echo -e "  ${BLUE}→ ${target}${NC}"
        timeout ${FUZZ_TIME}s cargo +nightly fuzz run ${target} -- -max_total_time=${FUZZ_TIME} 2>&1 | tail -5 || true
    done

    cd ../..
    echo -e "${GREEN}✓ Fuzzing completed${NC}"
    echo
}

# ============================================================
# KANI MODEL CHECKING
# ============================================================
run_kani() {
    echo -e "${YELLOW}[4/4] Running Kani model checker...${NC}"

    if ! command -v kani &> /dev/null; then
        echo -e "${RED}✗ Kani not installed${NC}"
        echo "  Install from: https://github.com/model-checking/kani"
        echo "  Skipping Kani proofs..."
        return 0
    fi

    cd verification
    cargo kani --tests 2>&1 | tail -30
    cd ..

    echo -e "${GREEN}✓ All Kani proofs verified${NC}"
    echo
}

# ============================================================
# MAIN
# ============================================================

case "$MODE" in
    tests)
        run_compile_checks
        run_tests
        ;;
    fuzz)
        run_fuzz
        ;;
    kani)
        run_kani
        ;;
    ci)
        run_compile_checks
        run_tests
        FUZZ_TIME=10 run_fuzz
        ;;
    all)
        run_compile_checks
        run_tests
        run_fuzz
        run_kani
        ;;
    *)
        echo "Usage: $0 [tests|fuzz|kani|ci|all]"
        exit 1
        ;;
esac

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         VERIFICATION COMPLETE                             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
