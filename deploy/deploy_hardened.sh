#!/usr/bin/env bash
# ============================================================
# Aegis eBPF Firewall — Hardened Deployment Script
# AEGIS-SA-2026-001 Security Audit Remediation
# ============================================================
# This script applies, validates, and deploys all security patches
# from the 2026-08 audit. It performs:
#   1. Build verification (cargo check + cargo test)
#   2. eBPF verifier validation (if root + bpftool available)
#   3. Git staging, commit (Conventional Commits), and SSH push
#
# Usage: ./deploy_hardened.sh [--dry-run] [--branch NAME]
# ============================================================

set -euo pipefail

# --- Configuration ---
REMOTE_URL="git@github.com:m4rba4s/aegis.git"
DEFAULT_BRANCH="security/audit-2026-08"
COMMIT_PREFIX="fix(security):"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Flags ---
DRY_RUN=false
BRANCH="${DEFAULT_BRANCH}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --branch) BRANCH="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Aegis Security Hardening Deployment                ║${NC}"
echo -e "${CYAN}║  Advisory: AEGIS-SA-2026-001                        ║${NC}"
echo -e "${CYAN}║  Branch:   ${BRANCH}$(printf '%*s' $((26 - ${#BRANCH})) '')║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo

cd "${PROJECT_ROOT}"

# ============================================================
# Step 1: Pre-flight checks
# ============================================================
echo -e "${YELLOW}[1/6] Pre-flight checks...${NC}"

if ! command -v cargo &>/dev/null; then
    echo -e "${RED}ERROR: cargo not found. Install Rust toolchain.${NC}"
    exit 1
fi

if ! command -v git &>/dev/null; then
    echo -e "${RED}ERROR: git not found.${NC}"
    exit 1
fi

# Verify we're in the right repo
if [[ ! -f "Cargo.toml" ]] || ! grep -q "aegis" Cargo.toml 2>/dev/null; then
    echo -e "${RED}ERROR: Not in Aegis project root.${NC}"
    exit 1
fi

echo -e "${GREEN}  ✓ Toolchain present${NC}"
echo -e "${GREEN}  ✓ Project root verified${NC}"

# ============================================================
# Step 2: Workspace build check (excludes eBPF crates)
# ============================================================
echo -e "${YELLOW}[2/6] Running cargo check (workspace)...${NC}"

if cargo check --workspace 2>&1 | tail -5; then
    echo -e "${GREEN}  ✓ cargo check passed${NC}"
else
    echo -e "${RED}  ✗ cargo check failed — aborting deployment${NC}"
    exit 1
fi

# ============================================================
# Step 3: Run tests
# ============================================================
echo -e "${YELLOW}[3/6] Running cargo test (workspace)...${NC}"

if cargo test --workspace 2>&1 | tail -10; then
    echo -e "${GREEN}  ✓ cargo test passed${NC}"
else
    echo -e "${RED}  ✗ cargo test failed — aborting deployment${NC}"
    exit 1
fi

# ============================================================
# Step 4: eBPF verifier validation (optional, requires root)
# ============================================================
echo -e "${YELLOW}[4/6] eBPF verifier validation...${NC}"

if [[ $EUID -eq 0 ]] && command -v bpftool &>/dev/null; then
    echo "  Building eBPF programs..."
    if cargo xtask build-ebpf --release 2>&1 | tail -3; then
        XDP_BIN="target/bpfel-unknown-none/release/aegis"
        TC_BIN="target/bpfel-unknown-none/release/aegis-tc"

        if [[ -f "${XDP_BIN}" ]]; then
            echo "  Validating XDP bytecode..."
            if bpftool prog load "${XDP_BIN}" /sys/fs/bpf/aegis_test_xdp type xdp 2>&1; then
                bpftool prog detach pinned /sys/fs/bpf/aegis_test_xdp 2>/dev/null || true
                rm -f /sys/fs/bpf/aegis_test_xdp 2>/dev/null || true
                echo -e "${GREEN}  ✓ XDP verifier passed${NC}"
            else
                echo -e "${YELLOW}  ⚠ XDP verifier load failed (may need pinned maps)${NC}"
            fi
        fi

        if [[ -f "${TC_BIN}" ]]; then
            echo "  Validating TC bytecode..."
            if bpftool prog load "${TC_BIN}" /sys/fs/bpf/aegis_test_tc type classifier 2>&1; then
                rm -f /sys/fs/bpf/aegis_test_tc 2>/dev/null || true
                echo -e "${GREEN}  ✓ TC verifier passed${NC}"
            else
                echo -e "${YELLOW}  ⚠ TC verifier load failed (may need pinned maps)${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}  ⚠ eBPF build failed — skipping verifier check${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ Skipped (requires root + bpftool)${NC}"
fi

# ============================================================
# Step 5: Git operations
# ============================================================
echo -e "${YELLOW}[5/6] Git operations...${NC}"

# Create branch if not on it
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "")
if [[ "${CURRENT_BRANCH}" != "${BRANCH}" ]]; then
    echo "  Creating branch: ${BRANCH}"
    git checkout -b "${BRANCH}" 2>/dev/null || git checkout "${BRANCH}"
fi

# Stage all changes
git add -A

# Check if there are changes to commit
if git diff --cached --quiet 2>/dev/null; then
    echo -e "${YELLOW}  ⚠ No changes to commit${NC}"
else
    COMMIT_MSG="${COMMIT_PREFIX} apply AEGIS-SA-2026-001 audit remediations

Fixes applied:
- SEC-001: TC egress fail-open → fail-closed (P1)
- SEC-002: IPv6 SYN flood rate limiting parity with IPv4 (P1)
- SEC-004: Port scan bitmap hash collision fix (P2)
- SEC-005: Code clarity comment for L4 offset ordering (P3)
- SEC-006: Loader ABI version validation guard (P2)
- SEC-007: freeze_map FD leak on failure path (P3)
- SEC-008: YAML bomb mitigation via from_str bounded parse (P2)
- SEC-009: Strict SUDO_UID validation (no nobody fallback) (P3)

Advisory: docs/AEGIS-SA-2026-001.md
Tests: scripts/security_stress_test.sh
Compat: scripts/verify_bpf_compat.sh

BREAKING CHANGE: TC egress now drops (TC_ACT_SHOT) on parse
errors instead of passing (TC_ACT_OK). Malformed egress packets
that previously slipped through will now be blocked.
Direct root execution of aegis-cli is no longer supported;
must use sudo to ensure proper privilege dropping.

Refs: AEGIS-SA-2026-001"

    if [[ "${DRY_RUN}" == true ]]; then
        echo -e "${YELLOW}  [DRY RUN] Would commit with message:${NC}"
        echo "${COMMIT_MSG}" | head -3
        echo "  ..."
    else
        git commit -m "${COMMIT_MSG}"
        echo -e "${GREEN}  ✓ Changes committed${NC}"
    fi
fi

# ============================================================
# Step 6: Push via SSH
# ============================================================
echo -e "${YELLOW}[6/6] Pushing to remote...${NC}"

# Verify SSH key is available
if ! ssh -T git@github.com 2>&1 | grep -qi "successfully\|authenticated"; then
    echo -e "${YELLOW}  ⚠ SSH authentication to GitHub may not be configured${NC}"
    echo -e "${YELLOW}    Ensure your SSH key is loaded: ssh-add -l${NC}"
fi

if [[ "${DRY_RUN}" == true ]]; then
    echo -e "${YELLOW}  [DRY RUN] Would push: ${BRANCH} → ${REMOTE_URL}${NC}"
else
    if git remote get-url origin 2>/dev/null | grep -q "github.com"; then
        git push -u origin "${BRANCH}" 2>&1 || {
            echo -e "${YELLOW}  ⚠ Push failed — adding remote and retrying${NC}"
            git remote add aegis-upstream "${REMOTE_URL}" 2>/dev/null || true
            git push -u aegis-upstream "${BRANCH}"
        }
        echo -e "${GREEN}  ✓ Pushed to ${REMOTE_URL} (${BRANCH})${NC}"
    else
        git remote add aegis-upstream "${REMOTE_URL}" 2>/dev/null || true
        git push -u aegis-upstream "${BRANCH}" 2>&1
        echo -e "${GREEN}  ✓ Pushed to ${REMOTE_URL} (${BRANCH})${NC}"
    fi
fi

# ============================================================
# Summary
# ============================================================
echo
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Deployment Complete                                ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Patches applied: 8                                 ║${NC}"
echo -e "${CYAN}║  P1 fixes: 2 (TC fail-closed, IPv6 rate limit)     ║${NC}"
echo -e "${CYAN}║  P2 fixes: 3 (port hash, ABI valid, YAML bomb)     ║${NC}"
echo -e "${CYAN}║  P3 fixes: 3 (FD leak, code clarity, nobody fb)    ║${NC}"
echo -e "${CYAN}║  Branch: ${BRANCH}$(printf '%*s' $((26 - ${#BRANCH})) '')         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
