#!/bin/bash
# ==============================================================================
# Aegis eBPF/XDP Firewall - BPF Verifier Compatibility Check
# ==============================================================================
# 1. Builds both XDP and TC programs in release mode
# 2. Attempts to load them with bpftool (dry-run if possible)
# 3. Reports kernel version compatibility
# 4. Checks for CO-RE BTF availability
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Aegis BPF Verifier & Kernel Compatibility Check${NC}"
echo "========================================================="

# 1. Kernel Version Check
KVER=$(uname -r)
echo -e "${BLUE}[INFO] Kernel Version: $KVER${NC}"
# eBPF CO-RE typically needs >= 5.8
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)

if [ "$KMAJ" -lt 5 ] || ([ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 8 ]); then
    echo -e "${YELLOW}[WARN] Kernel version $KVER might be too old for advanced CO-RE features. (Recommended: 5.8+)${NC}"
else
    echo -e "${GREEN}[PASS] Kernel version is sufficient for CO-RE.${NC}"
fi

# 2. CO-RE BTF Check
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    echo -e "${GREEN}[PASS] CO-RE BTF information found at /sys/kernel/btf/vmlinux${NC}"
else
    echo -e "${RED}[FAIL] CO-RE BTF information NOT found. Kernel may not support CONFIG_DEBUG_INFO_BTF.${NC}"
fi

# 3. Build XDP and TC programs in release mode
echo -e "\n${BLUE}[*] Building eBPF programs (Release Mode)...${NC}"
if [ -f "Cargo.toml" ]; then
    echo "[INFO] Detected Rust/Cargo project. Attempting generic eBPF build (cargo build-ebpf)..."
    # A standard xtask call for eBPF in Rust (Aya):
    cargo xtask build-ebpf --release
    BUILD_STAT=$?
elif [ -f "Makefile" ]; then
    echo "[INFO] Detected Makefile. Running make release..."
    make release
    BUILD_STAT=$?
else
    echo -e "${YELLOW}[WARN] No standard build file found in current directory. Assuming binaries are pre-built.${NC}"
    BUILD_STAT=0
fi

if [ $BUILD_STAT -ne 0 ]; then
    echo -e "${YELLOW}[WARN] Build process returned an error. We will proceed to check for any existing object files.${NC}"
fi

# 4. Attempt to load with bpftool (Dry-Run / Verification)
echo -e "\n${BLUE}[*] Verifying eBPF Object Loading...${NC}"

if ! command -v bpftool &> /dev/null; then
    echo -e "${RED}[FAIL] bpftool is not installed. Cannot verify BPF load.${NC}"
    exit 1
fi

# Find ELF/object files that might be our compiled eBPF code
OBJS=$(find . -maxdepth 4 -type f -name "*.o" -o -name "*.elf" | grep -E "xdp|tc|bpf|aegis" || true)

if [ -z "$OBJS" ]; then
    echo -e "${YELLOW}[WARN] No eBPF object files (*.o / *.elf) found to verify. Ensure the build succeeds.${NC}"
else
    for obj in $OBJS; do
        echo -n "Verifying $(basename "$obj") ... "
        # Heuristic to guess prog type
        PROG_TYPE="xdp"
        if [[ "$obj" == *"tc"* ]]; then
            PROG_TYPE="tc"
        fi
        
        # Load object into kernel strictly to pass the verifier, then we remove the pin
        # NOTE: bpftool prog load does an actual verifier check.
        TEST_PIN="/sys/fs/bpf/aegis_verify_test"
        rm -f "$TEST_PIN"
        
        bpftool prog load "$obj" "$TEST_PIN" type "$PROG_TYPE" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}PASS ($PROG_TYPE)${NC}"
            rm -f "$TEST_PIN"
        else
            echo -e "${RED}FAIL (Verifier rejected or invalid object format)${NC}"
            echo -e "${YELLOW}--- Verifier Output ---${NC}"
            # Re-run without redirecting output to show exactly why verifier failed
            bpftool prog load "$obj" "$TEST_PIN" type "$PROG_TYPE"
            echo -e "${YELLOW}-----------------------${NC}"
        fi
    done
fi

echo -e "\n${BLUE}[*] Compatibility Check Complete.${NC}"
