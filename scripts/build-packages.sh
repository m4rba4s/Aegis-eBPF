#!/usr/bin/env bash

# Aegis Package Builder (DEB & RPM)
# Requires: cargo-deb, cargo-generate-rpm

set -euo pipefail

cd "$(dirname "$0")/.."

CARGO_DEB_VERSION="${CARGO_DEB_VERSION:-3.7.0}"
CARGO_GENERATE_RPM_VERSION="${CARGO_GENERATE_RPM_VERSION:-0.21.0}"

echo "📦 Building Aegis eBPF packages..."

# Ensure tools are installed
if ! command -v cargo-deb &>/dev/null; then
    echo "⚙️ Installing cargo-deb..."
    cargo install cargo-deb --version "$CARGO_DEB_VERSION" --locked
fi

if ! command -v cargo-generate-rpm &>/dev/null; then
    echo "⚙️ Installing cargo-generate-rpm..."
    cargo install cargo-generate-rpm --version "$CARGO_GENERATE_RPM_VERSION" --locked
fi

echo "🔨 Compiling eBPF objects..."
cargo run --locked -p xtask -- build-all --profile release

echo "🔨 Compiling release binary..."
cargo build --locked --release -p aegis-cli

mkdir -p target/packages
find target/packages -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -delete

echo "📦 Generating Debian package (.deb)..."
cd aegis-cli
cargo deb -p aegis-cli -o ../target/packages/
cd ..

echo "📦 Generating RedHat package (.rpm)..."
strip target/release/aegis-cli || true
cargo generate-rpm -p aegis-cli -o target/packages/

deb_package=$(find target/packages -maxdepth 1 -type f -name '*.deb' -print -quit)
rpm_package=$(find target/packages -maxdepth 1 -type f -name '*.rpm' -print -quit)
[[ -n "$deb_package" && -s "$deb_package" ]] || {
    echo "❌ Debian package was not created"
    exit 1
}
[[ -n "$rpm_package" && -s "$rpm_package" ]] || {
    echo "❌ RPM package was not created"
    exit 1
}

if command -v ar >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
    deb_data_member=$(ar t "$deb_package" | awk '/^data\.tar\./ { print; exit }')
    [[ -n "$deb_data_member" ]] || {
        echo "❌ Debian package has no data archive"
        exit 1
    }
    case "$deb_data_member" in
        *.xz) deb_contents=$(ar p "$deb_package" "$deb_data_member" | tar -tJf -) ;;
        *.gz) deb_contents=$(ar p "$deb_package" "$deb_data_member" | tar -tzf -) ;;
        *.zst) deb_contents=$(ar p "$deb_package" "$deb_data_member" | tar --zstd -tf -) ;;
        *)
            echo "❌ Unsupported Debian data archive: $deb_data_member"
            exit 1
            ;;
    esac
    grep -qx './usr/local/bin/aegis-cli' <<<"$deb_contents" || {
        echo "❌ Debian package is missing /usr/local/bin/aegis-cli"
        exit 1
    }
fi

if command -v rpm >/dev/null 2>&1; then
    rpm -qlp "$rpm_package" | grep -qx '/usr/local/bin/aegis-cli' || {
        echo "❌ RPM package is missing /usr/local/bin/aegis-cli"
        exit 1
    }
fi

echo "✅ Packaging complete. Artifacts in target/packages/:"
ls -lh target/packages/
