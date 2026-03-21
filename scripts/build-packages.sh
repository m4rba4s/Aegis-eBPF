#!/usr/bin/env bash

# Aegis Package Builder (DEB & RPM)
# Requires: cargo-deb, cargo-generate-rpm

set -euo pipefail

cd "$(dirname "$0")/.."

echo "📦 Building Aegis eBPF packages..."

# Ensure tools are installed
if ! command -v cargo-deb &>/dev/null; then
    echo "⚙️ Installing cargo-deb..."
    cargo install cargo-deb
fi

if ! command -v cargo-generate-rpm &>/dev/null; then
    echo "⚙️ Installing cargo-generate-rpm..."
    cargo install cargo-generate-rpm
fi

echo "🔨 Compiling release binary..."
cargo build --release -p aegis-cli

mkdir -p target/packages

echo "📦 Generating Debian package (.deb)..."
cd aegis-cli
cargo deb -p aegis-cli -o ../target/packages/
cd ..

echo "📦 Generating RedHat package (.rpm)..."
cd aegis-cli
# cargo-generate-rpm requires stripping manually sometimes, but let's just run it
strip ../target/release/aegis-cli || true
cargo generate-rpm -o ../target/packages/
cd ..

echo "✅ Packaging complete. Artifacts in target/packages/:"
ls -lh target/packages/
