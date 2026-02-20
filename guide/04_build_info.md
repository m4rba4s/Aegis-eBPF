# Guide 04: Build Info + `--version`

> **Priority: MEDIUM** — Users and bug reports need exact build identification.

## Problem

`aegis-cli --version` currently shows `aegis-cli 0.1.0` (clap default).
No commit hash, no build date, no toolchain info. Bug reports are useless without this.

## Solution

Use `build.rs` to embed `git rev-parse HEAD`, build timestamp, and rustc version.
Display via `clap(version)` and a dedicated `version` subcommand with full info.

## Step-by-Step Implementation

### Step 1: Extend build.rs

In `aegis-cli/build.rs`, add at the end of `main()`:

```rust
use std::process::Command;

fn main() {
    // ... existing eBPF embedding code ...

    // Build metadata
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AEGIS_GIT_HASH={}", git_hash.trim());

    let build_date = Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AEGIS_BUILD_DATE={}", build_date.trim());

    // Rustc version
    let rustc = Command::new("rustc")
        .args(["--version"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AEGIS_RUSTC_VERSION={}", rustc.trim());
}
```

### Step 2: Create version string in main.rs

```rust
fn version_long() -> String {
    format!(
        "{} ({} {})\nrustc: {}\nkernel: {}",
        env!("CARGO_PKG_VERSION"),
        env!("AEGIS_GIT_HASH"),
        env!("AEGIS_BUILD_DATE"),
        env!("AEGIS_RUSTC_VERSION"),
        std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    )
}
```

### Step 3: Set clap version

```rust
#[derive(Parser)]
#[clap(
    name = "aegis-cli",
    about = "Aegis eBPF XDP/TC Firewall",
    version = env!("CARGO_PKG_VERSION"),
    long_version = version_long(),
)]
struct Opt { ... }
```

Note: `long_version` requires a `&'static str` or `String`. Use `lazy_static` or `once_cell`:
```rust
use std::sync::LazyLock;

static LONG_VERSION: LazyLock<String> = LazyLock::new(version_long);
```

Then: `long_version = LONG_VERSION.as_str()`.

### Step 4: TUI footer

Show version in the TUI footer bar:
```rust
let version = format!("Aegis v{} ({})", env!("CARGO_PKG_VERSION"), env!("AEGIS_GIT_HASH"));
```

## Expected Output

```
$ aegis-cli --version
aegis-cli 1.0.0

$ aegis-cli -V
aegis-cli 1.0.0 (a1b2c3d4 2025-02-19)
rustc: rustc 1.77.0-nightly
kernel: 6.7.4-200.fc39.x86_64
```

## Testing

1. `cargo build --release -p aegis-cli`
2. `./target/release/aegis-cli --version` → short version
3. `./target/release/aegis-cli -V` → long version with commit hash
4. Verify git hash matches `git rev-parse --short=8 HEAD`

## Acceptance Criteria

- [ ] `--version` shows semver
- [ ] `-V` shows commit hash + build date + rustc + kernel
- [ ] TUI footer shows version
- [ ] Works even without git (falls back to "unknown")

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/build.rs` | **MODIFY** — add git hash, date, rustc capture |
| `aegis-cli/src/main.rs` | **MODIFY** — version_long(), clap config |
| `aegis-cli/src/tui/mod.rs` | **MODIFY** — version in footer |
