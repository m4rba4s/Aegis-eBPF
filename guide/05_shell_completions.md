# Guide 05: Shell Completions (clap_complete)

> **Priority: MEDIUM** — Low effort, high professional polish.
> Tab completion makes CLI feel production-grade.

## Problem

`aegis-cli <TAB>` does nothing. Users must guess subcommands and flags.

## Solution

Use `clap_complete` to generate completions for bash, zsh, fish, elvish.
Generate at build time OR via `aegis-cli completions <shell>`.

## Dependencies

```toml
# aegis-cli/Cargo.toml
clap_complete = "4.0"
```

## Step-by-Step Implementation

### Step 1: Add completions subcommand

In `aegis-cli/src/main.rs`, add to the `Commands` enum:

```rust
use clap_complete::{generate, Shell};

#[derive(Subcommand)]
enum Commands {
    /// Interactive TUI mode
    Tui,
    /// Background daemon mode
    Daemon,
    /// Load eBPF and enter CLI
    Load,
    /// Generate shell completions
    Completions {
        /// Shell type: bash, zsh, fish, elvish
        #[clap(value_enum)]
        shell: Shell,
    },
}
```

### Step 2: Handle completions command

In the `match` on commands:

```rust
Commands::Completions { shell } => {
    let mut cmd = Opt::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
    return Ok(());
}
```

### Step 3: Install completions in install.sh

Add to `install.sh`:

```bash
install_completions() {
    local bin="$BIN_DIR/aegis-cli"

    if [[ ! -x "$bin" ]]; then
        log_warn "Binary not found, skipping completions"
        return
    fi

    # Bash
    if [[ -d /etc/bash_completion.d ]]; then
        "$bin" completions bash > /etc/bash_completion.d/aegis-cli 2>/dev/null && \
            log_ok "Bash completions installed"
    fi

    # Zsh
    if [[ -d /usr/share/zsh/site-functions ]]; then
        "$bin" completions zsh > /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null && \
            log_ok "Zsh completions installed"
    fi

    # Fish
    if [[ -d /usr/share/fish/vendor_completions.d ]]; then
        "$bin" completions fish > /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null && \
            log_ok "Fish completions installed"
    fi
}
```

Call `install_completions` at the end of `main()`, after binary install.

## Testing

```bash
# Generate and test
aegis-cli completions bash > /tmp/aegis.bash
source /tmp/aegis.bash
aegis-cli <TAB>      # should show: tui, daemon, load, completions
aegis-cli -<TAB>     # should show: -i, --iface, --ebpf-path, etc.
```

## Acceptance Criteria

- [ ] `aegis-cli completions bash/zsh/fish` outputs valid completion script
- [ ] `install.sh` auto-installs completions for detected shells
- [ ] Tab completion works for subcommands and flags

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/Cargo.toml` | **MODIFY** — add `clap_complete = "4.0"` |
| `aegis-cli/src/main.rs` | **MODIFY** — add Completions subcommand + handler |
| `install.sh` | **MODIFY** — add `install_completions()` |
