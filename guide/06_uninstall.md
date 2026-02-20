# Guide 06: Uninstall Flag (install.sh --uninstall)

> **Priority: MEDIUM** — No clean removal path. Users must manually find and delete files.

## Problem

Aegis installs files across multiple locations:
- `/usr/local/bin/aegis-cli`
- `/usr/local/share/aegis/`
- `/etc/systemd/system/aegis@.service` OR `/etc/init.d/aegis` + `/etc/conf.d/aegis`
- `/sys/fs/bpf/aegis/` (pinned BPF maps)
- `/var/log/aegis/`
- `/etc/aegis/` (config, if Guide 02 is implemented)
- `/var/lib/aegis/` (GeoIP db, if Guide 01 is implemented)
- Completions: `/etc/bash_completion.d/aegis-cli`, etc.

No automated cleanup = unprofessional.

## Step-by-Step Implementation

### Step 1: Add uninstall function to install.sh

```bash
uninstall_aegis() {
    log_info "Uninstalling Aegis..."

    # 1. Stop services
    stop_running_services

    # 2. Remove service files
    local init_system=$(detect_init_system)
    case "$init_system" in
        systemd)
            systemctl disable "aegis@*" 2>/dev/null || true
            rm -f /etc/systemd/system/aegis@.service
            systemctl daemon-reload
            log_ok "Systemd service removed"
            ;;
        openrc)
            rc-update del aegis 2>/dev/null || true
            rm -f /etc/init.d/aegis /etc/conf.d/aegis
            log_ok "OpenRC service removed"
            ;;
        sysvinit)
            update-rc.d aegis remove 2>/dev/null || true
            rm -f /etc/init.d/aegis
            log_ok "SysVinit service removed"
            ;;
    esac

    # 3. Remove binaries
    rm -f "$BIN_DIR/aegis-cli"
    log_ok "Binary removed"

    # 4. Remove shared data
    rm -rf "$SHARE_DIR"
    log_ok "Shared data removed"

    # 5. Clean BPF maps
    if [[ -d /sys/fs/bpf/aegis ]]; then
        rm -rf /sys/fs/bpf/aegis
        log_ok "BPF maps cleaned"
    fi

    # 6. Remove completions
    rm -f /etc/bash_completion.d/aegis-cli 2>/dev/null
    rm -f /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null
    rm -f /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null
    log_ok "Shell completions removed"

    # 7. Ask about config and logs
    if [[ -d /etc/aegis ]]; then
        echo ""
        read -rp "Remove config (/etc/aegis)? [y/N] " remove_config
        if [[ "$remove_config" =~ ^[Yy]$ ]]; then
            rm -rf /etc/aegis
            log_ok "Config removed"
        else
            log_info "Config preserved: /etc/aegis"
        fi
    fi

    if [[ -d /var/log/aegis ]]; then
        read -rp "Remove logs (/var/log/aegis)? [y/N] " remove_logs
        if [[ "$remove_logs" =~ ^[Yy]$ ]]; then
            rm -rf /var/log/aegis
            log_ok "Logs removed"
        else
            log_info "Logs preserved: /var/log/aegis"
        fi
    fi

    if [[ -d /var/lib/aegis ]]; then
        read -rp "Remove GeoIP database (/var/lib/aegis)? [y/N] " remove_geo
        if [[ "$remove_geo" =~ ^[Yy]$ ]]; then
            rm -rf /var/lib/aegis
            log_ok "GeoIP data removed"
        else
            log_info "GeoIP data preserved: /var/lib/aegis"
        fi
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ AEGIS UNINSTALLED"
    echo "═══════════════════════════════════════════════════════════"
}
```

### Step 2: Add to CLI option parser

In `main()`:
```bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-only) install_only=true; shift ;;
        --skip-service) skip_service=true; shift ;;
        --uninstall)    uninstall_aegis; exit 0 ;;     # ADD THIS
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --install-only   Install pre-built binaries (no cargo build)"
            echo "  --skip-service   Don't install init system service"
            echo "  --uninstall      Remove Aegis completely"               # ADD THIS
            echo "  --help           Show this help"
            exit 0
            ;;
        *) shift ;;
    esac
done
```

## Testing

1. Install Aegis: `sudo ./install.sh`
2. Verify files exist in all locations
3. Run `sudo ./install.sh --uninstall`
4. Verify: binary, service, BPF maps removed
5. Verify: config/logs prompt shown (answer N → preserved, Y → deleted)
6. Verify: second uninstall is idempotent (no errors)

## Acceptance Criteria

- [ ] `--uninstall` stops services before removing
- [ ] Binary, service, BPF maps always removed
- [ ] Config, logs, GeoIP: user prompted before removal
- [ ] Idempotent: running twice doesn't error
- [ ] Help text updated

## Files Changed

| File | Action |
|------|--------|
| `install.sh` | **MODIFY** — add `uninstall_aegis()`, `--uninstall` flag, help text |
