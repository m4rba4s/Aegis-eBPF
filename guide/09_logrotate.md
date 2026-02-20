# Guide 09: Logrotate Configuration

> **Priority: MEDIUM** — `/var/log/aegis/` will grow unbounded. Disk fill = system down.

## Problem

Aegis daemon writes logs to `/var/log/aegis/` but has no rotation policy.
On a busy server processing millions of packets, logs can grow to GBs in hours.

## Solution

Ship a logrotate config that rotates daily, compresses, and keeps 7 days.

## Step-by-Step Implementation

### Step 1: Create logrotate config file

Create `deploy/aegis.logrotate`:

```
/var/log/aegis/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        # Signal Aegis to reopen log files
        # Method depends on init system
        if command -v systemctl >/dev/null 2>&1; then
            systemctl kill --signal=HUP aegis@* 2>/dev/null || true
        elif [ -f /run/aegis.pid ]; then
            kill -HUP $(cat /run/aegis.pid) 2>/dev/null || true
        fi
    endscript
}
```

### Step 2: Handle SIGHUP in aegis-cli

In `main.rs`, add signal handler for log rotation:

```rust
use tokio::signal::unix::{signal, SignalKind};

// In the event loop or a separate task:
let mut sighup = signal(SignalKind::hangup())?;

tokio::spawn(async move {
    loop {
        sighup.recv().await;
        log::info!("Received SIGHUP — reopening log files");
        // If using file-based logging, reopen the file handle
        // This is needed for logrotate to work correctly
    }
});
```

**Note**: If using `tracing` (Guide 07), use `tracing-appender` which handles
rotation natively:

```rust
use tracing_appender::rolling;

let file_appender = rolling::daily("/var/log/aegis", "aegis.log");
let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

// Use non_blocking as the writer
tracing_subscriber::fmt()
    .with_writer(non_blocking)
    .init();
```

With `tracing-appender`, logrotate is optional but still useful as a safety net.

### Step 3: Install logrotate config

Add to `install.sh`:

```bash
install_logrotate() {
    local logrotate_dir="/etc/logrotate.d"

    if [[ -d "$logrotate_dir" ]]; then
        cat > "$logrotate_dir/aegis" << 'ROTATEEOF'
/var/log/aegis/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        if command -v systemctl >/dev/null 2>&1; then
            systemctl kill --signal=HUP aegis@* 2>/dev/null || true
        elif [ -f /run/aegis.pid ]; then
            kill -HUP $(cat /run/aegis.pid) 2>/dev/null || true
        fi
    endscript
}
ROTATEEOF
        log_ok "Logrotate config installed"
    else
        log_warn "logrotate not found, skipping log rotation setup"
    fi

    # Create log directory
    mkdir -p /var/log/aegis
    chmod 0750 /var/log/aegis
}
```

### Step 4: Alpine support (no logrotate)

Alpine uses `newsyslog` or manual cron rotation. Add a cron fallback:

```bash
# Alpine: use cron if logrotate is missing
if [[ "$distro" == "alpine" ]] && ! command -v logrotate &>/dev/null; then
    # Add weekly cron job
    cat > /etc/periodic/weekly/aegis-logclean << 'CRONEOF'
#!/bin/sh
# Rotate Aegis logs — keep 7 days
find /var/log/aegis -name "*.log" -mtime +7 -delete 2>/dev/null
CRONEOF
    chmod +x /etc/periodic/weekly/aegis-logclean
    log_ok "Alpine cron log cleanup installed"
fi
```

### Step 5: Uninstall integration (Guide 06)

Add to `uninstall_aegis()`:
```bash
rm -f /etc/logrotate.d/aegis
rm -f /etc/periodic/weekly/aegis-logclean
```

## Testing

```bash
# Force rotation
sudo logrotate -f /etc/logrotate.d/aegis

# Verify
ls -la /var/log/aegis/
# Should see: aegis.log (current) + aegis.log.1.gz (compressed yesterday)

# Verify Aegis still writes to new file
sudo aegis-cli status  # if Guide 08 implemented
```

## Acceptance Criteria

- [ ] Logrotate config installed by `install.sh`
- [ ] Logs rotate daily, 7 days retained
- [ ] Old logs compressed (gzip)
- [ ] SIGHUP handled (log file reopened)
- [ ] Alpine fallback via cron
- [ ] Removed on uninstall

## Files Changed

| File | Action |
|------|--------|
| `deploy/aegis.logrotate` | **NEW** |
| `install.sh` | **MODIFY** — add `install_logrotate()` |
| `aegis-cli/src/main.rs` | **MODIFY** — SIGHUP handler |
