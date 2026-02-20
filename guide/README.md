# Aegis Implementation Guides

Step-by-step guides for evolving Aegis from a personal tool to a production-grade eBPF firewall.
Ordered by **priority** — implement top-to-bottom.

> Each guide is self-contained. Any agent (human or AI) can pick one and implement it
> independently, following the exact steps and acceptance criteria.

| # | Guide | Priority | Effort | Status |
|---|-------|----------|--------|--------|
| 01 | [Offline GeoIP (MaxMind)](01_offline_geoip.md) | **CRITICAL** | ~3h | ⬜ |
| 02 | [Config File (TOML)](02_config_file.md) | **HIGH** | ~2h | ⬜ |
| 03 | [IP Allowlist](03_allowlist.md) | **HIGH** | ~2h | ⬜ |
| 04 | [Build Info + --version](04_build_info.md) | MEDIUM | ~30m | ⬜ |
| 05 | [Shell Completions](05_shell_completions.md) | MEDIUM | ~30m | ⬜ |
| 06 | [Uninstall (--uninstall)](06_uninstall.md) | MEDIUM | ~30m | ⬜ |
| 07 | [Structured JSON Logging](07_json_logging.md) | MEDIUM | ~2h | ⬜ |
| 08 | [Status Command](08_status_command.md) | MEDIUM | ~1h | ⬜ |
| 09 | [Logrotate Config](09_logrotate.md) | MEDIUM | ~30m | ⬜ |
| 10 | [Prometheus Metrics](10_prometheus_metrics.md) | LOW | ~3h | ⬜ |

## Dependency Graph

```
01 Offline GeoIP ─────────────────────────── standalone
02 Config File ──────┬──── 03 Allowlist (uses config.allowlist section)
                     ├──── 07 JSON Logging (uses config.logging section)
                     └──── 10 Prometheus (uses config.metrics section)
04 Build Info ────────────────────────────── standalone
05 Shell Completions ─────────────────────── standalone
06 Uninstall ─────────────────────────────── standalone (refs 01, 02 dirs)
08 Status Command ────────────────────────── standalone
09 Logrotate ─────────── depends on 07 (SIGHUP handler)
```

## For AI Agents

Each guide contains:
- **Problem** — what's wrong and why it matters
- **Solution** — architecture and approach
- **Dependencies** — Cargo.toml changes
- **Step-by-step code** — exact Rust code, file paths, line references
- **Testing** — verification commands
- **Acceptance criteria** — checkboxes for done definition
- **Files changed** — table of all touched files with actions
