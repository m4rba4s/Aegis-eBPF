# Guide 01: Offline GeoIP (MaxMind GeoLite2)

> **Priority: CRITICAL** — Current implementation leaks every observed IP to ip-api.com via HTTP.
> This is a privacy/OPSEC violation and has a 45 req/min rate limit.

## Problem

File: `aegis-cli/src/tui/mod.rs`, lines 170-210.

Current flow:
```
1. TUI observes connection to IP X
2. Spawns thread → HTTP GET http://ip-api.com/json/X
3. Parses JSON → extracts countryCode, city, isp
4. Caches in HashMap<IpAddr, String>
```

Issues:
- **Privacy leak**: every IP your firewall sees gets sent to a third party
- **Rate limit**: ip-api.com free tier = 45 requests/minute, then 429 errors
- **Latency**: 200-500ms per lookup, spawns unbounded threads
- **Offline broken**: no network = no geo at all

## Solution

Use MaxMind GeoLite2-City mmdb database with the `maxminddb` Rust crate.
Lookups are local, instant (~1μs), and unlimited.

## Dependencies

Add to `aegis-cli/Cargo.toml`:
```toml
maxminddb = "0.24"
```

Remove (no longer needed for geo):
```toml
# reqwest is still needed for feed downloads, keep it
# serde_json is still needed, keep it
```

## Step-by-Step Implementation

### Step 1: Download GeoLite2 database

MaxMind requires free registration at https://dev.maxmind.com/geoip/geolite2-free-geolite2-databases

The database file is `GeoLite2-City.mmdb` (~70MB).

For distribution, embed a download step in `install.sh`:

```bash
# Add to install.sh after binary install
install_geoip_db() {
    local db_dir="/var/lib/aegis"
    local db_path="$db_dir/GeoLite2-City.mmdb"

    mkdir -p "$db_dir"

    if [[ -f "$db_path" ]]; then
        log_ok "GeoIP database exists: $db_path"
        return 0
    fi

    log_info "GeoIP database not found at $db_path"
    log_info "Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolite2-databases"
    log_info "Place it at: $db_path"
    log_warn "TUI will show 'No GeoDB' until database is installed"
}
```

### Step 2: Create geo module

Create new file `aegis-cli/src/geo.rs`:

```rust
use maxminddb::{self, geoip2};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

const GEODB_PATHS: &[&str] = &[
    "/var/lib/aegis/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",     // Debian/Ubuntu default
    "/usr/share/GeoIP2/GeoLite2-City.mmdb",     // Fedora
];

pub struct GeoLookup {
    reader: maxminddb::Reader<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct GeoResult {
    pub country_code: String,
    pub city: String,
    pub isp: String,  // Not available in GeoLite2-City, needs GeoLite2-ASN
}

impl GeoLookup {
    /// Try to open GeoIP database from known paths
    pub fn open() -> Option<Self> {
        for path in GEODB_PATHS {
            if Path::new(path).exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(reader) => {
                        log::info!("GeoIP database loaded: {}", path);
                        return Some(Self { reader });
                    }
                    Err(e) => {
                        log::warn!("Failed to open {}: {}", path, e);
                    }
                }
            }
        }
        log::warn!("No GeoIP database found. TUI will show 'No GeoDB'");
        None
    }

    /// Look up an IP address — returns (country_code, city) or None
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoResult> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?;

        let country_code = city.country
            .as_ref()
            .and_then(|c| c.iso_code)
            .unwrap_or("??")
            .to_string();

        let city_name = city.city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .unwrap_or(&"")
            .to_string();

        Some(GeoResult {
            country_code,
            city: city_name,
            isp: String::new(), // Requires separate ASN database
        })
    }
}

/// Thread-safe wrapper for optional GeoIP
pub type SharedGeoLookup = Option<Arc<GeoLookup>>;
```

### Step 3: Modify TUI to use offline lookup

In `aegis-cli/src/tui/mod.rs`:

1. Add field to `App`:
```rust
pub struct App<T: ...> {
    // ... existing fields ...
    pub geo_db: SharedGeoLookup,  // ADD THIS
}
```

2. Initialize in `App::new()`:
```rust
pub fn new(blocklist: ...) -> Self {
    let geo_db = GeoLookup::open().map(Arc::new);
    Self {
        // ... existing fields ...
        geo_db,
    }
}
```

3. Replace the HTTP lookup block in `on_tick()` (lines 153-215).

**REMOVE** the entire block that does:
- `thread::spawn` with `reqwest::blocking::Client`
- HTTP GET to `ip-api.com`
- JSON parsing

**REPLACE WITH**:
```rust
// Geo lookup for public IPs — offline database
if let Some(ref db) = self.geo_db {
    match db.lookup(ip) {
        Some(result) => {
            let geo_str = if result.city.is_empty() {
                result.country_code
            } else {
                format!("{} {}", result.country_code, result.city)
            };
            geo = geo_str;
        }
        None => {
            geo = "Unknown".to_string();
        }
    }
} else {
    geo = "No GeoDB".to_string();
}
```

4. **Remove** the `geo_cache` field from `App` — no longer needed (lookups are instant).

5. **Remove** `use serde_json::Value` if no longer needed elsewhere in TUI.

### Step 4: Register module

In `aegis-cli/src/main.rs`, add:
```rust
mod geo;
```

### Step 5: Update ConnectionInfo

Remove `isp` field OR keep it but populate from GeoLite2-ASN database (separate download).

### Step 6: Update Cargo.toml

```toml
maxminddb = "0.24"
```

## Testing

1. Download GeoLite2-City.mmdb to `/var/lib/aegis/`
2. Run `sudo aegis-cli -i eth0 tui`
3. Verify:
   - Geo column shows country codes instantly (no "..." delay)
   - No HTTP requests to ip-api.com (check with `tcpdump port 80`)
   - Private IPs still show "LAN" / "Localhost"
   - Missing database shows "No GeoDB" (not a crash)

## Acceptance Criteria

- [ ] No HTTP calls for GeoIP lookup
- [ ] Lookups < 1ms per IP
- [ ] Graceful degradation when no database
- [ ] Country code + city displayed in TUI
- [ ] `reqwest` still works for feed downloads (don't remove it)

## Files Changed

| File | Action |
|------|--------|
| `aegis-cli/src/geo.rs` | **NEW** — GeoIP module |
| `aegis-cli/src/tui/mod.rs` | **MODIFY** — replace HTTP lookup with mmdb |
| `aegis-cli/src/main.rs` | **MODIFY** — add `mod geo;` |
| `aegis-cli/Cargo.toml` | **MODIFY** — add `maxminddb = "0.24"` |
| `install.sh` | **MODIFY** — add GeoIP download helper |
