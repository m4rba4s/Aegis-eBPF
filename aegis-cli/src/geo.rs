use maxminddb::{self, geoip2};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

const GEODB_PATHS: &[&str] = &[
    "/var/lib/aegis/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",     // Debian/Ubuntu default
    "/usr/share/GeoIP2/GeoLite2-City.mmdb",     // Fedora
    "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
    "GeoLite2-City.mmdb",                        // Local dev
];

pub struct GeoLookup {
    reader: maxminddb::Reader<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct GeoResult {
    pub country_code: String,
    pub city: String,
    pub isp: String,  // Not available in GeoLite2-City (requires ASN db), kept for API compatibility
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

    /// Look up an IP address — returns (country_code, city, isp)
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
            isp: String::new(), // Requires separate ASN database or Enterprise db
        })
    }
}

/// Thread-safe wrapper for optional GeoIP
pub type SharedGeoLookup = Option<Arc<GeoLookup>>;
