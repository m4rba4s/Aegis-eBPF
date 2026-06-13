//! Policy reload lifecycle.
//!
//! Live replacement is intentionally disabled for this release candidate.
//! Updating several BPF maps entry by entry cannot provide an atomic datapath
//! policy switch: packets could observe an empty or partially replaced policy.
//! Operators must stage complete configuration files and restart the service.

use tracing::warn;

pub const HOT_RELOAD_SUPPORTED: bool = false;
const _: () = assert!(!HOT_RELOAD_SUPPORTED);

/// Report the release policy for configuration changes.
///
/// The paths remain arguments so the daemon call site documents both policy
/// inputs. No watcher is spawned and no live BPF map is modified.
pub fn spawn_config_watcher(toml_path: &str, yaml_path: &str) {
    warn!(
        toml_path,
        yaml_path,
        "live policy reload is disabled for this release candidate; \
         validate complete files and restart Aegis to apply policy changes"
    );
}
