#![no_main]

use libfuzzer_sys::fuzz_target;
use aegis_cli::config::AegisConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<AegisConfig>(s);
    }
});
