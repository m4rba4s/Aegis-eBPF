use anyhow::Result;
use log::{error, info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    /// Recursively find all .yar/.yara rules, compile them, and return a YaraEngine instance.
    pub fn load_from_directory(dir_path: &str) -> Result<Option<Self>> {
        let path = Path::new(dir_path);
        if !path.exists() || !path.is_dir() {
            warn!("YARA Engine: Directory '{}' does not exist or is not a directory. Skipping YARA engine.", dir_path);
            return Ok(None);
        }

        let mut compiler = Compiler::new();
        let mut loaded_count = 0;

        // Collect all .yar and .yara files
        let yar_files = Self::find_rules_recursive(path)?;

        if yar_files.is_empty() {
            warn!(
                "YARA Engine: No .yar or .yara files found in '{}'.",
                dir_path
            );
            return Ok(None);
        }

        for file_path in yar_files {
            match fs::read_to_string(&file_path) {
                Ok(content) => {
                    if let Err(e) = compiler.add_source(content.as_str()) {
                        error!(
                            "YARA Engine: Failed to compile rule file '{}': {}",
                            file_path.display(),
                            e
                        );
                    } else {
                        loaded_count += 1;
                    }
                }
                Err(e) => {
                    error!(
                        "YARA Engine: Failed to read rule file '{}': {}",
                        file_path.display(),
                        e
                    );
                }
            }
        }

        if loaded_count == 0 {
            warn!("YARA Engine: Failed to load any valid rules.");
            return Ok(None);
        }

        let rules = compiler.build();
        info!(
            "YARA Engine: Compiled {} rules files from '{}'.",
            loaded_count, dir_path
        );

        Ok(Some(Self { rules }))
    }

    /// Recursively find rule files
    fn find_rules_recursive(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    files.extend(Self::find_rules_recursive(&path)?);
                } else if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        files.push(path);
                    }
                }
            }
        }
        Ok(files)
    }

    /// Scan a payload buffer against compiled YARA rules.
    /// Returns a list of matched rule names.
    pub fn scan_payload(&self, payload: &[u8]) -> Vec<String> {
        let mut scanner = Scanner::new(&self.rules);
        match scanner.scan(payload) {
            Ok(scan_results) => {
                let mut matched_rules = Vec::new();
                for rule in scan_results.matching_rules() {
                    matched_rules.push(rule.identifier().to_string());
                }
                matched_rules
            }
            Err(e) => {
                error!("YARA Engine: Scanning error: {}", e);
                Vec::new()
            }
        }
    }
}
