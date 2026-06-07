use std::process::Command;

#[test]
fn test_cli_completions_no_banner() {
    let cargo_bin = env!("CARGO_BIN_EXE_aegis-cli");
    let output = Command::new(cargo_bin)
        .arg("completions")
        .arg("bash")
        .output()
        .expect("Failed to execute aegis-cli completions bash");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // The banner contains the following string, it must NOT be in the completions output
    assert!(!stdout.contains("AEGIS eBPF FIREWALL"));
    assert!(!stdout.contains("██████"));

    // The output should contain bash completion scripts
    assert!(stdout.contains("_aegis-cli() {"));
}

#[test]
fn test_cli_manpage_no_banner() {
    let cargo_bin = env!("CARGO_BIN_EXE_aegis-cli");
    
    let temp_dir = std::env::temp_dir();
    let man_path = temp_dir.join("aegis_man_test");
    std::fs::create_dir_all(&man_path).unwrap();

    let output = Command::new(cargo_bin)
        .arg("manpage")
        .arg(&man_path)
        .output()
        .expect("Failed to execute aegis-cli manpage");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // The banner should NOT be in the stdout
    assert!(!stdout.contains("AEGIS eBPF FIREWALL"));
    assert!(!stdout.contains("██████"));

    // Verify generated files
    assert!(
        std::fs::read_dir(&man_path).unwrap().next().is_some(),
        "manpage command should generate at least one manpage file"
    );

    let mut combined = String::new();
    for entry in std::fs::read_dir(&man_path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            combined.push_str(&std::fs::read_to_string(path).unwrap_or_default());
        }
    }

    assert!(!combined.contains("AEGIS eBPF FIREWALL"));
    assert!(!combined.contains("██████"));
}
