use std::process::Command;

#[test]
fn prints_help_and_reports_invalid_usage_with_distinct_exit_statuses() {
    let executable = env!("CARGO_BIN_EXE_blt_unlock");
    let help = Command::new(executable).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: blt_unlock"));

    let invalid = Command::new(executable)
        .args(["--weight", "--seconds", "0"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("Usage: blt_unlock"));
}
