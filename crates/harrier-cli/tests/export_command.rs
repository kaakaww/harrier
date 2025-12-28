use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

#[allow(deprecated)]
fn get_harrier_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin("harrier")
}

fn get_sample_har() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/sample.har")
}

#[test]
fn test_export_command_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Export HAR analysis"))
        .stdout(predicate::str::contains("--hawkscan"))
        .stdout(predicate::str::contains("--host"))
        .stdout(predicate::str::contains("--all-hosts"))
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn test_export_hawkscan_default() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export").arg(get_sample_har()).arg("--hawkscan");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("HawkScan Configuration"))
        .stdout(predicate::str::contains("app:"))
        .stdout(predicate::str::contains("applicationId:"))
        .stdout(predicate::str::contains("host:"));
}

#[test]
fn test_export_hawkscan_json() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export")
        .arg(get_sample_har())
        .arg("--hawkscan")
        .arg("--format")
        .arg("json");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"host\""))
        .stdout(predicate::str::contains("\"port\""))
        .stdout(predicate::str::contains("\"is_primary\""))
        .stdout(predicate::str::contains("\"is_scannable\""));
}

#[test]
fn test_export_hawkscan_table() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export")
        .arg(get_sample_har())
        .arg("--hawkscan")
        .arg("--format")
        .arg("table");

    cmd.assert().success().stdout(predicate::str::contains(
        "Host,Port,Primary,Scannable,Notes",
    ));
}

#[test]
fn test_export_defaults_to_hawkscan() {
    // Without --hawkscan flag, should still work (with a note)
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export").arg(get_sample_har());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("defaulting to --hawkscan"))
        .stdout(predicate::str::contains("HawkScan Configuration"));
}

#[test]
fn test_export_file_not_found() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export")
        .arg("/nonexistent/file.har")
        .arg("--hawkscan");

    cmd.assert().failure();
}

#[test]
fn test_export_host_filter() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export")
        .arg(get_sample_har())
        .arg("--hawkscan")
        .arg("--host")
        .arg("api.example.com");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("api.example.com"));
}

#[test]
fn test_export_all_hosts() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("export")
        .arg(get_sample_har())
        .arg("--hawkscan")
        .arg("--all-hosts");

    // With --all-hosts, should include non-scannable hosts as well
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("HawkScan Configuration"));
}
