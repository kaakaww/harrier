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
fn test_analyze_command_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Analyze HAR"))
        .stdout(predicate::str::contains("--focus"))
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--host"));
}

#[test]
fn test_analyze_default_output() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze").arg(get_sample_har());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Harrier Analysis"))
        .stdout(predicate::str::contains("Overview"))
        .stdout(predicate::str::contains("Architecture"))
        .stdout(predicate::str::contains("Authentication"))
        .stdout(predicate::str::contains("Next Steps"));
}

#[test]
fn test_analyze_focus_map() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--focus")
        .arg("map");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Architecture"))
        .stdout(predicate::str::contains("Primary Host"))
        .stdout(predicate::str::contains("Hosts:"));
}

#[test]
fn test_analyze_focus_auth() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--focus")
        .arg("auth");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Authentication"))
        .stdout(predicate::str::contains("Method:"));
}

#[test]
fn test_analyze_all_flag() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze").arg(get_sample_har()).arg("--all");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Architecture"))
        .stdout(predicate::str::contains("Authentication"))
        // --all should NOT show "Next Steps"
        .stdout(predicate::str::contains("Next Steps").not());
}

#[test]
fn test_analyze_json_output() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--format")
        .arg("json");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"file_name\""))
        .stdout(predicate::str::contains("\"total_entries\""))
        .stdout(predicate::str::contains("\"architecture\""))
        .stdout(predicate::str::contains("\"authentication\""));
}

#[test]
fn test_analyze_table_output() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--format")
        .arg("table");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Metric,Value"))
        .stdout(predicate::str::contains("Total Entries"));
}

#[test]
fn test_analyze_multiple_focus() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--focus")
        .arg("map")
        .arg("--focus")
        .arg("auth");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Architecture"))
        .stdout(predicate::str::contains("Authentication"));
}

#[test]
fn test_analyze_file_not_found() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze").arg("/nonexistent/file.har");

    cmd.assert().failure();
}

#[test]
fn test_analyze_host_filter() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("analyze")
        .arg(get_sample_har())
        .arg("--host")
        .arg("api.example.com")
        .arg("--focus")
        .arg("map");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("api.example.com"));
}
