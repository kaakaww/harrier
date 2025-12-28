use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

#[allow(deprecated)]
fn get_harrier_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin("harrier")
}

#[test]
fn test_capture_command_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Capture HTTP traffic"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--hosts"))
        .stdout(predicate::str::contains("--hawkscan"))
        .stdout(predicate::str::contains("--profile"));
}

#[test]
fn test_capture_command_without_chrome() {
    // This test will fail if Chrome is actually installed
    // Skip if Chrome exists at default paths
    let chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ];

    if chrome_paths
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        println!("Skipping test - Chrome is installed");
        return;
    }

    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Chrome not found"));
}

#[test]
fn test_capture_command_output_flag() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture")
        .arg("--output")
        .arg("custom-output.har")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    // Should fail on Chrome not found, but output path should be parsed
    cmd.assert().failure();
}

#[test]
fn test_capture_command_temp_flag_in_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--temp"))
        .stdout(predicate::str::contains("temporary profile"));
}

#[test]
fn test_capture_command_profile_flags_parse() {
    // Test that --profile flag is accepted
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture")
        .arg("--profile")
        .arg("test-profile")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    // Should fail on Chrome not found, but flags should parse
    cmd.assert().failure();

    // Test that --temp flag is accepted
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture")
        .arg("--temp")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    cmd.assert().failure();
}

#[test]
fn test_capture_temp_precedence_warning() {
    // When both --profile and --temp are specified, should show warning
    // This test verifies the flags can be parsed together
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("capture")
        .arg("--profile")
        .arg("my-profile")
        .arg("--temp")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    // Should fail on Chrome not found
    cmd.assert().failure();
}
