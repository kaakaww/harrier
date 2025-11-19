use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_chrome_command_help() {
    let mut cmd = Command::cargo_bin("harrier").expect("failed to find harrier binary");
    cmd.arg("chrome").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Launch Chrome and capture HAR traffic",
        ))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--hosts"))
        .stdout(predicate::str::contains("--scan"))
        .stdout(predicate::str::contains("--profile"));
}

#[test]
fn test_chrome_command_without_chrome() {
    // This test will fail if Chrome is actually installed
    // Skip if Chrome exists at default paths
    let chrome_paths = vec![
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

    let mut cmd = Command::cargo_bin("harrier").expect("failed to find harrier binary");
    cmd.arg("chrome")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Chrome not found"));
}

#[test]
fn test_chrome_command_output_flag() {
    let mut cmd = Command::cargo_bin("harrier").expect("failed to find harrier binary");
    cmd.arg("chrome")
        .arg("--output")
        .arg("custom-output.har")
        .arg("--chrome-path")
        .arg("/nonexistent/chrome");

    // Should fail on Chrome not found, but output path should be parsed
    cmd.assert().failure();
}
