use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

#[allow(deprecated)]
fn get_harrier_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin("harrier")
}

#[test]
fn test_profile_command_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Manage Chrome profiles"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("clean"));
}

#[test]
fn test_profile_list_command() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("list");

    // Should succeed and show profiles or "No profiles found"
    cmd.assert().success();
}

#[test]
fn test_profile_list_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("list").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("List all available profiles"));
}

#[test]
fn test_profile_info_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("info").arg("--help");

    cmd.assert().success().stdout(predicate::str::contains(
        "Show detailed information about a profile",
    ));
}

#[test]
fn test_profile_info_nonexistent() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile")
        .arg("info")
        .arg("nonexistent-profile-12345");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_profile_delete_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("delete").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Delete a profile"))
        .stdout(predicate::str::contains("--force"));
}

#[test]
fn test_profile_delete_nonexistent() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile")
        .arg("delete")
        .arg("nonexistent-profile-12345")
        .arg("--force");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_profile_delete_default_requires_force() {
    // This test verifies the error message, not actual deletion
    // We won't actually delete the default profile in tests
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("delete").arg("default");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
}

#[test]
fn test_profile_clean_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("clean").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Clear cache from profiles"))
        .stdout(predicate::str::contains("--profile"));
}

#[test]
fn test_profile_clean_command() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile").arg("clean");

    // Should succeed even if no profiles exist
    cmd.assert().success();
}

#[test]
fn test_profile_clean_specific() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("profile")
        .arg("clean")
        .arg("--profile")
        .arg("nonexistent-profile-12345");

    // Should fail if profile doesn't exist
    cmd.assert().failure();
}
