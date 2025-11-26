use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

#[allow(deprecated)]
fn get_harrier_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin("harrier")
}

#[test]
fn test_completion_command_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Generate shell completion scripts",
        ))
        .stdout(predicate::str::contains("SUPPORTED SHELLS"))
        .stdout(predicate::str::contains("bash"))
        .stdout(predicate::str::contains("zsh"))
        .stdout(predicate::str::contains("fish"))
        .stdout(predicate::str::contains("powershell"))
        .stdout(predicate::str::contains("INSTALLATION"))
        .stdout(predicate::str::contains("~/.bashrc"))
        .stdout(predicate::str::contains("~/.zshrc"));
}

#[test]
fn test_completion_bash_generates_script() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--shell").arg("bash");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("_harrier()"))
        .stdout(predicate::str::contains("complete -F _harrier"));
}

#[test]
fn test_completion_zsh_generates_script() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--shell").arg("zsh");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("#compdef harrier"))
        .stdout(predicate::str::contains("_harrier()"));
}

#[test]
fn test_completion_fish_generates_script() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--shell").arg("fish");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("__fish_harrier"))
        .stdout(predicate::str::contains("complete -c harrier"));
}

#[test]
fn test_completion_powershell_generates_script() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--shell").arg("powershell");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Register-ArgumentCompleter"))
        .stdout(predicate::str::contains("-CommandName 'harrier'"));
}

#[test]
fn test_completion_invalid_shell() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion").arg("--shell").arg("invalid-shell");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn test_completion_requires_shell_flag() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("completion");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_completion_appears_in_main_help() {
    let mut cmd = Command::new(get_harrier_bin());
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("completion"))
        .stdout(predicate::str::contains("Generate shell completion"));
}
