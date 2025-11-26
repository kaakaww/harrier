use crate::{Error, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Manages Chrome process lifecycle
pub struct ChromeLauncher {
    chrome_path: PathBuf,
    profile_path: PathBuf,
    debugging_port: u16,
}

impl ChromeLauncher {
    /// Create a new ChromeLauncher
    /// Note: Chrome always launches to about:blank. Use CdpSession::navigate_to() to navigate after clearing cache.
    pub fn new(chrome_path: PathBuf, profile_path: PathBuf) -> Self {
        Self {
            chrome_path,
            profile_path,
            debugging_port: 9222,
        }
    }

    /// Launch Chrome process
    pub fn launch(&self) -> Result<Child> {
        let args = self.build_args();

        Command::new(&self.chrome_path)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Browser(format!("Failed to launch Chrome: {}", e)))
    }

    /// Build Chrome command-line arguments
    fn build_args(&self) -> Vec<String> {
        vec![
            format!("--remote-debugging-port={}", self.debugging_port),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
            format!("--user-data-dir={}", self.profile_path.display()),
            "about:blank".to_string(),
        ]
    }

    /// Get the debugging port
    pub fn debugging_port(&self) -> u16 {
        self.debugging_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_chrome_launcher_builds_args() {
        let chrome_path = PathBuf::from("/usr/bin/google-chrome");
        let profile_path = PathBuf::from("/tmp/profile");

        let launcher = ChromeLauncher::new(chrome_path, profile_path);
        let args = launcher.build_args();

        assert!(args.contains(&"--remote-debugging-port=9222".to_string()));
        assert!(args.contains(&"--no-first-run".to_string()));
        assert!(args.contains(&"--no-default-browser-check".to_string()));
        assert!(args.iter().any(|a| a.starts_with("--user-data-dir=")));
        assert!(args.contains(&"about:blank".to_string()));
    }

    #[test]
    fn test_chrome_launcher_always_uses_blank() {
        let chrome_path = PathBuf::from("/usr/bin/google-chrome");
        let profile_path = PathBuf::from("/tmp/profile");

        let launcher = ChromeLauncher::new(chrome_path, profile_path);
        let args = launcher.build_args();

        // Should always use about:blank, navigation happens via CDP
        assert!(args.contains(&"about:blank".to_string()));
        assert_eq!(args.iter().filter(|a| a.contains("http")).count(), 0);
    }
}
