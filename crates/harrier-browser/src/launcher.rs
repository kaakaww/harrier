use crate::{Error, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Manages Chrome process lifecycle
pub struct ChromeLauncher {
    chrome_path: PathBuf,
    profile_path: PathBuf,
    initial_url: Option<String>,
    debugging_port: u16,
}

impl ChromeLauncher {
    /// Create a new ChromeLauncher
    pub fn new(chrome_path: PathBuf, profile_path: PathBuf, initial_url: Option<String>) -> Self {
        Self {
            chrome_path,
            profile_path,
            initial_url,
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
        let mut args = vec![
            format!("--remote-debugging-port={}", self.debugging_port),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
            format!("--user-data-dir={}", self.profile_path.display()),
        ];

        // Add initial URL with proper scheme
        if let Some(url) = &self.initial_url {
            let url = if !url.starts_with("http://") && !url.starts_with("https://") {
                format!("https://{}", url)
            } else {
                url.clone()
            };
            args.push(url);
        } else {
            args.push("about:blank".to_string());
        }

        args
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

        let launcher = ChromeLauncher {
            chrome_path,
            profile_path,
            initial_url: Some("https://example.com".to_string()),
            debugging_port: 9222,
        };

        let args = launcher.build_args();

        assert!(args.contains(&"--remote-debugging-port=9222".to_string()));
        assert!(args.contains(&"--no-first-run".to_string()));
        assert!(args.contains(&"--no-default-browser-check".to_string()));
        assert!(args.iter().any(|a| a.starts_with("--user-data-dir=")));
        assert!(args.contains(&"https://example.com".to_string()));
    }

    #[test]
    fn test_chrome_launcher_default_url() {
        let chrome_path = PathBuf::from("/usr/bin/google-chrome");
        let profile_path = PathBuf::from("/tmp/profile");

        let launcher = ChromeLauncher {
            chrome_path,
            profile_path,
            initial_url: None,
            debugging_port: 9222,
        };

        let args = launcher.build_args();

        assert!(args.contains(&"about:blank".to_string()));
    }
}
