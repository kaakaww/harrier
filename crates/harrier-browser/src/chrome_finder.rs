use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Locates Chrome binary on the system
pub struct ChromeFinder {
    custom_path: Option<PathBuf>,
}

impl ChromeFinder {
    /// Create a new ChromeFinder with optional custom path
    pub fn new(custom_path: Option<PathBuf>) -> Self {
        Self { custom_path }
    }

    /// Find Chrome binary, checking custom path first, then platform defaults
    pub fn find(&self) -> Result<PathBuf> {
        // Try custom path first
        if let Some(ref path) = self.custom_path {
            return self.validate_chrome_path(path);
        }

        // Try platform-specific default paths
        let default_paths = Self::default_paths();
        for path in default_paths {
            if let Ok(valid_path) = self.validate_chrome_path(&path) {
                return Ok(valid_path);
            }
        }

        Err(Error::Browser(format!(
            "Chrome not found. Checked: {}. Use --chrome-path to specify location.",
            Self::default_paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// Get platform-specific default Chrome paths
    fn default_paths() -> Vec<PathBuf> {
        #[cfg(target_os = "macos")]
        return vec![
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        ];

        #[cfg(target_os = "linux")]
        return vec![
            PathBuf::from("/usr/bin/google-chrome"),
            PathBuf::from("/usr/bin/chromium"),
            PathBuf::from("/usr/bin/chromium-browser"),
        ];

        #[cfg(target_os = "windows")]
        return vec![
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        ];

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return vec![];
    }

    /// Validate that a path exists and is executable
    fn validate_chrome_path(&self, path: &Path) -> Result<PathBuf> {
        if !path.exists() {
            return Err(Error::Browser(format!(
                "Chrome not found at: {}",
                path.display()
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).map_err(Error::Io)?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 == 0 {
                return Err(Error::Browser(format!(
                    "Chrome binary not executable: {}",
                    path.display()
                )));
            }
        }

        Ok(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_chrome_finder_finds_custom_path() {
        // Create temp chrome executable
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let finder = ChromeFinder::new(Some(path.to_path_buf()));
        let result = finder.find();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn test_chrome_finder_fails_when_not_found() {
        let finder = ChromeFinder::new(Some(PathBuf::from("/nonexistent/chrome")));
        let result = finder.find();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
}
