use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Manages Chrome profile directories
pub struct ProfileManager {
    path: PathBuf,
    is_temporary: bool,
}

impl ProfileManager {
    /// Create a temporary profile that will be deleted on drop
    pub fn temporary() -> Result<Self> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| Error::Io(e.into()))?;

        let path = temp_dir.keep();

        Ok(Self {
            path,
            is_temporary: true,
        })
    }

    /// Create or use a persistent profile at the given path
    pub fn persistent(path: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(&path)
                .map_err(|e| Error::Io(e))?;
        }

        Ok(Self {
            path,
            is_temporary: false,
        })
    }

    /// Get the profile directory path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if this is a temporary profile
    pub fn is_temporary(&self) -> bool {
        self.is_temporary
    }
}

impl Drop for ProfileManager {
    fn drop(&mut self) {
        if self.is_temporary && self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_profile_creates_and_cleans_up() {
        let profile = ProfileManager::temporary().unwrap();
        let path = profile.path().to_path_buf();

        assert!(path.exists());
        assert!(path.is_dir());

        drop(profile);

        // Temp profile should be deleted
        assert!(!path.exists());
    }

    #[test]
    fn test_persistent_profile_is_not_deleted() {
        let temp_dir = tempfile::tempdir().unwrap();
        let profile_path = temp_dir.path().join("test-profile");

        let profile = ProfileManager::persistent(profile_path.clone()).unwrap();
        assert!(profile_path.exists());

        drop(profile);

        // Persistent profile should still exist
        assert!(profile_path.exists());

        // Cleanup
        std::fs::remove_dir_all(profile_path).unwrap();
    }

    #[test]
    fn test_persistent_profile_creates_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let profile_path = temp_dir.path().join("new-profile");

        assert!(!profile_path.exists());

        let profile = ProfileManager::persistent(profile_path.clone()).unwrap();
        assert!(profile_path.exists());
        assert!(profile_path.is_dir());

        drop(profile);
        std::fs::remove_dir_all(profile_path).unwrap();
    }
}
