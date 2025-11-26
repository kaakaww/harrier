//! Chrome profile management for HAR capture.
//!
//! This module provides functionality for managing Chrome user profiles, which persist
//! browser state (cookies, extensions, settings) across HAR capture sessions.
//!
//! # Profile Types
//!
//! - **Temporary**: Auto-deleted after use. Created in temp directory.
//! - **Persistent**: Stored in `~/.harrier/profiles/<name>`. Survives across sessions.
//! - **Default**: Special persistent profile at `~/.harrier/profiles/default`.
//!
//! # Cache Management
//!
//! Profiles retain all browser data except cache, which is cleared on every `chrome` command
//! run via CDP. This ensures:
//! - Fresh network requests that appear in HAR files
//! - Preserved authentication and session state
//! - Consistent capture behavior
//!
//! # Examples
//!
//! ```no_run
//! use harrier_browser::ProfileManager;
//!
//! // Create a temporary profile
//! let temp = ProfileManager::temporary()?;
//! // Profile deleted when `temp` is dropped
//!
//! // Create a persistent profile
//! let persistent = ProfileManager::persistent("/path/to/profile".into())?;
//!
//! // Use the default profile
//! let default = ProfileManager::default_profile()?;
//! # Ok::<(), harrier_browser::Error>(())
//! ```

use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Calculate the total size of a directory recursively
fn calculate_dir_size(path: &Path) -> Result<u64> {
    let mut total_size = 0u64;

    if path.is_dir() {
        for entry in std::fs::read_dir(path).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                total_size += calculate_dir_size(&entry_path)?;
            } else {
                total_size += entry.metadata().map_err(Error::Io)?.len();
            }
        }
    }

    Ok(total_size)
}

/// Manages Chrome profile directories
pub struct ProfileManager {
    path: PathBuf,
    is_temporary: bool,
}

impl ProfileManager {
    /// Create a temporary profile that will be deleted on drop
    pub fn temporary() -> Result<Self> {
        let temp_dir = tempfile::tempdir().map_err(Error::Io)?;

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
            std::fs::create_dir_all(&path).map_err(Error::Io)?;
        }

        Ok(Self {
            path,
            is_temporary: false,
        })
    }

    /// Create or use the default persistent profile
    pub fn default_profile() -> Result<Self> {
        let default_path = Self::get_default_profile_path()?;
        let is_new = !default_path.exists();

        let profile = Self::persistent(default_path.clone())?;

        if is_new {
            eprintln!("📁 Created default profile at {}", default_path.display());
            eprintln!(
                "   This profile will persist between sessions, retaining logins and extensions."
            );
            eprintln!(
                "   Use --temp for temporary profiles or --profile <name> for named profiles."
            );
        }

        Ok(profile)
    }

    /// Get the path to the default profile directory
    pub fn get_default_profile_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Browser("Could not determine home directory".to_string()))?;

        Ok(home.join(".harrier").join("profiles").join("default"))
    }

    /// Get the path to the profiles directory
    pub fn get_profiles_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Browser("Could not determine home directory".to_string()))?;

        Ok(home.join(".harrier").join("profiles"))
    }

    /// Get the profile directory path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if this is a temporary profile
    pub fn is_temporary(&self) -> bool {
        self.is_temporary
    }

    /// Calculate the disk size of the profile directory in bytes
    pub fn get_size(&self) -> Result<u64> {
        calculate_dir_size(&self.path)
    }

    /// Clear the cache directories within the profile
    /// This removes Cache, Code Cache, GPUCache, etc. but preserves cookies, extensions, etc.
    pub fn clear_cache(&self) -> Result<()> {
        let cache_dirs = vec![
            "Cache",
            "Code Cache",
            "GPUCache",
            "Service Worker",
            "DawnCache",
        ];

        for cache_dir in cache_dirs {
            let cache_path = self.path.join(cache_dir);
            if cache_path.exists() {
                std::fs::remove_dir_all(&cache_path).map_err(Error::Io)?;
            }
        }

        Ok(())
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

    #[test]
    fn test_default_profile_is_persistent() {
        // Note: This test uses the actual default profile location
        // In a real scenario, you might want to mock this
        let profile = ProfileManager::default_profile().unwrap();
        let path = profile.path().to_path_buf();

        assert!(path.exists());
        assert!(path.is_dir());
        assert!(!profile.is_temporary());
        assert!(path.ends_with("default"));

        drop(profile);

        // Default profile should still exist after drop
        assert!(path.exists());
    }

    #[test]
    fn test_get_size_calculates_correctly() {
        let temp_dir = tempfile::tempdir().unwrap();
        let profile_path = temp_dir.path().join("size-test");

        let profile = ProfileManager::persistent(profile_path.clone()).unwrap();

        // Create some test files
        std::fs::write(profile_path.join("file1.txt"), "hello").unwrap();
        std::fs::write(profile_path.join("file2.txt"), "world!").unwrap();

        let size = profile.get_size().unwrap();
        assert_eq!(size, 11); // "hello" (5) + "world!" (6)

        drop(profile);
        std::fs::remove_dir_all(profile_path).unwrap();
    }

    #[test]
    fn test_clear_cache_preserves_other_data() {
        let temp_dir = tempfile::tempdir().unwrap();
        let profile_path = temp_dir.path().join("cache-test");

        let profile = ProfileManager::persistent(profile_path.clone()).unwrap();

        // Create cache directories
        std::fs::create_dir(profile_path.join("Cache")).unwrap();
        std::fs::write(profile_path.join("Cache").join("data"), "cached").unwrap();

        std::fs::create_dir(profile_path.join("Code Cache")).unwrap();
        std::fs::write(profile_path.join("Code Cache").join("data"), "code").unwrap();

        // Create non-cache data
        std::fs::write(profile_path.join("Cookies"), "cookies").unwrap();
        std::fs::create_dir(profile_path.join("Extensions")).unwrap();
        std::fs::write(profile_path.join("Extensions").join("ext"), "ext").unwrap();

        profile.clear_cache().unwrap();

        // Cache should be gone
        assert!(!profile_path.join("Cache").exists());
        assert!(!profile_path.join("Code Cache").exists());

        // Other data should remain
        assert!(profile_path.join("Cookies").exists());
        assert!(profile_path.join("Extensions").exists());
        assert!(profile_path.join("Extensions").join("ext").exists());

        drop(profile);
        std::fs::remove_dir_all(profile_path).unwrap();
    }
}
