//! Profile management commands for Chrome profiles.
//!
//! This module provides CLI commands for managing Chrome profiles used by the `chrome` command.
//! Profiles store browser state (cookies, extensions, settings) and can be:
//! - Listed to see all available profiles
//! - Inspected for detailed information (size, extensions, cookies)
//! - Deleted to reclaim disk space
//! - Cleaned to remove cache while preserving other data
//!
//! # Examples
//!
//! ```bash
//! # List all profiles
//! harrier profile list
//!
//! # Show profile details
//! harrier profile info default
//!
//! # Delete a profile
//! harrier profile delete old-profile
//!
//! # Clean cache from all profiles
//! harrier profile clean
//! ```

use anyhow::{Result, anyhow};
use harrier_browser::ProfileManager;
use std::fs;
use std::io::{self, Write};

/// List all available profiles
pub fn list() -> Result<()> {
    let profiles_dir = ProfileManager::get_profiles_dir()?;

    if !profiles_dir.exists() {
        println!(
            "No profiles found. Profiles will be created in: {}",
            profiles_dir.display()
        );
        return Ok(());
    }

    let mut profiles = Vec::new();

    for entry in fs::read_dir(&profiles_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow!("Invalid profile name"))?
                .to_string();

            let profile = ProfileManager::persistent(path.clone())?;
            let size = profile.get_size().unwrap_or(0);

            profiles.push((name, path, size));
        }
    }

    if profiles.is_empty() {
        println!("No profiles found.");
        return Ok(());
    }

    profiles.sort_by(|a, b| a.0.cmp(&b.0));

    println!("Available profiles:");
    println!();

    const SIZE_WARNING_THRESHOLD: u64 = 1_073_741_824; // 1GB
    let mut has_warnings = false;

    for (name, path, size) in profiles {
        let is_default = name == "default";
        let marker = if is_default { "* " } else { "  " };
        let size_mb = size as f64 / 1_048_576.0;

        let warning = if size > SIZE_WARNING_THRESHOLD {
            has_warnings = true;
            " ⚠️  Large"
        } else {
            ""
        };

        println!(
            "{}{:<20} {:>8.1} MB    {}{}",
            marker,
            name,
            size_mb,
            path.display(),
            warning
        );
    }

    if has_warnings {
        println!();
        println!(
            "⚠️  Some profiles exceed 1GB. Consider using 'harrier profile clean' to reclaim space."
        );
    }

    Ok(())
}

/// Show detailed information about a profile
pub fn info(name: &str) -> Result<()> {
    let profiles_dir = ProfileManager::get_profiles_dir()?;
    let profile_path = profiles_dir.join(name);

    if !profile_path.exists() {
        return Err(anyhow!("Profile '{}' not found", name));
    }

    let profile = ProfileManager::persistent(profile_path.clone())?;
    let size = profile.get_size()?;
    let size_mb = size as f64 / 1_048_576.0;

    // Get metadata
    let metadata = fs::metadata(&profile_path)?;
    let created = metadata.created().ok().and_then(|time| {
        use std::time::SystemTime;
        let duration = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        Some(
            chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)?
                .format("%Y-%m-%d")
                .to_string(),
        )
    });

    // Count extensions and cookies (approximate)
    let extensions_dir = profile_path.join("Extensions");
    let extensions_count = if extensions_dir.exists() {
        fs::read_dir(&extensions_dir)?.count()
    } else {
        0
    };

    let cookies_file = profile_path.join("Cookies");
    let has_cookies = cookies_file.exists();

    println!("Profile: {}", name);
    println!("Path: {}", profile_path.display());
    println!("Size: {:.1} MB ({} bytes)", size_mb, size);

    if let Some(created_date) = created {
        println!("Created: {}", created_date);
    }

    println!("Extensions: {}", extensions_count);
    println!("Cookies: {}", if has_cookies { "Yes" } else { "No" });

    Ok(())
}

/// Delete a profile
pub fn delete(name: &str, force: bool) -> Result<()> {
    let profiles_dir = ProfileManager::get_profiles_dir()?;
    let profile_path = profiles_dir.join(name);

    if !profile_path.exists() {
        return Err(anyhow!("Profile '{}' not found", name));
    }

    // Protect default profile unless force is used
    if name == "default" && !force {
        return Err(anyhow!(
            "Cannot delete 'default' profile without --force flag.\n\
             The default profile is used when no profile is specified.\n\
             Use: harrier profile delete default --force"
        ));
    }

    // Require confirmation
    if !force {
        print!(
            "⚠️  This will permanently delete profile '{}' and all its data.\nType '{}' to confirm: ",
            name, name
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim() != name {
            println!("Deletion cancelled.");
            return Ok(());
        }
    }

    fs::remove_dir_all(&profile_path)?;
    println!("✅ Profile '{}' deleted", name);

    Ok(())
}

/// Clean cache from profiles
pub fn clean(profile_name: Option<&str>) -> Result<()> {
    let profiles_dir = ProfileManager::get_profiles_dir()?;

    if !profiles_dir.exists() {
        println!("No profiles found.");
        return Ok(());
    }

    if let Some(name) = profile_name {
        // Clean specific profile
        let profile_path = profiles_dir.join(name);

        if !profile_path.exists() {
            return Err(anyhow!("Profile '{}' not found", name));
        }

        let profile = ProfileManager::persistent(profile_path)?;
        profile.clear_cache()?;
        println!("✅ Cache cleared for profile '{}'", name);
    } else {
        // Clean all profiles
        let mut cleaned = 0;

        for entry in fs::read_dir(&profiles_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow!("Invalid profile name"))?
                    .to_string();

                let profile = ProfileManager::persistent(path)?;
                profile.clear_cache()?;
                cleaned += 1;
                println!("  Cleaned: {}", name);
            }
        }

        println!("✅ Cache cleared from {} profile(s)", cleaned);
    }

    Ok(())
}
