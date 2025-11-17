use anyhow::Result;
use harrier_browser::{ChromeFinder, ChromeLauncher, ProfileManager};
use std::path::{Path, PathBuf};

pub fn execute(
    output: &Path,
    hosts: Vec<String>,
    scan: bool,
    chrome_path: Option<PathBuf>,
    url: Option<String>,
    profile: Option<String>,
) -> Result<()> {
    // Step 1: Find Chrome binary
    println!("🔍 Locating Chrome...");
    let finder = ChromeFinder::new(chrome_path);
    let chrome_binary = finder.find()?;
    println!("✅ Found Chrome at: {}", chrome_binary.display());

    // Step 2: Setup profile
    let profile_manager = if let Some(profile_name) = profile {
        let profile_path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
            .join(".harrier")
            .join("profiles")
            .join(profile_name.clone());

        println!("📁 Using profile: {}", profile_path.display());
        ProfileManager::persistent(profile_path)?
    } else {
        println!("📁 Using temporary profile");
        ProfileManager::temporary()?
    };

    // Step 3: Create launcher
    let launcher = ChromeLauncher::new(
        chrome_binary,
        profile_manager.path().to_path_buf(),
        url.clone(),
    );

    // Step 4: Launch Chrome
    println!("🚀 Launching Chrome...");
    let mut chrome_process = launcher.launch()?;
    println!("✅ Chrome started successfully");

    if let Some(start_url) = url {
        println!("📍 Navigating to: {}", start_url);
    }

    // TODO: Connect to CDP and capture traffic
    println!("📊 Capturing network traffic...");
    println!("   • Close Chrome when done");
    println!("   • Or press Ctrl+C to prompt shutdown");

    // Wait for Chrome to exit
    let status = chrome_process.wait()?;
    println!("🛑 Chrome closed (exit code: {})", status.code().unwrap_or(-1));

    // TODO: Save HAR file
    println!("📝 Output will be written to: {}", output.display());

    if !hosts.is_empty() {
        println!("🔍 Filters: {:?}", hosts);
    }

    if scan {
        println!("🦅 StackHawk scan will be triggered");
    }

    Ok(())
}
