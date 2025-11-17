use anyhow::Result;
use harrier_browser::{CdpSession, ChromeFinder, ChromeLauncher, ProfileManager};
use std::path::{Path, PathBuf};

pub fn execute(
    output: &Path,
    hosts: Vec<String>,
    scan: bool,
    chrome_path: Option<PathBuf>,
    url: Option<String>,
    profile: Option<String>,
) -> Result<()> {
    // Create tokio runtime for async operations
    let runtime = tokio::runtime::Runtime::new()?;

    runtime.block_on(async {
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

        let debugging_port = launcher.debugging_port();

        // Step 4: Launch Chrome
        println!("🚀 Launching Chrome...");
        let mut chrome_process = launcher.launch()?;
        println!("✅ Chrome started successfully");

        if let Some(start_url) = url {
            println!("📍 Starting at: {}", start_url);
        }

        println!("📊 Capturing network traffic...");
        println!("   • Close Chrome when done");
        println!("   • Or press Ctrl+C to prompt shutdown");

        // Step 5: Create CDP session and start capture
        let cdp_session = CdpSession::new(debugging_port);

        // Spawn CDP capture task
        let capture_handle = tokio::spawn(async move {
            cdp_session.capture_traffic().await
        });

        // Step 6: Wait for Chrome to exit
        let status = chrome_process.wait()?;
        println!("🛑 Chrome closed (exit code: {})", status.code().unwrap_or(-1));

        // Step 7: Get captured traffic
        let network_capture = capture_handle.await
            .map_err(|e| anyhow::anyhow!("CDP capture task failed: {}", e))??;

        let request_count = network_capture.count();
        println!("📊 Captured {} HTTP requests", request_count);

        // Step 8: Convert to HAR
        let mut har = network_capture.to_har();

        // Step 9: Apply host filters if specified
        if !hosts.is_empty() {
            println!("🔍 Filtering to hosts: {}", hosts.join(", "));
            har = apply_host_filter(har, hosts)?;
            println!("📝 Filtered to {} requests", har.log.entries.len());
        }

        // Step 10: Write HAR file
        let har_json = serde_json::to_string_pretty(&har)?;
        std::fs::write(output, har_json)?;
        println!("✅ HAR file written to: {}", output.display());

        // Step 11: Run hawk scan if requested
        if scan {
            println!("🦅 Running StackHawk scan...");
            run_hawk_scan(output)?;
            println!("✅ Scan complete");
        }

        Ok(())
    })
}

/// Apply host filtering to HAR file
fn apply_host_filter(
    har: harrier_core::har::Har,
    host_patterns: Vec<String>,
) -> Result<harrier_core::har::Har> {
    use harrier_core::filter::FilterCriteria;

    let criteria = FilterCriteria::new().with_hosts(host_patterns)?;

    harrier_core::filter::filter_har(&har, &criteria)
        .map_err(|e| anyhow::anyhow!("Filter failed: {}", e))
}

/// Run StackHawk scan with HAR file
fn run_hawk_scan(har_path: &Path) -> Result<()> {
    use std::process::Command;

    // Check if hawk binary exists
    if which::which("hawk").is_err() {
        return Err(anyhow::anyhow!(
            "hawk command not found. Install StackHawk CLI or omit --scan flag."
        ));
    }

    // Check for stackhawk.yml
    if !std::path::Path::new("stackhawk.yml").exists() {
        println!("⚠️  No stackhawk.yml found, running scan with defaults");
    }

    // Run hawk scan
    let output = Command::new("hawk")
        .arg("scan")
        .arg(har_path)
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "hawk scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Print hawk output
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
