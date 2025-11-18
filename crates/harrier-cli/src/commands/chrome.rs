use anyhow::Result;
use harrier_browser::{CdpSession, ChromeFinder, ChromeLauncher, ProfileManager};
use std::path::{Path, PathBuf};

/// Kill a process by PID (cross-platform)
fn kill_process_by_pid(pid: u32) {
    #[cfg(unix)]
    {
        use std::process::Command;
        // Use kill command to send SIGTERM
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
}

pub fn execute(
    output: &Path,
    hosts: Vec<String>,
    scan: bool,
    chrome_path: Option<PathBuf>,
    url: Option<String>,
    profile: Option<String>,
) -> Result<()> {
    // Create tokio runtime for async operations
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let result = runtime.block_on(async {
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
        let chrome_pid = chrome_process.id();
        println!("✅ Chrome started successfully");

        if let Some(start_url) = url {
            println!("📍 Starting at: {}", start_url);
        }

        println!("📊 Capturing network traffic...");
        println!();
        println!("What would you like to do?");
        println!("  s) Stop capturing and save HAR (Chrome continues)");
        println!("  k) Kill Chrome and save HAR");
        println!("  a) Abort everything - kill Chrome, no HAR, no scan");
        println!();
        println!("Press a key when ready, or close Chrome naturally...");

        // Step 5: Create CDP session and start capture
        let cdp_session = CdpSession::new(debugging_port);

        // Start CDP capture (returns shutdown channel and result receiver)
        let (shutdown_tx, capture_rx) = cdp_session.capture_traffic().await?;

        // Step 6: Wait for Chrome to exit or user input
        use console::Term;

        // Spawn user input task (non-blocking read)
        let input_task = tokio::task::spawn_blocking(move || {
            let term = Term::stdout();
            term.read_char()
        });

        // Spawn Chrome wait task (wrap in Option for conditional consumption)
        let wait_task = tokio::task::spawn_blocking(move || chrome_process.wait());
        let mut wait_task = Some(wait_task);

        // Wait for either Chrome to exit or user to press a key
        enum Action {
            ChromeExited,
            StopCapture,
            KillChrome,
            AbortAll,
        }

        let action = tokio::select! {
            // Chrome exits naturally
            result = wait_task.as_mut().unwrap() => {
                let status = result??;
                let exit_code = status.code().unwrap_or(-1);
                println!("\n🛑 Chrome closed (exit code: {})", exit_code);
                wait_task = None; // Task consumed
                Action::ChromeExited
            }

            // User presses a key
            result = input_task => {
                let key = result??;
                match key.to_lowercase().next().unwrap_or(' ') {
                    's' => {
                        println!("\n⏹️  Stopping capture...");
                        Action::StopCapture
                    }
                    'k' => {
                        println!("\n🛑 Killing Chrome...");
                        Action::KillChrome
                    }
                    'a' => {
                        println!("\n❌ Aborting everything...");
                        Action::AbortAll
                    }
                    _ => {
                        // Invalid key - wait for Chrome to exit naturally
                        println!("\n⚠️  Invalid key '{}'. Waiting for Chrome to close naturally...", key);
                        let status = wait_task.take().unwrap().await??;
                        let exit_code = status.code().unwrap_or(-1);
                        println!("🛑 Chrome closed (exit code: {})", exit_code);
                        Action::ChromeExited
                    }
                }
            }
        };

        // Handle the action
        let network_capture = match action {
            Action::StopCapture => {
                // Signal CDP to stop capturing and get results
                let _ = shutdown_tx.send(());
                println!("✅ Capture stopped - Chrome continues running");
                println!("   Note: Chrome remains open for continued use");
                // Abort wait_task to stop waiting for Chrome (if still present)
                if let Some(task) = wait_task.take() {
                    task.abort();
                }
                // Get captured traffic
                capture_rx
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?
            }
            Action::KillChrome => {
                // Kill Chrome by PID and wait for exit
                kill_process_by_pid(chrome_pid);
                println!("⏳ Waiting for Chrome to terminate...");
                if let Some(task) = wait_task.take() {
                    let status = task.await??;
                    println!("✅ Chrome stopped (exit code: {})", status.code().unwrap_or(-1));
                }
                // Signal CDP to stop and get captured traffic
                let _ = shutdown_tx.send(());
                capture_rx
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?
            }
            Action::AbortAll => {
                // Kill Chrome and exit immediately without saving HAR
                kill_process_by_pid(chrome_pid);
                println!("🛑 Killing Chrome...");
                if let Some(task) = wait_task.take() {
                    let _ = task.await; // Wait for termination but ignore result
                }
                println!("❌ Aborted - no HAR saved");
                return Ok(());
            }
            Action::ChromeExited => {
                // Chrome exited naturally, signal CDP to stop and get captured traffic
                let _ = shutdown_tx.send(());
                capture_rx
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?
            }
        };

        // Step 7: Process captured traffic

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
    });

    // Explicitly shutdown runtime with timeout to prevent hanging on blocking tasks
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));

    result
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
    let output = Command::new("hawk").arg("scan").arg(har_path).output()?;

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
