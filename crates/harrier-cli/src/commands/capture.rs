use anyhow::Result;
use std::path::{Path, PathBuf};

/// Capture mode - browser (default) or proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptureMode {
    #[default]
    Browser,
    Proxy,
}

/// Kill a process by PID (cross-platform)
fn kill_process_by_pid(pid: u32) {
    #[cfg(unix)]
    {
        use std::process::Command;
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

#[allow(clippy::too_many_arguments)]
pub fn execute(
    mode: CaptureMode,
    output: &Path,
    hosts: Vec<String>,
    hawkscan: bool,
    // Browser-specific options
    url: Option<String>,
    profile: Option<String>,
    temp: bool,
    chrome_path: Option<PathBuf>,
    // Proxy-specific options
    port: u16,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<()> {
    match mode {
        CaptureMode::Browser => {
            execute_browser(output, hosts, hawkscan, url, profile, temp, chrome_path)
        }
        CaptureMode::Proxy => execute_proxy(port, output, cert.as_deref(), key.as_deref()),
    }
}

/// Execute browser-based capture (Chrome with DevTools Protocol)
fn execute_browser(
    output: &Path,
    hosts: Vec<String>,
    hawkscan: bool,
    url: Option<String>,
    profile: Option<String>,
    temp: bool,
    chrome_path: Option<PathBuf>,
) -> Result<()> {
    use harrier_browser::{CdpSession, ChromeFinder, ChromeLauncher, ProfileManager};

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
        let profile_manager = if temp {
            if profile.is_some() {
                eprintln!("⚠️  Both --profile and --temp specified. Using temporary profile.");
            }
            println!("📁 Using temporary profile");
            ProfileManager::temporary()?
        } else if let Some(profile_name) = profile {
            let profile_path = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
                .join(".harrier")
                .join("profiles")
                .join(&profile_name);

            println!("📁 Using profile: {}", profile_name);
            ProfileManager::persistent(profile_path)?
        } else {
            println!("📁 Using profile: default");
            ProfileManager::default_profile()?
        };

        // Step 3: Create launcher
        let launcher = ChromeLauncher::new(
            chrome_binary,
            profile_manager.path().to_path_buf(),
        );

        let debugging_port = launcher.debugging_port();

        // Step 4: Launch Chrome
        println!("🚀 Launching Chrome...");
        let mut chrome_process = launcher.launch()?;
        let chrome_pid = chrome_process.id();
        println!("✅ Chrome started successfully");

        // Step 5: Create CDP session, clear cache, and navigate if needed
        let cdp_session = CdpSession::new(debugging_port);

        // Clear browser cache
        println!("🧹 Clearing browser cache...");
        match cdp_session.clear_browser_cache().await {
            Ok(_) => println!("✅ Cache cleared"),
            Err(e) => {
                eprintln!("⚠️  Warning: Failed to clear cache: {}", e);
                eprintln!("   Continuing anyway - some requests may be served from cache");
            }
        }

        // Navigate to URL if provided
        if let Some(start_url) = &url {
            println!("🌐 Navigating to {}...", start_url);
            cdp_session.navigate_to(start_url).await?;
            println!("✅ Navigation complete");
        } else {
            println!("💡 Tip: Use --url <target> to ensure accurate primary host detection");
        }

        println!("📊 Capturing network traffic...");
        println!();
        println!("What would you like to do?");
        println!("  s) Stop capturing and save HAR (Chrome continues)");
        println!("  k) Kill Chrome and save HAR");
        println!("  a) Abort everything - kill Chrome, no HAR, no scan");
        println!();
        println!("Press a key when ready, or close Chrome naturally...");

        // Step 6: Start capture
        let (shutdown_tx, capture_rx) = cdp_session.capture_traffic().await?;

        // Step 7: Wait for Chrome to exit or user input
        use console::Term;

        let input_task = tokio::task::spawn_blocking(move || {
            let term = Term::stdout();
            term.read_char()
        });

        let wait_task = tokio::task::spawn_blocking(move || chrome_process.wait());
        let mut wait_task = Some(wait_task);

        enum Action {
            ChromeExited,
            StopCapture,
            KillChrome,
            AbortAll,
        }

        let action = tokio::select! {
            result = wait_task.as_mut().unwrap() => {
                let status = result??;
                let exit_code = status.code().unwrap_or(-1);
                println!("\n🛑 Chrome closed (exit code: {})", exit_code);
                wait_task = None;
                Action::ChromeExited
            }

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
                let _ = shutdown_tx.send(());
                println!("✅ Capture stopped - Chrome continues running");
                println!("   Note: Chrome remains open for continued use");
                if let Some(task) = wait_task.take() {
                    task.abort();
                }
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    capture_rx
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timeout waiting for capture data"))?
                .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?
            }
            Action::KillChrome => {
                let _ = shutdown_tx.send(());
                let capture = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    capture_rx
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timeout waiting for capture data"))?
                .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?;

                kill_process_by_pid(chrome_pid);
                println!("⏳ Waiting for Chrome to terminate...");
                if let Some(task) = wait_task.take() {
                    let status = task.await??;
                    println!("✅ Chrome stopped (exit code: {})", status.code().unwrap_or(-1));
                }

                capture
            }
            Action::AbortAll => {
                kill_process_by_pid(chrome_pid);
                println!("🛑 Killing Chrome...");
                if let Some(task) = wait_task.take() {
                    let _ = task.await;
                }
                println!("❌ Aborted - no HAR saved");
                return Ok(());
            }
            Action::ChromeExited => {
                let _ = shutdown_tx.send(());
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    capture_rx
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timeout waiting for capture data"))?
                .map_err(|e| anyhow::anyhow!("Failed to receive capture data: {}", e))?
            }
        };

        // Step 8: Process captured traffic
        let request_count = network_capture.count();
        println!("📊 Captured {} HTTP requests", request_count);

        // Step 9: Convert to HAR with metadata
        let mut har = network_capture.to_har_with_metadata(
            url.as_deref(),
            Some("browser"),
        );

        // Step 10: Apply host filters if specified
        if !hosts.is_empty() {
            println!("🔍 Filtering to hosts: {}", hosts.join(", "));
            har = apply_host_filter(har, hosts)?;
            println!("📝 Filtered to {} requests", har.log.entries.len());
        }

        // Step 11: Write HAR file
        let har_json = serde_json::to_string_pretty(&har)?;
        std::fs::write(output, har_json)?;
        println!("✅ HAR file written to: {}", output.display());

        // Remind about --url if not specified
        if url.is_none() {
            println!("💡 Next time, use --url <target> for accurate primary host detection");
        }

        // Step 12: Print HawkScan guidance if requested
        if hawkscan {
            print_hawkscan_guidance(output);
        }

        Ok(())
    });

    runtime.shutdown_timeout(std::time::Duration::from_millis(100));

    result
}

/// Execute proxy-based capture (MITM proxy)
fn execute_proxy(
    port: u16,
    output: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<()> {
    use harrier_proxy::{CertificateAuthority, ProxyServer};

    tracing::info!("Starting Harrier MITM proxy on port {}", port);

    // Load or generate CA certificate
    let ca = if let (Some(cert), Some(key)) = (cert_path, key_path) {
        tracing::info!("Loading CA certificate from custom paths");
        CertificateAuthority::load_from_pem(cert, key)?
    } else {
        tracing::info!("Using default CA certificate location");
        CertificateAuthority::load_or_generate()?
    };

    println!("🌐 Starting proxy on port {}...", port);
    println!("📝 Output will be written to: {}", output.display());
    println!();
    println!(
        "Configure your browser/app to use proxy: http://localhost:{}",
        port
    );
    println!("Press Ctrl+C to stop capturing and save HAR file");
    println!();

    // Create and start proxy server
    let server = ProxyServer::new(port, ca);

    let runtime = tokio::runtime::Runtime::new()?;
    let handler = runtime.block_on(async { server.start().await })?;

    println!();
    println!("🛑 Proxy stopped");

    // Get captured entries
    let entries = runtime.block_on(async { handler.entries().lock().await.clone() });

    println!("📊 Captured {} HTTP transactions", entries.len());

    // Generate HAR file
    if !entries.is_empty() {
        use serde_json::json;
        use std::fs;

        let har_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                let duration = entry
                    .completed_at
                    .duration_since(entry.started_at)
                    .unwrap_or_default();

                json!({
                    "startedDateTime": format!("{:?}", entry.started_at),
                    "time": duration.as_millis() as i64,
                    "request": {
                        "method": entry.method,
                        "url": entry.url,
                        "httpVersion": "HTTP/1.1",
                        "headers": entry.request_headers.iter().map(|(k, v)| {
                            json!({
                                "name": k,
                                "value": v
                            })
                        }).collect::<Vec<_>>(),
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": -1
                    },
                    "response": {
                        "status": entry.response_status,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": entry.response_headers.iter().map(|(k, v)| {
                            json!({
                                "name": k,
                                "value": v
                            })
                        }).collect::<Vec<_>>(),
                        "cookies": [],
                        "content": {
                            "size": -1,
                            "mimeType": "application/octet-stream"
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": -1
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": duration.as_millis() as i64,
                        "receive": 0
                    }
                })
            })
            .collect();

        let har = json!({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Harrier",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "entries": har_entries,
                "_harrier": {
                    "capture_mode": "proxy"
                }
            }
        });

        let har_json = serde_json::to_string_pretty(&har)?;
        fs::write(output, har_json)?;

        println!("✅ HAR file written to: {}", output.display());
    } else {
        println!("⚠️  No traffic captured, HAR file not generated");
    }

    Ok(())
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

/// Print HawkScan configuration guidance
fn print_hawkscan_guidance(har_path: &Path) {
    println!();
    println!("📋 To use this HAR with HawkScan, add the following to your stackhawk.yml:");
    println!();
    println!("hawk:");
    println!("  spider:");
    println!("    har:");
    println!("      file:");
    println!("        paths:");
    println!("          - {}", har_path.display());
    println!();
    println!("Then run: hawk scan");
}
