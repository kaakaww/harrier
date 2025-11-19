# Phase 5: Chrome Integration Design

**Date:** January 16, 2025
**Status:** Design Complete
**Implementation Status:** Not Started

## Overview

Phase 5 adds browser automation to Harrier, enabling users to capture HAR files from real Chrome browsing sessions. This provides a more user-friendly alternative to the MITM proxy for HAR collection, especially useful for authenticated workflows and single-page applications.

## Goals

- **Primary:** Enable `harrier chrome` command that launches Chrome, captures traffic, and saves HAR file
- **Secondary:** Integrate with StackHawk's `hawk` CLI for seamless security scanning
- **Tertiary:** Support authenticated workflows with persistent browser profiles

## Command Interface

### Signature

```bash
harrier chrome [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <PATH>` | HAR output file path | `chrome-capture.har` |
| `--hosts <PATTERNS>` | Filter to specific hosts (supports globs, repeatable) | None (capture all) |
| `--scan` | Run `hawk scan` after capturing HAR | Disabled |
| `--chrome-path <PATH>` | Override Chrome binary location | Auto-detected |
| `--url <URL>` | Starting URL to navigate to on launch | `about:blank` |
| `--profile <NAME>` | Use persistent profile at `~/.harrier/profiles/<NAME>` | None |
| `--temp-profile` | Use temporary profile (deleted on exit) | **Default** |

### Usage Examples

```bash
# Basic capture with temporary profile
harrier chrome

# Start at specific URL
harrier chrome --url https://app.example.com

# Use persistent profile for authenticated testing
harrier chrome --profile production-app --url https://app.example.com

# Multiple profiles for different environments
harrier chrome --profile staging-admin --hosts "staging-api.example.com"
harrier chrome --profile prod-user --hosts "api.example.com"

# Filter to API traffic only
harrier chrome --hosts "*.api.example.com" -o api-traffic.har

# Capture and immediately scan with StackHawk
harrier chrome --profile myapp --hosts "api.example.com" --scan

# Custom Chrome location (if not auto-detected)
harrier chrome --chrome-path "/opt/chrome/chrome" --output traffic.har
```

## User Experience Flow

### Standard Flow

1. User runs `harrier chrome [options]`
2. Harrier detects/validates Chrome installation
3. Chrome launches in headed mode with CDP enabled
4. User browses and interacts with web applications
5. User closes Chrome window or application
6. Harrier detects Chrome exit
7. Harrier converts captured CDP events to HAR format
8. If `--hosts` specified, applies host filtering
9. Writes HAR file to specified output path
10. If `--scan` specified, runs StackHawk scan
11. Displays success message and exits

### Session Completion Methods

Users have two ways to signal completion:

#### Method 1: Close Chrome (Primary)
- User closes Chrome window or quits application (Cmd+Q, Alt+F4, etc.)
- Harrier detects process exit or CDP disconnection
- Automatically proceeds to save HAR

#### Method 2: Ctrl+C (Secondary)
- User presses Ctrl+C in terminal
- Harrier catches SIGINT and prompts: `Chrome is still running. Close Chrome and save HAR? (y/n):`
- **If yes:** Gracefully close Chrome, wait for exit, save HAR
- **If no:** Cancel interrupt, continue capturing

### Status Messages

```bash
🔍 Found Chrome at: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
📁 Using profile: ~/.harrier/profiles/myapp
🚀 Launching Chrome...
✅ Chrome started successfully
📊 Capturing network traffic...
   • Close Chrome when done
   • Or press Ctrl+C to prompt shutdown

[User browses and closes Chrome]

🛑 Chrome closed
📊 Captured 247 HTTP requests
🔍 Filtering to hosts: *.api.example.com
📝 Filtered to 89 requests
✅ HAR file written to: chrome-capture.har

[If --scan specified]
🦅 Running StackHawk scan...
[hawk output passes through]
✅ Scan complete
```

## Architecture

### Component Structure

Implementation lives primarily in `crates/harrier-browser` with CLI wiring in `crates/harrier-cli`.

#### 1. ChromeFinder

**Purpose:** Locate Chrome binary on the system

**Responsibilities:**
- Check platform-specific default paths
- Support `--chrome-path` override
- Validate binary exists and is executable
- Return helpful error if not found

**Platform Paths:**
- **macOS:** `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`
- **Linux:** `/usr/bin/google-chrome`, `/usr/bin/chromium`, `/usr/bin/chromium-browser`
- **Windows:** `C:\Program Files\Google\Chrome\Application\chrome.exe`

**Error Handling:**
- Not found: List checked paths, suggest `--chrome-path`
- Not executable: Permissions error with fix suggestion

#### 2. ChromeLauncher

**Purpose:** Manage Chrome process lifecycle

**Responsibilities:**
- Spawn Chrome with appropriate flags
- Create/manage profile directories
- Monitor process for exit
- Handle graceful and forced shutdown
- Cleanup temporary profiles

**Chrome Launch Flags:**
```rust
vec![
    "--remote-debugging-port=9222",      // Enable CDP
    "--no-first-run",                    // Skip first-run wizards
    "--no-default-browser-check",        // Skip default browser prompt
    format!("--user-data-dir={}", profile_path),  // Profile location
    initial_url,                         // Starting page
]
```

**Profile Management:**
- **Temporary:** Creates temp dir, deletes on exit
- **Persistent:** Creates `~/.harrier/profiles/<name>` if doesn't exist
- **Cleanup:** Only deletes temp profiles, preserves persistent ones

**Shutdown Sequence:**
1. Detect completion signal (Chrome exit or user Ctrl+C confirmation)
2. If CDP connected, send `Browser.close()` command
3. Wait up to 5 seconds for graceful exit
4. If still running, send SIGTERM (force kill)
5. Cleanup temp profile if applicable

#### 3. CdpSession

**Purpose:** Chrome DevTools Protocol client wrapper

**Responsibilities:**
- Establish CDP connection using `chromiumoxide`
- Enable Network domain for traffic capture
- Subscribe to network events
- Handle CDP disconnection gracefully
- Buffer events in memory

**Network Events Captured:**
- `Network.requestWillBeSent` - Request initiated
- `Network.responseReceived` - Response headers received
- `Network.loadingFinished` - Request completed with body size
- `Network.requestWillBeSentExtraInfo` - Additional request details
- `Network.responseReceivedExtraInfo` - Additional response details

**Event Storage:**
```rust
struct NetworkRequest {
    request_id: String,
    started_at: SystemTime,
    method: String,
    url: String,
    headers: HashMap<String, String>,
    post_data: Option<String>,
    response: Option<NetworkResponse>,
    completed: bool,
    encoded_data_length: i64,
}

// Stored in HashMap<RequestId, NetworkRequest>
```

#### 4. NetworkCapture

**Purpose:** Convert CDP events to HAR format

**Responsibilities:**
- Pair requests with responses by `requestId`
- Fetch request bodies using `Network.getRequestPostData()`
- Calculate timing information
- Convert headers to HAR format
- Handle incomplete requests (no response)
- Generate W3C HAR 1.2 compliant output

**Request Body Capture:**
- Only for POST, PUT, PATCH, DELETE methods
- Use `Network.getRequestPostData(requestId)` CDP method
- Store in HAR `request.postData.text` field
- Include MIME type in `request.postData.mimeType`

**Response Bodies:**
- **NOT captured in MVP** (headers only)
- Can be added post-MVP if needed for security scanning

**Incomplete Requests:**
- Request sent but no response (page closed, navigation cancelled)
- Include in HAR with status 0 and timing up to last event
- Mark as incomplete in timing comments

#### 5. HawkIntegration

**Purpose:** StackHawk scanner integration (optional)

**Responsibilities:**
- Check if `hawk` binary exists in PATH
- Detect `stackhawk.yml` configuration file
- Spawn `hawk scan` process with HAR file
- Stream hawk output to user
- Return error if hawk not found or fails

**Implementation:**
```rust
async fn run_hawk_scan(har_path: &Path) -> Result<()> {
    // Verify hawk binary exists
    which::which("hawk")
        .map_err(|_| Error::Browser("hawk command not found".into()))?;

    // Check for stackhawk.yml
    let has_config = Path::new("stackhawk.yml").exists();
    if !has_config {
        println!("⚠️  No stackhawk.yml found, running scan with defaults");
    }

    // Run hawk scan
    let output = Command::new("hawk")
        .arg("scan")
        .arg(har_path)
        .stdout(Stdio::inherit())  // Stream to user
        .stderr(Stdio::inherit())
        .output()
        .await?;

    if !output.status.success() {
        return Err(Error::Browser("hawk scan failed".into()));
    }

    Ok(())
}
```

**StackHawk.yml Awareness:**
- If present: `hawk scan` will use configuration automatically
- If absent: Warn user, run with defaults
- No explicit parsing of stackhawk.yml in Harrier

### Data Flow

```
User Command
    ↓
ChromeFinder: Locate binary
    ↓
ChromeLauncher: Spawn Chrome process
    ↓
CdpSession: Connect and enable Network domain
    ↓
[User browses - NetworkCapture buffers CDP events]
    ↓
User closes Chrome (or Ctrl+C confirmation)
    ↓
ChromeLauncher: Detect exit, initiate shutdown
    ↓
NetworkCapture: Convert buffered events to HAR entries
    ↓
Filter: Apply host patterns (reuse harrier-core logic)
    ↓
Writer: Write HAR file to disk
    ↓
[Optional] HawkIntegration: Run hawk scan
    ↓
Cleanup: Remove temp profile if applicable
    ↓
Exit with success message
```

## Error Handling

### Error Categories

Using existing `harrier_browser::Error` enum:

```rust
pub enum Error {
    Browser(String),    // Chrome-related errors
    Cdp(String),        // DevTools Protocol errors
    Io(std::io::Error), // File/IO errors
}
```

### Error Cases

#### Chrome Not Found
- **Trigger:** Binary not at default paths or `--chrome-path`
- **Message:** "Chrome not found. Checked: [list of paths]. Use --chrome-path to specify location."
- **Recovery:** User installs Chrome or provides path

#### Chrome Fails to Launch
- **Trigger:** Process exits immediately, permissions issues
- **Message:** "Failed to launch Chrome: [reason]"
- **Recovery:** Check permissions, verify Chrome installation

#### Chrome Crashes During Session
- **Trigger:** Chrome process exits unexpectedly with non-zero code
- **Message:** "⚠️  Chrome crashed. Saving captured traffic up to crash point..."
- **Recovery:** Save partial HAR, report as warning not error

#### CDP Connection Lost
- **Trigger:** CDP disconnects mid-session
- **Message:** "⚠️  CDP connection lost - some traffic may not be captured"
- **Recovery:** Continue, save partial data

#### Profile Already in Use
- **Trigger:** Chrome locks profile, another instance using it
- **Message:** "Profile '<name>' is already in use. Close other Chrome instances or use a different profile."
- **Recovery:** User closes other Chrome or uses different profile

#### No Traffic Captured
- **Trigger:** User closes Chrome immediately, no requests made
- **Message:** "⚠️  No traffic captured (0 requests)"
- **Recovery:** Generate valid but empty HAR file

#### Hawk Not Found
- **Trigger:** `--scan` specified but `hawk` not in PATH
- **Message:** "`hawk` command not found. Install StackHawk CLI or omit --scan flag."
- **Action:** Save HAR successfully, skip scan

#### Cannot Write HAR File
- **Trigger:** Output path not writable, disk full
- **Message:** "Failed to write HAR file: [reason]"
- **Recovery:** Suggest different output path

### Graceful Degradation

- CDP issues → Save partial data with warnings
- No traffic → Empty but valid HAR file
- Hawk missing → Save HAR, skip scan
- Incomplete requests → Include with status 0

## Implementation Details

### Chrome Launch Configuration

```rust
use std::process::Command;

fn launch_chrome(
    chrome_path: &Path,
    profile_path: &Path,
    initial_url: Option<&str>,
) -> Result<Child> {
    Command::new(chrome_path)
        .args(&[
            "--remote-debugging-port=9222",
            "--no-first-run",
            "--no-default-browser-check",
            &format!("--user-data-dir={}", profile_path.display()),
        ])
        .arg(initial_url.unwrap_or("about:blank"))
        .spawn()
        .map_err(|e| Error::Browser(format!("Failed to launch Chrome: {}", e)))
}
```

### CDP Network Event Capture

```rust
use chromiumoxide::Browser;

async fn capture_network_traffic(browser: &Browser) -> Result<Vec<NetworkRequest>> {
    let page = browser.new_page("about:blank").await?;
    page.enable_network().await?;

    let mut requests = HashMap::new();
    let mut handler = page.event_listener();

    loop {
        match handler.next().await {
            Some(Event::NetworkRequestWillBeSent(req)) => {
                requests.insert(req.request_id.clone(), NetworkRequest {
                    request_id: req.request_id,
                    started_at: SystemTime::now(),
                    method: req.request.method,
                    url: req.request.url,
                    headers: req.request.headers,
                    post_data: None,
                    response: None,
                    completed: false,
                    encoded_data_length: 0,
                });

                // Fetch request body for POST/PUT/PATCH/DELETE
                if matches!(req.request.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
                    if let Ok(body) = page.get_request_post_data(&req.request_id).await {
                        if let Some(net_req) = requests.get_mut(&req.request_id) {
                            net_req.post_data = Some(body);
                        }
                    }
                }
            }

            Some(Event::NetworkResponseReceived(resp)) => {
                if let Some(net_req) = requests.get_mut(&resp.request_id) {
                    net_req.response = Some(NetworkResponse {
                        status: resp.response.status,
                        status_text: resp.response.status_text,
                        headers: resp.response.headers,
                    });
                }
            }

            Some(Event::NetworkLoadingFinished(finish)) => {
                if let Some(net_req) = requests.get_mut(&finish.request_id) {
                    net_req.completed = true;
                    net_req.encoded_data_length = finish.encoded_data_length;
                }
            }

            None => break,  // CDP disconnected or Chrome closed
        }
    }

    Ok(requests.into_values().collect())
}
```

### HAR Conversion

```rust
use harrier_core::har::{Har, Log, Entry, Request, Response, Creator};

fn convert_to_har(network_requests: Vec<NetworkRequest>) -> Har {
    let entries: Vec<Entry> = network_requests
        .into_iter()
        .map(|net_req| {
            let duration = net_req.response
                .as_ref()
                .map(|_| SystemTime::now().duration_since(net_req.started_at).unwrap())
                .unwrap_or_default();

            Entry {
                started_datetime: format!("{:?}", net_req.started_at),
                time: duration.as_millis() as i64,
                request: Request {
                    method: net_req.method,
                    url: net_req.url,
                    http_version: "HTTP/1.1".to_string(),
                    headers: convert_headers(net_req.headers),
                    query_string: vec![],
                    cookies: vec![],
                    headers_size: -1,
                    body_size: net_req.post_data.as_ref().map(|s| s.len() as i64).unwrap_or(-1),
                    post_data: net_req.post_data.map(|text| PostData {
                        mime_type: "application/json".to_string(),  // Could be detected
                        text,
                        params: vec![],
                    }),
                },
                response: net_req.response.map(|resp| Response {
                    status: resp.status,
                    status_text: resp.status_text,
                    http_version: "HTTP/1.1".to_string(),
                    headers: convert_headers(resp.headers),
                    cookies: vec![],
                    content: Content {
                        size: net_req.encoded_data_length,
                        mime_type: "application/octet-stream".to_string(),
                        text: None,  // Not captured in MVP
                        encoding: None,
                    },
                    redirect_url: String::new(),
                    headers_size: -1,
                    body_size: net_req.encoded_data_length,
                }).unwrap_or_default(),
                cache: Cache::default(),
                timings: Timings {
                    send: 0,
                    wait: duration.as_millis() as i64,
                    receive: 0,
                    blocked: None,
                    dns: None,
                    connect: None,
                    ssl: None,
                },
                server_ip_address: None,
                connection: None,
                comment: None,
            }
        })
        .collect();

    Har {
        log: Log {
            version: "1.2".to_string(),
            creator: Creator {
                name: "Harrier".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            browser: Some(Browser {
                name: "Chrome".to_string(),
                version: "Unknown".to_string(),
            }),
            pages: vec![],
            entries,
            comment: None,
        }
    }
}
```

### Host Filtering

Reuse existing filter logic from `harrier-core`:

```rust
use harrier_core::filter::{FilterCriteria, apply_filters};

fn apply_host_filter(mut har: Har, host_patterns: Vec<String>) -> Result<Har> {
    let criteria = FilterCriteria {
        hosts: Some(host_patterns),
        status: None,
        method: None,
        content_type: None,
    };

    apply_filters(har, criteria)
}
```

### Ctrl+C Handling

```rust
use tokio::signal;
use std::io::{self, Write};

async fn wait_for_completion(chrome_process: &mut Child) -> Result<()> {
    tokio::select! {
        // Chrome exits naturally
        status = chrome_process.wait() => {
            println!("🛑 Chrome closed");
            Ok(())
        }

        // User presses Ctrl+C
        _ = signal::ctrl_c() => {
            print!("\n⚠️  Chrome is still running. Close Chrome and save HAR? (y/n): ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().eq_ignore_ascii_case("y") {
                println!("🛑 Closing Chrome...");
                chrome_process.kill().await?;
                Ok(())
            } else {
                println!("Continuing capture...");
                wait_for_completion(chrome_process).await
            }
        }
    }
}
```

## Testing Strategy

### Unit Tests

#### ChromeFinder Tests
- ✅ Platform-specific path detection
- ✅ Fallback to custom path
- ✅ Error messages when not found
- ✅ Mock filesystem for testing without Chrome

#### NetworkCapture Tests
- ✅ CDP event → HAR entry conversion
- ✅ Request/response pairing by requestId
- ✅ Handling incomplete requests (no response)
- ✅ Header conversion format
- ✅ Timing calculations
- ✅ Request body inclusion for POST/PUT/PATCH
- ✅ Empty request list (0 entries)

#### HAR Generation Tests
- ✅ Valid W3C HAR 1.2 structure
- ✅ Metadata (version, creator, browser)
- ✅ Empty HAR (0 entries) is valid
- ✅ Request bodies in postData field

#### Profile Management Tests
- ✅ Temp profile creation
- ✅ Temp profile cleanup after exit
- ✅ Persistent profile creation at correct path
- ✅ Profile name validation/sanitization
- ✅ Multiple profiles don't conflict

### Integration Tests

#### End-to-End with Mock Browser
```rust
#[tokio::test]
async fn test_chrome_capture_basic() {
    // Mock Chrome process that exits after 1 second
    // Mock CDP events (pre-recorded sequence)
    // Verify HAR file written correctly
    // Verify temp profile cleaned up
}

#[tokio::test]
async fn test_chrome_capture_with_filter() {
    // Capture mock traffic with multiple hosts
    // Apply host filters
    // Verify filtered HAR contains only matching entries
}
```

#### Filter Integration Tests
- ✅ Reuse existing filter test fixtures from `harrier-core`
- ✅ Test glob patterns work with Chrome-captured HAR
- ✅ Test multiple host patterns

#### Hawk Integration Tests
```rust
#[tokio::test]
async fn test_hawk_scan_integration() {
    // Mock hawk binary in PATH
    // Verify called with correct arguments
    // Test behavior when hawk not found
    // Test behavior when stackhawk.yml present/absent
}
```

### Manual Testing Checklist

```markdown
- [ ] Launch Chrome on macOS with temp profile
- [ ] Launch Chrome on Linux with persistent profile
- [ ] Launch Chrome on Windows with custom chrome-path
- [ ] Browse to multiple sites, verify traffic captured
- [ ] Close Chrome normally, verify HAR written
- [ ] Ctrl+C with 'yes' response, verify Chrome closes
- [ ] Ctrl+C with 'no' response, verify capture continues
- [ ] Filter to specific host, verify output correct
- [ ] Run with --scan flag, verify hawk launches
- [ ] Multiple profiles (create different named profiles)
- [ ] Chrome not installed (verify error message helpful)
- [ ] Chrome already running with same profile (verify error)
- [ ] Navigate to HTTPS sites (verify no certificate errors)
- [ ] POST requests with JSON bodies (verify captured)
- [ ] Empty session (close immediately, verify empty HAR valid)
- [ ] CDP disconnects mid-session (verify partial save)
```

## MVP Scope

### Included in MVP

✅ **Headed Chrome only**
- No headless mode in initial release
- Users see and interact with real browser

✅ **Request bodies included**
- Capture POST/PUT/PATCH/DELETE request payloads
- Essential for API discovery and security testing
- Uses CDP `Network.getRequestPostData()` method

✅ **Response bodies excluded**
- Headers and status codes captured only
- Can add in post-MVP if needed for deeper security analysis
- Keeps HAR files smaller and implementation simpler

✅ **Host filtering only**
- Use `--hosts` flag with glob patterns
- Leverage existing filter logic from `harrier-core`
- Status/method filtering can be added later if needed

✅ **Simple hawk integration**
- Shell out to `hawk scan` command
- No library dependency on StackHawk
- Loose coupling for easier maintenance

✅ **Persistent profiles**
- Support named profiles for authenticated workflows
- Store in `~/.harrier/profiles/<name>`
- Temp profiles by default

✅ **Basic error handling**
- Chrome not found, launch failures, CDP errors
- Graceful degradation for partial captures

### Deferred to Post-MVP

⏸️ **Headless mode**
- Add `--headless` flag for automation
- Useful for CI/CD integration

⏸️ **Response body capture**
- Add `--include-response-bodies` flag
- For deeper security analysis if needed

⏸️ **Live filtering during capture**
- Filter at CDP level before buffering
- Reduces memory for focused captures

⏸️ **HAR file streaming**
- Write entries as they complete
- For very long sessions or low memory

⏸️ **Browser selection**
- Support Chromium, Edge, Brave
- Use `--browser` flag

⏸️ **Advanced timing details**
- DNS, connection, SSL timings from CDP
- More accurate performance analysis

⏸️ **Screenshot capture**
- Take screenshots at intervals or on errors
- Helps document testing sessions

⏸️ **Custom CDP scripts**
- Allow users to inject JavaScript
- Advanced automation scenarios

## Success Criteria

### MVP Complete When:

1. ✅ `harrier chrome` launches Chrome and captures traffic
2. ✅ Users can close Chrome to save HAR file
3. ✅ Ctrl+C prompts for confirmation before closing
4. ✅ HAR files are valid W3C HAR 1.2 format
5. ✅ Request bodies included for POST/PUT/PATCH/DELETE
6. ✅ Host filtering works using existing filter logic
7. ✅ `--scan` flag integrates with StackHawk successfully
8. ✅ Persistent profiles support authenticated workflows
9. ✅ Error messages are clear and actionable
10. ✅ Works on macOS (primary target), Linux, Windows

### Quality Gates:

- All unit tests pass
- Integration tests with mocked CDP pass
- Manual testing checklist completed
- HAR files successfully import into HawkScan
- Documentation updated (README, proxy-setup.md if relevant)
- No memory leaks during long captures (basic profiling)

## Related Documentation

- [HAR 1.2 Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
- [Chrome DevTools Protocol - Network Domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [StackHawk HawkScan Documentation](https://docs.stackhawk.com/hawkscan/)
- [chromiumoxide Crate Documentation](https://docs.rs/chromiumoxide/)

## Implementation Timeline

Estimated effort: **2-3 weeks** for MVP

**Week 1:** Core functionality
- ChromeFinder and ChromeLauncher
- CDP connection and event capture
- Basic HAR generation

**Week 2:** Polish and integration
- Request body capture
- Host filtering integration
- Hawk integration
- Profile management

**Week 3:** Testing and refinement
- Unit and integration tests
- Manual testing across platforms
- Error handling refinement
- Documentation updates

## Open Questions

None - design is complete and ready for implementation.

## Approval

Design reviewed and approved on: January 16, 2025

Ready to proceed with implementation.
