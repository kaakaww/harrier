use crate::OutputFormat;
use anyhow::Result;
use clap::ValueEnum;
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::{AppTypeDetector, AuthAnalyzer, AuthMethod};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Focus areas for analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Focus {
    /// Architecture map - hosts, API types, relationships
    Map,
    /// Authentication analysis - methods, flows, sessions
    Auth,
}

/// Host information for analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostInfo {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub request_count: usize,
    pub api_type: Option<String>,
    pub auth_method: Option<String>,
    pub role: Option<String>,
    pub category: String,
}

/// Full analysis result
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisResult {
    pub file_name: String,
    pub total_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<ArchitectureAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationAnalysis>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
    pub duration_display: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchitectureAnalysis {
    pub primary_host: Option<String>,
    pub hosts: Vec<HostInfo>,
    pub host_count: usize,
    pub same_domain_count: usize,
    pub third_party_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthenticationAnalysis {
    pub primary_method: Option<String>,
    pub session_type: Option<String>,
    pub methods: Vec<String>,
    pub flow_count: usize,
    pub jwt_count: usize,
}

/// Extract root domain using Public Suffix List
fn get_root_domain(domain: &str) -> String {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return domain.to_string();
    }

    match psl::domain(domain.as_bytes()) {
        Some(root) => String::from_utf8_lossy(root.as_bytes()).to_string(),
        None => {
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                domain.to_string()
            }
        }
    }
}

/// Detect auth method for a set of entries
fn detect_auth_for_entries(entries: &[&Entry]) -> Option<String> {
    for entry in entries {
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "authorization" {
                let value = header.value.to_lowercase();
                if value.starts_with("bearer") {
                    let token = header.value.trim_start_matches("Bearer ").trim();
                    if token.matches('.').count() == 2 {
                        return Some("Bearer JWT".to_string());
                    }
                    return Some("Bearer Token".to_string());
                } else if value.starts_with("basic") {
                    return Some("Basic Auth".to_string());
                }
            }
            let header_lower = header.name.to_lowercase();
            if header_lower == "x-api-key" || header_lower == "api-key" || header_lower == "apikey"
            {
                return Some(format!("API Key ({})", header.name));
            }
        }

        for cookie in &entry.request.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return Some("Cookie".to_string());
            }
        }
    }
    None
}

/// Infer the role of a host based on its characteristics
fn infer_host_role(host: &str, api_type: &str) -> Option<String> {
    let host_lower = host.to_lowercase();

    if host_lower.contains("auth0")
        || host_lower.contains("okta")
        || host_lower.contains("cognito")
        || host_lower.contains("oauth")
        || host_lower.contains("login")
        || host_lower.contains("identity")
    {
        return Some("Authentication provider".to_string());
    }

    if host_lower.contains("cdn")
        || host_lower.contains("static")
        || host_lower.contains("assets")
        || host_lower.contains("cloudfront")
        || host_lower.contains("akamai")
    {
        return Some("CDN / Static assets".to_string());
    }

    if host_lower.contains("analytics")
        || host_lower.contains("tracking")
        || host_lower.contains("segment")
        || host_lower.contains("mixpanel")
        || host_lower.contains("amplitude")
    {
        return Some("Analytics".to_string());
    }

    if host_lower.contains("sentry")
        || host_lower.contains("datadog")
        || host_lower.contains("newrelic")
        || host_lower.contains("bugsnag")
    {
        return Some("Error monitoring".to_string());
    }

    if api_type == "GraphQL" {
        return Some("GraphQL API".to_string());
    }

    None
}

/// Check if a URL should be considered for primary host detection
fn is_web_traffic(protocol: &str, domain: &str) -> bool {
    // Only HTTP/HTTPS are web traffic
    if protocol != "http" && protocol != "https" {
        return false;
    }
    // Skip localhost/loopback for primary detection
    if domain == "localhost" || domain.starts_with("127.") || domain == "[::1]" {
        return false;
    }
    true
}

/// Analyze hosts from HAR file
fn analyze_hosts(har: &Har) -> ArchitectureAnalysis {
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>)> = HashMap::new();
    let mut first_host_key: Option<String> = None;

    // Check if target host was specified via --url during capture
    let target_host = har
        .log
        .harrier_metadata
        .as_ref()
        .and_then(|m| m.target_host.clone());

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url
                .port()
                .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });

            // Skip non-web traffic (chrome-extension://, data:, etc.)
            if !is_web_traffic(&protocol, &domain) {
                continue;
            }

            let key = format!("{}://{}:{}", protocol, domain, port);

            // Use metadata target_host if available, otherwise first web traffic URL
            if first_host_key.is_none() {
                if let Some(ref th) = target_host {
                    // Check if this entry matches the target host
                    if domain == *th || domain.ends_with(&format!(".{}", th)) {
                        first_host_key = Some(key.clone());
                    }
                } else {
                    first_host_key = Some(key.clone());
                }
            }

            host_entries
                .entry(key)
                .and_modify(|(_, _, _, entries)| entries.push(entry))
                .or_insert((protocol, domain, port, vec![entry]));
        }
    }

    // If target_host was specified but no entries matched, find it in host_entries
    if first_host_key.is_none()
        && let Some(ref th) = target_host
    {
        for (key, (_, domain, _, _)) in &host_entries {
            if domain == th || domain.ends_with(&format!(".{}", th)) {
                first_host_key = Some(key.clone());
                break;
            }
        }
    }

    // Final fallback: use first host in entries
    if first_host_key.is_none() {
        first_host_key = host_entries.keys().next().cloned();
    }

    let first_root_domain = first_host_key.as_ref().and_then(|key| {
        host_entries
            .get(key)
            .map(|(_, domain, _, _)| get_root_domain(domain))
    });

    let mut hosts: Vec<HostInfo> = Vec::new();
    let mut primary_host: Option<String> = None;
    let mut same_domain_count = 0;
    let mut third_party_count = 0;

    for (key, (protocol, domain, port, entries)) in &host_entries {
        let is_primary = first_host_key.as_ref() == Some(key);
        let root_domain = get_root_domain(domain);
        let is_same_domain = first_root_domain
            .as_ref()
            .is_some_and(|first| &root_domain == first);

        let category = if is_primary {
            "Primary".to_string()
        } else if is_same_domain {
            same_domain_count += 1;
            "Same Domain".to_string()
        } else {
            third_party_count += 1;
            "Third Party".to_string()
        };

        // Detect API type
        let api_type_results = AppTypeDetector::detect_for_host(entries);
        let api_type = api_type_results
            .first()
            .map(|(t, _, _)| t.as_str().to_string());

        let api_type_str = api_type.clone().unwrap_or_else(|| "Unknown".to_string());

        // Detect auth and role
        let auth_method = detect_auth_for_entries(entries);
        let role = infer_host_role(domain, &api_type_str);

        if is_primary {
            primary_host = Some(domain.clone());
        }

        hosts.push(HostInfo {
            host: domain.clone(),
            port: *port,
            protocol: protocol.clone(),
            request_count: entries.len(),
            api_type,
            auth_method,
            role,
            category,
        });
    }

    // Sort hosts: primary first, then same domain by count, then third party by count
    hosts.sort_by(|a, b| match (a.category.as_str(), b.category.as_str()) {
        ("Primary", _) => std::cmp::Ordering::Less,
        (_, "Primary") => std::cmp::Ordering::Greater,
        ("Same Domain", "Third Party") => std::cmp::Ordering::Less,
        ("Third Party", "Same Domain") => std::cmp::Ordering::Greater,
        _ => b.request_count.cmp(&a.request_count),
    });

    ArchitectureAnalysis {
        primary_host,
        host_count: hosts.len(),
        same_domain_count,
        third_party_count,
        hosts,
    }
}

/// Analyze authentication from HAR file
fn analyze_auth(har: &Har) -> Option<AuthenticationAnalysis> {
    let auth_analysis = AuthAnalyzer::analyze(har).ok()?;

    if auth_analysis.methods.is_empty() && auth_analysis.sessions.is_empty() {
        return None;
    }

    let primary_method = auth_analysis.methods.first().map(|m| match m {
        AuthMethod::Jwt => "JWT".to_string(),
        AuthMethod::Bearer => "Bearer Token".to_string(),
        AuthMethod::OAuth => "OAuth 2.0".to_string(),
        AuthMethod::Basic => "Basic Auth".to_string(),
        AuthMethod::ApiKey(header) => format!("API Key ({})", header),
        AuthMethod::Cookie => "Cookie-based".to_string(),
        AuthMethod::Custom(header) => format!("Custom ({})", header),
    });

    let session_type = if !auth_analysis.jwt_tokens.is_empty() {
        Some("JWT Bearer tokens (stateless)".to_string())
    } else if auth_analysis.sessions.iter().any(|s| {
        matches!(
            s.session_type,
            harrier_detectors::SessionType::Cookie { .. }
        )
    }) {
        Some("Cookie-based sessions".to_string())
    } else if !auth_analysis.sessions.is_empty() {
        Some("Token-based sessions".to_string())
    } else {
        None
    };

    let methods: Vec<String> = auth_analysis
        .methods
        .iter()
        .map(|m| m.as_str().to_string())
        .collect();

    Some(AuthenticationAnalysis {
        primary_method,
        session_type,
        methods,
        flow_count: auth_analysis.flows.len(),
        jwt_count: auth_analysis.jwt_tokens.len(),
    })
}

/// Format duration for display
fn format_duration(start: &str, end: &str) -> String {
    use chrono::{DateTime, Utc};

    let start_dt = DateTime::parse_from_rfc3339(start)
        .ok()
        .map(|d| d.with_timezone(&Utc));
    let end_dt = DateTime::parse_from_rfc3339(end)
        .ok()
        .map(|d| d.with_timezone(&Utc));

    match (start_dt, end_dt) {
        (Some(s), Some(e)) => {
            let duration = e.signed_duration_since(s);
            let secs = duration.num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else if secs < 3600 {
                format!("{}m {}s", secs / 60, secs % 60)
            } else {
                format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
            }
        }
        _ => "unknown".to_string(),
    }
}

/// Get time range from HAR entries
fn get_time_range(har: &Har) -> Option<TimeRange> {
    let mut timestamps: Vec<&str> = har
        .log
        .entries
        .iter()
        .map(|e| e.started_date_time.as_str())
        .collect();

    if timestamps.is_empty() {
        return None;
    }

    timestamps.sort();

    let start = timestamps.first()?.to_string();
    let end = timestamps.last()?.to_string();
    let duration_display = format_duration(&start, &end);

    Some(TimeRange {
        start,
        end,
        duration_display,
    })
}

pub fn execute(
    file: &Path,
    focus: Vec<Focus>,
    all: bool,
    host_filter: Vec<String>,
    format: OutputFormat,
) -> Result<()> {
    let har = HarReader::from_file(file)?;

    // Determine what to analyze
    let run_all = all || focus.is_empty();
    let run_map = run_all || focus.contains(&Focus::Map);
    let run_auth = run_all || focus.contains(&Focus::Auth);

    // Build analysis result
    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let time_range = get_time_range(&har);

    let architecture = if run_map {
        let mut arch = analyze_hosts(&har);

        // Apply host filter if specified
        if !host_filter.is_empty() {
            arch.hosts
                .retain(|h| host_filter.iter().any(|f| h.host.contains(f)));
        }

        Some(arch)
    } else {
        None
    };

    let authentication = if run_auth { analyze_auth(&har) } else { None };

    let result = AnalysisResult {
        file_name,
        total_entries: har.log.entries.len(),
        time_range,
        architecture,
        authentication,
    };

    match format {
        OutputFormat::Json => output_json(&result)?,
        OutputFormat::Table => output_table(&result)?,
        OutputFormat::Pretty => output_pretty(&result, file, &focus, all)?,
    }

    Ok(())
}

fn output_pretty(result: &AnalysisResult, file: &Path, focus: &[Focus], all: bool) -> Result<()> {
    use console::style;

    println!(
        "\n{}",
        style(format!("Harrier Analysis: {}", result.file_name))
            .bold()
            .cyan()
    );
    println!();

    // Overview (always shown)
    println!("{}", style("Overview").bold());
    println!(
        "  Entries:      {} requests",
        style(result.total_entries).yellow()
    );

    if let Some(ref tr) = result.time_range {
        let start_display = tr.start.split('T').next().unwrap_or(&tr.start);
        let end_display = tr.end.split('T').next().unwrap_or(&tr.end);
        println!(
            "  Time Range:   {} to {} ({})",
            start_display, end_display, tr.duration_display
        );
    }

    // Architecture section
    if let Some(ref arch) = result.architecture {
        println!("\n{}", style("Architecture").bold());

        if let Some(ref host) = arch.primary_host {
            println!("  Primary Host: {}", style(host).green());
        }

        println!(
            "  Hosts:        {} total ({} same domain, {} third party)",
            arch.host_count, arch.same_domain_count, arch.third_party_count
        );

        // Show host details if focused on map or showing all
        if all || focus.contains(&Focus::Map) {
            println!();
            for host in arch.hosts.iter().take(10) {
                let api_type = host.api_type.as_deref().unwrap_or("Unknown");
                let auth = host.auth_method.as_deref().unwrap_or("None");

                let host_display = format!("{}:{}", host.host, host.port);
                match host.category.as_str() {
                    "Primary" => {
                        println!(
                            "  {} {}",
                            style("*").green(),
                            style(&host_display).green().bold()
                        );
                    }
                    "Same Domain" => {
                        println!("  {} {}", style("-").yellow(), host_display);
                    }
                    _ => {
                        println!("  {} {}", style("-").blue(), style(&host_display).dim());
                    }
                }
                println!("    {} | {} | {} req", api_type, auth, host.request_count);

                if let Some(ref role) = host.role {
                    println!("    {}", style(role).cyan());
                }
            }

            if arch.hosts.len() > 10 {
                println!("  ... and {} more hosts", arch.hosts.len() - 10);
            }
        }
    }

    // Authentication section
    if let Some(ref auth) = result.authentication {
        println!("\n{}", style("Authentication").bold());

        if let Some(ref method) = auth.primary_method {
            println!("  Method:       {}", style(method).yellow());
        } else {
            println!("  Method:       {}", style("None detected").dim());
        }

        if let Some(ref session) = auth.session_type {
            println!("  Session:      {}", session);
        }

        if auth.flow_count > 0 {
            println!("  Flows:        {} detected", auth.flow_count);
        }

        if auth.jwt_count > 0 {
            println!("  JWT Tokens:   {} found", auth.jwt_count);
        }
    }

    // Next steps (only in summary mode)
    if focus.is_empty() && !all {
        println!("\n{}", style("Next Steps").dim());
        println!(
            "  {} for detailed architecture",
            style(format!("harrier analyze {} --focus map", file.display())).cyan()
        );
        println!(
            "  {} for auth flow details",
            style(format!("harrier analyze {} --focus auth", file.display())).cyan()
        );
        println!(
            "  {} for everything",
            style(format!("harrier analyze {} --all", file.display())).cyan()
        );
        println!(
            "  {} for HawkScan config",
            style(format!("harrier export {} --hawkscan", file.display())).cyan()
        );
    }

    println!();
    Ok(())
}

fn output_json(result: &AnalysisResult) -> Result<()> {
    let json_str = serde_json::to_string_pretty(result)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(result: &AnalysisResult) -> Result<()> {
    println!("Metric,Value");
    println!("File,{}", result.file_name);
    println!("Total Entries,{}", result.total_entries);

    if let Some(ref tr) = result.time_range {
        println!("Time Range Start,{}", tr.start);
        println!("Time Range End,{}", tr.end);
        println!("Duration,{}", tr.duration_display);
    }

    if let Some(ref arch) = result.architecture {
        println!();
        println!("Host Count,{}", arch.host_count);
        println!("Same Domain Count,{}", arch.same_domain_count);
        println!("Third Party Count,{}", arch.third_party_count);

        if let Some(ref host) = arch.primary_host {
            println!("Primary Host,{}", host);
        }

        println!();
        println!("Category,Host,Port,Type,Auth,Requests");
        for host in &arch.hosts {
            let api_type = host.api_type.as_deref().unwrap_or("");
            let auth = host.auth_method.as_deref().unwrap_or("");
            println!(
                "{},{},{},{},{},{}",
                host.category, host.host, host.port, api_type, auth, host.request_count
            );
        }
    }

    if let Some(ref auth) = result.authentication {
        println!();
        if let Some(ref method) = auth.primary_method {
            println!("Auth Method,{}", method);
        }
        if let Some(ref session) = auth.session_type {
            println!("Session Type,{}", session);
        }
        println!("Flow Count,{}", auth.flow_count);
        println!("JWT Count,{}", auth.jwt_count);
    }

    Ok(())
}
