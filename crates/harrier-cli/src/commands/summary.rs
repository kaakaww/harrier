use crate::OutputFormat;
use anyhow::Result;
use harrier_core::analysis::{Analyzer, SummaryAnalyzer};
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::{AppTypeDetector, AuthAnalyzer, AuthMethod};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Host information for summary display
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostInfo {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub request_count: usize,
    pub api_type: Option<String>,
    pub is_primary: bool,
    pub is_same_domain: bool,
}

/// Quick summary of a HAR file
#[derive(Debug, Clone, serde::Serialize)]
pub struct HarSummary {
    pub file_name: String,
    pub total_entries: usize,
    pub time_range: Option<TimeRange>,
    pub primary_host: Option<String>,
    pub architecture: ArchitectureSummary,
    pub auth_summary: Option<AuthSummaryBrief>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
    pub duration_display: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchitectureSummary {
    pub target: Option<HostBrief>,
    pub same_domain: Vec<HostBrief>,
    pub third_party: Vec<HostBrief>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HostBrief {
    pub host: String,
    pub api_type: String,
    pub request_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthSummaryBrief {
    pub method: String,
    pub session_type: String,
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

/// Analyze hosts and group by relationship to primary
fn analyze_hosts(har: &Har) -> (Option<HostInfo>, Vec<HostInfo>, Vec<HostInfo>) {
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>)> = HashMap::new();
    let mut first_host_key: Option<String> = None;

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url
                .port()
                .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });

            let key = format!("{}://{}:{}", protocol, domain, port);

            if first_host_key.is_none() {
                first_host_key = Some(key.clone());
            }

            host_entries
                .entry(key)
                .and_modify(|(_, _, _, entries)| entries.push(entry))
                .or_insert((protocol, domain, port, vec![entry]));
        }
    }

    let first_root_domain = first_host_key.as_ref().and_then(|key| {
        host_entries
            .get(key)
            .map(|(_, domain, _, _)| get_root_domain(domain))
    });

    let mut primary: Option<HostInfo> = None;
    let mut same_domain: Vec<HostInfo> = Vec::new();
    let mut third_party: Vec<HostInfo> = Vec::new();

    for (key, (protocol, domain, port, entries)) in host_entries {
        let is_primary = first_host_key.as_ref() == Some(&key);
        let root_domain = get_root_domain(&domain);
        let is_same_domain = first_root_domain
            .as_ref()
            .is_some_and(|first| &root_domain == first);

        // Detect API type
        let api_type_results = AppTypeDetector::detect_for_host(&entries);
        let api_type = api_type_results
            .first()
            .map(|(t, _, _)| t.as_str().to_string());

        let host_info = HostInfo {
            host: domain,
            port,
            protocol,
            request_count: entries.len(),
            api_type,
            is_primary,
            is_same_domain,
        };

        if is_primary {
            primary = Some(host_info);
        } else if is_same_domain {
            same_domain.push(host_info);
        } else {
            third_party.push(host_info);
        }
    }

    // Sort by request count descending
    same_domain.sort_by(|a, b| b.request_count.cmp(&a.request_count));
    third_party.sort_by(|a, b| b.request_count.cmp(&a.request_count));

    (primary, same_domain, third_party)
}

/// Get brief auth summary
fn get_auth_summary(har: &Har) -> Option<AuthSummaryBrief> {
    let auth_analysis = AuthAnalyzer::analyze(har).ok()?;

    if auth_analysis.methods.is_empty() {
        return None;
    }

    // Determine primary method
    let method = auth_analysis
        .methods
        .first()
        .map(|m| match m {
            AuthMethod::Jwt => "JWT".to_string(),
            AuthMethod::Bearer => "Bearer Token".to_string(),
            AuthMethod::OAuth => "OAuth 2.0".to_string(),
            AuthMethod::Basic => "Basic Auth".to_string(),
            AuthMethod::ApiKey(header) => format!("API Key ({})", header),
            AuthMethod::Cookie => "Cookie-based".to_string(),
            AuthMethod::Custom(header) => format!("Custom ({})", header),
        })
        .unwrap_or_else(|| "Unknown".to_string());

    // Determine session type
    let session_type = if !auth_analysis.jwt_tokens.is_empty() {
        "JWT Bearer tokens (stateless)".to_string()
    } else if auth_analysis
        .sessions
        .iter()
        .any(|s| matches!(s.session_type, harrier_detectors::SessionType::Cookie { .. }))
    {
        "Cookie-based sessions".to_string()
    } else if !auth_analysis.sessions.is_empty() {
        "Token-based sessions".to_string()
    } else {
        "None detected".to_string()
    };

    Some(AuthSummaryBrief {
        method,
        session_type,
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

pub fn execute(file: &Path, format: OutputFormat) -> Result<()> {
    let har = HarReader::from_file(file)?;

    // Get basic summary
    let summary_analyzer = SummaryAnalyzer;
    let basic_summary = summary_analyzer.analyze(&har)?;

    // Analyze hosts
    let (primary, same_domain, third_party) = analyze_hosts(&har);

    // Get auth summary
    let auth_summary = get_auth_summary(&har);

    // Build time range
    let time_range = basic_summary.date_range.as_ref().map(|(start, end)| TimeRange {
        start: start.clone(),
        end: end.clone(),
        duration_display: format_duration(start, end),
    });

    // Build architecture summary
    let architecture = ArchitectureSummary {
        target: primary.as_ref().map(|h| HostBrief {
            host: format!("{}:{}", h.host, h.port),
            api_type: h.api_type.clone().unwrap_or_else(|| "Unknown".to_string()),
            request_count: h.request_count,
        }),
        same_domain: same_domain
            .iter()
            .map(|h| HostBrief {
                host: format!("{}:{}", h.host, h.port),
                api_type: h.api_type.clone().unwrap_or_else(|| "Unknown".to_string()),
                request_count: h.request_count,
            })
            .collect(),
        third_party: third_party
            .iter()
            .map(|h| HostBrief {
                host: format!("{}:{}", h.host, h.port),
                api_type: h.api_type.clone().unwrap_or_else(|| "Unknown".to_string()),
                request_count: h.request_count,
            })
            .collect(),
    };

    let summary = HarSummary {
        file_name: file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        total_entries: basic_summary.total_entries,
        time_range,
        primary_host: primary.as_ref().map(|h| h.host.clone()),
        architecture,
        auth_summary,
    };

    match format {
        OutputFormat::Json => output_json(&summary)?,
        OutputFormat::Table => output_table(&summary)?,
        OutputFormat::Pretty => output_pretty(&summary, file)?,
    }

    Ok(())
}

fn output_pretty(summary: &HarSummary, file: &Path) -> Result<()> {
    use console::style;

    println!(
        "\n{}",
        style(format!("Harrier Analysis: {}", summary.file_name))
            .bold()
            .cyan()
    );
    println!();

    // Overview section
    println!("{}", style("Overview").bold());
    println!(
        "  Entries:      {} requests",
        style(summary.total_entries).yellow()
    );

    if let Some(ref tr) = summary.time_range {
        // Format timestamps more readably
        let start_display = tr.start.split('T').next().unwrap_or(&tr.start);
        let end_display = tr.end.split('T').next().unwrap_or(&tr.end);
        println!(
            "  Time Range:   {} to {} ({})",
            start_display, end_display, tr.duration_display
        );
    }

    if let Some(ref host) = summary.primary_host {
        println!("  Primary Host: {}", style(host).green());
    }

    // Architecture section
    println!("\n{}", style("Architecture").bold());

    if let Some(ref target) = summary.architecture.target {
        println!(
            "  Target:       {} ({}, {} requests)",
            style(&target.host).green(),
            target.api_type,
            target.request_count
        );
    }

    for host in &summary.architecture.same_domain {
        println!(
            "  Same Domain:  {} ({}, {} requests)",
            host.host, host.api_type, host.request_count
        );
    }

    for host in summary.architecture.third_party.iter().take(3) {
        println!(
            "  Third Party:  {} ({}, {} requests)",
            host.host, host.api_type, host.request_count
        );
    }

    if summary.architecture.third_party.len() > 3 {
        println!(
            "  ... and {} more third-party hosts",
            summary.architecture.third_party.len() - 3
        );
    }

    // Authentication section
    if let Some(ref auth) = summary.auth_summary {
        println!("\n{}", style("Authentication").bold());
        println!("  Method:       {}", style(&auth.method).yellow());
        println!("  Session:      {}", auth.session_type);
    } else {
        println!("\n{}", style("Authentication").bold());
        println!("  {}", style("No authentication detected").dim());
    }

    // Next steps
    println!("\n{}", style("Commands").dim());
    println!(
        "  {} for architecture diagram",
        style(format!("harrier map {}", file.display())).cyan()
    );
    println!(
        "  {} for auth flow details",
        style(format!("harrier auth {}", file.display())).cyan()
    );
    println!(
        "  {} for HawkScan snippets",
        style(format!("harrier config {}", file.display())).cyan()
    );

    println!();
    Ok(())
}

fn output_json(summary: &HarSummary) -> Result<()> {
    let json_str = serde_json::to_string_pretty(summary)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(summary: &HarSummary) -> Result<()> {
    println!("Metric,Value");
    println!("File,{}", summary.file_name);
    println!("Total Entries,{}", summary.total_entries);

    if let Some(ref tr) = summary.time_range {
        println!("Time Range Start,{}", tr.start);
        println!("Time Range End,{}", tr.end);
        println!("Duration,{}", tr.duration_display);
    }

    if let Some(ref host) = summary.primary_host {
        println!("Primary Host,{}", host);
    }

    println!();
    println!("Category,Host,API Type,Requests");

    if let Some(ref target) = summary.architecture.target {
        println!("Target,{},{},{}", target.host, target.api_type, target.request_count);
    }

    for host in &summary.architecture.same_domain {
        println!("Same Domain,{},{},{}", host.host, host.api_type, host.request_count);
    }

    for host in &summary.architecture.third_party {
        println!("Third Party,{},{},{}", host.host, host.api_type, host.request_count);
    }

    if let Some(ref auth) = summary.auth_summary {
        println!();
        println!("Auth Method,{}", auth.method);
        println!("Session Type,{}", auth.session_type);
    }

    Ok(())
}
