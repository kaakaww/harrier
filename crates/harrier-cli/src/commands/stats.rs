use crate::OutputFormat;
use anyhow::Result;
use harrier_core::analysis::{AnalysisReport, Analyzer, PerformanceAnalyzer, SummaryAnalyzer};
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::{AppType, AppTypeDetector, AuthAnalysis, AuthAnalyzer};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Analyze a HAR file and return structured results
pub fn analyze_har(har: &Har, include_timings: bool) -> Result<AnalysisReport> {
    // Run summary analysis
    let summary_analyzer = SummaryAnalyzer;
    let summary = summary_analyzer.analyze(har)?;

    // Run performance analysis
    let performance_analyzer = if include_timings {
        PerformanceAnalyzer::default()
    } else {
        PerformanceAnalyzer::new(0) // No slowest requests if timings not requested
    };
    let performance = performance_analyzer.analyze(har)?;

    Ok(AnalysisReport {
        summary,
        performance,
    })
}

/// API type information for a host
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiTypeInfo {
    pub api_type: AppType,
    pub confidence: f64,
    pub request_count: usize,
}

/// Statistics for a single host
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostStats {
    pub protocol: String,
    pub domain: String,
    pub port: u16,
    pub hit_count: usize,
    pub api_types: Vec<ApiTypeInfo>,
}

/// Extract root domain from a domain string using the Public Suffix List
/// Examples: api.example.com -> example.com, www.example.com -> example.com, api.co.uk -> example.co.uk
/// This properly handles public suffixes like .co.uk, .com.au, etc.
fn get_root_domain(domain: &str) -> String {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return domain.to_string();
    }

    // Use the psl crate to get the registrable domain (eTLD+1)
    // This handles public suffixes correctly
    match psl::domain(domain.as_bytes()) {
        Some(root) => {
            // Convert bytes back to string
            String::from_utf8_lossy(root.as_bytes()).to_string()
        }
        None => {
            // Fallback to simple logic for IP addresses or invalid domains
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                domain.to_string()
            }
        }
    }
}

/// Analyze hosts from HAR file entries
/// Returns hosts with first request's host first, followed by same root domain hosts by hit count,
/// then all other hosts by hit count descending
pub fn analyze_hosts(har: &Har) -> Vec<HostStats> {
    // Group entries by host
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>, bool)> =
        HashMap::new();
    let mut first_host_key: Option<String> = None;

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url
                .port()
                .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });

            let key = format!("{}://{}:{}", protocol, domain, port);

            // Track first host
            if first_host_key.is_none() {
                first_host_key = Some(key.clone());
            }

            let is_first = first_host_key.as_ref() == Some(&key);

            host_entries
                .entry(key)
                .and_modify(|(_, _, _, entries, _)| entries.push(entry))
                .or_insert((protocol, domain, port, vec![entry], is_first));
        }
    }

    // Get the first host's domain for grouping
    let first_host_domain = if let Some(first_key) = &first_host_key {
        host_entries
            .get(first_key)
            .map(|(_, domain, _, _, _)| get_root_domain(domain))
    } else {
        None
    };

    // Convert to HostStats with API type detection
    let mut hosts: Vec<(HostStats, bool, String)> = host_entries
        .into_iter()
        .map(|(_, (protocol, domain, port, entries, is_first))| {
            let hit_count = entries.len();
            let root_domain = get_root_domain(&domain);

            // Detect API types for this host
            let api_type_results = AppTypeDetector::detect_for_host(&entries);
            let api_types = api_type_results
                .into_iter()
                .map(|(api_type, confidence, request_count)| ApiTypeInfo {
                    api_type,
                    confidence,
                    request_count,
                })
                .collect();

            (
                HostStats {
                    protocol,
                    domain,
                    port,
                    hit_count,
                    api_types,
                },
                is_first,
                root_domain,
            )
        })
        .collect();

    // Sort with three-tier logic:
    // 1. First host (always first)
    // 2. Hosts with same root domain as first, sorted by hit count descending
    // 3. All other hosts, sorted by hit count descending
    hosts.sort_by(|(a, a_is_first, a_root), (b, b_is_first, b_root)| {
        match (a_is_first, b_is_first) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                // Neither is first, group by root domain
                if let Some(ref first_root) = first_host_domain {
                    let a_same_domain = a_root == first_root;
                    let b_same_domain = b_root == first_root;

                    match (a_same_domain, b_same_domain) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => b.hit_count.cmp(&a.hit_count),
                    }
                } else {
                    // No first host, just sort by hit count
                    b.hit_count.cmp(&a.hit_count)
                }
            }
        }
    });

    // Extract just the HostStats
    hosts.into_iter().map(|(stats, _, _)| stats).collect()
}

pub fn execute(
    file: &Path,
    timings: bool,
    show_hosts: bool,
    show_auth: bool,
    verbose: bool,
    format: OutputFormat,
) -> Result<()> {
    tracing::info!("Analyzing HAR file: {}", file.display());

    // Read HAR file once for all analyses
    let har = HarReader::from_file(file)?;

    // Analyze the HAR file
    let report = analyze_har(&har, timings)?;

    // Optionally analyze hosts
    let hosts = if show_hosts {
        Some(analyze_hosts(&har))
    } else {
        None
    };

    // Optionally analyze authentication
    let auth = if show_auth {
        Some(AuthAnalyzer::analyze(&har)?)
    } else {
        None
    };

    // Output results based on format
    match format {
        OutputFormat::Json => output_json(&report, hosts.as_deref(), auth.as_ref())?,
        OutputFormat::Table => output_table(&report, hosts.as_deref(), auth.as_ref(), timings)?,
        OutputFormat::Pretty => {
            output_pretty(&report, hosts.as_deref(), auth.as_ref(), timings, verbose)?
        }
    }

    Ok(())
}

fn output_pretty(
    report: &AnalysisReport,
    hosts: Option<&[HostStats]>,
    auth: Option<&AuthAnalysis>,
    include_timings: bool,
    verbose: bool,
) -> Result<()> {
    use console::style;
    use harrier_detectors::AuthSummaryGenerator;

    println!("\n{}", style("HAR Analysis Report").bold().cyan());
    println!("{}", style("===================").cyan());

    // Summary section
    println!("\n{}", style("Summary:").bold());
    println!("  Total Entries:      {}", report.summary.total_entries);
    println!("  Unique Domains:     {}", report.summary.unique_domains);
    println!("  Response Body Size: {} bytes", report.summary.total_size);

    if let Some((start, end)) = &report.summary.date_range {
        println!("  Date Range:         {} to {}", start, end);
    }

    if !report.summary.http_versions.is_empty() {
        println!(
            "  HTTP Versions:      {}",
            report.summary.http_versions.join(", ")
        );
    }

    // Hosts section (if requested)
    if let Some(host_list) = hosts {
        println!("\n{}", style("Hosts:").bold());
        for (i, host) in host_list.iter().enumerate() {
            let first_marker = if i == 0 { " [first]" } else { "" };

            // Format API types
            let api_types_str = if !host.api_types.is_empty() {
                let types: Vec<String> = host
                    .api_types
                    .iter()
                    .map(|t| t.api_type.as_str().to_string())
                    .collect();
                format!(" [{}]", types.join(", "))
            } else {
                String::new()
            };

            println!(
                "  {}://{}:{}  ({} requests){}{}",
                host.protocol, host.domain, host.port, host.hit_count, api_types_str, first_marker
            );
        }
    }

    // Performance section (if requested)
    if include_timings {
        println!("\n{}", style("Performance:").bold());
        println!(
            "  Total Time:       {:.2} ms",
            report.performance.total_time
        );
        println!(
            "  Average Time:     {:.2} ms",
            report.performance.average_time
        );
        println!(
            "  Median Time:      {:.2} ms",
            report.performance.median_time
        );

        if !report.performance.slowest_requests.is_empty() {
            println!("\n{}", style("Slowest Requests:").bold());
            for (i, req) in report.performance.slowest_requests.iter().enumerate() {
                println!(
                    "  {}. [{:.2} ms] {} {} - {}",
                    i + 1,
                    req.time,
                    req.method,
                    req.status,
                    req.url
                );
            }
        }
    }

    // Authentication section (if requested)
    if let Some(auth_analysis) = auth {
        // Generate authentication summary
        let auth_summary = AuthSummaryGenerator::generate_summary(auth_analysis);
        let security_summary = AuthSummaryGenerator::aggregate_security_findings(auth_analysis);

        if let Some(summary) = auth_summary {
            // Authentication Summary Section (NEW - Top Priority)
            println!(
                "\n{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").cyan()
            );
            println!("{}", style("Authentication Summary").bold().cyan());
            println!(
                "{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").cyan()
            );

            println!("\n{}", style("Primary Method:").bold());
            println!(
                "  {}",
                style(&summary.primary_method.method_type).green().bold()
            );
            println!("  {}", summary.primary_method.description);

            println!("\n{}", style("Session Mechanism:").bold());
            println!("  {}", summary.session_mechanism.mechanism_type);
            println!("  {}", summary.session_mechanism.details);

            // Key Endpoints
            if !summary.key_endpoints.is_empty() {
                println!("\n{}", style("Key Endpoints:").bold());
                for endpoint in summary.key_endpoints.iter().take(5) {
                    println!("  {} {}", style(&endpoint.method).yellow(), endpoint.path);
                    println!("      → {}", style(&endpoint.purpose).dim());
                }
                if summary.key_endpoints.len() > 5 {
                    println!(
                        "  ... and {} more endpoints",
                        summary.key_endpoints.len() - 5
                    );
                }
            }

            // HawkScan Configuration
            println!("\n{}", style("For HawkScan Configuration:").bold().green());
            println!("{}", style("─────────────────────────────").green());
            for note in &summary.hawkscan_config.notes {
                println!("  • {}", note);
            }
            println!("\n{}", style("Example stackhawk.yml:").dim());
            for line in summary.hawkscan_config.config_snippet.lines() {
                println!("  {}", style(line).dim());
            }

            // Additional Info
            if !summary.additional_info.is_empty() {
                println!("\n{}", style("Additional Information:").bold());
                for info in &summary.additional_info {
                    println!("  ℹ {}", info);
                }
            }

            println!(
                "\n{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").cyan()
            );
        } else {
            // No authentication detected
            println!(
                "\n{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").yellow()
            );
            println!("{}", style("Authentication Summary").bold().yellow());
            println!(
                "{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").yellow()
            );
            println!(
                "\n{}",
                style("⚠ No authentication mechanisms detected in this HAR file.").yellow()
            );
            println!("\n{}", style("Possible reasons:").bold());
            println!("  1. HAR was captured before authentication");
            println!("  2. Application uses authentication not yet supported");
            println!("  3. Cookies/headers were sanitized from the HAR file");
            println!("\n{}", style("To improve detection:").bold());
            println!("  • Ensure HAR includes a complete authentication flow");
            println!("  • Capture from login page through authenticated requests");
            println!("  • Verify cookies and authorization headers are included");
            println!("\n{}", style("For HawkScan:").bold().green());
            println!("  • You'll need to configure authentication manually");
            println!("  • See: https://docs.stackhawk.com/hawkscan/authenticated-scanning.html");
            println!(
                "\n{}",
                style("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").yellow()
            );
        }

        // Security Findings Summary (Aggregated and Deduplicated)
        let total_critical = security_summary.critical.len();
        let total_warnings = security_summary.warnings.len();
        let total_info = security_summary.info.len();

        if total_critical + total_warnings + total_info > 0 {
            println!("\n{}", style("Security Findings Summary").bold());
            println!("{}", style("──────────────────────────").dim());

            if total_critical > 0 {
                println!(
                    "\n{} {}",
                    style(format!("⚠ {} Critical", total_critical)).red().bold(),
                    style("issues found:").red()
                );
                for finding in &security_summary.critical {
                    println!(
                        "  {} ({} occurrence{})",
                        finding.message,
                        finding.count,
                        if finding.count > 1 { "s" } else { "" }
                    );
                    if verbose && !finding.sample_entries.is_empty() {
                        println!(
                            "      Sample entries: {}",
                            finding
                                .sample_entries
                                .iter()
                                .map(|e| format!("#{}", e))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
            }

            if total_warnings > 0 {
                println!(
                    "\n{} {}",
                    style(format!("⚠ {} Warning", total_warnings))
                        .yellow()
                        .bold(),
                    style("issues found:").yellow()
                );
                let max_warnings = if verbose { total_warnings } else { 5 };
                for finding in security_summary.warnings.iter().take(max_warnings) {
                    println!(
                        "  {} ({} occurrence{})",
                        finding.message,
                        finding.count,
                        if finding.count > 1 { "s" } else { "" }
                    );
                }
                if !verbose && total_warnings > 5 {
                    println!(
                        "  ... and {} more warnings (use --verbose to see all)",
                        total_warnings - 5
                    );
                }
            }

            if verbose && total_info > 0 {
                println!(
                    "\n{} {}",
                    style(format!("ℹ {} Info", total_info)).blue(),
                    style("findings:").blue()
                );
                for finding in &security_summary.info {
                    println!(
                        "  {} ({} occurrence{})",
                        finding.message,
                        finding.count,
                        if finding.count > 1 { "s" } else { "" }
                    );
                }
            }
        }

        // Verbose Details (Only if --verbose flag is set)
        if verbose {
            // Show detailed session information
            if !auth_analysis.sessions.is_empty() {
                println!("\n{}", style("Detailed Session Information").bold());
                println!("{}", style("─────────────────────────────").dim());
                for (i, session) in auth_analysis.sessions.iter().enumerate() {
                    println!("\n{}. {}", i + 1, session.identifier);
                    println!("   First seen:  {}", session.first_seen);
                    println!("   Last seen:   {}", session.last_seen);
                    println!("   Requests:    {}", session.request_count);
                    println!("   Duration:    {:.1}s", session.duration_ms / 1000.0);

                    if let Some(ref attrs) = session.attributes {
                        let mut security_flags = Vec::new();
                        if attrs.http_only == Some(true) {
                            security_flags.push("HttpOnly ✓");
                        } else {
                            security_flags.push("HttpOnly ✗");
                        }
                        if attrs.secure == Some(true) {
                            security_flags.push("Secure ✓");
                        } else {
                            security_flags.push("Secure ✗");
                        }
                        println!("   Security:    {}", security_flags.join(", "));
                    }
                }
            }

            // Show JWT details
            if !auth_analysis.jwt_tokens.is_empty() {
                println!("\n{}", style("JWT Token Details").bold());
                println!("{}", style("──────────────────").dim());
                for (i, token) in auth_analysis.jwt_tokens.iter().enumerate() {
                    println!("\n{}. {}", i + 1, token.raw_token);
                    if let Some(ref alg) = token.header.alg {
                        println!("   Algorithm:  {}", alg);
                    }
                    if let Some(ref iss) = token.claims.iss {
                        println!("   Issuer:     {}", iss);
                    }
                    if let Some(ref sub) = token.claims.sub {
                        println!("   Subject:    {}", sub);
                    }
                    if let Some(exp) = token.claims.exp {
                        println!("   Expires:    {} (Unix timestamp)", exp);
                    }
                    println!("   Usage:      {} requests", token.usage_count);
                }
            }

            // Show authentication events
            if !auth_analysis.events.is_empty() {
                println!("\n{}", style("Authentication Events").bold());
                println!("{}", style("──────────────────────").dim());
                for event in auth_analysis.events.iter().take(10) {
                    let icon = match event.event_type {
                        harrier_detectors::AuthEventType::LoginSuccess => style("✓").green(),
                        harrier_detectors::AuthEventType::LoginFailure => style("✗").red(),
                        harrier_detectors::AuthEventType::Logout => style("→").blue(),
                        harrier_detectors::AuthEventType::TokenRefresh => style("↻").cyan(),
                        harrier_detectors::AuthEventType::SessionExpired => style("⌛").yellow(),
                        harrier_detectors::AuthEventType::PasswordReset => style("⚡").magenta(),
                    };
                    println!(
                        "  {} {} - {}",
                        icon,
                        event.event_type.as_str(),
                        event.details.description
                    );
                }
                if auth_analysis.events.len() > 10 {
                    println!("  ... and {} more events", auth_analysis.events.len() - 10);
                }
            }
        }
    }

    println!(); // trailing newline
    Ok(())
}

fn output_json(
    report: &AnalysisReport,
    hosts: Option<&[HostStats]>,
    auth: Option<&AuthAnalysis>,
) -> Result<()> {
    use serde_json::json;

    let mut output = json!({
        "summary": report.summary,
        "performance": report.performance,
    });

    if let Some(host_list) = hosts {
        output["hosts"] = json!(host_list);
    }

    if let Some(auth_analysis) = auth {
        output["authentication"] = json!(auth_analysis);
    }

    let json_str = serde_json::to_string_pretty(&output)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(
    report: &AnalysisReport,
    hosts: Option<&[HostStats]>,
    auth: Option<&AuthAnalysis>,
    include_timings: bool,
) -> Result<()> {
    // Simple table format
    println!("Metric,Value");
    println!("Total Entries,{}", report.summary.total_entries);
    println!("Unique Domains,{}", report.summary.unique_domains);
    println!("Response Body Size (bytes),{}", report.summary.total_size);

    if let Some(host_list) = hosts {
        println!();
        println!("Host,Requests,API Types");
        for host in host_list {
            // Format API types for CSV (quote if contains comma)
            let api_types_str = if !host.api_types.is_empty() {
                let types: Vec<String> = host
                    .api_types
                    .iter()
                    .map(|t| t.api_type.as_str().to_string())
                    .collect();
                let types_joined = types.join(", ");
                // Quote if contains comma
                if types_joined.contains(',') {
                    format!("\"{}\"", types_joined)
                } else {
                    types_joined
                }
            } else {
                String::new()
            };

            println!(
                "{}://{}:{},{},{}",
                host.protocol, host.domain, host.port, host.hit_count, api_types_str
            );
        }
    }

    if include_timings {
        println!();
        println!("Metric,Value");
        println!("Total Time (ms),{:.2}", report.performance.total_time);
        println!("Average Time (ms),{:.2}", report.performance.average_time);
        println!("Median Time (ms),{:.2}", report.performance.median_time);
    }

    if let Some(auth_analysis) = auth {
        println!();
        println!("Authentication Methods");
        for method in &auth_analysis.methods {
            println!("{},", method.as_str());
        }

        if !auth_analysis.flows.is_empty() {
            println!();
            println!("Flow Type,Started,Steps");
            for flow in &auth_analysis.flows {
                println!(
                    "\"{}\",{},{}",
                    flow.flow_type.as_str(),
                    flow.start_time,
                    flow.steps.len()
                );
            }
        }

        if !auth_analysis.events.is_empty() {
            println!();
            println!("Event Type,Timestamp,Description");
            for event in &auth_analysis.events {
                println!(
                    "\"{}\",{},\"{}\"",
                    event.event_type.as_str(),
                    event.timestamp,
                    event.details.description
                );
            }
        }

        if !auth_analysis.sessions.is_empty() {
            println!();
            println!("Session,Requests,Duration (s)");
            for session in &auth_analysis.sessions {
                println!(
                    "\"{}\",{},{:.1}",
                    session.identifier,
                    session.request_count,
                    session.duration_ms / 1000.0
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_root_domain_simple() {
        // Standard domains
        assert_eq!(get_root_domain("api.example.com"), "example.com");
        assert_eq!(get_root_domain("www.example.com"), "example.com");
        assert_eq!(get_root_domain("example.com"), "example.com");
    }

    #[test]
    fn test_get_root_domain_public_suffixes() {
        // Domains with public suffixes like .co.uk
        assert_eq!(get_root_domain("api.example.co.uk"), "example.co.uk");
        assert_eq!(get_root_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(get_root_domain("example.co.uk"), "example.co.uk");

        // Other public suffixes
        assert_eq!(get_root_domain("test.example.com.au"), "example.com.au");
        assert_eq!(get_root_domain("api.example.org.uk"), "example.org.uk");
    }

    #[test]
    fn test_get_root_domain_edge_cases() {
        // Single label domain
        assert_eq!(get_root_domain("localhost"), "localhost");

        // IP addresses should be returned as-is
        assert_eq!(get_root_domain("192.168.1.1"), "192.168.1.1");

        // Multi-level domains
        assert_eq!(get_root_domain("a.b.c.example.com"), "example.com");
    }
}
