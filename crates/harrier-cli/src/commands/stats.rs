use anyhow::Result;
use harrier_core::analysis::{AnalysisReport, Analyzer, PerformanceAnalyzer, SummaryAnalyzer};
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::{AppType, AppTypeDetector};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Analyze a HAR file and return structured results
pub fn analyze_har(file: &Path, include_timings: bool) -> Result<AnalysisReport> {
    tracing::debug!("Reading HAR file: {}", file.display());

    // Read HAR file
    let har = HarReader::from_file(file)?;

    // Run summary analysis
    let summary_analyzer = SummaryAnalyzer;
    let summary = summary_analyzer.analyze(&har)?;

    // Run performance analysis
    let performance_analyzer = if include_timings {
        PerformanceAnalyzer::default()
    } else {
        PerformanceAnalyzer::new(0) // No slowest requests if timings not requested
    };
    let performance = performance_analyzer.analyze(&har)?;

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

/// Extract root domain from a domain string
/// Examples: api.example.com -> example.com, www.example.com -> example.com
fn get_root_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    }
}

/// Analyze hosts from HAR file entries
/// Returns hosts with first request's host first, followed by same root domain hosts by hit count,
/// then all other hosts by hit count descending
pub fn analyze_hosts(har: &Har) -> Vec<HostStats> {
    // Group entries by host
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>, bool)> = HashMap::new();
    let mut first_host_key: Option<String> = None;

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url.port().unwrap_or_else(|| {
                if protocol == "https" {
                    443
                } else {
                    80
                }
            });

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

pub fn execute(file: &Path, timings: bool, show_hosts: bool, format: &str) -> Result<()> {
    tracing::info!("Analyzing HAR file: {}", file.display());

    // Read HAR file
    let har = HarReader::from_file(file)?;

    // Analyze the HAR file
    let report = analyze_har(file, timings)?;

    // Optionally analyze hosts
    let hosts = if show_hosts {
        Some(analyze_hosts(&har))
    } else {
        None
    };

    // Output results based on format
    match format {
        "json" => output_json(&report, hosts.as_deref())?,
        "table" => output_table(&report, hosts.as_deref(), timings)?,
        _ => output_pretty(&report, hosts.as_deref(), timings)?, // "pretty" is default
    }

    Ok(())
}

fn output_pretty(
    report: &AnalysisReport,
    hosts: Option<&[HostStats]>,
    include_timings: bool,
) -> Result<()> {
    use console::style;

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
                let types: Vec<String> = host.api_types
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

    println!(); // trailing newline
    Ok(())
}

fn output_json(report: &AnalysisReport, hosts: Option<&[HostStats]>) -> Result<()> {
    use serde_json::json;

    let output = if let Some(host_list) = hosts {
        json!({
            "summary": report.summary,
            "performance": report.performance,
            "hosts": host_list,
        })
    } else {
        json!(report)
    };

    let json_str = serde_json::to_string_pretty(&output)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(
    report: &AnalysisReport,
    hosts: Option<&[HostStats]>,
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
                let types: Vec<String> = host.api_types
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

    Ok(())
}
