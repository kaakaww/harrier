use anyhow::Result;
use harrier_core::analysis::{AnalysisReport, Analyzer, PerformanceAnalyzer, SummaryAnalyzer};
use harrier_core::har::{Har, HarReader};
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

/// Statistics for a single host
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostStats {
    pub protocol: String,
    pub domain: String,
    pub port: u16,
    pub hit_count: usize,
}

/// Analyze hosts from HAR file entries
/// Returns hosts with first request's host first, then sorted by hit count descending
pub fn analyze_hosts(har: &Har) -> Vec<HostStats> {
    let mut host_map: HashMap<String, (HostStats, bool)> = HashMap::new();
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

            host_map
                .entry(key)
                .and_modify(|(stats, _)| stats.hit_count += 1)
                .or_insert((
                    HostStats {
                        protocol: protocol.clone(),
                        domain: domain.clone(),
                        port,
                        hit_count: 1,
                    },
                    is_first,
                ));
        }
    }

    // Convert to vector and sort
    let mut hosts: Vec<_> = host_map.into_values().collect();

    // Sort: first host first, then by hit count descending
    hosts.sort_by(|(a, a_is_first), (b, b_is_first)| {
        match (a_is_first, b_is_first) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b.hit_count.cmp(&a.hit_count),
        }
    });

    // Extract just the HostStats
    hosts.into_iter().map(|(stats, _)| stats).collect()
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
            println!(
                "  {}://{}:{}  ({} requests){}",
                host.protocol, host.domain, host.port, host.hit_count, first_marker
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
        println!("Host,Requests");
        for host in host_list {
            println!(
                "{}://{}:{},{}",
                host.protocol, host.domain, host.port, host.hit_count
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
