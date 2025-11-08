use anyhow::Result;
use harrier_core::analysis::{AnalysisReport, Analyzer, PerformanceAnalyzer, SummaryAnalyzer};
use harrier_core::har::HarReader;
use std::path::Path;

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

pub fn execute(file: &Path, timings: bool, format: &str) -> Result<()> {
    tracing::info!("Analyzing HAR file: {}", file.display());

    // Analyze the HAR file
    let report = analyze_har(file, timings)?;

    // Output results based on format
    match format {
        "json" => output_json(&report)?,
        "table" => output_table(&report, timings)?,
        _ => output_pretty(&report, timings)?, // "pretty" is default
    }

    Ok(())
}

fn output_pretty(report: &AnalysisReport, include_timings: bool) -> Result<()> {
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

fn output_json(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{}", json);
    Ok(())
}

fn output_table(report: &AnalysisReport, include_timings: bool) -> Result<()> {
    // Simple table format
    println!("Metric,Value");
    println!("Total Entries,{}", report.summary.total_entries);
    println!("Unique Domains,{}", report.summary.unique_domains);
    println!("Response Body Size (bytes),{}", report.summary.total_size);

    if include_timings {
        println!("Total Time (ms),{:.2}", report.performance.total_time);
        println!("Average Time (ms),{:.2}", report.performance.average_time);
        println!("Median Time (ms),{:.2}", report.performance.median_time);
    }

    Ok(())
}
