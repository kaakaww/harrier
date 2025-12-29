use crate::OutputFormat;
use anyhow::Result;
use harrier_core::filter::FilterCriteria;
use harrier_core::har::{Har, HarReader, HarWriter};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub fn execute(
    file: &Path,
    hosts: Vec<String>,
    status: Option<String>,
    method: Option<String>,
    content_type: Option<String>,
    output: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    // Read HAR from file or stdin
    let har = if file.as_os_str() == "-" {
        tracing::debug!("Reading HAR from stdin");
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        serde_json::from_str(&buffer)?
    } else {
        tracing::debug!("Reading HAR file: {}", file.display());
        HarReader::from_file(file)?
    };

    // Parse host patterns from CLI (handle comma-separated values)
    let host_patterns: Vec<String> = hosts
        .iter()
        .flat_map(|h| h.split(',').map(|s| s.trim().to_string()))
        .collect();

    // Build filter criteria
    let mut criteria = FilterCriteria::new();

    if !host_patterns.is_empty() {
        criteria = criteria.with_hosts(host_patterns)?;
    }

    if let Some(status_pattern) = status {
        criteria = criteria.with_status(status_pattern)?;
    }

    if let Some(method_filter) = method {
        criteria = criteria.with_method(method_filter);
    }

    if let Some(content_type_filter) = content_type {
        criteria = criteria.with_content_type(content_type_filter);
    }

    // Apply filter
    let original_count = har.log.entries.len();
    tracing::debug!("Applying filter criteria");
    let filtered_har = harrier_core::filter::filter_har(&har, &criteria)?;
    let filtered_count = filtered_har.log.entries.len();

    // Generate output based on format
    match format {
        OutputFormat::Json => output_json(&filtered_har, output)?,
        OutputFormat::Pretty => {
            output_pretty(&filtered_har, original_count, filtered_count, output)?
        }
        OutputFormat::Table => output_table(&filtered_har, output)?,
    }

    Ok(())
}

fn output_json(har: &Har, output: Option<PathBuf>) -> Result<()> {
    if let Some(output_path) = output {
        tracing::debug!("Writing filtered HAR to: {}", output_path.display());
        HarWriter::to_file(har, &output_path)?;
    } else {
        let json = serde_json::to_string_pretty(har)?;
        io::stdout().write_all(json.as_bytes())?;
        io::stdout().write_all(b"\n")?;
    }
    Ok(())
}

fn output_pretty(
    har: &Har,
    original_count: usize,
    filtered_count: usize,
    output: Option<PathBuf>,
) -> Result<()> {
    use console::style;

    let mut out = String::new();

    out.push_str(&format!("\n{}\n\n", style("Filter Results").bold().cyan()));

    out.push_str(&format!(
        "  {} {} {} {}\n\n",
        style(original_count).bold(),
        "entries",
        style("→").dim(),
        style(filtered_count).bold().green()
    ));

    if filtered_count == 0 {
        out.push_str(&format!(
            "  {}\n",
            style("No entries matched the filter criteria.").yellow()
        ));
    } else {
        // Group by host
        let mut hosts: std::collections::HashMap<String, Vec<&harrier_core::har::Entry>> =
            std::collections::HashMap::new();
        for entry in &har.log.entries {
            if let Ok(url) = url::Url::parse(&entry.request.url) {
                let host = url.host_str().unwrap_or("unknown").to_string();
                hosts.entry(host).or_default().push(entry);
            }
        }

        for (host, entries) in &hosts {
            out.push_str(&format!("  {} ({})\n", style(host).bold(), entries.len()));
            for entry in entries.iter().take(5) {
                let status = entry.response.status;
                let status_style = if (200..300).contains(&status) {
                    style(status).green()
                } else if status >= 400 {
                    style(status).red()
                } else {
                    style(status).yellow()
                };

                if let Ok(url) = url::Url::parse(&entry.request.url) {
                    out.push_str(&format!(
                        "    {} {} {}\n",
                        style(&entry.request.method).dim(),
                        status_style,
                        url.path()
                    ));
                }
            }
            if entries.len() > 5 {
                out.push_str(&format!(
                    "    {} more...\n",
                    style(format!("... and {}", entries.len() - 5)).dim()
                ));
            }
        }
    }

    if let Some(output_path) = output {
        // Write full HAR to file, show summary to stderr
        HarWriter::to_file(har, &output_path)?;
        eprint!("{}", out);
        eprintln!("\n  {} {}\n", style("Wrote:").dim(), output_path.display());
    } else {
        print!("{}", out);
        println!(
            "\n  {}\n",
            style("Use --format json for full HAR output, or -o to write to file.").dim()
        );
    }

    Ok(())
}

fn output_table(har: &Har, output: Option<PathBuf>) -> Result<()> {
    let mut out = String::new();
    out.push_str("Method,Status,Host,Path,Content-Type,Size\n");

    for entry in &har.log.entries {
        if let Ok(url) = url::Url::parse(&entry.request.url) {
            let host = url.host_str().unwrap_or("unknown");
            let path = url.path();
            let content_type = if entry.response.content.mime_type.is_empty() {
                "-"
            } else {
                &entry.response.content.mime_type
            };
            let size = entry.response.content.size;

            out.push_str(&format!(
                "{},{},{},{},\"{}\",{}\n",
                entry.request.method, entry.response.status, host, path, content_type, size
            ));
        }
    }

    if let Some(output_path) = output {
        std::fs::write(&output_path, &out)?;
        eprintln!("Wrote table to: {}", output_path.display());
    } else {
        print!("{}", out);
    }

    Ok(())
}
