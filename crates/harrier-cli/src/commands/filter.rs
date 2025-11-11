use anyhow::Result;
use harrier_core::filter::FilterCriteria;
use harrier_core::har::{HarReader, HarWriter};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn execute(
    file: &Path,
    hosts: Vec<String>,
    status: Option<String>,
    method: Option<String>,
    content_type: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    tracing::debug!("Filtering HAR file: {}", file.display());

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

    // Read HAR file
    tracing::debug!("Reading HAR file");
    let har = HarReader::from_file(file)?;

    // Apply filter
    tracing::debug!("Applying filter criteria");
    let filtered_har = harrier_core::filter::filter_har(&har, &criteria)?;

    // Write output (to file or stdout)
    if let Some(output_path) = output {
        tracing::debug!("Writing filtered HAR to: {}", output_path.display());
        HarWriter::to_file(&filtered_har, &output_path)?;
    } else {
        // Write to stdout
        tracing::debug!("Writing filtered HAR to stdout");
        let json = serde_json::to_string_pretty(&filtered_har)?;
        io::stdout().write_all(json.as_bytes())?;
        io::stdout().write_all(b"\n")?;
    }

    Ok(())
}
