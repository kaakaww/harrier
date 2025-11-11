use super::{Analyzer, SummaryStats};
use crate::Result;
use crate::har::Har;
use std::collections::HashSet;
use url::Url;

pub struct SummaryAnalyzer;

impl Analyzer for SummaryAnalyzer {
    type Output = SummaryStats;

    fn analyze(&self, har: &Har) -> Result<Self::Output> {
        tracing::debug!("Analyzing HAR summary statistics");

        let entries = &har.log.entries;
        let total_entries = entries.len();

        // Calculate total size
        let total_size: u64 = entries
            .iter()
            .map(|e| e.response.body_size.max(0) as u64)
            .sum();

        // Extract unique domains
        let mut domains = HashSet::new();
        for entry in entries {
            if let Ok(url) = Url::parse(&entry.request.url)
                && let Some(domain) = url.domain()
            {
                domains.insert(domain.to_string());
            }
        }

        // Extract date range
        let date_range = if !entries.is_empty() {
            let first = entries.first().map(|e| e.started_date_time.clone());
            let last = entries.last().map(|e| e.started_date_time.clone());
            match (first, last) {
                (Some(f), Some(l)) => Some((f, l)),
                _ => None,
            }
        } else {
            None
        };

        // Extract HTTP versions and normalize them
        let mut http_versions = HashSet::new();
        for entry in entries {
            let normalized = normalize_http_version(&entry.request.http_version);
            // Skip empty versions
            if !normalized.is_empty() {
                http_versions.insert(normalized);
            }
        }

        tracing::info!(
            "Summary analysis complete: {} entries, {} domains",
            total_entries,
            domains.len()
        );

        Ok(SummaryStats {
            total_entries,
            total_size,
            unique_domains: domains.len(),
            date_range,
            http_versions: http_versions.into_iter().collect(),
        })
    }
}

/// Normalize HTTP version strings to a consistent format
fn normalize_http_version(version: &str) -> String {
    let lower = version.to_lowercase();
    match lower.as_str() {
        "h2" | "http/2" | "http/2.0" => "HTTP/2.0".to_string(),
        "h3" | "http/3" | "http/3.0" => "HTTP/3.0".to_string(),
        "http/1.0" => "HTTP/1.0".to_string(),
        "http/1.1" => "HTTP/1.1".to_string(),
        _ => {
            // Try to handle uppercase versions like HTTP/1.1, HTTP/2.0
            if version.starts_with("HTTP/") {
                version.to_string()
            } else {
                // Unknown format, return as-is
                version.to_string()
            }
        }
    }
}
