use super::{Analyzer, SummaryStats};
use crate::har::Har;
use crate::Result;
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
            if let Ok(url) = Url::parse(&entry.request.url) {
                if let Some(domain) = url.domain() {
                    domains.insert(domain.to_string());
                }
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

        // Extract HTTP versions
        let mut http_versions = HashSet::new();
        for entry in entries {
            http_versions.insert(entry.request.http_version.clone());
        }

        tracing::info!("Summary analysis complete: {} entries, {} domains", total_entries, domains.len());

        Ok(SummaryStats {
            total_entries,
            total_size,
            unique_domains: domains.len(),
            date_range,
            http_versions: http_versions.into_iter().collect(),
        })
    }
}
