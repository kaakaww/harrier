mod host_matcher;

pub use host_matcher::HostPattern;

use crate::har::{Entry, Har};
use url::Url;

/// Filter criteria for HAR entries
///
/// All filter conditions are combined with AND logic - an entry must match
/// ALL specified criteria to be included in the filtered output.
#[derive(Debug, Default)]
pub struct FilterCriteria {
    /// Host patterns to match (any pattern matching = pass)
    pub hosts: Vec<HostPattern>,
    /// HTTP status filter (e.g., "2xx", "404", "500-599")
    pub status: Option<StatusFilter>,
    /// HTTP method filter (case-insensitive)
    pub method: Option<String>,
    /// Content-Type filter (substring match, case-insensitive)
    pub content_type: Option<String>,
}

impl FilterCriteria {
    /// Create a new FilterCriteria with default (no filtering)
    pub fn new() -> Self {
        Self::default()
    }

    /// Add host patterns from a list of pattern strings
    pub fn with_hosts(mut self, patterns: Vec<String>) -> crate::Result<Self> {
        for pattern in patterns {
            self.hosts.push(HostPattern::parse(&pattern)?);
        }
        Ok(self)
    }

    /// Set status filter from a status pattern string
    pub fn with_status(mut self, pattern: String) -> crate::Result<Self> {
        self.status = Some(StatusFilter::parse(&pattern)?);
        Ok(self)
    }

    /// Set method filter (case-insensitive)
    pub fn with_method(mut self, method: String) -> Self {
        self.method = Some(method.to_uppercase());
        self
    }

    /// Set content-type filter (substring match, case-insensitive)
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type.to_lowercase());
        self
    }

    /// Check if an entry matches all filter criteria
    pub fn matches(&self, entry: &Entry) -> bool {
        // AND logic - all conditions must match
        if !self.matches_host(entry) {
            return false;
        }
        if !self.matches_status(entry) {
            return false;
        }
        if !self.matches_method(entry) {
            return false;
        }
        if !self.matches_content_type(entry) {
            return false;
        }
        true
    }

    /// Check if entry matches host criteria
    fn matches_host(&self, entry: &Entry) -> bool {
        // If no host filters specified, all entries pass
        if self.hosts.is_empty() {
            return true;
        }

        // Extract hostname from URL
        let url = match Url::parse(&entry.request.url) {
            Ok(url) => url,
            Err(e) => {
                tracing::debug!("Failed to parse URL {}: {}", entry.request.url, e);
                return false;
            }
        };

        let hostname = match url.host_str() {
            Some(host) => host,
            None => {
                tracing::debug!("No host in URL: {}", entry.request.url);
                return false;
            }
        };

        // Entry passes if ANY host pattern matches (OR logic within hosts)
        self.hosts.iter().any(|pattern| pattern.matches(hostname))
    }

    /// Check if entry matches status criteria
    fn matches_status(&self, entry: &Entry) -> bool {
        match &self.status {
            None => true, // No filter = all pass
            Some(filter) => filter.matches(entry.response.status),
        }
    }

    /// Check if entry matches method criteria
    fn matches_method(&self, entry: &Entry) -> bool {
        match &self.method {
            None => true, // No filter = all pass
            Some(method) => entry.request.method.to_uppercase() == *method,
        }
    }

    /// Check if entry matches content-type criteria
    fn matches_content_type(&self, entry: &Entry) -> bool {
        match &self.content_type {
            None => true, // No filter = all pass
            Some(filter) => {
                let mime_type = entry.response.content.mime_type.to_lowercase();
                mime_type.contains(filter)
            }
        }
    }
}

/// Status filter for HTTP status codes
#[derive(Debug, Clone)]
pub enum StatusFilter {
    /// Exact status code (e.g., 404)
    Exact(i64),
    /// Status code range (e.g., 200-299 for "2xx")
    Range(i64, i64),
}

impl StatusFilter {
    /// Parse a status filter pattern
    ///
    /// Supports:
    /// - Exact: "404", "200"
    /// - Range shorthand: "2xx", "4xx", "5xx"
    /// - Explicit range: "200-299", "500-599"
    pub fn parse(pattern: &str) -> crate::Result<Self> {
        // Handle "2xx", "4xx", etc.
        if pattern.len() == 3 && pattern.ends_with("xx") {
            let first_digit = pattern.chars().next().unwrap();
            if let Some(digit) = first_digit.to_digit(10) {
                let start = digit as i64 * 100;
                let end = start + 99;
                return Ok(StatusFilter::Range(start, end));
            }
        }

        // Handle explicit range "200-299"
        if let Some((start_str, end_str)) = pattern.split_once('-') {
            let start = start_str.trim().parse::<i64>().map_err(|_| {
                crate::Error::InvalidPattern(format!("Invalid status range start: {}", start_str))
            })?;
            let end = end_str.trim().parse::<i64>().map_err(|_| {
                crate::Error::InvalidPattern(format!("Invalid status range end: {}", end_str))
            })?;
            return Ok(StatusFilter::Range(start, end));
        }

        // Handle exact status code
        let code = pattern.trim().parse::<i64>().map_err(|_| {
            crate::Error::InvalidPattern(format!("Invalid status code: {}", pattern))
        })?;
        Ok(StatusFilter::Exact(code))
    }

    /// Check if a status code matches this filter
    pub fn matches(&self, status: i64) -> bool {
        match self {
            StatusFilter::Exact(code) => status == *code,
            StatusFilter::Range(start, end) => status >= *start && status <= *end,
        }
    }
}

/// Filter a HAR file based on criteria
///
/// Returns a new HAR with only entries that match the filter criteria.
/// Preserves all metadata (creator, browser, pages).
///
/// Returns an error if no entries match the filter.
pub fn filter_har(har: &Har, criteria: &FilterCriteria) -> crate::Result<Har> {
    let filtered_entries: Vec<Entry> = har
        .log
        .entries
        .iter()
        .filter(|entry| criteria.matches(entry))
        .cloned()
        .collect();

    if filtered_entries.is_empty() {
        return Err(crate::Error::Analysis(
            "No entries matched the filter criteria".to_string(),
        ));
    }

    Ok(Har {
        log: crate::har::Log {
            version: har.log.version.clone(),
            creator: har.log.creator.clone(),
            browser: har.log.browser.clone(),
            pages: har.log.pages.clone(),
            entries: filtered_entries,
            comment: har.log.comment.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_filter_exact() {
        let filter = StatusFilter::parse("404").unwrap();
        assert!(filter.matches(404));
        assert!(!filter.matches(200));
        assert!(!filter.matches(500));
    }

    #[test]
    fn test_status_filter_2xx() {
        let filter = StatusFilter::parse("2xx").unwrap();
        assert!(filter.matches(200));
        assert!(filter.matches(201));
        assert!(filter.matches(299));
        assert!(!filter.matches(199));
        assert!(!filter.matches(300));
        assert!(!filter.matches(404));
    }

    #[test]
    fn test_status_filter_4xx() {
        let filter = StatusFilter::parse("4xx").unwrap();
        assert!(filter.matches(400));
        assert!(filter.matches(404));
        assert!(filter.matches(499));
        assert!(!filter.matches(399));
        assert!(!filter.matches(500));
    }

    #[test]
    fn test_status_filter_explicit_range() {
        let filter = StatusFilter::parse("500-599").unwrap();
        assert!(filter.matches(500));
        assert!(filter.matches(503));
        assert!(filter.matches(599));
        assert!(!filter.matches(499));
        assert!(!filter.matches(600));
    }

    #[test]
    fn test_status_filter_invalid() {
        assert!(StatusFilter::parse("abc").is_err());
        assert!(StatusFilter::parse("1xxx").is_err());
        assert!(StatusFilter::parse("200-abc").is_err());
    }
}
