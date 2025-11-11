use glob::Pattern;

/// Represents a host pattern for filtering HAR entries
#[derive(Debug, Clone)]
pub enum HostPattern {
    /// Exact hostname match (case-insensitive)
    Exact(String),
    /// Glob pattern match (e.g., *.example.com)
    Glob(Pattern),
}

impl HostPattern {
    /// Parse a host pattern string into a HostPattern
    ///
    /// If the pattern contains '*' or '?', it's treated as a glob pattern.
    /// Otherwise, it's treated as an exact match (case-insensitive).
    pub fn parse(pattern: &str) -> crate::Result<Self> {
        if pattern.contains('*') || pattern.contains('?') {
            // Glob pattern - lowercase for case-insensitive matching
            let pattern_lower = pattern.to_lowercase();
            let glob_pattern = Pattern::new(&pattern_lower).map_err(|e| {
                crate::Error::InvalidPattern(format!("Invalid glob pattern '{}': {}", pattern, e))
            })?;
            Ok(HostPattern::Glob(glob_pattern))
        } else {
            // Exact match (lowercase for case-insensitive comparison)
            Ok(HostPattern::Exact(pattern.to_lowercase()))
        }
    }

    /// Check if a hostname matches this pattern
    ///
    /// Matching is case-insensitive for both exact and glob patterns.
    pub fn matches(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();
        match self {
            HostPattern::Exact(pattern) => &hostname_lower == pattern,
            HostPattern::Glob(pattern) => pattern.matches(&hostname_lower),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = HostPattern::parse("api.example.com").unwrap();
        assert!(pattern.matches("api.example.com"));
        assert!(pattern.matches("API.EXAMPLE.COM")); // Case-insensitive
        assert!(!pattern.matches("web.example.com"));
        assert!(!pattern.matches("api.example.com.extra"));
    }

    #[test]
    fn test_glob_wildcard_prefix() {
        let pattern = HostPattern::parse("*.example.com").unwrap();
        assert!(pattern.matches("api.example.com"));
        assert!(pattern.matches("web.example.com"));
        assert!(pattern.matches("api-v2.example.com"));
        assert!(pattern.matches("API.EXAMPLE.COM")); // Case-insensitive
        assert!(!pattern.matches("example.com")); // No subdomain
        assert!(!pattern.matches("api.different.com"));
    }

    #[test]
    fn test_glob_wildcard_suffix() {
        let pattern = HostPattern::parse("api-*.com").unwrap();
        assert!(pattern.matches("api-v1.com"));
        assert!(pattern.matches("api-v2.com"));
        assert!(pattern.matches("api-production.com"));
        assert!(!pattern.matches("web-v1.com"));
        assert!(!pattern.matches("api.com"));
    }

    #[test]
    fn test_glob_multiple_wildcards() {
        let pattern = HostPattern::parse("api-*.*example.com").unwrap();
        assert!(pattern.matches("api-v1.staging.example.com"));
        assert!(pattern.matches("api-v2.prod.example.com"));
        assert!(!pattern.matches("web-v1.staging.example.com"));
    }

    #[test]
    fn test_glob_question_mark() {
        let pattern = HostPattern::parse("api?.example.com").unwrap();
        assert!(pattern.matches("api1.example.com"));
        assert!(pattern.matches("api2.example.com"));
        assert!(pattern.matches("apiX.example.com"));
        assert!(!pattern.matches("api.example.com")); // Missing character
        assert!(!pattern.matches("api12.example.com")); // Too many characters
    }

    #[test]
    fn test_case_insensitive() {
        let exact = HostPattern::parse("API.Example.Com").unwrap();
        assert!(exact.matches("api.example.com"));
        assert!(exact.matches("API.EXAMPLE.COM"));
        assert!(exact.matches("Api.Example.Com"));

        let glob = HostPattern::parse("*.Example.COM").unwrap();
        assert!(glob.matches("api.example.com"));
        assert!(glob.matches("WEB.EXAMPLE.COM"));
    }
}
