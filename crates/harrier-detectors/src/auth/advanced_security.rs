use crate::Result;
use harrier_core::har::Har;
use serde::{Deserialize, Serialize};

use super::security::Severity;

/// Advanced security analysis findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSecurityAnalysis {
    pub token_exposures: Vec<TokenExposure>,
    pub cors_issues: Vec<CorsIssue>,
    pub csp_findings: Vec<CspFinding>,
    pub refresh_patterns: Vec<TokenRefreshPattern>,
}

/// Token exposure in insecure locations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExposure {
    pub severity: Severity,
    pub exposure_type: ExposureType,
    pub location: String,
    pub entry_index: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureType {
    TokenInUrl,
    TokenInQueryParam,
    TokenInReferer,
    CredentialsInUrl,
    SensitiveDataInUrl,
}

/// CORS configuration issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsIssue {
    pub severity: Severity,
    pub issue_type: CorsIssueType,
    pub origin: String,
    pub entry_index: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorsIssueType {
    WildcardWithCredentials,
    OverlyPermissiveOrigin,
    MissingCorsHeaders,
    InsecureOrigin,
}

/// Content Security Policy findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspFinding {
    pub severity: Severity,
    pub finding_type: CspFindingType,
    pub entry_index: usize,
    pub message: String,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CspFindingType {
    MissingCsp,
    UnsafeInline,
    UnsafeEval,
    WildcardSource,
    WeakPolicy,
}

/// Token refresh pattern analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRefreshPattern {
    pub pattern_type: RefreshPatternType,
    pub frequency: f64,
    pub token_lifetime: Option<f64>,
    pub refresh_count: usize,
    pub entry_indices: Vec<usize>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshPatternType {
    ProactiveRefresh,
    OnDemandRefresh,
    AutomaticRotation,
    ManualRefresh,
}

pub struct AdvancedSecurityAnalyzer;

impl AdvancedSecurityAnalyzer {
    /// Perform advanced security analysis
    pub fn analyze(har: &Har) -> Result<AdvancedSecurityAnalysis> {
        let token_exposures = Self::detect_token_exposures(har)?;
        let cors_issues = Self::analyze_cors(har)?;
        let csp_findings = Self::analyze_csp(har)?;
        let refresh_patterns = Self::analyze_refresh_patterns(har)?;

        Ok(AdvancedSecurityAnalysis {
            token_exposures,
            cors_issues,
            csp_findings,
            refresh_patterns,
        })
    }

    /// Detect tokens and credentials exposed in insecure locations
    fn detect_token_exposures(har: &Har) -> Result<Vec<TokenExposure>> {
        let mut exposures = Vec::new();

        for (idx, entry) in har.log.entries.iter().enumerate() {
            let url = &entry.request.url;

            // Check for tokens in URL
            if Self::has_token_in_url(url) {
                exposures.push(TokenExposure {
                    severity: Severity::Critical,
                    exposure_type: ExposureType::TokenInUrl,
                    location: Self::truncate_url(url),
                    entry_index: idx,
                    message: "Authentication token found in URL (will be logged)".to_string(),
                });
            }

            // Check for credentials in query parameters
            if Self::has_credentials_in_query(url) {
                exposures.push(TokenExposure {
                    severity: Severity::Critical,
                    exposure_type: ExposureType::CredentialsInUrl,
                    location: Self::truncate_url(url),
                    entry_index: idx,
                    message: "Credentials (username/password) found in URL".to_string(),
                });
            }

            // Check for sensitive data in URL
            if Self::has_sensitive_data_in_url(url) {
                exposures.push(TokenExposure {
                    severity: Severity::Warning,
                    exposure_type: ExposureType::SensitiveDataInUrl,
                    location: Self::truncate_url(url),
                    entry_index: idx,
                    message: "Potentially sensitive data in URL".to_string(),
                });
            }

            // Check Referer header for token leakage
            for header in &entry.request.headers {
                if header.name.to_lowercase() == "referer" && Self::has_token_in_url(&header.value)
                {
                    exposures.push(TokenExposure {
                        severity: Severity::Warning,
                        exposure_type: ExposureType::TokenInReferer,
                        location: Self::truncate_url(&header.value),
                        entry_index: idx,
                        message: "Token leaked in Referer header".to_string(),
                    });
                }
            }
        }

        Ok(exposures)
    }

    /// Analyze CORS configuration
    fn analyze_cors(har: &Har) -> Result<Vec<CorsIssue>> {
        let mut issues = Vec::new();

        for (idx, entry) in har.log.entries.iter().enumerate() {
            let mut cors_origin: Option<String> = None;
            let mut allows_credentials = false;

            // Check response headers
            for header in &entry.response.headers {
                let name_lower = header.name.to_lowercase();

                if name_lower == "access-control-allow-origin" {
                    cors_origin = Some(header.value.clone());

                    // Check for wildcard with credentials
                    if header.value == "*" {
                        // This will be checked with credentials flag below
                    } else if header.value.starts_with("http://") {
                        issues.push(CorsIssue {
                            severity: Severity::Warning,
                            issue_type: CorsIssueType::InsecureOrigin,
                            origin: header.value.clone(),
                            entry_index: idx,
                            message: "CORS allows insecure HTTP origin".to_string(),
                        });
                    }
                } else if name_lower == "access-control-allow-credentials" {
                    allows_credentials = header.value.to_lowercase() == "true";
                }
            }

            // Check for wildcard with credentials (insecure combination)
            if let Some(ref origin) = cors_origin
                && origin == "*"
                && allows_credentials
            {
                issues.push(CorsIssue {
                    severity: Severity::Critical,
                    issue_type: CorsIssueType::WildcardWithCredentials,
                    origin: origin.clone(),
                    entry_index: idx,
                    message: "CORS wildcard (*) used with credentials (security risk)".to_string(),
                });
            }

            // Check for missing CORS headers on cross-origin requests
            if Self::is_cors_request(entry) && cors_origin.is_none() {
                issues.push(CorsIssue {
                    severity: Severity::Info,
                    issue_type: CorsIssueType::MissingCorsHeaders,
                    origin: "unknown".to_string(),
                    entry_index: idx,
                    message: "Cross-origin request without CORS headers".to_string(),
                });
            }
        }

        Ok(issues)
    }

    /// Analyze Content Security Policy
    fn analyze_csp(har: &Har) -> Result<Vec<CspFinding>> {
        let mut findings = Vec::new();
        let mut html_responses_without_csp = 0;

        for (idx, entry) in har.log.entries.iter().enumerate() {
            // Only check HTML responses
            if !entry.response.content.mime_type.contains("text/html") {
                continue;
            }

            let mut has_csp = false;

            // Check for CSP headers
            for header in &entry.response.headers {
                let name_lower = header.name.to_lowercase();
                if name_lower == "content-security-policy"
                    || name_lower == "content-security-policy-report-only"
                {
                    has_csp = true;

                    // Analyze policy
                    let policy_lower = header.value.to_lowercase();

                    if policy_lower.contains("'unsafe-inline'") {
                        findings.push(CspFinding {
                            severity: Severity::Warning,
                            finding_type: CspFindingType::UnsafeInline,
                            entry_index: idx,
                            message: "CSP allows 'unsafe-inline' (XSS risk)".to_string(),
                            policy: Some(header.value.clone()),
                        });
                    }

                    if policy_lower.contains("'unsafe-eval'") {
                        findings.push(CspFinding {
                            severity: Severity::Warning,
                            finding_type: CspFindingType::UnsafeEval,
                            entry_index: idx,
                            message: "CSP allows 'unsafe-eval' (code injection risk)".to_string(),
                            policy: Some(header.value.clone()),
                        });
                    }

                    if policy_lower.contains("*") && !policy_lower.contains("data:") {
                        findings.push(CspFinding {
                            severity: Severity::Warning,
                            finding_type: CspFindingType::WildcardSource,
                            entry_index: idx,
                            message: "CSP uses wildcard source (overly permissive)".to_string(),
                            policy: Some(header.value.clone()),
                        });
                    }
                }
            }

            if !has_csp {
                html_responses_without_csp += 1;
            }
        }

        // Report missing CSP if multiple HTML responses lack it
        if html_responses_without_csp > 0 {
            findings.push(CspFinding {
                severity: Severity::Info,
                finding_type: CspFindingType::MissingCsp,
                entry_index: 0,
                message: format!(
                    "{} HTML response(s) without Content-Security-Policy header",
                    html_responses_without_csp
                ),
                policy: None,
            });
        }

        Ok(findings)
    }

    /// Analyze token refresh patterns
    fn analyze_refresh_patterns(har: &Har) -> Result<Vec<TokenRefreshPattern>> {
        let mut patterns = Vec::new();
        let mut refresh_requests = Vec::new();

        // Find all token refresh requests
        for (idx, entry) in har.log.entries.iter().enumerate() {
            if Self::is_token_refresh_request(entry) {
                refresh_requests.push((idx, entry.started_date_time.clone()));
            }
        }

        if refresh_requests.len() > 1 {
            // Analyze refresh frequency
            let entry_indices: Vec<usize> = refresh_requests.iter().map(|(idx, _)| *idx).collect();

            // Simple pattern detection
            let pattern_type = if refresh_requests.len() >= 3 {
                RefreshPatternType::AutomaticRotation
            } else {
                RefreshPatternType::OnDemandRefresh
            };

            patterns.push(TokenRefreshPattern {
                pattern_type,
                frequency: refresh_requests.len() as f64,
                token_lifetime: None,
                refresh_count: refresh_requests.len(),
                entry_indices,
                description: format!(
                    "Token refreshed {} times during session",
                    refresh_requests.len()
                ),
            });
        }

        Ok(patterns)
    }

    // Helper methods

    fn has_token_in_url(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        url_lower.contains("token=")
            || url_lower.contains("access_token=")
            || url_lower.contains("auth_token=")
            || url_lower.contains("bearer%20")
            || url.contains("eyJ") // JWT pattern
    }

    fn has_credentials_in_query(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        (url_lower.contains("username=")
            || url_lower.contains("user=")
            || url_lower.contains("email="))
            && url_lower.contains("password=")
    }

    fn has_sensitive_data_in_url(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        url_lower.contains("api_key=")
            || url_lower.contains("apikey=")
            || url_lower.contains("secret=")
            || url_lower.contains("key=")
    }

    fn is_cors_request(entry: &harrier_core::har::Entry) -> bool {
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "origin" {
                return true;
            }
        }
        false
    }

    fn is_token_refresh_request(entry: &harrier_core::har::Entry) -> bool {
        if entry.request.method != "POST" {
            return false;
        }

        let url_lower = entry.request.url.to_lowercase();
        if !(url_lower.contains("/token") || url_lower.contains("/refresh")) {
            return false;
        }

        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("grant_type=refresh_token")
                || text.contains("\"refresh_token\"")
                || text.contains("refreshToken");
        }

        false
    }

    fn truncate_url(url: &str) -> String {
        if url.len() > 100 {
            format!("{}...", &url[..97])
        } else {
            url.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_token_in_url() {
        assert!(AdvancedSecurityAnalyzer::has_token_in_url(
            "https://example.com/api?token=abc123"
        ));
        assert!(AdvancedSecurityAnalyzer::has_token_in_url(
            "https://example.com/api?access_token=abc123"
        ));
        assert!(!AdvancedSecurityAnalyzer::has_token_in_url(
            "https://example.com/api/users"
        ));
    }

    #[test]
    fn test_has_credentials_in_query() {
        assert!(AdvancedSecurityAnalyzer::has_credentials_in_query(
            "https://example.com/login?username=user&password=pass"
        ));
        assert!(!AdvancedSecurityAnalyzer::has_credentials_in_query(
            "https://example.com/api/users"
        ));
    }

    #[test]
    fn test_has_sensitive_data_in_url() {
        assert!(AdvancedSecurityAnalyzer::has_sensitive_data_in_url(
            "https://example.com/api?api_key=secret123"
        ));
        assert!(!AdvancedSecurityAnalyzer::has_sensitive_data_in_url(
            "https://example.com/api/users"
        ));
    }
}
