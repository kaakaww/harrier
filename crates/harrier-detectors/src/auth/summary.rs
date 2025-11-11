use super::{AuthAnalysis, AuthFlowType, AuthMethod, SessionType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// High-level authentication summary for AppSec engineers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSummary {
    pub primary_method: AuthMethodSummary,
    pub session_mechanism: SessionMechanismSummary,
    pub key_endpoints: Vec<EndpointInfo>,
    pub hawkscan_config: HawkScanConfig,
    pub additional_info: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethodSummary {
    pub method_type: String,
    pub description: String,
    pub confidence: ConfidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMechanismSummary {
    pub mechanism_type: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub method: String,
    pub path: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HawkScanConfig {
    pub auth_type: String,
    pub config_snippet: String,
    pub notes: Vec<String>,
}

/// Aggregated security findings (deduplicated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFindingsSummary {
    pub critical: Vec<AggregatedFinding>,
    pub warnings: Vec<AggregatedFinding>,
    pub info: Vec<AggregatedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedFinding {
    pub finding_type: String,
    pub message: String,
    pub count: usize,
    pub sample_entries: Vec<usize>,
}

pub struct AuthSummaryGenerator;

impl AuthSummaryGenerator {
    /// Generate authentication summary from analysis results
    pub fn generate_summary(analysis: &AuthAnalysis) -> Option<AuthenticationSummary> {
        // If no authentication detected, return None
        if analysis.methods.is_empty()
            && analysis.sessions.is_empty()
            && analysis.flows.is_empty()
            && analysis.jwt_tokens.is_empty()
        {
            return None;
        }

        let primary_method = Self::determine_primary_method(analysis);
        let session_mechanism = Self::determine_session_mechanism(analysis);
        let key_endpoints = Self::extract_key_endpoints(analysis);
        let hawkscan_config =
            Self::generate_hawkscan_config(&primary_method, &session_mechanism, analysis);
        let additional_info = Self::generate_additional_info(analysis);

        Some(AuthenticationSummary {
            primary_method,
            session_mechanism,
            key_endpoints,
            hawkscan_config,
            additional_info,
        })
    }

    /// Aggregate and deduplicate security findings
    pub fn aggregate_security_findings(analysis: &AuthAnalysis) -> SecurityFindingsSummary {
        let mut critical = HashMap::new();
        let mut warnings = HashMap::new();
        let mut info = HashMap::new();

        // Aggregate security notes
        for note in &analysis.security_notes {
            let key = format!("{} - {}", note.category, note.message);
            let target_map = match note.severity {
                super::Severity::Critical => &mut critical,
                super::Severity::Warning => &mut warnings,
                super::Severity::Info => &mut info,
            };

            target_map
                .entry(key.clone())
                .and_modify(|(count, entries): &mut (usize, Vec<usize>)| {
                    *count += 1;
                    if entries.len() < 3
                        && let Some(entry_idx) = note.entry_index
                    {
                        entries.push(entry_idx);
                    }
                })
                .or_insert((1, note.entry_index.map(|i| vec![i]).unwrap_or_default()));
        }

        // Aggregate advanced security findings
        for exposure in &analysis.advanced_security.token_exposures {
            let key = format!("Token Exposure - {}", exposure.exposure_type.as_str());
            let target_map = match exposure.severity {
                super::Severity::Critical => &mut critical,
                super::Severity::Warning => &mut warnings,
                super::Severity::Info => &mut info,
            };

            target_map
                .entry(key.clone())
                .and_modify(|(count, entries): &mut (usize, Vec<usize>)| {
                    *count += 1;
                    if entries.len() < 3 {
                        entries.push(exposure.entry_index);
                    }
                })
                .or_insert((1, vec![exposure.entry_index]));
        }

        // Aggregate CORS issues
        let mut cors_by_type: HashMap<String, (usize, Vec<usize>)> = HashMap::new();
        for issue in &analysis.advanced_security.cors_issues {
            let key = issue.issue_type.as_str();
            cors_by_type
                .entry(key.to_string())
                .and_modify(|(count, entries)| {
                    *count += 1;
                    if entries.len() < 3 {
                        entries.push(issue.entry_index);
                    }
                })
                .or_insert((1, vec![issue.entry_index]));
        }

        for (issue_type, (count, entries)) in cors_by_type {
            let message = format!("CORS {}", issue_type.replace('_', " "));
            let target_map = &mut warnings; // CORS issues are warnings
            target_map.insert(message, (count, entries));
        }

        // Aggregate CSP findings
        let mut csp_by_type: HashMap<String, (usize, Vec<usize>)> = HashMap::new();
        for finding in &analysis.advanced_security.csp_findings {
            let key = finding.finding_type.as_str();
            csp_by_type
                .entry(key.to_string())
                .and_modify(|(count, entries)| {
                    *count += 1;
                    if entries.len() < 3 {
                        entries.push(finding.entry_index);
                    }
                })
                .or_insert((1, vec![finding.entry_index]));
        }

        for (finding_type, (count, entries)) in csp_by_type {
            let message = format!("CSP {}", finding_type.replace('_', " "));
            let target_map = &mut info; // CSP findings are info
            target_map.insert(message, (count, entries));
        }

        // Convert to AggregatedFinding
        let to_findings = |map: HashMap<String, (usize, Vec<usize>)>| {
            let mut findings: Vec<AggregatedFinding> = map
                .into_iter()
                .map(|(key, (count, entries))| AggregatedFinding {
                    finding_type: key.split(" - ").next().unwrap_or(&key).to_string(),
                    message: key,
                    count,
                    sample_entries: entries,
                })
                .collect();
            findings.sort_by(|a, b| b.count.cmp(&a.count));
            findings
        };

        SecurityFindingsSummary {
            critical: to_findings(critical),
            warnings: to_findings(warnings),
            info: to_findings(info),
        }
    }

    fn determine_primary_method(analysis: &AuthAnalysis) -> AuthMethodSummary {
        // Check for OAuth flows first
        if let Some(oauth_flow) = analysis.flows.iter().find(|f| {
            matches!(
                f.flow_type,
                AuthFlowType::OAuth2AuthorizationCode { .. }
                    | AuthFlowType::OAuth2ClientCredentials
                    | AuthFlowType::OAuth2Implicit
            )
        }) {
            let pkce = matches!(
                oauth_flow.flow_type,
                AuthFlowType::OAuth2AuthorizationCode { pkce: true }
            );
            return AuthMethodSummary {
                method_type: if pkce {
                    "OAuth 2.0 Authorization Code with PKCE".to_string()
                } else {
                    oauth_flow.flow_type.as_str().to_string()
                },
                description: "OAuth 2.0 flow detected with token-based authentication".to_string(),
                confidence: ConfidenceLevel::High,
            };
        }

        // Check for SAML
        if !analysis.saml_flows.is_empty() {
            return AuthMethodSummary {
                method_type: "SAML SSO".to_string(),
                description: format!("{} SAML flow(s) detected", analysis.saml_flows.len()),
                confidence: ConfidenceLevel::High,
            };
        }

        // Check for JWT tokens
        if !analysis.jwt_tokens.is_empty() {
            return AuthMethodSummary {
                method_type: "JWT Bearer Token".to_string(),
                description: format!(
                    "JWT tokens in Authorization header (algorithm: {})",
                    analysis
                        .jwt_tokens
                        .first()
                        .and_then(|t| t.header.alg.as_ref())
                        .unwrap_or(&"unknown".to_string())
                ),
                confidence: ConfidenceLevel::High,
            };
        }

        // Check sessions for cookie-based auth
        if let Some(session) = analysis.sessions.first() {
            match &session.session_type {
                SessionType::Cookie { name } => {
                    return AuthMethodSummary {
                        method_type: "Cookie-Based Session".to_string(),
                        description: format!("Session cookie: {}", name),
                        confidence: ConfidenceLevel::High,
                    };
                }
                SessionType::BearerToken { is_jwt } => {
                    return AuthMethodSummary {
                        method_type: if *is_jwt {
                            "JWT Bearer Token"
                        } else {
                            "Bearer Token"
                        }
                        .to_string(),
                        description: "Token-based authentication in Authorization header"
                            .to_string(),
                        confidence: ConfidenceLevel::High,
                    };
                }
                SessionType::ApiKey { header_name } => {
                    return AuthMethodSummary {
                        method_type: "API Key".to_string(),
                        description: format!("API key in {} header", header_name),
                        confidence: ConfidenceLevel::High,
                    };
                }
            }
        }

        // Check for form-based login
        if analysis
            .flows
            .iter()
            .any(|f| f.flow_type == AuthFlowType::FormBased)
        {
            return AuthMethodSummary {
                method_type: "Form-Based Login".to_string(),
                description: "Traditional form-based authentication flow detected".to_string(),
                confidence: ConfidenceLevel::Medium,
            };
        }

        // Check for JSON API auth
        if analysis
            .flows
            .iter()
            .any(|f| f.flow_type == AuthFlowType::JsonApi)
        {
            return AuthMethodSummary {
                method_type: "JSON API Authentication".to_string(),
                description: "JSON-based authentication endpoint detected".to_string(),
                confidence: ConfidenceLevel::Medium,
            };
        }

        // Check for Basic auth
        if analysis
            .methods
            .iter()
            .any(|m| matches!(m, AuthMethod::Basic))
        {
            return AuthMethodSummary {
                method_type: "HTTP Basic Authentication".to_string(),
                description: "Username and password in Authorization header".to_string(),
                confidence: ConfidenceLevel::High,
            };
        }

        // Fallback - check methods
        if !analysis.methods.is_empty() {
            return AuthMethodSummary {
                method_type: "Unknown Authentication".to_string(),
                description: format!(
                    "{} authentication method(s) detected but type unclear",
                    analysis.methods.len()
                ),
                confidence: ConfidenceLevel::Low,
            };
        }

        // No authentication detected
        AuthMethodSummary {
            method_type: "None Detected".to_string(),
            description: "No clear authentication mechanism found in HAR file".to_string(),
            confidence: ConfidenceLevel::Low,
        }
    }

    fn determine_session_mechanism(analysis: &AuthAnalysis) -> SessionMechanismSummary {
        // Check for JWT (stateless)
        if !analysis.jwt_tokens.is_empty() {
            return SessionMechanismSummary {
                mechanism_type: "Stateless (JWT)".to_string(),
                details: format!(
                    "JWT tokens with {}-second lifetime",
                    analysis
                        .jwt_tokens
                        .first()
                        .and_then(|t| t.claims.exp.zip(t.claims.iat))
                        .map(|(exp, iat)| exp - iat)
                        .unwrap_or(0)
                ),
            };
        }

        // Check for session cookies
        if let Some(session) = analysis
            .sessions
            .iter()
            .find(|s| matches!(s.session_type, SessionType::Cookie { .. }))
            && let SessionType::Cookie { name } = &session.session_type
        {
            return SessionMechanismSummary {
                mechanism_type: "Stateful (Server-Side Sessions)".to_string(),
                details: format!(
                    "Session cookie: {} ({} requests)",
                    name, session.request_count
                ),
            };
        }

        // Check for bearer tokens
        if analysis
            .sessions
            .iter()
            .any(|s| matches!(s.session_type, SessionType::BearerToken { .. }))
        {
            return SessionMechanismSummary {
                mechanism_type: "Token-Based".to_string(),
                details: "Bearer tokens in Authorization header".to_string(),
            };
        }

        // Check for API keys
        if analysis
            .sessions
            .iter()
            .any(|s| matches!(s.session_type, SessionType::ApiKey { .. }))
        {
            return SessionMechanismSummary {
                mechanism_type: "API Key".to_string(),
                details: "Static API key authentication".to_string(),
            };
        }

        SessionMechanismSummary {
            mechanism_type: "Unknown".to_string(),
            details: "Could not determine session mechanism".to_string(),
        }
    }

    fn extract_key_endpoints(analysis: &AuthAnalysis) -> Vec<EndpointInfo> {
        let mut endpoints = Vec::new();
        let mut seen_paths = HashSet::new();

        // Extract from flows
        for flow in &analysis.flows {
            for step in &flow.steps {
                let path = Self::extract_path(&step.url);
                if !path.is_empty() && seen_paths.insert(path.clone()) {
                    endpoints.push(EndpointInfo {
                        method: step.method.clone(),
                        path: path.clone(),
                        purpose: step.description.clone(),
                    });
                }
            }
        }

        // Extract from SAML flows
        for flow in &analysis.saml_flows {
            for step in &flow.steps {
                let path = Self::extract_path(&step.url);
                if !path.is_empty() && seen_paths.insert(path.clone()) {
                    endpoints.push(EndpointInfo {
                        method: step.method.clone(),
                        path: path.clone(),
                        purpose: step.description.clone(),
                    });
                }
            }
        }

        // Limit to most important endpoints
        endpoints.truncate(10);
        endpoints
    }

    fn extract_path(url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path().to_string();
            // Simplify query params
            if !parsed.query().unwrap_or("").is_empty() {
                format!("{}?...", path)
            } else {
                path
            }
        } else {
            String::new()
        }
    }

    fn generate_hawkscan_config(
        primary_method: &AuthMethodSummary,
        _session_mechanism: &SessionMechanismSummary,
        analysis: &AuthAnalysis,
    ) -> HawkScanConfig {
        let mut notes = Vec::new();

        let (auth_type, config_snippet) = if primary_method.method_type.contains("Cookie") {
            if let Some(session) = analysis.sessions.first() {
                if let SessionType::Cookie { name } = &session.session_type {
                    notes.push(format!(
                        "Set AUTH_COOKIE environment variable with {}",
                        name
                    ));
                    notes.push("Ensure cookie includes HttpOnly and Secure flags".to_string());

                    (
                        "cookieAuthn".to_string(),
                        format!(
                            r#"authentication:
  type: cookieAuthn
  cookieName: {}
  cookieValue: "${{AUTH_COOKIE}}""#,
                            name
                        ),
                    )
                } else {
                    (
                        "unknown".to_string(),
                        "# Unable to determine configuration".to_string(),
                    )
                }
            } else {
                (
                    "cookieAuthn".to_string(),
                    "# Cookie-based auth detected but no session found".to_string(),
                )
            }
        } else if primary_method.method_type.contains("JWT")
            || primary_method.method_type.contains("Bearer")
        {
            notes.push("Extract token from login response".to_string());
            notes.push("Set AUTH_TOKEN environment variable".to_string());
            if !analysis.jwt_tokens.is_empty() {
                notes.push("Token should be refreshed periodically".to_string());
            }

            (
                "tokenAuthn".to_string(),
                r#"authentication:
  type: tokenAuthn
  tokenValue: "Bearer ${AUTH_TOKEN}""#
                    .to_string(),
            )
        } else if primary_method.method_type.contains("OAuth") {
            notes.push("Configure OAuth 2.0 client credentials".to_string());
            notes.push("HawkScan will obtain tokens automatically".to_string());

            (
                "oauth2".to_string(),
                r#"authentication:
  type: oauth2
  oauth2:
    tokenUrl: # Add your token endpoint
    clientId: ${OAUTH_CLIENT_ID}
    clientSecret: ${OAUTH_CLIENT_SECRET}"#
                    .to_string(),
            )
        } else if primary_method.method_type.contains("API Key") {
            if let Some(session) = analysis
                .sessions
                .iter()
                .find(|s| matches!(s.session_type, SessionType::ApiKey { .. }))
            {
                if let SessionType::ApiKey { header_name } = &session.session_type {
                    notes.push("Set API_KEY environment variable".to_string());

                    (
                        "customAuthn".to_string(),
                        format!(
                            r#"authentication:
  type: customAuthn
  customAuthn:
    headers:
      {}: "${{API_KEY}}""#,
                            header_name
                        ),
                    )
                } else {
                    (
                        "customAuthn".to_string(),
                        "# API key auth configuration".to_string(),
                    )
                }
            } else {
                (
                    "customAuthn".to_string(),
                    "# API key auth configuration".to_string(),
                )
            }
        } else {
            notes.push("Manual configuration required".to_string());
            notes.push("Refer to HawkScan documentation".to_string());

            (
                "unknown".to_string(),
                "# Authentication type could not be automatically determined
# Please configure manually based on your application"
                    .to_string(),
            )
        };

        HawkScanConfig {
            auth_type,
            config_snippet,
            notes,
        }
    }

    fn generate_additional_info(analysis: &AuthAnalysis) -> Vec<String> {
        let mut info = Vec::new();

        // Add info about events
        let login_count = analysis
            .events
            .iter()
            .filter(|e| matches!(e.event_type, super::AuthEventType::LoginSuccess))
            .count();
        let logout_count = analysis
            .events
            .iter()
            .filter(|e| matches!(e.event_type, super::AuthEventType::Logout))
            .count();

        if login_count > 0 {
            info.push(format!("{} login event(s) detected", login_count));
        }
        if logout_count > 0 {
            info.push(format!("{} logout event(s) detected", logout_count));
        }

        // Add info about token refresh
        if !analysis.advanced_security.refresh_patterns.is_empty() {
            info.push(format!(
                "Token refresh pattern detected ({} refresh operations)",
                analysis
                    .advanced_security
                    .refresh_patterns
                    .iter()
                    .map(|p| p.refresh_count)
                    .sum::<usize>()
            ));
        }

        info
    }
}

impl super::ExposureType {
    fn as_str(&self) -> &str {
        match self {
            super::ExposureType::TokenInUrl => "Token in URL",
            super::ExposureType::TokenInQueryParam => "Token in query parameter",
            super::ExposureType::TokenInReferer => "Token in Referer header",
            super::ExposureType::CredentialsInUrl => "Credentials in URL",
            super::ExposureType::SensitiveDataInUrl => "Sensitive data in URL",
        }
    }
}

impl super::CorsIssueType {
    fn as_str(&self) -> &str {
        match self {
            super::CorsIssueType::WildcardWithCredentials => "wildcard with credentials",
            super::CorsIssueType::OverlyPermissiveOrigin => "overly permissive origin",
            super::CorsIssueType::MissingCorsHeaders => "missing CORS headers",
            super::CorsIssueType::InsecureOrigin => "insecure origin",
        }
    }
}

impl super::CspFindingType {
    fn as_str(&self) -> &str {
        match self {
            super::CspFindingType::MissingCsp => "missing CSP",
            super::CspFindingType::UnsafeInline => "unsafe-inline",
            super::CspFindingType::UnsafeEval => "unsafe-eval",
            super::CspFindingType::WildcardSource => "wildcard source",
            super::CspFindingType::WeakPolicy => "weak policy",
        }
    }
}
