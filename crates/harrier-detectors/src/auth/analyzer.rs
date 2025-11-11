use crate::Result;
use harrier_core::har::Har;
use serde::{Deserialize, Serialize};

use super::advanced_security::{AdvancedSecurityAnalysis, AdvancedSecurityAnalyzer};
use super::events::{AuthEvent, EventDetector};
use super::flows::{AuthFlow, FlowDetector};
use super::jwt::{JwtAnalyzer, JwtSecurityIssue, JwtToken};
use super::methods::{AuthDetector, AuthMethod};
use super::saml::{SamlDetector, SamlFlow, SamlSecurityIssue};
use super::security::{SecurityAnalyzer, SecurityNote};
use super::sessions::{AuthSession, SessionTracker};

/// Complete authentication analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAnalysis {
    pub methods: Vec<AuthMethod>,
    pub sessions: Vec<AuthSession>,
    pub flows: Vec<AuthFlow>,
    pub events: Vec<AuthEvent>,
    pub security_notes: Vec<SecurityNote>,

    // Phase 3: Advanced features
    pub jwt_tokens: Vec<JwtToken>,
    pub jwt_issues: Vec<JwtSecurityIssue>,
    pub saml_flows: Vec<SamlFlow>,
    pub saml_issues: Vec<SamlSecurityIssue>,
    pub advanced_security: AdvancedSecurityAnalysis,
}

pub struct AuthAnalyzer;

impl AuthAnalyzer {
    /// Perform comprehensive authentication analysis on a HAR file
    pub fn analyze(har: &Har) -> Result<AuthAnalysis> {
        tracing::debug!("Starting authentication analysis");

        // 1. Detect authentication methods (existing functionality)
        let methods = AuthDetector::detect(har)?;
        tracing::debug!("Detected {} authentication methods", methods.len());

        // 2. Track sessions
        let sessions = SessionTracker::track_sessions(har)?;
        tracing::debug!("Tracked {} authentication sessions", sessions.len());

        // 3. Detect authentication flows
        let flows = FlowDetector::detect_flows(har)?;
        tracing::debug!("Detected {} authentication flows", flows.len());

        // 4. Detect authentication events
        let events = EventDetector::detect_events(har)?;
        tracing::debug!("Detected {} authentication events", events.len());

        // 5. Analyze security
        let security_notes = SecurityAnalyzer::analyze(har, &methods, &sessions)?;
        tracing::debug!("Generated {} security notes", security_notes.len());

        // Phase 3: Advanced features

        // 6. Analyze JWT tokens
        let (jwt_tokens, jwt_issues) = JwtAnalyzer::analyze(har)?;
        tracing::debug!(
            "Found {} JWT tokens with {} security issues",
            jwt_tokens.len(),
            jwt_issues.len()
        );

        // 7. Detect SAML flows
        let (saml_flows, saml_issues) = SamlDetector::detect_flows(har)?;
        tracing::debug!(
            "Detected {} SAML flows with {} security issues",
            saml_flows.len(),
            saml_issues.len()
        );

        // 8. Advanced security analysis
        let advanced_security = AdvancedSecurityAnalyzer::analyze(har)?;
        tracing::debug!(
            "Advanced security: {} token exposures, {} CORS issues, {} CSP findings, {} refresh patterns",
            advanced_security.token_exposures.len(),
            advanced_security.cors_issues.len(),
            advanced_security.csp_findings.len(),
            advanced_security.refresh_patterns.len()
        );

        Ok(AuthAnalysis {
            methods,
            sessions,
            flows,
            events,
            security_notes,
            jwt_tokens,
            jwt_issues,
            saml_flows,
            saml_issues,
            advanced_security,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harrier_core::har::*;

    fn create_minimal_har() -> Har {
        Har {
            log: Log {
                version: "1.2".to_string(),
                creator: Creator {
                    name: "test".to_string(),
                    version: "1.0".to_string(),
                    comment: None,
                },
                browser: None,
                pages: None,
                entries: vec![],
                comment: None,
            },
        }
    }

    #[test]
    fn test_analyze_empty_har() {
        let har = create_minimal_har();
        let result = AuthAnalyzer::analyze(&har);

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.methods.len(), 0);
        assert_eq!(analysis.sessions.len(), 0);
    }
}
