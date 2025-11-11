use crate::Result;
use harrier_core::har::{Entry, Har};
use serde::{Deserialize, Serialize};

/// Represents a detected SAML authentication flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlFlow {
    pub flow_type: SamlFlowType,
    pub start_time: String,
    pub end_time: Option<String>,
    pub steps: Vec<SamlStep>,
    pub idp_entity_id: Option<String>,
    pub sp_entity_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamlFlowType {
    SpInitiated,
    IdpInitiated,
    Logout,
}

impl SamlFlowType {
    pub fn as_str(&self) -> &str {
        match self {
            SamlFlowType::SpInitiated => "SAML SP-Initiated SSO",
            SamlFlowType::IdpInitiated => "SAML IdP-Initiated SSO",
            SamlFlowType::Logout => "SAML Single Logout",
        }
    }
}

/// Individual step in a SAML flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlStep {
    pub entry_index: usize,
    pub timestamp: String,
    pub role: SamlStepRole,
    pub method: String,
    pub url: String,
    pub status: i64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamlStepRole {
    AuthnRequest,
    IdpRedirect,
    SamlResponse,
    AssertionConsumerService,
    LogoutRequest,
    LogoutResponse,
}

/// SAML security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSecurityIssue {
    pub severity: super::security::Severity,
    pub message: String,
    pub entry_index: usize,
}

pub struct SamlDetector;

impl SamlDetector {
    /// Detect SAML authentication flows in the HAR file
    pub fn detect_flows(har: &Har) -> Result<(Vec<SamlFlow>, Vec<SamlSecurityIssue>)> {
        let mut flows = Vec::new();
        let mut security_issues = Vec::new();
        let entries = &har.log.entries;

        // Detect SP-initiated SSO flows
        for (i, entry) in entries.iter().enumerate() {
            if Self::is_saml_authn_request(entry)
                && let Some(flow) = Self::build_sp_initiated_flow(entries, i, &mut security_issues)
            {
                flows.push(flow);
            }
        }

        // Detect IdP-initiated SSO flows
        for (i, entry) in entries.iter().enumerate() {
            if Self::is_saml_response(entry)
                && !Self::is_part_of_sp_flow(&flows, i)
                && let Some(flow) = Self::build_idp_initiated_flow(entries, i)
            {
                flows.push(flow);
            }
        }

        // Detect logout flows
        for (i, entry) in entries.iter().enumerate() {
            if Self::is_saml_logout_request(entry)
                && let Some(flow) = Self::build_logout_flow(entries, i)
            {
                flows.push(flow);
            }
        }

        Ok((flows, security_issues))
    }

    fn build_sp_initiated_flow(
        entries: &[Entry],
        start_idx: usize,
        security_issues: &mut Vec<SamlSecurityIssue>,
    ) -> Option<SamlFlow> {
        let start_entry = &entries[start_idx];
        let mut steps = vec![SamlStep {
            entry_index: start_idx,
            timestamp: start_entry.started_date_time.clone(),
            role: SamlStepRole::AuthnRequest,
            method: start_entry.request.method.clone(),
            url: Self::truncate_url(&start_entry.request.url),
            status: start_entry.response.status,
            description: "SAML AuthnRequest sent to IdP".to_string(),
        }];

        // Check if sent over HTTP (security issue)
        if start_entry.request.url.starts_with("http://") {
            security_issues.push(SamlSecurityIssue {
                severity: super::security::Severity::Critical,
                message: "SAML AuthnRequest sent over unencrypted HTTP".to_string(),
                entry_index: start_idx,
            });
        }

        // Look for IdP redirect/interaction
        if let Some((idp_idx, idp_entry)) = Self::find_idp_interaction(entries, start_idx + 1) {
            steps.push(SamlStep {
                entry_index: idp_idx,
                timestamp: idp_entry.started_date_time.clone(),
                role: SamlStepRole::IdpRedirect,
                method: idp_entry.request.method.clone(),
                url: Self::truncate_url(&idp_entry.request.url),
                status: idp_entry.response.status,
                description: "User authentication at IdP".to_string(),
            });
        }

        // Look for SAML response
        if let Some((response_idx, response_entry)) =
            Self::find_saml_response(entries, start_idx + 1)
        {
            steps.push(SamlStep {
                entry_index: response_idx,
                timestamp: response_entry.started_date_time.clone(),
                role: SamlStepRole::SamlResponse,
                method: response_entry.request.method.clone(),
                url: Self::truncate_url(&response_entry.request.url),
                status: response_entry.response.status,
                description: "SAML Response received from IdP".to_string(),
            });

            // Check if sent over HTTP
            if response_entry.request.url.starts_with("http://") {
                security_issues.push(SamlSecurityIssue {
                    severity: super::security::Severity::Critical,
                    message: "SAML Response sent over unencrypted HTTP".to_string(),
                    entry_index: response_idx,
                });
            }

            // Look for ACS processing
            if let Some((acs_idx, acs_entry)) = Self::find_acs_request(entries, response_idx + 1) {
                steps.push(SamlStep {
                    entry_index: acs_idx,
                    timestamp: acs_entry.started_date_time.clone(),
                    role: SamlStepRole::AssertionConsumerService,
                    method: acs_entry.request.method.clone(),
                    url: Self::truncate_url(&acs_entry.request.url),
                    status: acs_entry.response.status,
                    description: "Assertion Consumer Service processed response".to_string(),
                });
            }
        }

        if steps.len() > 1 {
            Some(SamlFlow {
                flow_type: SamlFlowType::SpInitiated,
                start_time: steps.first().unwrap().timestamp.clone(),
                end_time: steps.last().map(|s| s.timestamp.clone()),
                steps,
                idp_entity_id: None,
                sp_entity_id: None,
            })
        } else {
            None
        }
    }

    fn build_idp_initiated_flow(entries: &[Entry], start_idx: usize) -> Option<SamlFlow> {
        let start_entry = &entries[start_idx];
        let mut steps = vec![SamlStep {
            entry_index: start_idx,
            timestamp: start_entry.started_date_time.clone(),
            role: SamlStepRole::SamlResponse,
            method: start_entry.request.method.clone(),
            url: Self::truncate_url(&start_entry.request.url),
            status: start_entry.response.status,
            description: "SAML Response received from IdP".to_string(),
        }];

        // Look for ACS processing
        if let Some((acs_idx, acs_entry)) = Self::find_acs_request(entries, start_idx + 1) {
            steps.push(SamlStep {
                entry_index: acs_idx,
                timestamp: acs_entry.started_date_time.clone(),
                role: SamlStepRole::AssertionConsumerService,
                method: acs_entry.request.method.clone(),
                url: Self::truncate_url(&acs_entry.request.url),
                status: acs_entry.response.status,
                description: "Assertion Consumer Service processed response".to_string(),
            });
        }

        Some(SamlFlow {
            flow_type: SamlFlowType::IdpInitiated,
            start_time: steps.first().unwrap().timestamp.clone(),
            end_time: steps.last().map(|s| s.timestamp.clone()),
            steps,
            idp_entity_id: None,
            sp_entity_id: None,
        })
    }

    fn build_logout_flow(entries: &[Entry], start_idx: usize) -> Option<SamlFlow> {
        let start_entry = &entries[start_idx];
        let mut steps = vec![SamlStep {
            entry_index: start_idx,
            timestamp: start_entry.started_date_time.clone(),
            role: SamlStepRole::LogoutRequest,
            method: start_entry.request.method.clone(),
            url: Self::truncate_url(&start_entry.request.url),
            status: start_entry.response.status,
            description: "SAML Logout Request".to_string(),
        }];

        // Look for logout response
        if let Some((response_idx, response_entry)) =
            Self::find_logout_response(entries, start_idx + 1)
        {
            steps.push(SamlStep {
                entry_index: response_idx,
                timestamp: response_entry.started_date_time.clone(),
                role: SamlStepRole::LogoutResponse,
                method: response_entry.request.method.clone(),
                url: Self::truncate_url(&response_entry.request.url),
                status: response_entry.response.status,
                description: "SAML Logout Response".to_string(),
            });
        }

        Some(SamlFlow {
            flow_type: SamlFlowType::Logout,
            start_time: steps.first().unwrap().timestamp.clone(),
            end_time: steps.last().map(|s| s.timestamp.clone()),
            steps,
            idp_entity_id: None,
            sp_entity_id: None,
        })
    }

    // Detection helper methods

    fn is_saml_authn_request(entry: &Entry) -> bool {
        let url = &entry.request.url;
        let url_lower = url.to_lowercase();

        // Check URL patterns
        if url_lower.contains("/saml/sso")
            || url_lower.contains("/saml2/sso")
            || url_lower.contains("samlrequest=")
        {
            return true;
        }

        // Check POST data for SAMLRequest
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("SAMLRequest");
        }

        false
    }

    fn is_saml_response(entry: &Entry) -> bool {
        // Check URL for SAMLResponse parameter
        if entry.request.url.to_lowercase().contains("samlresponse=") {
            return true;
        }

        // Check POST data for SAMLResponse
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("SAMLResponse");
        }

        false
    }

    fn is_saml_logout_request(entry: &Entry) -> bool {
        let url_lower = entry.request.url.to_lowercase();
        url_lower.contains("/saml/logout")
            || url_lower.contains("/saml2/logout")
            || url_lower.contains("samllogoutrequest=")
    }

    fn find_idp_interaction(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            let url_lower = entry.request.url.to_lowercase();
            // Look for IdP login/authentication endpoints
            if url_lower.contains("/idp/")
                || url_lower.contains("/sso/")
                || url_lower.contains("/auth/")
            {
                return Some((i, entry));
            }

            // Don't look too far ahead
            if i - start_idx > 10 {
                break;
            }
        }
        None
    }

    fn find_saml_response(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            if Self::is_saml_response(entry) {
                return Some((i, entry));
            }

            // Don't look too far ahead
            if i - start_idx > 15 {
                break;
            }
        }
        None
    }

    fn find_acs_request(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            let url_lower = entry.request.url.to_lowercase();
            // Look for Assertion Consumer Service endpoints
            if url_lower.contains("/acs")
                || url_lower.contains("/saml/acs")
                || url_lower.contains("/consume")
            {
                return Some((i, entry));
            }

            // Don't look too far ahead
            if i - start_idx > 5 {
                break;
            }
        }
        None
    }

    fn find_logout_response(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            if entry
                .request
                .url
                .to_lowercase()
                .contains("samllogoutresponse=")
            {
                return Some((i, entry));
            }

            // Don't look too far ahead
            if i - start_idx > 5 {
                break;
            }
        }
        None
    }

    fn is_part_of_sp_flow(flows: &[SamlFlow], entry_idx: usize) -> bool {
        for flow in flows {
            if flow.flow_type == SamlFlowType::SpInitiated {
                for step in &flow.steps {
                    if step.entry_index == entry_idx {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn truncate_url(url: &str) -> String {
        if url.len() > 80 {
            format!("{}...", &url[..77])
        } else {
            url.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_flow_type_as_str() {
        assert_eq!(SamlFlowType::SpInitiated.as_str(), "SAML SP-Initiated SSO");
        assert_eq!(
            SamlFlowType::IdpInitiated.as_str(),
            "SAML IdP-Initiated SSO"
        );
        assert_eq!(SamlFlowType::Logout.as_str(), "SAML Single Logout");
    }

    #[test]
    fn test_is_saml_authn_request() {
        let entry = create_test_entry("https://sp.example.com/saml/sso?SAMLRequest=...", "GET");
        assert!(SamlDetector::is_saml_authn_request(&entry));

        let entry2 = create_test_entry("https://example.com/api/users", "GET");
        assert!(!SamlDetector::is_saml_authn_request(&entry2));
    }

    #[test]
    fn test_is_saml_response() {
        let entry = create_test_entry("https://sp.example.com/acs?SAMLResponse=...", "POST");
        assert!(SamlDetector::is_saml_response(&entry));

        let entry2 = create_test_entry("https://example.com/api/users", "GET");
        assert!(!SamlDetector::is_saml_response(&entry2));
    }

    fn create_test_entry(url: &str, method: &str) -> Entry {
        use harrier_core::har::*;
        Entry {
            page_ref: None,
            started_date_time: "2024-01-01T00:00:00Z".to_string(),
            time: 100.0,
            request: Request {
                method: method.to_string(),
                url: url.to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![],
                query_string: vec![],
                post_data: None,
                headers_size: 0,
                body_size: 0,
                comment: None,
            },
            response: Response {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![],
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: "text/html".to_string(),
                    text: None,
                    encoding: None,
                    comment: None,
                },
                redirect_url: String::new(),
                headers_size: 0,
                body_size: 0,
                comment: None,
            },
            cache: Cache {
                before_request: None,
                after_request: None,
                comment: None,
            },
            timings: Timings {
                blocked: None,
                dns: None,
                connect: None,
                send: 10.0,
                wait: 50.0,
                receive: 40.0,
                ssl: None,
                comment: None,
            },
            server_ip_address: None,
            connection: None,
            comment: None,
        }
    }
}
