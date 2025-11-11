use crate::Result;
use chrono::{DateTime, Utc};
use harrier_core::har::{Entry, Har};
use serde::{Deserialize, Serialize};

/// Represents a detected authentication flow with its sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub flow_type: AuthFlowType,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_ms: f64,
    pub steps: Vec<FlowStep>,
}

/// Type of authentication flow
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthFlowType {
    OAuth2AuthorizationCode { pkce: bool },
    OAuth2ClientCredentials,
    OAuth2Implicit,
    FormBased,
    JsonApi,
    Unknown,
}

impl AuthFlowType {
    pub fn as_str(&self) -> &str {
        match self {
            AuthFlowType::OAuth2AuthorizationCode { pkce: true } => {
                "OAuth 2.0 Authorization Code (with PKCE)"
            }
            AuthFlowType::OAuth2AuthorizationCode { pkce: false } => "OAuth 2.0 Authorization Code",
            AuthFlowType::OAuth2ClientCredentials => "OAuth 2.0 Client Credentials",
            AuthFlowType::OAuth2Implicit => "OAuth 2.0 Implicit",
            AuthFlowType::FormBased => "Form-based Login",
            AuthFlowType::JsonApi => "JSON API Authentication",
            AuthFlowType::Unknown => "Unknown",
        }
    }
}

/// Individual step in an authentication flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub entry_index: usize,
    pub timestamp: String,
    pub role: FlowRole,
    pub method: String,
    pub url: String,
    pub status: i64,
    pub description: String,
}

/// Role of a step in the authentication flow
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowRole {
    LoginPage,
    CredentialsSubmission,
    AuthorizationRequest,
    AuthorizationCallback,
    TokenExchange,
    TokenResponse,
    FirstAuthenticatedRequest,
}

pub struct FlowDetector;

impl FlowDetector {
    /// Detect all authentication flows in the HAR file
    pub fn detect_flows(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();

        // Detect OAuth 2.0 flows
        flows.extend(Self::detect_oauth2_authorization_code(har)?);
        flows.extend(Self::detect_oauth2_client_credentials(har)?);
        flows.extend(Self::detect_oauth2_implicit(har)?);

        // Detect form-based login flows
        flows.extend(Self::detect_form_login(har)?);

        // Detect JSON API authentication flows
        flows.extend(Self::detect_json_api_auth(har)?);

        // Sort by start time
        flows.sort_by(|a, b| a.start_time.cmp(&b.start_time));

        Ok(flows)
    }

    /// Detect OAuth 2.0 Authorization Code flow (with optional PKCE)
    fn detect_oauth2_authorization_code(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();
        let entries = &har.log.entries;

        for (i, entry) in entries.iter().enumerate() {
            // Look for authorization request
            if Self::is_oauth_authorize_request(entry) {
                let has_pkce = Self::has_pkce_challenge(entry);

                let mut steps = vec![FlowStep {
                    entry_index: i,
                    timestamp: entry.started_date_time.clone(),
                    role: FlowRole::AuthorizationRequest,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    description: "Authorization request initiated".to_string(),
                }];

                // Look for authorization callback with code
                if let Some((callback_idx, callback_entry)) =
                    Self::find_authorization_callback(entries, i + 1)
                {
                    steps.push(FlowStep {
                        entry_index: callback_idx,
                        timestamp: callback_entry.started_date_time.clone(),
                        role: FlowRole::AuthorizationCallback,
                        method: callback_entry.request.method.clone(),
                        url: Self::truncate_url(&callback_entry.request.url),
                        status: callback_entry.response.status,
                        description: "Authorization code received".to_string(),
                    });

                    // Look for token exchange
                    if let Some((token_idx, token_entry)) =
                        Self::find_token_exchange(entries, callback_idx + 1, has_pkce)
                    {
                        steps.push(FlowStep {
                            entry_index: token_idx,
                            timestamp: token_entry.started_date_time.clone(),
                            role: FlowRole::TokenExchange,
                            method: token_entry.request.method.clone(),
                            url: Self::truncate_url(&token_entry.request.url),
                            status: token_entry.response.status,
                            description: "Token exchange request".to_string(),
                        });

                        // Look for first authenticated request with Bearer token
                        if let Some((auth_idx, auth_entry)) =
                            Self::find_first_bearer_request(entries, token_idx + 1)
                        {
                            steps.push(FlowStep {
                                entry_index: auth_idx,
                                timestamp: auth_entry.started_date_time.clone(),
                                role: FlowRole::FirstAuthenticatedRequest,
                                method: auth_entry.request.method.clone(),
                                url: Self::truncate_url(&auth_entry.request.url),
                                status: auth_entry.response.status,
                                description: "First authenticated request".to_string(),
                            });
                        }
                    }
                }

                if steps.len() > 1 {
                    let start_time = steps.first().unwrap().timestamp.clone();
                    let end_time = steps.last().map(|s| s.timestamp.clone());
                    let duration_ms = Self::calculate_duration(&start_time, end_time.as_deref());

                    flows.push(AuthFlow {
                        flow_type: AuthFlowType::OAuth2AuthorizationCode { pkce: has_pkce },
                        start_time,
                        end_time,
                        duration_ms,
                        steps,
                    });
                }
            }
        }

        Ok(flows)
    }

    /// Detect OAuth 2.0 Client Credentials flow
    fn detect_oauth2_client_credentials(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();
        let entries = &har.log.entries;

        for (i, entry) in entries.iter().enumerate() {
            // Look for direct token request with client_credentials
            if Self::is_client_credentials_request(entry) {
                let mut steps = vec![FlowStep {
                    entry_index: i,
                    timestamp: entry.started_date_time.clone(),
                    role: FlowRole::TokenExchange,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    description: "Client credentials token request".to_string(),
                }];

                // Look for first authenticated request
                if let Some((auth_idx, auth_entry)) =
                    Self::find_first_bearer_request(entries, i + 1)
                {
                    steps.push(FlowStep {
                        entry_index: auth_idx,
                        timestamp: auth_entry.started_date_time.clone(),
                        role: FlowRole::FirstAuthenticatedRequest,
                        method: auth_entry.request.method.clone(),
                        url: Self::truncate_url(&auth_entry.request.url),
                        status: auth_entry.response.status,
                        description: "First authenticated request".to_string(),
                    });
                }

                let start_time = steps.first().unwrap().timestamp.clone();
                let end_time = steps.last().map(|s| s.timestamp.clone());
                let duration_ms = Self::calculate_duration(&start_time, end_time.as_deref());

                flows.push(AuthFlow {
                    flow_type: AuthFlowType::OAuth2ClientCredentials,
                    start_time,
                    end_time,
                    duration_ms,
                    steps,
                });
            }
        }

        Ok(flows)
    }

    /// Detect OAuth 2.0 Implicit flow (deprecated but may exist)
    fn detect_oauth2_implicit(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();
        let entries = &har.log.entries;

        for (i, entry) in entries.iter().enumerate() {
            // Look for authorization request with response_type=token
            if Self::is_oauth_implicit_request(entry) {
                let steps = vec![FlowStep {
                    entry_index: i,
                    timestamp: entry.started_date_time.clone(),
                    role: FlowRole::AuthorizationRequest,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    description: "Implicit flow authorization (token in redirect)".to_string(),
                }];

                let start_time = steps.first().unwrap().timestamp.clone();

                flows.push(AuthFlow {
                    flow_type: AuthFlowType::OAuth2Implicit,
                    start_time: start_time.clone(),
                    end_time: Some(start_time),
                    duration_ms: 0.0,
                    steps,
                });
            }
        }

        Ok(flows)
    }

    /// Detect form-based login flows
    fn detect_form_login(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();
        let entries = &har.log.entries;

        for (i, entry) in entries.iter().enumerate() {
            // Look for login page GET
            if Self::is_login_page_request(entry) {
                let mut steps = vec![FlowStep {
                    entry_index: i,
                    timestamp: entry.started_date_time.clone(),
                    role: FlowRole::LoginPage,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    description: "Login page loaded".to_string(),
                }];

                // Look for form submission POST
                if let Some((submit_idx, submit_entry)) = Self::find_form_submission(entries, i + 1)
                {
                    steps.push(FlowStep {
                        entry_index: submit_idx,
                        timestamp: submit_entry.started_date_time.clone(),
                        role: FlowRole::CredentialsSubmission,
                        method: submit_entry.request.method.clone(),
                        url: Self::truncate_url(&submit_entry.request.url),
                        status: submit_entry.response.status,
                        description: "Credentials submitted".to_string(),
                    });

                    // Check if session was established
                    if Self::session_established(submit_entry) {
                        // Look for first authenticated request with session
                        if let Some((auth_idx, auth_entry)) =
                            Self::find_first_session_request(entries, submit_idx + 1)
                        {
                            steps.push(FlowStep {
                                entry_index: auth_idx,
                                timestamp: auth_entry.started_date_time.clone(),
                                role: FlowRole::FirstAuthenticatedRequest,
                                method: auth_entry.request.method.clone(),
                                url: Self::truncate_url(&auth_entry.request.url),
                                status: auth_entry.response.status,
                                description: "First authenticated request".to_string(),
                            });
                        }
                    }
                }

                if steps.len() > 1 {
                    let start_time = steps.first().unwrap().timestamp.clone();
                    let end_time = steps.last().map(|s| s.timestamp.clone());
                    let duration_ms = Self::calculate_duration(&start_time, end_time.as_deref());

                    flows.push(AuthFlow {
                        flow_type: AuthFlowType::FormBased,
                        start_time,
                        end_time,
                        duration_ms,
                        steps,
                    });
                }
            }
        }

        Ok(flows)
    }

    /// Detect JSON API authentication flows
    fn detect_json_api_auth(har: &Har) -> Result<Vec<AuthFlow>> {
        let mut flows = Vec::new();
        let entries = &har.log.entries;

        for (i, entry) in entries.iter().enumerate() {
            // Look for JSON login/auth endpoint
            if Self::is_json_auth_request(entry) {
                let mut steps = vec![FlowStep {
                    entry_index: i,
                    timestamp: entry.started_date_time.clone(),
                    role: FlowRole::CredentialsSubmission,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    description: "JSON authentication request".to_string(),
                }];

                // Check if token was returned
                if entry.response.status == 200 && Self::has_json_token_response(entry) {
                    steps.push(FlowStep {
                        entry_index: i,
                        timestamp: entry.started_date_time.clone(),
                        role: FlowRole::TokenResponse,
                        method: entry.request.method.clone(),
                        url: Self::truncate_url(&entry.request.url),
                        status: entry.response.status,
                        description: "Token received in JSON response".to_string(),
                    });

                    // Look for first authenticated request
                    if let Some((auth_idx, auth_entry)) =
                        Self::find_first_bearer_request(entries, i + 1)
                    {
                        steps.push(FlowStep {
                            entry_index: auth_idx,
                            timestamp: auth_entry.started_date_time.clone(),
                            role: FlowRole::FirstAuthenticatedRequest,
                            method: auth_entry.request.method.clone(),
                            url: Self::truncate_url(&auth_entry.request.url),
                            status: auth_entry.response.status,
                            description: "First authenticated request".to_string(),
                        });
                    }
                }

                if steps.len() > 1 {
                    let start_time = steps.first().unwrap().timestamp.clone();
                    let end_time = steps.last().map(|s| s.timestamp.clone());
                    let duration_ms = Self::calculate_duration(&start_time, end_time.as_deref());

                    flows.push(AuthFlow {
                        flow_type: AuthFlowType::JsonApi,
                        start_time,
                        end_time,
                        duration_ms,
                        steps,
                    });
                }
            }
        }

        Ok(flows)
    }

    // Helper methods for pattern detection

    fn is_oauth_authorize_request(entry: &Entry) -> bool {
        let url = &entry.request.url;
        url.contains("/authorize") || url.contains("/oauth/authorize")
    }

    fn has_pkce_challenge(entry: &Entry) -> bool {
        entry.request.url.contains("code_challenge=")
            && entry.request.url.contains("code_challenge_method=")
    }

    fn find_authorization_callback(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            if entry.request.url.contains("?code=") || entry.request.url.contains("&code=") {
                return Some((i, entry));
            }
            // Don't look too far ahead (max 10 requests)
            if i - start_idx > 10 {
                break;
            }
        }
        None
    }

    fn find_token_exchange(
        entries: &[Entry],
        start_idx: usize,
        expect_pkce: bool,
    ) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            if entry.request.method == "POST"
                && (entry.request.url.contains("/token")
                    || entry.request.url.contains("/oauth/token"))
                && let Some(ref post_data) = entry.request.post_data
                && let Some(ref text) = post_data.text
                && text.contains("grant_type=authorization_code")
            {
                if expect_pkce {
                    // Verify PKCE verifier is present
                    if text.contains("code_verifier=") {
                        return Some((i, entry));
                    }
                } else {
                    return Some((i, entry));
                }
            }
            // Don't look too far ahead
            if i - start_idx > 10 {
                break;
            }
        }
        None
    }

    fn is_client_credentials_request(entry: &Entry) -> bool {
        if entry.request.method == "POST"
            && (entry.request.url.contains("/token") || entry.request.url.contains("/oauth/token"))
            && let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("grant_type=client_credentials");
        }
        false
    }

    fn is_oauth_implicit_request(entry: &Entry) -> bool {
        entry.request.url.contains("/authorize")
            && entry.request.url.contains("response_type=token")
    }

    fn is_login_page_request(entry: &Entry) -> bool {
        entry.request.method == "GET"
            && (entry.request.url.contains("/login")
                || entry.request.url.contains("/signin")
                || entry.request.url.contains("/auth/login"))
            && entry.response.content.mime_type.contains("text/html")
    }

    fn find_form_submission(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            if entry.request.method == "POST"
                && (entry.request.url.contains("/login")
                    || entry.request.url.contains("/signin")
                    || entry.request.url.contains("/auth"))
                && let Some(ref post_data) = entry.request.post_data
                && (post_data
                    .mime_type
                    .contains("application/x-www-form-urlencoded")
                    || post_data.mime_type.contains("multipart/form-data"))
                && let Some(ref text) = post_data.text
                && ((text.contains("username") || text.contains("email"))
                    && text.contains("password"))
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

    fn session_established(entry: &Entry) -> bool {
        // Check if response sets a session cookie
        for cookie in &entry.response.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return true;
            }
        }
        false
    }

    fn find_first_bearer_request(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            for header in &entry.request.headers {
                if header.name.to_lowercase() == "authorization"
                    && header.value.starts_with("Bearer ")
                {
                    return Some((i, entry));
                }
            }
            // Don't look too far ahead
            if i - start_idx > 10 {
                break;
            }
        }
        None
    }

    fn find_first_session_request(entries: &[Entry], start_idx: usize) -> Option<(usize, &Entry)> {
        for (i, entry) in entries.iter().enumerate().skip(start_idx) {
            for cookie in &entry.request.cookies {
                let name_lower = cookie.name.to_lowercase();
                if name_lower.contains("session")
                    || name_lower.contains("auth")
                    || name_lower.contains("token")
                {
                    return Some((i, entry));
                }
            }
            // Don't look too far ahead
            if i - start_idx > 10 {
                break;
            }
        }
        None
    }

    fn is_json_auth_request(entry: &Entry) -> bool {
        if entry.request.method == "POST"
            && (entry.request.url.contains("/login")
                || entry.request.url.contains("/auth/login")
                || entry.request.url.contains("/api/login")
                || entry.request.url.contains("/api/auth"))
            && let Some(ref post_data) = entry.request.post_data
            && post_data.mime_type.contains("application/json")
            && let Some(ref text) = post_data.text
        {
            return (text.contains("\"username\"") || text.contains("\"email\""))
                && text.contains("\"password\"");
        }
        false
    }

    fn has_json_token_response(entry: &Entry) -> bool {
        if entry
            .response
            .content
            .mime_type
            .contains("application/json")
            && let Some(ref text) = entry.response.content.text
        {
            return text.contains("\"token\"")
                || text.contains("\"access_token\"")
                || text.contains("\"accessToken\"");
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

    fn calculate_duration(start: &str, end: Option<&str>) -> f64 {
        let Some(end_str) = end else {
            return 0.0;
        };

        // Parse ISO 8601 timestamps
        let start_time = match DateTime::parse_from_rfc3339(start) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return 0.0, // Return 0 if parsing fails
        };

        let end_time = match DateTime::parse_from_rfc3339(end_str) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return 0.0, // Return 0 if parsing fails
        };

        // Calculate duration in milliseconds
        let duration = end_time.signed_duration_since(start_time);
        duration.num_milliseconds() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_type_as_str() {
        let flow = AuthFlowType::OAuth2AuthorizationCode { pkce: true };
        assert_eq!(flow.as_str(), "OAuth 2.0 Authorization Code (with PKCE)");

        let flow2 = AuthFlowType::FormBased;
        assert_eq!(flow2.as_str(), "Form-based Login");
    }

    #[test]
    fn test_is_oauth_authorize_request() {
        let mut entry = create_test_entry("https://auth.example.com/authorize?response_type=code");
        assert!(FlowDetector::is_oauth_authorize_request(&entry));

        entry.request.url = "https://api.example.com/users".to_string();
        assert!(!FlowDetector::is_oauth_authorize_request(&entry));
    }

    #[test]
    fn test_calculate_duration() {
        // Test valid timestamps - 1.5 seconds apart
        let start = "2024-01-01T00:00:00.000Z";
        let end = "2024-01-01T00:00:01.500Z";
        let duration = FlowDetector::calculate_duration(start, Some(end));
        assert_eq!(duration, 1500.0);

        // Test valid timestamps - 2 seconds apart
        let start2 = "2024-01-01T12:00:00Z";
        let end2 = "2024-01-01T12:00:02Z";
        let duration2 = FlowDetector::calculate_duration(start2, Some(end2));
        assert_eq!(duration2, 2000.0);

        // Test with no end time
        let duration3 = FlowDetector::calculate_duration(start, None);
        assert_eq!(duration3, 0.0);

        // Test with invalid timestamp format
        let duration4 = FlowDetector::calculate_duration("invalid", Some(end));
        assert_eq!(duration4, 0.0);

        // Test with timezone offset
        let start5 = "2024-01-01T00:00:00-05:00";
        let end5 = "2024-01-01T00:00:03-05:00";
        let duration5 = FlowDetector::calculate_duration(start5, Some(end5));
        assert_eq!(duration5, 3000.0);
    }

    fn create_test_entry(url: &str) -> Entry {
        use harrier_core::har::*;
        Entry {
            page_ref: None,
            started_date_time: "2024-01-01T00:00:00Z".to_string(),
            time: 100.0,
            request: Request {
                method: "GET".to_string(),
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
