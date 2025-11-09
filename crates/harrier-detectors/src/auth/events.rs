use crate::Result;
use harrier_core::har::{Entry, Har};
use serde::{Deserialize, Serialize};

/// Represents a detected authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub event_type: AuthEventType,
    pub timestamp: String,
    pub entry_index: usize,
    pub method: String,
    pub url: String,
    pub status: i64,
    pub details: EventDetails,
}

/// Type of authentication event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthEventType {
    LoginSuccess,
    LoginFailure,
    Logout,
    TokenRefresh,
    SessionExpired,
    PasswordReset,
}

impl AuthEventType {
    pub fn as_str(&self) -> &str {
        match self {
            AuthEventType::LoginSuccess => "Login Success",
            AuthEventType::LoginFailure => "Login Failure",
            AuthEventType::Logout => "Logout",
            AuthEventType::TokenRefresh => "Token Refresh",
            AuthEventType::SessionExpired => "Session Expired",
            AuthEventType::PasswordReset => "Password Reset",
        }
    }
}

/// Additional details about an authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetails {
    pub description: String,
    pub credential_type: Option<String>,
    pub error_message: Option<String>,
}

pub struct EventDetector;

impl EventDetector {
    /// Detect all authentication events in the HAR file
    pub fn detect_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        // Detect login events (both success and failure)
        events.extend(Self::detect_login_events(har)?);

        // Detect logout events
        events.extend(Self::detect_logout_events(har)?);

        // Detect token refresh events
        events.extend(Self::detect_token_refresh_events(har)?);

        // Detect session expiration events
        events.extend(Self::detect_session_expiration_events(har)?);

        // Detect password reset events
        events.extend(Self::detect_password_reset_events(har)?);

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(events)
    }

    /// Detect login events (successful and failed)
    fn detect_login_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        for (i, entry) in har.log.entries.iter().enumerate() {
            // Check for login attempts via form submission
            if Self::is_login_attempt(entry) {
                let is_success = Self::is_successful_login(entry);
                let event_type = if is_success {
                    AuthEventType::LoginSuccess
                } else {
                    AuthEventType::LoginFailure
                };

                let credential_type = Self::detect_credential_type(entry);
                let error_message = if !is_success {
                    Self::extract_error_message(entry)
                } else {
                    None
                };

                events.push(AuthEvent {
                    event_type,
                    timestamp: entry.started_date_time.clone(),
                    entry_index: i,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    details: EventDetails {
                        description: if is_success {
                            "User successfully authenticated".to_string()
                        } else {
                            "Login attempt failed".to_string()
                        },
                        credential_type,
                        error_message,
                    },
                });
            }
        }

        Ok(events)
    }

    /// Detect logout events
    fn detect_logout_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        for (i, entry) in har.log.entries.iter().enumerate() {
            if Self::is_logout_request(entry) {
                events.push(AuthEvent {
                    event_type: AuthEventType::Logout,
                    timestamp: entry.started_date_time.clone(),
                    entry_index: i,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    details: EventDetails {
                        description: "User logged out".to_string(),
                        credential_type: None,
                        error_message: None,
                    },
                });
            }
        }

        Ok(events)
    }

    /// Detect token refresh events
    fn detect_token_refresh_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        for (i, entry) in har.log.entries.iter().enumerate() {
            if Self::is_token_refresh_request(entry) {
                let is_success = entry.response.status == 200;

                events.push(AuthEvent {
                    event_type: AuthEventType::TokenRefresh,
                    timestamp: entry.started_date_time.clone(),
                    entry_index: i,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    details: EventDetails {
                        description: if is_success {
                            "Access token refreshed successfully".to_string()
                        } else {
                            "Token refresh failed".to_string()
                        },
                        credential_type: Some("refresh_token".to_string()),
                        error_message: if !is_success {
                            Self::extract_error_message(entry)
                        } else {
                            None
                        },
                    },
                });
            }
        }

        Ok(events)
    }

    /// Detect session expiration events
    fn detect_session_expiration_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        for (i, entry) in har.log.entries.iter().enumerate() {
            if Self::is_session_expired_response(entry) {
                events.push(AuthEvent {
                    event_type: AuthEventType::SessionExpired,
                    timestamp: entry.started_date_time.clone(),
                    entry_index: i,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    details: EventDetails {
                        description: "Session expired or invalid".to_string(),
                        credential_type: None,
                        error_message: Self::extract_error_message(entry),
                    },
                });
            }
        }

        Ok(events)
    }

    /// Detect password reset events
    fn detect_password_reset_events(har: &Har) -> Result<Vec<AuthEvent>> {
        let mut events = Vec::new();

        for (i, entry) in har.log.entries.iter().enumerate() {
            if Self::is_password_reset_request(entry) {
                events.push(AuthEvent {
                    event_type: AuthEventType::PasswordReset,
                    timestamp: entry.started_date_time.clone(),
                    entry_index: i,
                    method: entry.request.method.clone(),
                    url: Self::truncate_url(&entry.request.url),
                    status: entry.response.status,
                    details: EventDetails {
                        description: "Password reset request".to_string(),
                        credential_type: None,
                        error_message: None,
                    },
                });
            }
        }

        Ok(events)
    }

    // Helper methods for event detection

    fn is_login_attempt(entry: &Entry) -> bool {
        // POST to login/signin/auth endpoint
        if entry.request.method != "POST" {
            return false;
        }

        let url_lower = entry.request.url.to_lowercase();
        let is_login_url = url_lower.contains("/login")
            || url_lower.contains("/signin")
            || url_lower.contains("/auth/login")
            || url_lower.contains("/api/auth")
            || url_lower.contains("/authenticate");

        if !is_login_url {
            return false;
        }

        // Check for credentials in POST data
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            let has_credentials =
                (text.contains("username") || text.contains("email") || text.contains("\"user\""))
                    && text.contains("password");
            return has_credentials;
        }

        // Check for OAuth token endpoint with password grant
        if (url_lower.contains("/token") || url_lower.contains("/oauth/token"))
            && let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("grant_type=password");
        }

        false
    }

    fn is_successful_login(entry: &Entry) -> bool {
        // Status 200 or 201
        if entry.response.status != 200 && entry.response.status != 201 {
            return false;
        }

        // Check if session was established (cookie set)
        for cookie in &entry.response.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return true;
            }
        }

        // Check if token was returned in response
        if entry
            .response
            .content
            .mime_type
            .contains("application/json")
            && let Some(ref text) = entry.response.content.text
            && (text.contains("\"token\"")
                || text.contains("\"access_token\"")
                || text.contains("\"accessToken\""))
        {
            return true;
        }

        // If we have a redirect (302/303), that's often a successful login
        if entry.response.status >= 300 && entry.response.status < 400 {
            return true;
        }

        false
    }

    fn is_logout_request(entry: &Entry) -> bool {
        let url_lower = entry.request.url.to_lowercase();
        (url_lower.contains("/logout") || url_lower.contains("/signout"))
            && (entry.request.method == "GET" || entry.request.method == "POST")
    }

    fn is_token_refresh_request(entry: &Entry) -> bool {
        if entry.request.method != "POST" {
            return false;
        }

        let url_lower = entry.request.url.to_lowercase();
        if !(url_lower.contains("/token") || url_lower.contains("/refresh")) {
            return false;
        }

        // Check for refresh_token in POST data
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            return text.contains("grant_type=refresh_token")
                || text.contains("\"refresh_token\"")
                || text.contains("refreshToken");
        }

        false
    }

    fn is_session_expired_response(entry: &Entry) -> bool {
        // 401 Unauthorized typically indicates expired session
        if entry.response.status != 401 {
            return false;
        }

        // Check if request had authentication
        let has_auth =
            entry.request.headers.iter().any(|h| {
                h.name.to_lowercase() == "authorization" || h.name.to_lowercase() == "cookie"
            });

        if !has_auth {
            return false;
        }

        // Check for expired/invalid session messages
        if let Some(ref text) = entry.response.content.text {
            let text_lower = text.to_lowercase();
            return text_lower.contains("expired")
                || text_lower.contains("invalid")
                || text_lower.contains("unauthorized");
        }

        true
    }

    fn is_password_reset_request(entry: &Entry) -> bool {
        let url_lower = entry.request.url.to_lowercase();
        (url_lower.contains("/reset") || url_lower.contains("/forgot"))
            && (url_lower.contains("password") || url_lower.contains("pwd"))
            && entry.request.method == "POST"
    }

    fn detect_credential_type(entry: &Entry) -> Option<String> {
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            if text.contains("username") {
                return Some("username_password".to_string());
            } else if text.contains("email") {
                return Some("email_password".to_string());
            } else if text.contains("grant_type=password") {
                return Some("oauth_password".to_string());
            }
        }
        None
    }

    fn extract_error_message(entry: &Entry) -> Option<String> {
        if let Some(ref text) = entry.response.content.text {
            // Try to extract error message from JSON response
            if entry
                .response
                .content
                .mime_type
                .contains("application/json")
            {
                // Simple extraction - look for common error fields
                if let Some(start) = text.find("\"error\"")
                    && let Some(colon) = text[start..].find(':')
                {
                    let after_colon = &text[start + colon + 1..];
                    if let Some(quote_start) = after_colon.find('"')
                        && let Some(quote_end) = after_colon[quote_start + 1..].find('"')
                    {
                        let error = &after_colon[quote_start + 1..quote_start + 1 + quote_end];
                        return Some(error.to_string());
                    }
                }

                // Try "message" field
                if let Some(start) = text.find("\"message\"")
                    && let Some(colon) = text[start..].find(':')
                {
                    let after_colon = &text[start + colon + 1..];
                    if let Some(quote_start) = after_colon.find('"')
                        && let Some(quote_end) = after_colon[quote_start + 1..].find('"')
                    {
                        let message = &after_colon[quote_start + 1..quote_start + 1 + quote_end];
                        return Some(message.to_string());
                    }
                }
            }
        }
        None
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
    fn test_event_type_as_str() {
        assert_eq!(AuthEventType::LoginSuccess.as_str(), "Login Success");
        assert_eq!(AuthEventType::Logout.as_str(), "Logout");
        assert_eq!(AuthEventType::TokenRefresh.as_str(), "Token Refresh");
    }

    #[test]
    fn test_is_logout_request() {
        let entry = create_test_entry("https://example.com/logout", "GET", 200);
        assert!(EventDetector::is_logout_request(&entry));

        let entry2 = create_test_entry("https://example.com/api/users", "GET", 200);
        assert!(!EventDetector::is_logout_request(&entry2));
    }

    #[test]
    fn test_is_session_expired_response() {
        let mut entry = create_test_entry("https://example.com/api/data", "GET", 401);
        entry.request.headers.push(harrier_core::har::Header {
            name: "Authorization".to_string(),
            value: "Bearer token123".to_string(),
            comment: None,
        });
        assert!(EventDetector::is_session_expired_response(&entry));

        let entry2 = create_test_entry("https://example.com/api/data", "GET", 200);
        assert!(!EventDetector::is_session_expired_response(&entry2));
    }

    fn create_test_entry(url: &str, method: &str, status: i64) -> Entry {
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
                status,
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
