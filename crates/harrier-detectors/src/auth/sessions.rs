use crate::Result;
use harrier_core::har::{Cookie, Entry, Har};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a tracked authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_type: SessionType,
    pub identifier: String,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: usize,
    pub duration_ms: f64,
    pub entry_indices: Vec<usize>,
    pub attributes: Option<SessionAttributes>,
}

/// Type of authentication session
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionType {
    Cookie { name: String },
    BearerToken { is_jwt: bool },
    ApiKey { header_name: String },
}

/// Security attributes for cookie-based sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAttributes {
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub same_site: Option<String>,
    pub expires: Option<String>,
    pub path: Option<String>,
    pub domain: Option<String>,
}

impl SessionAttributes {
    fn from_cookie(cookie: &Cookie) -> Self {
        Self {
            http_only: cookie.http_only,
            secure: cookie.secure,
            same_site: None, // HAR spec doesn't include SameSite in standard fields
            expires: cookie.expires.clone(),
            path: cookie.path.clone(),
            domain: cookie.domain.clone(),
        }
    }
}

pub struct SessionTracker;

impl SessionTracker {
    /// Track all authentication sessions in the HAR file
    pub fn track_sessions(har: &Har) -> Result<Vec<AuthSession>> {
        let mut cookie_sessions: HashMap<String, Vec<(usize, &Entry, &Cookie)>> = HashMap::new();
        let mut bearer_sessions: HashMap<String, Vec<(usize, &Entry, String)>> = HashMap::new();
        let mut apikey_sessions: HashMap<String, Vec<(usize, &Entry, String)>> = HashMap::new();

        // First pass: group entries by session identifier
        for (idx, entry) in har.log.entries.iter().enumerate() {
            // Track cookie-based sessions
            for cookie in &entry.request.cookies {
                if Self::is_auth_cookie(&cookie.name) {
                    cookie_sessions
                        .entry(cookie.name.clone())
                        .or_default()
                        .push((idx, entry, cookie));
                }
            }

            // Track Bearer token sessions
            for header in &entry.request.headers {
                if header.name.to_lowercase() == "authorization"
                    && let Some(token) = Self::extract_bearer_token(&header.value)
                {
                    let token_key = Self::token_identifier(token);
                    bearer_sessions.entry(token_key).or_default().push((
                        idx,
                        entry,
                        token.to_string(),
                    ));
                }
            }

            // Track API key sessions
            for header in &entry.request.headers {
                if Self::is_api_key_header(&header.name) {
                    let key = format!("{}:{}", header.name, Self::truncate_value(&header.value));
                    apikey_sessions.entry(key.clone()).or_default().push((
                        idx,
                        entry,
                        header.name.clone(),
                    ));
                }
            }
        }

        let mut sessions = Vec::new();

        // Convert cookie sessions
        for (cookie_name, entries) in cookie_sessions {
            if let Some(session) = Self::build_cookie_session(&cookie_name, entries) {
                sessions.push(session);
            }
        }

        // Convert bearer token sessions
        for (token_key, entries) in bearer_sessions {
            if let Some(session) = Self::build_bearer_session(&token_key, entries) {
                sessions.push(session);
            }
        }

        // Convert API key sessions
        for (key, entries) in apikey_sessions {
            if let Some(session) = Self::build_apikey_session(&key, entries) {
                sessions.push(session);
            }
        }

        // Sort by first seen timestamp
        sessions.sort_by(|a, b| a.first_seen.cmp(&b.first_seen));

        Ok(sessions)
    }

    fn build_cookie_session(
        cookie_name: &str,
        entries: Vec<(usize, &Entry, &Cookie)>,
    ) -> Option<AuthSession> {
        if entries.is_empty() {
            return None;
        }

        let first = entries.first()?;
        let last = entries.last()?;

        let first_time = Self::parse_timestamp(&first.1.started_date_time);
        let last_time = Self::parse_timestamp(&last.1.started_date_time);
        let duration_ms = last_time - first_time;

        // Get attributes from the first cookie (they should be consistent)
        let attributes = Some(SessionAttributes::from_cookie(first.2));

        // Truncate the value for display
        let value_preview = Self::truncate_value(&first.2.value);

        Some(AuthSession {
            session_type: SessionType::Cookie {
                name: cookie_name.to_string(),
            },
            identifier: format!("{}={}", cookie_name, value_preview),
            first_seen: first.1.started_date_time.clone(),
            last_seen: last.1.started_date_time.clone(),
            request_count: entries.len(),
            duration_ms,
            entry_indices: entries.iter().map(|(idx, _, _)| *idx).collect(),
            attributes,
        })
    }

    fn build_bearer_session(
        token_key: &str,
        entries: Vec<(usize, &Entry, String)>,
    ) -> Option<AuthSession> {
        if entries.is_empty() {
            return None;
        }

        let first = entries.first()?;
        let last = entries.last()?;

        let first_time = Self::parse_timestamp(&first.1.started_date_time);
        let last_time = Self::parse_timestamp(&last.1.started_date_time);
        let duration_ms = last_time - first_time;

        // Check if it's a JWT
        let is_jwt = Self::is_jwt(&first.2);

        Some(AuthSession {
            session_type: SessionType::BearerToken { is_jwt },
            identifier: format!("Bearer {}", Self::truncate_value(token_key)),
            first_seen: first.1.started_date_time.clone(),
            last_seen: last.1.started_date_time.clone(),
            request_count: entries.len(),
            duration_ms,
            entry_indices: entries.iter().map(|(idx, _, _)| *idx).collect(),
            attributes: None,
        })
    }

    fn build_apikey_session(
        _key: &str,
        entries: Vec<(usize, &Entry, String)>,
    ) -> Option<AuthSession> {
        if entries.is_empty() {
            return None;
        }

        let first = entries.first()?;
        let last = entries.last()?;

        let first_time = Self::parse_timestamp(&first.1.started_date_time);
        let last_time = Self::parse_timestamp(&last.1.started_date_time);
        let duration_ms = last_time - first_time;

        let header_name = first.2.clone();

        Some(AuthSession {
            session_type: SessionType::ApiKey {
                header_name: header_name.clone(),
            },
            identifier: format!("{}: ***", header_name),
            first_seen: first.1.started_date_time.clone(),
            last_seen: last.1.started_date_time.clone(),
            request_count: entries.len(),
            duration_ms,
            entry_indices: entries.iter().map(|(idx, _, _)| *idx).collect(),
            attributes: None,
        })
    }

    fn is_auth_cookie(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("session")
            || lower.contains("auth")
            || lower.contains("token")
            || lower.contains("jwt")
            || lower.contains("sid")
            || lower == "connect.sid"
            || lower == "jsessionid"
            || lower == "phpsessid"
            || lower.starts_with("__host-")
            || lower.starts_with("__secure-")
    }

    fn is_api_key_header(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower == "x-api-key"
            || lower == "api-key"
            || lower == "apikey"
            || lower == "x-api-token"
            || lower == "api-token"
    }

    fn extract_bearer_token(header_value: &str) -> Option<&str> {
        header_value.strip_prefix("Bearer ").map(|s| s.trim())
    }

    fn is_jwt(token: &str) -> bool {
        // JWT format: xxxxx.yyyyy.zzzzz
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
    }

    fn token_identifier(token: &str) -> String {
        // Use first 16 characters as identifier (enough to distinguish tokens)
        if token.len() > 16 {
            format!("{}...", &token[..16])
        } else {
            token.to_string()
        }
    }

    fn truncate_value(value: &str) -> String {
        if value.len() > 12 {
            format!("{}...", &value[..12])
        } else {
            value.to_string()
        }
    }

    fn parse_timestamp(timestamp: &str) -> f64 {
        // Parse ISO 8601 timestamp to milliseconds since Unix epoch
        use chrono::{DateTime, Utc};

        // Try to parse the timestamp as ISO 8601
        if let Ok(dt) = timestamp.parse::<DateTime<Utc>>() {
            dt.timestamp_millis() as f64
        } else {
            // If parsing fails, return 0 to avoid incorrect calculations
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_auth_cookie() {
        assert!(SessionTracker::is_auth_cookie("sessionId"));
        assert!(SessionTracker::is_auth_cookie("auth_token"));
        assert!(SessionTracker::is_auth_cookie("JWT"));
        assert!(SessionTracker::is_auth_cookie("connect.sid"));
        assert!(SessionTracker::is_auth_cookie("JSESSIONID"));
        assert!(!SessionTracker::is_auth_cookie("_ga"));
        assert!(!SessionTracker::is_auth_cookie("analytics"));
    }

    #[test]
    fn test_is_api_key_header() {
        assert!(SessionTracker::is_api_key_header("X-API-Key"));
        assert!(SessionTracker::is_api_key_header("API-Key"));
        assert!(SessionTracker::is_api_key_header("apikey"));
        assert!(!SessionTracker::is_api_key_header("Authorization"));
        assert!(!SessionTracker::is_api_key_header("Content-Type"));
    }

    #[test]
    fn test_is_jwt() {
        assert!(SessionTracker::is_jwt("eyJhbGc.eyJzdWI.SflKxwRJ"));
        assert!(!SessionTracker::is_jwt("simple_token"));
        assert!(!SessionTracker::is_jwt("one.two"));
        assert!(!SessionTracker::is_jwt(""));
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            SessionTracker::extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
        assert_eq!(SessionTracker::extract_bearer_token("Bearer "), Some(""));
        assert_eq!(SessionTracker::extract_bearer_token("Basic abc123"), None);
    }
}
