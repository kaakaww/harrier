use crate::Result;
use harrier_core::har::Har;
use serde::{Deserialize, Serialize};

use super::methods::AuthMethod;
use super::sessions::{AuthSession, SessionType};

/// Security observation with severity level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityNote {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub entry_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

pub struct SecurityAnalyzer;

impl SecurityAnalyzer {
    /// Analyze security aspects of authentication
    pub fn analyze(
        har: &Har,
        methods: &[AuthMethod],
        sessions: &[AuthSession],
    ) -> Result<Vec<SecurityNote>> {
        let mut notes = Vec::new();

        // Analyze authentication methods
        notes.extend(Self::analyze_methods(methods));

        // Analyze sessions
        notes.extend(Self::analyze_sessions(sessions, har));

        // Analyze request patterns
        notes.extend(Self::analyze_requests(har));

        Ok(notes)
    }

    fn analyze_methods(methods: &[AuthMethod]) -> Vec<SecurityNote> {
        let mut notes = Vec::new();

        for method in methods {
            match method {
                AuthMethod::Basic => {
                    notes.push(SecurityNote {
                        severity: Severity::Warning,
                        category: "Authentication Method".to_string(),
                        message: "Basic Authentication detected - credentials encoded in header (use HTTPS)".to_string(),
                        entry_index: None,
                    });
                }
                AuthMethod::ApiKey(_) => {
                    notes.push(SecurityNote {
                        severity: Severity::Info,
                        category: "Authentication Method".to_string(),
                        message: "API Key authentication detected".to_string(),
                        entry_index: None,
                    });
                }
                _ => {}
            }
        }

        notes
    }

    fn analyze_sessions(sessions: &[AuthSession], har: &Har) -> Vec<SecurityNote> {
        let mut notes = Vec::new();

        for session in sessions {
            match &session.session_type {
                SessionType::Cookie { name } => {
                    // Check cookie security attributes
                    if let Some(ref attrs) = session.attributes {
                        // Check HttpOnly
                        if attrs.http_only == Some(false) || attrs.http_only.is_none() {
                            notes.push(SecurityNote {
                                severity: Severity::Warning,
                                category: "Cookie Security".to_string(),
                                message: format!(
                                    "Cookie '{}' missing HttpOnly flag (vulnerable to XSS)",
                                    name
                                ),
                                entry_index: session.entry_indices.first().copied(),
                            });
                        }

                        // Check Secure flag (only on HTTPS)
                        if let Some(first_idx) = session.entry_indices.first()
                            && let Some(entry) = har.log.entries.get(*first_idx)
                            && entry.request.url.starts_with("https://")
                            && (attrs.secure == Some(false) || attrs.secure.is_none())
                        {
                            notes.push(SecurityNote {
                                severity: Severity::Warning,
                                category: "Cookie Security".to_string(),
                                message: format!(
                                    "Cookie '{}' on HTTPS connection missing Secure flag",
                                    name
                                ),
                                entry_index: Some(*first_idx),
                            });
                        }

                        // Note about missing SameSite
                        if attrs.same_site.is_none() {
                            notes.push(SecurityNote {
                                severity: Severity::Info,
                                category: "Cookie Security".to_string(),
                                message: format!(
                                    "Cookie '{}' missing SameSite attribute (consider setting to Lax or Strict)",
                                    name
                                ),
                                entry_index: session.entry_indices.first().copied(),
                            });
                        }
                    }
                }
                SessionType::BearerToken { is_jwt } => {
                    if *is_jwt {
                        notes.push(SecurityNote {
                            severity: Severity::Info,
                            category: "Token Security".to_string(),
                            message:
                                "JWT tokens detected - ensure tokens are validated and not expired"
                                    .to_string(),
                            entry_index: session.entry_indices.first().copied(),
                        });
                    }
                }
                SessionType::ApiKey { .. } => {
                    // Check if API key is in URL (insecure)
                    if let Some(first_idx) = session.entry_indices.first()
                        && let Some(entry) = har.log.entries.get(*first_idx)
                        && (entry.request.url.contains("api_key=")
                            || entry.request.url.contains("apikey=")
                            || entry.request.url.contains("key="))
                    {
                        notes.push(SecurityNote {
                            severity: Severity::Warning,
                            category: "API Key Security".to_string(),
                            message: "API key detected in query parameter (prefer header-based authentication)".to_string(),
                            entry_index: Some(*first_idx),
                        });
                    }
                }
            }
        }

        notes
    }

    fn analyze_requests(har: &Har) -> Vec<SecurityNote> {
        let mut notes = Vec::new();
        let mut http_auth_seen = false;

        for (idx, entry) in har.log.entries.iter().enumerate() {
            // Check for authentication over HTTP (not HTTPS)
            if entry.request.url.starts_with("http://") {
                // Check if this request has authentication
                let has_auth = entry.request.headers.iter().any(|h| {
                    let name_lower = h.name.to_lowercase();
                    name_lower == "authorization" || name_lower.contains("api")
                });

                let has_auth_cookie = entry
                    .request
                    .cookies
                    .iter()
                    .any(|c| Self::is_auth_cookie(&c.name));

                if (has_auth || has_auth_cookie) && !http_auth_seen {
                    notes.push(SecurityNote {
                        severity: Severity::Critical,
                        category: "Transport Security".to_string(),
                        message: "Authentication credentials sent over unencrypted HTTP connection (use HTTPS)".to_string(),
                        entry_index: Some(idx),
                    });
                    http_auth_seen = true;
                }
            }
        }

        notes
    }

    fn is_auth_cookie(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("session")
            || lower.contains("auth")
            || lower.contains("token")
            || lower.contains("jwt")
            || lower.contains("sid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_note_severity() {
        let note = SecurityNote {
            severity: Severity::Warning,
            category: "Test".to_string(),
            message: "Test message".to_string(),
            entry_index: None,
        };

        assert_eq!(note.severity, Severity::Warning);
    }
}
