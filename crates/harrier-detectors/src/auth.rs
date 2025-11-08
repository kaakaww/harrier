use crate::Result;
use harrier_core::har::Har;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthMethod {
    Basic,
    Bearer,
    ApiKey(String), // Header name
    OAuth,
    Jwt,
    Cookie,
    Custom(String),
}

impl AuthMethod {
    pub fn as_str(&self) -> &str {
        match self {
            AuthMethod::Basic => "Basic Auth",
            AuthMethod::Bearer => "Bearer Token",
            AuthMethod::ApiKey(_) => "API Key",
            AuthMethod::OAuth => "OAuth",
            AuthMethod::Jwt => "JWT",
            AuthMethod::Cookie => "Cookie-based",
            AuthMethod::Custom(_) => "Custom",
        }
    }
}

lazy_static! {
    static ref JWT_PATTERN: Regex =
        Regex::new(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$").unwrap();
}

pub struct AuthDetector;

impl AuthDetector {
    pub fn detect(har: &Har) -> Result<Vec<AuthMethod>> {
        tracing::debug!("Detecting authentication methods from HAR entries");

        let mut auth_methods = HashSet::new();

        for entry in &har.log.entries {
            // Check request headers
            for header in &entry.request.headers {
                let header_name = header.name.to_lowercase();
                let header_value = &header.value;

                match header_name.as_str() {
                    "authorization" => {
                        if header_value.starts_with("Basic ") {
                            auth_methods.insert(AuthMethod::Basic);
                        } else if header_value.starts_with("Bearer ") {
                            let token = header_value.trim_start_matches("Bearer ");
                            if JWT_PATTERN.is_match(token) {
                                auth_methods.insert(AuthMethod::Jwt);
                            } else {
                                auth_methods.insert(AuthMethod::Bearer);
                            }
                        } else if header_value.starts_with("OAuth ") {
                            auth_methods.insert(AuthMethod::OAuth);
                        }
                    }
                    "x-api-key" | "api-key" | "apikey" => {
                        auth_methods.insert(AuthMethod::ApiKey(header.name.clone()));
                    }
                    "cookie" => {
                        if Self::has_auth_cookie(header_value) {
                            auth_methods.insert(AuthMethod::Cookie);
                        }
                    }
                    _ => {
                        // Check for custom auth headers
                        if header_name.contains("auth") || header_name.contains("token") {
                            auth_methods.insert(AuthMethod::Custom(header.name.clone()));
                        }
                    }
                }
            }

            // Check cookies
            for cookie in &entry.request.cookies {
                if Self::is_auth_cookie(&cookie.name) {
                    auth_methods.insert(AuthMethod::Cookie);
                }
            }
        }

        let methods: Vec<_> = auth_methods.into_iter().collect();
        tracing::info!("Detected {} authentication method(s)", methods.len());

        Ok(methods)
    }

    fn has_auth_cookie(cookie_header: &str) -> bool {
        let cookie_names = ["session", "auth", "token", "jwt", "sid"];
        let lower = cookie_header.to_lowercase();

        cookie_names.iter().any(|name| lower.contains(name))
    }

    fn is_auth_cookie(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("session")
            || lower.contains("auth")
            || lower.contains("token")
            || lower.contains("jwt")
            || lower == "sid"
    }
}
