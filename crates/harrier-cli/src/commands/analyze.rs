use crate::OutputFormat;
use anyhow::Result;
use clap::ValueEnum;
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::{AppTypeDetector, AuthAnalyzer, AuthMethod};
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Focus areas for analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Focus {
    /// Architecture map - hosts, API types, relationships
    Map,
    /// Authentication analysis - methods, flows, sessions
    Auth,
}

/// Host information for analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostInfo {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub request_count: usize,
    pub api_type: Option<String>,
    pub auth_method: Option<String>,
    pub session_cookies: Vec<String>,
    pub role: Option<String>,
    pub category: String,
}

/// Full analysis result
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisResult {
    pub file_name: String,
    pub total_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<ArchitectureAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationAnalysis>,
    /// Enhanced authentication section (for --focus auth)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_details: Option<AuthenticationSection>,
    /// Enhanced authorization section (for --focus auth)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_details: Option<AuthorizationSection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
    pub duration_display: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchitectureAnalysis {
    pub primary_host: Option<String>,
    pub hosts: Vec<HostInfo>,
    pub host_count: usize,
    pub same_domain_count: usize,
    pub third_party_count: usize,
}

/// Legacy AuthenticationAnalysis (kept for JSON compatibility)
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthenticationAnalysis {
    pub primary_method: Option<String>,
    pub session_type: Option<String>,
    pub methods: Vec<String>,
    pub flow_count: usize,
    pub jwt_count: usize,
}

// ============================================================================
// Enhanced Auth Analysis Structures (Phase 1)
// ============================================================================

/// Enhanced authentication section for detailed output
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthenticationSection {
    /// Detected auth provider (Entra, Auth0, Okta, etc.)
    pub provider: Option<AuthProvider>,
    /// Primary authentication method description
    pub method: Option<String>,
    /// OAuth/SAML flow steps observed
    pub flow_steps: Vec<AuthFlowSummary>,
    /// Authentication events (login, logout, refresh)
    pub events: Vec<AuthEventSummary>,
}

/// Third-party authentication provider info
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthProvider {
    /// Provider name (e.g., "Microsoft Entra", "Auth0", "Okta")
    pub name: String,
    /// Provider host (e.g., "login.microsoftonline.com")
    pub host: String,
    /// Whether this is a third-party provider
    pub is_third_party: bool,
}

/// Summary of an authentication flow for display
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthFlowSummary {
    /// Flow type description
    pub flow_type: String,
    /// Flow steps
    pub steps: Vec<FlowStepSummary>,
    /// Duration in milliseconds
    pub duration_ms: f64,
}

/// Individual step in an auth flow
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowStepSummary {
    /// HTTP method
    pub method: String,
    /// URL path (truncated)
    pub path: String,
    /// Step description
    pub description: Option<String>,
}

/// Summary of an authentication event
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthEventSummary {
    /// Event type (Login, Logout, Refresh, etc.)
    pub event_type: String,
    /// HTTP status code
    pub status: i64,
    /// Timestamp (time only for display)
    pub time: String,
}

/// Enhanced authorization section for detailed output
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthorizationSection {
    /// Session type description
    pub session_type: String,
    /// Authorization headers found
    pub auth_headers: Vec<AuthHeaderInfo>,
    /// Session cookies with security attributes
    pub session_cookies: Vec<SessionCookieInfo>,
    /// Token refresh pattern info
    pub token_refresh: Option<TokenRefreshInfo>,
    /// Traced credentials with their origins
    pub traced_credentials: Vec<TracedCredential>,
}

/// Authorization header details
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthHeaderInfo {
    /// Header name (e.g., "Authorization")
    pub header_name: String,
    /// Header type (e.g., "Bearer JWT", "Basic")
    pub header_type: String,
    /// JWT details if applicable
    pub jwt_details: Option<JwtDetails>,
    /// Security warnings
    pub warnings: Vec<String>,
}

/// JWT token details for display
#[derive(Debug, Clone, serde::Serialize)]
pub struct JwtDetails {
    /// Algorithm (RS256, HS256, etc.)
    pub algorithm: Option<String>,
    /// Issuer URL
    pub issuer: Option<String>,
    /// Audience
    pub audience: Option<String>,
    /// Expiration time (formatted)
    pub expires_at: Option<String>,
    /// Token lifetime description
    pub expires_in: Option<String>,
    /// All claims as key-value pairs
    pub claims: Vec<(String, String)>,
}

/// Session cookie with security attributes
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionCookieInfo {
    /// Cookie name
    pub name: String,
    /// Security attributes (HttpOnly, Secure, SameSite, etc.)
    pub attributes: Vec<String>,
    /// Security warnings
    pub warnings: Vec<String>,
}

/// Token refresh pattern info
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenRefreshInfo {
    /// Pattern description
    pub pattern: String,
    /// Number of refreshes observed
    pub count: usize,
    /// Average interval between refreshes
    pub interval: Option<String>,
}

/// Traced authentication credential - shows where a token/cookie originated
#[derive(Debug, Clone, serde::Serialize)]
pub struct TracedCredential {
    /// Type of credential (cookie, header, etc.)
    pub credential_type: String,
    /// Name of the credential (cookie name or header name)
    pub name: String,
    /// Origin endpoint where this credential was first set
    pub origin: Option<CredentialOrigin>,
    /// Number of requests using this credential
    pub usage_count: usize,
    /// Whether this appears to be a JWT
    pub is_jwt: bool,
}

/// Where a credential originated
#[derive(Debug, Clone, serde::Serialize)]
pub struct CredentialOrigin {
    /// HTTP method
    pub method: String,
    /// URL path
    pub url: String,
    /// Response status code
    pub status: i64,
    /// How the credential was set (Set-Cookie header, response body, etc.)
    pub set_via: String,
    /// Timestamp
    pub timestamp: Option<String>,
}

/// Extract root domain using Public Suffix List
fn get_root_domain(domain: &str) -> String {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return domain.to_string();
    }

    match psl::domain(domain.as_bytes()) {
        Some(root) => String::from_utf8_lossy(root.as_bytes()).to_string(),
        None => {
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                domain.to_string()
            }
        }
    }
}

/// Detect auth method for a set of entries
fn detect_auth_for_entries(entries: &[&Entry]) -> Option<String> {
    for entry in entries {
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "authorization" {
                let value = header.value.to_lowercase();
                if value.starts_with("bearer") {
                    let token = header.value.trim_start_matches("Bearer ").trim();
                    if token.matches('.').count() == 2 {
                        return Some("Bearer JWT".to_string());
                    }
                    return Some("Bearer Token".to_string());
                } else if value.starts_with("basic") {
                    return Some("Basic Auth".to_string());
                }
            }
            let header_lower = header.name.to_lowercase();
            if header_lower == "x-api-key" || header_lower == "api-key" || header_lower == "apikey"
            {
                return Some(format!("API Key ({})", header.name));
            }
        }

        for cookie in &entry.request.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return Some("Cookie".to_string());
            }
        }
    }
    None
}

/// Detect session/auth cookies for a set of entries
fn detect_session_cookies(entries: &[&Entry]) -> Vec<String> {
    use std::collections::HashSet;
    let mut cookies: HashSet<String> = HashSet::new();

    for entry in entries {
        // Check request cookies
        for cookie in &entry.request.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
                || name_lower.contains("jwt")
                || name_lower.contains("sid")
                || name_lower.contains("csrf")
                || name_lower == "id"
            {
                cookies.insert(cookie.name.clone());
            }
        }

        // Check Set-Cookie response headers
        for header in &entry.response.headers {
            if header.name.to_lowercase() == "set-cookie" {
                // Extract cookie name (before '=')
                if let Some(name) = header.value.split('=').next() {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("session")
                        || name_lower.contains("auth")
                        || name_lower.contains("token")
                        || name_lower.contains("jwt")
                        || name_lower.contains("sid")
                        || name_lower.contains("csrf")
                        || name_lower == "id"
                    {
                        cookies.insert(name.to_string());
                    }
                }
            }
        }
    }

    let mut result: Vec<String> = cookies.into_iter().collect();
    result.sort();
    result
}

/// Known auth-related cookie name patterns
fn is_auth_cookie_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("session")
        || lower.contains("auth")
        || lower.contains("token")
        || lower.contains("jwt")
        || lower.contains("sid")
        || lower.contains("csrf")
        || lower.contains("xsrf")
        || lower == "id"
        || lower.contains("identity")
        || lower.contains("refresh")
        || lower.contains("access")
        || lower.starts_with("__host-")
        || lower.starts_with("__secure-")
        || lower == "connect.sid"
        || lower == "jsessionid"
        || lower == "phpsessid"
        || lower == "asp.net_sessionid"
        || lower == "laravel_session"
        || lower == "_rails_session"
}

/// Known auth-related header names
fn is_auth_header_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "authorization"
        || lower == "x-api-key"
        || lower == "api-key"
        || lower == "x-auth-token"
        || lower == "x-access-token"
        || lower == "x-session-id"
        || lower == "x-csrf-token"
        || lower == "x-xsrf-token"
        || lower.starts_with("x-auth")
        || lower.starts_with("x-token")
}

/// Safely truncate a string to max_len characters (not bytes), adding "..." if truncated.
/// Handles UTF-8 multi-byte characters correctly without panicking.
fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        // Reserve 3 chars for "..."
        let truncate_at = max_len.saturating_sub(3);
        let truncated: String = s.chars().take(truncate_at).collect();
        format!("{}...", truncated)
    }
}

/// Check if a value looks like a JWT
fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| p.len() > 10)
}

/// Trace credentials back to their origin in the HAR
fn trace_credentials(har: &Har) -> Vec<TracedCredential> {
    use std::collections::HashMap;

    let mut credentials: Vec<TracedCredential> = Vec::new();
    let mut cookie_origins: HashMap<String, CredentialOrigin> = HashMap::new();
    let mut header_usage: HashMap<String, (String, usize, bool)> = HashMap::new(); // name -> (value, count, is_jwt)

    // First pass: find where cookies are SET (Set-Cookie response headers)
    for entry in &har.log.entries {
        for header in &entry.response.headers {
            if header.name.to_lowercase() == "set-cookie" {
                // Parse cookie name from Set-Cookie header
                if let Some(cookie_name) = header.value.split('=').next() {
                    let cookie_name = cookie_name.trim().to_string();
                    if is_auth_cookie_name(&cookie_name)
                        && !cookie_origins.contains_key(&cookie_name)
                    {
                        let url_display = Url::parse(&entry.request.url)
                            .ok()
                            .map(|u| {
                                format!(
                                    "{}://{}{}",
                                    u.scheme(),
                                    u.host_str().unwrap_or(""),
                                    u.path()
                                )
                            })
                            .unwrap_or_else(|| entry.request.url.clone());

                        cookie_origins.insert(
                            cookie_name,
                            CredentialOrigin {
                                method: entry.request.method.clone(),
                                url: url_display,
                                status: entry.response.status,
                                set_via: "Set-Cookie header".to_string(),
                                timestamp: Some(entry.started_date_time.clone()),
                            },
                        );
                    }
                }
            }
        }
    }

    // Second pass: count cookie usage and find auth headers
    let mut cookie_usage: HashMap<String, usize> = HashMap::new();
    for entry in &har.log.entries {
        // Count cookie usage
        for cookie in &entry.request.cookies {
            if is_auth_cookie_name(&cookie.name) {
                *cookie_usage.entry(cookie.name.clone()).or_insert(0) += 1;
            }
        }

        // Find auth headers and track their usage
        for header in &entry.request.headers {
            if is_auth_header_name(&header.name) {
                let is_jwt = looks_like_jwt(&header.value)
                    || header.value.starts_with("Bearer ")
                        && looks_like_jwt(header.value.trim_start_matches("Bearer ").trim());

                let entry = header_usage
                    .entry(header.name.clone())
                    .or_insert_with(|| (header.value.clone(), 0, is_jwt));
                entry.1 += 1;
            }
        }
    }

    // Build traced credentials for cookies
    for (name, count) in cookie_usage {
        let origin = cookie_origins.get(&name).cloned();
        let is_jwt = origin.is_some() && {
            // Check if the Set-Cookie value contains a JWT
            har.log.entries.iter().any(|e| {
                e.response.headers.iter().any(|h| {
                    h.name.to_lowercase() == "set-cookie"
                        && h.value.starts_with(&format!("{}=", name))
                        && looks_like_jwt(&h.value)
                })
            })
        };

        credentials.push(TracedCredential {
            credential_type: "Cookie".to_string(),
            name,
            origin,
            usage_count: count,
            is_jwt,
        });
    }

    // Build traced credentials for headers
    for (name, (value, count, is_jwt)) in header_usage {
        // Try to find where this header value originated (response body or Set-Cookie)
        let mut origin: Option<CredentialOrigin> = None;

        // For Authorization headers, try to find where the token came from
        let search_value = if value.starts_with("Bearer ") {
            value.trim_start_matches("Bearer ").trim()
        } else {
            &value
        };

        // Search response bodies for the token value (first 50 chars to avoid false matches)
        // Use safe slice to handle UTF-8 boundaries
        let search_prefix = search_value.get(..50).unwrap_or(search_value);

        for entry in &har.log.entries {
            // Check response body for token
            if let Some(ref text) = entry.response.content.text
                && text.contains(search_prefix)
            {
                let url_display = Url::parse(&entry.request.url)
                    .ok()
                    .map(|u| {
                        format!(
                            "{}://{}{}",
                            u.scheme(),
                            u.host_str().unwrap_or(""),
                            u.path()
                        )
                    })
                    .unwrap_or_else(|| entry.request.url.clone());

                origin = Some(CredentialOrigin {
                    method: entry.request.method.clone(),
                    url: url_display,
                    status: entry.response.status,
                    set_via: "Response body".to_string(),
                    timestamp: Some(entry.started_date_time.clone()),
                });
                break;
            }
        }

        credentials.push(TracedCredential {
            credential_type: "Header".to_string(),
            name,
            origin,
            usage_count: count,
            is_jwt,
        });
    }

    // Sort by usage count (most used first)
    credentials.sort_by(|a, b| b.usage_count.cmp(&a.usage_count));

    credentials
}

/// Detect authentication provider from host
fn detect_auth_provider(host: &str) -> Option<AuthProvider> {
    let host_lower = host.to_lowercase();

    // Microsoft Entra / Azure AD
    if host_lower.contains("login.microsoftonline.com")
        || host_lower.contains("login.microsoft.com")
        || host_lower.contains("b2clogin.com")
        || host_lower.contains("login.windows.net")
        || host_lower.contains("sts.windows.net")
    {
        return Some(AuthProvider {
            name: "Microsoft Entra".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Auth0
    if host_lower.contains(".auth0.com") || host_lower.contains(".auth0.net") {
        return Some(AuthProvider {
            name: "Auth0".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Okta
    if host_lower.contains(".okta.com")
        || host_lower.contains(".oktapreview.com")
        || host_lower.contains(".okta-emea.com")
    {
        return Some(AuthProvider {
            name: "Okta".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Google Identity
    if host_lower.contains("accounts.google.com")
        || host_lower.contains("oauth2.googleapis.com")
        || host_lower.contains("www.googleapis.com/oauth2")
    {
        return Some(AuthProvider {
            name: "Google".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // AWS Cognito
    if (host_lower.contains("cognito-idp") || host_lower.contains("cognito-identity"))
        && host_lower.contains("amazonaws.com")
    {
        return Some(AuthProvider {
            name: "AWS Cognito".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Firebase Auth
    if host_lower.contains("identitytoolkit.googleapis.com")
        || host_lower.contains("securetoken.googleapis.com")
    {
        return Some(AuthProvider {
            name: "Firebase Auth".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Keycloak (pattern-based - often self-hosted)
    if host_lower.contains("/auth/realms/") || host_lower.contains("/realms/") {
        return Some(AuthProvider {
            name: "Keycloak".to_string(),
            host: host.to_string(),
            is_third_party: false, // Typically self-hosted
        });
    }

    // OneLogin
    if host_lower.contains(".onelogin.com") {
        return Some(AuthProvider {
            name: "OneLogin".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Ping Identity
    if host_lower.contains(".pingone.com")
        || host_lower.contains(".pingidentity.com")
        || host_lower.contains(".pingfederate")
    {
        return Some(AuthProvider {
            name: "Ping Identity".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // Salesforce Identity
    if host_lower.contains("login.salesforce.com")
        || host_lower.contains(".force.com/services/oauth2")
    {
        return Some(AuthProvider {
            name: "Salesforce".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    // GitHub OAuth
    if host_lower == "github.com" && host_lower.contains("/login/oauth") {
        return Some(AuthProvider {
            name: "GitHub".to_string(),
            host: host.to_string(),
            is_third_party: true,
        });
    }

    None
}

/// Infer the role of a host based on its characteristics
fn infer_host_role(host: &str, api_type: &str) -> Option<String> {
    let host_lower = host.to_lowercase();

    if host_lower.contains("auth0")
        || host_lower.contains("okta")
        || host_lower.contains("cognito")
        || host_lower.contains("oauth")
        || host_lower.contains("login")
        || host_lower.contains("identity")
    {
        return Some("Authentication provider".to_string());
    }

    if host_lower.contains("cdn")
        || host_lower.contains("static")
        || host_lower.contains("assets")
        || host_lower.contains("cloudfront")
        || host_lower.contains("akamai")
    {
        return Some("CDN / Static assets".to_string());
    }

    if host_lower.contains("analytics")
        || host_lower.contains("tracking")
        || host_lower.contains("segment")
        || host_lower.contains("mixpanel")
        || host_lower.contains("amplitude")
    {
        return Some("Analytics".to_string());
    }

    if host_lower.contains("sentry")
        || host_lower.contains("datadog")
        || host_lower.contains("newrelic")
        || host_lower.contains("bugsnag")
    {
        return Some("Error monitoring".to_string());
    }

    if api_type == "GraphQL" {
        return Some("GraphQL API".to_string());
    }

    None
}

/// Check if a URL should be considered for primary host detection
fn is_web_traffic(protocol: &str, domain: &str) -> bool {
    // Only HTTP/HTTPS are web traffic
    if protocol != "http" && protocol != "https" {
        return false;
    }
    // Skip localhost/loopback for primary detection
    if domain == "localhost" || domain.starts_with("127.") || domain == "[::1]" {
        return false;
    }
    true
}

/// Analyze hosts from HAR file
fn analyze_hosts(har: &Har) -> ArchitectureAnalysis {
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>)> = HashMap::new();
    let mut first_host_key: Option<String> = None;

    // Check if target host was specified via --url during capture
    let target_host = har
        .log
        .harrier_metadata
        .as_ref()
        .and_then(|m| m.target_host.clone());

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url
                .port()
                .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });

            // Skip non-web traffic (chrome-extension://, data:, etc.)
            if !is_web_traffic(&protocol, &domain) {
                continue;
            }

            let key = format!("{}://{}:{}", protocol, domain, port);

            // Use metadata target_host if available, otherwise first web traffic URL
            if first_host_key.is_none() {
                if let Some(ref th) = target_host {
                    // Check if this entry matches the target host
                    if domain == *th || domain.ends_with(&format!(".{}", th)) {
                        first_host_key = Some(key.clone());
                    }
                } else {
                    first_host_key = Some(key.clone());
                }
            }

            host_entries
                .entry(key)
                .and_modify(|(_, _, _, entries)| entries.push(entry))
                .or_insert((protocol, domain, port, vec![entry]));
        }
    }

    // If target_host was specified but no entries matched, find it in host_entries
    if first_host_key.is_none()
        && let Some(ref th) = target_host
    {
        for (key, (_, domain, _, _)) in &host_entries {
            if domain == th || domain.ends_with(&format!(".{}", th)) {
                first_host_key = Some(key.clone());
                break;
            }
        }
    }

    // Final fallback: use first host in entries
    if first_host_key.is_none() {
        first_host_key = host_entries.keys().next().cloned();
    }

    let first_root_domain = first_host_key.as_ref().and_then(|key| {
        host_entries
            .get(key)
            .map(|(_, domain, _, _)| get_root_domain(domain))
    });

    let mut hosts: Vec<HostInfo> = Vec::new();
    let mut primary_host: Option<String> = None;
    let mut same_domain_count = 0;
    let mut third_party_count = 0;

    for (key, (protocol, domain, port, entries)) in &host_entries {
        let is_primary = first_host_key.as_ref() == Some(key);
        let root_domain = get_root_domain(domain);
        let is_same_domain = first_root_domain
            .as_ref()
            .is_some_and(|first| &root_domain == first);

        let category = if is_primary {
            "Primary".to_string()
        } else if is_same_domain {
            same_domain_count += 1;
            "Same Domain".to_string()
        } else {
            third_party_count += 1;
            "Third Party".to_string()
        };

        // Detect API type
        let api_type_results = AppTypeDetector::detect_for_host(entries);
        let api_type = api_type_results
            .first()
            .map(|(t, _, _)| t.as_str().to_string());

        let api_type_str = api_type.clone().unwrap_or_else(|| "Unknown".to_string());

        // Detect auth, cookies, and role
        let auth_method = detect_auth_for_entries(entries);
        let session_cookies = detect_session_cookies(entries);
        let role = infer_host_role(domain, &api_type_str);

        if is_primary {
            primary_host = Some(domain.clone());
        }

        hosts.push(HostInfo {
            host: domain.clone(),
            port: *port,
            protocol: protocol.clone(),
            request_count: entries.len(),
            api_type,
            auth_method,
            session_cookies,
            role,
            category,
        });
    }

    // Sort hosts: primary first, then same domain by count, then third party by count
    hosts.sort_by(|a, b| match (a.category.as_str(), b.category.as_str()) {
        ("Primary", _) => std::cmp::Ordering::Less,
        (_, "Primary") => std::cmp::Ordering::Greater,
        ("Same Domain", "Third Party") => std::cmp::Ordering::Less,
        ("Third Party", "Same Domain") => std::cmp::Ordering::Greater,
        _ => b.request_count.cmp(&a.request_count),
    });

    ArchitectureAnalysis {
        primary_host,
        host_count: hosts.len(),
        same_domain_count,
        third_party_count,
        hosts,
    }
}

/// Analyze authentication from HAR file
fn analyze_auth(har: &Har) -> Option<AuthenticationAnalysis> {
    let auth_analysis = AuthAnalyzer::analyze(har).ok()?;

    if auth_analysis.methods.is_empty() && auth_analysis.sessions.is_empty() {
        return None;
    }

    let primary_method = auth_analysis.methods.first().map(|m| match m {
        AuthMethod::Jwt => "JWT".to_string(),
        AuthMethod::Bearer => "Bearer Token".to_string(),
        AuthMethod::OAuth => "OAuth 2.0".to_string(),
        AuthMethod::Basic => "Basic Auth".to_string(),
        AuthMethod::ApiKey(header) => format!("API Key ({})", header),
        AuthMethod::Cookie => "Cookie-based".to_string(),
        AuthMethod::Custom(header) => format!("Custom ({})", header),
    });

    let session_type = if !auth_analysis.jwt_tokens.is_empty() {
        Some("JWT Bearer tokens (stateless)".to_string())
    } else if auth_analysis.sessions.iter().any(|s| {
        matches!(
            s.session_type,
            harrier_detectors::SessionType::Cookie { .. }
        )
    }) {
        Some("Cookie-based sessions".to_string())
    } else if !auth_analysis.sessions.is_empty() {
        Some("Token-based sessions".to_string())
    } else {
        None
    };

    let methods: Vec<String> = auth_analysis
        .methods
        .iter()
        .map(|m| m.as_str().to_string())
        .collect();

    Some(AuthenticationAnalysis {
        primary_method,
        session_type,
        methods,
        flow_count: auth_analysis.flows.len(),
        jwt_count: auth_analysis.jwt_tokens.len(),
    })
}

/// Enhanced auth analysis returning both Authentication and Authorization sections
fn analyze_auth_enhanced(
    har: &Har,
) -> (Option<AuthenticationSection>, Option<AuthorizationSection>) {
    let auth_analysis = match AuthAnalyzer::analyze(har) {
        Ok(a) => a,
        Err(_) => return (None, None),
    };

    // Scan all entries for auth providers
    let mut provider: Option<AuthProvider> = None;
    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url)
            && let Some(host) = url.host_str()
            && let Some(p) = detect_auth_provider(host)
        {
            provider = Some(p);
            break;
        }
    }

    // Also check JWT issuer for provider hints
    if provider.is_none() {
        for jwt in &auth_analysis.jwt_tokens {
            if let Some(ref iss) = jwt.claims.iss
                && let Some(p) = detect_auth_provider(iss)
            {
                provider = Some(p);
                break;
            }
        }
    }

    // Check JWT claims for provider field (e.g., "provider": "google")
    if provider.is_none() {
        for jwt in &auth_analysis.jwt_tokens {
            if let Some(provider_value) = jwt.claims.other.get("provider")
                && let Some(provider_name) = provider_value.as_str()
            {
                let name = match provider_name.to_lowercase().as_str() {
                    "google" => "Google",
                    "github" => "GitHub",
                    "microsoft" | "azure" | "aad" => "Microsoft Entra",
                    "okta" => "Okta",
                    "auth0" => "Auth0",
                    _ => provider_name,
                };
                provider = Some(AuthProvider {
                    name: name.to_string(),
                    host: format!("(via {})", jwt.claims.iss.as_deref().unwrap_or("token")),
                    is_third_party: true,
                });
                break;
            }
        }
    }

    // Scan HAR for OAuth flow evidence (custom implementations)
    let mut oauth_flow_detected = false;
    let mut oauth_provider_url: Option<String> = None;
    let mut token_endpoint: Option<String> = None;
    let mut login_endpoint: Option<String> = None;

    for entry in &har.log.entries {
        let url_lower = entry.request.url.to_lowercase();

        // Look for OAuth authorization URLs
        if url_lower.contains("/oauth2/authorization/")
            || url_lower.contains("/oauth/authorize")
            || url_lower.contains("/authorize?")
        {
            oauth_flow_detected = true;
            // Extract provider from URL like /oauth2/authorization/google
            if let Some(idx) = url_lower.find("/oauth2/authorization/") {
                // Safe slice: use .get() to avoid panic on bounds/UTF-8 issues
                if let Some(after) = entry.request.url.get(idx + 22..) {
                    if let Some(end) = after.find(['?', '/', '#']) {
                        if let Some(provider) = after.get(..end) {
                            oauth_provider_url = Some(provider.to_string());
                        }
                    } else {
                        oauth_provider_url = Some(after.to_string());
                    }
                }
            }
        }

        // Look for token endpoints with state parameter (OAuth callback)
        if (url_lower.contains("/token") && url_lower.contains("state="))
            || url_lower.contains("/callback")
        {
            oauth_flow_detected = true;
            if let Ok(url) = Url::parse(&entry.request.url) {
                token_endpoint = Some(format!(
                    "{}://{}{}",
                    url.scheme(),
                    url.host_str().unwrap_or(""),
                    url.path()
                ));
            }
        }

        // Look for login pages
        if url_lower.contains("/login")
            && entry.response.status == 200
            && let Ok(url) = Url::parse(&entry.request.url)
        {
            login_endpoint = Some(format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or(""),
                url.path()
            ));
        }
    }

    // If we detected OAuth but don't have a provider yet, use the URL-based provider
    if provider.is_none()
        && let Some(ref provider_name) = oauth_provider_url
    {
        let name = match provider_name.to_lowercase().as_str() {
            "google" => "Google",
            "github" => "GitHub",
            "microsoft" | "azure" | "azuread" => "Microsoft Entra",
            "okta" => "Okta",
            "auth0" => "Auth0",
            _ => provider_name.as_str(),
        };
        provider = Some(AuthProvider {
            name: name.to_string(),
            host: "(OAuth 2.0)".to_string(),
            is_third_party: true,
        });
    }

    // Determine primary auth method
    let method = if !auth_analysis.flows.is_empty() {
        Some(auth_analysis.flows[0].flow_type.as_str().to_string())
    } else if oauth_flow_detected {
        // We detected OAuth flow from URL patterns
        let provider_part = provider
            .as_ref()
            .map(|p| format!(" via {}", p.name))
            .unwrap_or_default();
        Some(format!("OAuth 2.0{}", provider_part))
    } else if !auth_analysis.methods.is_empty() {
        Some(
            auth_analysis
                .methods
                .first()
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
        )
    } else {
        None
    };

    // Build custom flow steps if we detected OAuth from URL patterns
    let custom_flow_steps = if oauth_flow_detected && auth_analysis.flows.is_empty() {
        let mut steps = Vec::new();
        if let Some(ref login) = login_endpoint {
            steps.push(FlowStepSummary {
                method: "GET".to_string(),
                path: login.clone(),
                description: Some("Login page".to_string()),
            });
        }
        if oauth_provider_url.is_some() {
            steps.push(FlowStepSummary {
                method: "GET".to_string(),
                path: format!(
                    "/oauth2/authorization/{}",
                    oauth_provider_url.as_deref().unwrap_or("provider")
                ),
                description: Some("OAuth authorization redirect".to_string()),
            });
        }
        if let Some(ref token) = token_endpoint {
            steps.push(FlowStepSummary {
                method: "GET".to_string(),
                path: token.clone(),
                description: Some("Token exchange (with state)".to_string()),
            });
        }
        if !steps.is_empty() {
            vec![AuthFlowSummary {
                flow_type: "OAuth 2.0 (custom implementation)".to_string(),
                steps,
                duration_ms: 0.0,
            }]
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Convert flows to summaries
    let mut flow_steps: Vec<AuthFlowSummary> = auth_analysis
        .flows
        .iter()
        .map(|flow| {
            let steps: Vec<FlowStepSummary> = flow
                .steps
                .iter()
                .map(|step| {
                    // Extract path from URL
                    let path = Url::parse(&step.url)
                        .ok()
                        .map(|u| u.path().to_string())
                        .unwrap_or_else(|| step.url.clone());
                    FlowStepSummary {
                        method: step.method.clone(),
                        path,
                        description: Some(step.description.clone()),
                    }
                })
                .collect();
            AuthFlowSummary {
                flow_type: flow.flow_type.as_str().to_string(),
                steps,
                duration_ms: flow.duration_ms,
            }
        })
        .collect();

    // Add custom-detected flow steps if no flows were detected by the analyzer
    if flow_steps.is_empty() {
        flow_steps.extend(custom_flow_steps);
    }

    // Convert events to summaries
    let events: Vec<AuthEventSummary> = auth_analysis
        .events
        .iter()
        .map(|event| {
            // Extract time from timestamp
            let time = event
                .timestamp
                .split('T')
                .nth(1)
                .and_then(|t| t.split('.').next())
                .unwrap_or(&event.timestamp)
                .to_string();
            AuthEventSummary {
                event_type: event.event_type.as_str().to_string(),
                status: event.status,
                time,
            }
        })
        .collect();

    // Build Authentication section
    let auth_section = if method.is_some() || provider.is_some() || !flow_steps.is_empty() {
        Some(AuthenticationSection {
            provider,
            method,
            flow_steps,
            events,
        })
    } else {
        None
    };

    // Build Authorization section
    let session_type = if !auth_analysis.jwt_tokens.is_empty() {
        "Bearer Token (stateless JWT)".to_string()
    } else if auth_analysis.sessions.iter().any(|s| {
        matches!(
            s.session_type,
            harrier_detectors::SessionType::Cookie { .. }
        )
    }) {
        "Cookie-based session".to_string()
    } else if !auth_analysis.sessions.is_empty() {
        "Token-based session".to_string()
    } else {
        "Unknown".to_string()
    };

    // Build auth headers from JWT tokens
    let mut auth_headers: Vec<AuthHeaderInfo> = Vec::new();
    for jwt in &auth_analysis.jwt_tokens {
        let mut warnings: Vec<String> = Vec::new();

        // Check for security issues related to this token
        for issue in &auth_analysis.jwt_issues {
            // Safe slice: use .get() to handle bounds and UTF-8 correctly
            let token_prefix = jwt.raw_token.get(..20).unwrap_or(&jwt.raw_token);
            if issue.token_preview.starts_with(token_prefix) {
                warnings.push(issue.message.clone());
            }
        }

        // Format expiration
        let (expires_at, expires_in) = if let Some(exp) = jwt.claims.exp {
            use chrono::{TimeZone, Utc};
            let exp_dt = Utc.timestamp_opt(exp, 0).single();
            let expires_at = exp_dt.map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string());

            let expires_in = if let (Some(iat), Some(_exp_dt)) = (jwt.claims.iat, exp_dt) {
                let lifetime_secs = exp - iat;
                if lifetime_secs < 3600 {
                    Some(format!("{} minutes", lifetime_secs / 60))
                } else if lifetime_secs < 86400 {
                    Some(format!("{} hours", lifetime_secs / 3600))
                } else {
                    Some(format!("{} days", lifetime_secs / 86400))
                }
            } else {
                None
            };

            (expires_at, expires_in)
        } else {
            (None, None)
        };

        // Build claims list
        let mut claims: Vec<(String, String)> = Vec::new();
        if let Some(ref sub) = jwt.claims.sub {
            claims.push(("sub".to_string(), sub.clone()));
        }
        // Add other claims from the 'other' HashMap
        for (key, value) in &jwt.claims.other {
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => {
                    let items: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    format!("[{}]", items.join(", "))
                }
                other => other.to_string(),
            };
            claims.push((key.clone(), value_str));
        }

        let jwt_details = JwtDetails {
            algorithm: jwt.header.alg.clone(),
            issuer: jwt.claims.iss.clone(),
            audience: jwt.claims.aud.clone(),
            expires_at,
            expires_in,
            claims,
        };

        auth_headers.push(AuthHeaderInfo {
            header_name: "Authorization".to_string(),
            header_type: "Bearer JWT".to_string(),
            jwt_details: Some(jwt_details),
            warnings,
        });
    }

    // Build session cookies with attributes
    let mut session_cookies: Vec<SessionCookieInfo> = Vec::new();
    for session in &auth_analysis.sessions {
        if let harrier_detectors::SessionType::Cookie { name } = &session.session_type {
            let mut attributes: Vec<String> = Vec::new();
            let mut warnings: Vec<String> = Vec::new();

            if let Some(ref attrs) = session.attributes {
                if attrs.http_only == Some(true) {
                    attributes.push("HttpOnly".to_string());
                } else {
                    warnings.push("Missing HttpOnly flag".to_string());
                }
                if attrs.secure == Some(true) {
                    attributes.push("Secure".to_string());
                } else {
                    warnings.push("Missing Secure flag".to_string());
                }
                if let Some(ref same_site) = attrs.same_site {
                    attributes.push(format!("SameSite={}", same_site));
                    if same_site.to_lowercase() == "none" {
                        warnings.push("SameSite=None allows cross-site requests".to_string());
                    }
                } else {
                    warnings.push("Missing SameSite attribute".to_string());
                }
            }

            session_cookies.push(SessionCookieInfo {
                name: name.clone(),
                attributes,
                warnings,
            });
        }
    }

    // Detect token refresh patterns
    let token_refresh = if !auth_analysis.advanced_security.refresh_patterns.is_empty() {
        let pattern = &auth_analysis.advanced_security.refresh_patterns[0];
        // Use frequency (refreshes per minute) to calculate interval
        let interval = if pattern.frequency > 0.0 {
            let interval_secs = 60.0 / pattern.frequency;
            if interval_secs < 60.0 {
                Some(format!("~{:.0} seconds", interval_secs))
            } else {
                Some(format!("~{:.0} minutes", interval_secs / 60.0))
            }
        } else {
            None
        };
        Some(TokenRefreshInfo {
            pattern: format!("{:?}", pattern.pattern_type),
            count: pattern.refresh_count,
            interval,
        })
    } else {
        // Check events for refresh count
        let refresh_count = auth_analysis
            .events
            .iter()
            .filter(|e| matches!(e.event_type, harrier_detectors::AuthEventType::TokenRefresh))
            .count();
        if refresh_count > 0 {
            Some(TokenRefreshInfo {
                pattern: "Observed".to_string(),
                count: refresh_count,
                interval: None,
            })
        } else {
            None
        }
    };

    // Trace credentials back to their origins
    let traced_credentials = trace_credentials(har);

    let authz_section = if !auth_headers.is_empty()
        || !session_cookies.is_empty()
        || !traced_credentials.is_empty()
    {
        Some(AuthorizationSection {
            session_type,
            auth_headers,
            session_cookies,
            token_refresh,
            traced_credentials,
        })
    } else {
        None
    };

    (auth_section, authz_section)
}

/// Format duration for display
fn format_duration(start: &str, end: &str) -> String {
    use chrono::{DateTime, Utc};

    let start_dt = DateTime::parse_from_rfc3339(start)
        .ok()
        .map(|d| d.with_timezone(&Utc));
    let end_dt = DateTime::parse_from_rfc3339(end)
        .ok()
        .map(|d| d.with_timezone(&Utc));

    match (start_dt, end_dt) {
        (Some(s), Some(e)) => {
            let duration = e.signed_duration_since(s);
            let secs = duration.num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else if secs < 3600 {
                format!("{}m {}s", secs / 60, secs % 60)
            } else {
                format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
            }
        }
        _ => "unknown".to_string(),
    }
}

/// Get time range from HAR entries
fn get_time_range(har: &Har) -> Option<TimeRange> {
    let mut timestamps: Vec<&str> = har
        .log
        .entries
        .iter()
        .map(|e| e.started_date_time.as_str())
        .collect();

    if timestamps.is_empty() {
        return None;
    }

    timestamps.sort();

    let start = timestamps.first()?.to_string();
    let end = timestamps.last()?.to_string();
    let duration_display = format_duration(&start, &end);

    Some(TimeRange {
        start,
        end,
        duration_display,
    })
}

pub fn execute(
    file: &Path,
    focus: Vec<Focus>,
    all: bool,
    host_filter: Vec<String>,
    format: OutputFormat,
) -> Result<()> {
    let har = HarReader::from_file(file)?;

    // Determine what to analyze
    let run_all = all || focus.is_empty();
    let run_map = run_all || focus.contains(&Focus::Map);
    let run_auth = run_all || focus.contains(&Focus::Auth);

    // Build analysis result
    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let time_range = get_time_range(&har);

    let architecture = if run_map {
        let mut arch = analyze_hosts(&har);

        // Apply host filter if specified
        if !host_filter.is_empty() {
            arch.hosts
                .retain(|h| host_filter.iter().any(|f| h.host.contains(f)));
        }

        Some(arch)
    } else {
        None
    };

    let authentication = if run_auth { analyze_auth(&har) } else { None };

    // Enhanced auth analysis for --focus auth
    let (auth_details, authz_details) = if run_auth {
        analyze_auth_enhanced(&har)
    } else {
        (None, None)
    };

    let result = AnalysisResult {
        file_name,
        total_entries: har.log.entries.len(),
        time_range,
        architecture,
        authentication,
        auth_details,
        authz_details,
    };

    match format {
        OutputFormat::Json => output_json(&result)?,
        OutputFormat::Table => output_table(&result)?,
        OutputFormat::Pretty => output_pretty(&result, file, &focus, all)?,
    }

    Ok(())
}

fn output_pretty(result: &AnalysisResult, file: &Path, focus: &[Focus], all: bool) -> Result<()> {
    use console::style;

    println!(
        "\n{}",
        style(format!("Harrier Analysis: {}", result.file_name))
            .bold()
            .cyan()
    );
    println!();

    // Overview (always shown)
    println!("{}", style("Overview").bold());
    println!(
        "  Entries:      {} requests",
        style(result.total_entries).yellow()
    );

    if let Some(ref tr) = result.time_range {
        let start_display = tr.start.split('T').next().unwrap_or(&tr.start);
        let end_display = tr.end.split('T').next().unwrap_or(&tr.end);
        println!(
            "  Time Range:   {} to {} ({})",
            start_display, end_display, tr.duration_display
        );
    }

    // Architecture section
    if let Some(ref arch) = result.architecture {
        println!("\n{}", style("Architecture").bold());

        println!(
            "  {} hosts ({} same domain, {} third party)",
            arch.host_count, arch.same_domain_count, arch.third_party_count
        );

        // Show host table if focused on map or showing all
        if all || focus.contains(&Focus::Map) {
            println!();

            // Calculate column widths
            let cat_width = 12;
            let host_width = arch
                .hosts
                .iter()
                .map(|h| {
                    let display = if h.port == 80 || h.port == 443 {
                        h.host.len()
                    } else {
                        h.host.len() + 1 + h.port.to_string().len()
                    };
                    display.min(35)
                })
                .max()
                .unwrap_or(20)
                .max(4);
            let type_width = 10;
            let auth_width = 12;
            let cookie_width = 20;
            let role_width = 18;

            // Print header
            println!(
                "  {:<cat_width$}  {:<host_width$}  {:<type_width$}  {:<auth_width$}  {:<cookie_width$}  {:<role_width$}  {:>5}",
                style("CATEGORY").dim(),
                style("HOST").dim(),
                style("TYPE").dim(),
                style("AUTH").dim(),
                style("COOKIES").dim(),
                style("ROLE").dim(),
                style("REQS").dim(),
            );
            println!(
                "  {:<cat_width$}  {:<host_width$}  {:<type_width$}  {:<auth_width$}  {:<cookie_width$}  {:<role_width$}  {:>5}",
                style("─".repeat(cat_width)).dim(),
                style("─".repeat(host_width)).dim(),
                style("─".repeat(type_width)).dim(),
                style("─".repeat(auth_width)).dim(),
                style("─".repeat(cookie_width)).dim(),
                style("─".repeat(role_width)).dim(),
                style("─────").dim(),
            );

            // Print rows
            for host in arch.hosts.iter().take(20) {
                let host_display = if host.port == 80 || host.port == 443 {
                    host.host.clone()
                } else {
                    format!("{}:{}", host.host, host.port)
                };
                let host_display = truncate_with_ellipsis(&host_display, 35);

                let api_type = host.api_type.as_deref().unwrap_or("-");
                let api_type = truncate_with_ellipsis(api_type, type_width);

                let auth = host.auth_method.as_deref().unwrap_or("-");
                let auth = truncate_with_ellipsis(auth, auth_width);

                let cookies = if host.session_cookies.is_empty() {
                    "-".to_string()
                } else {
                    let joined = host.session_cookies.join(", ");
                    truncate_with_ellipsis(&joined, cookie_width)
                };

                let role = host.role.as_deref().unwrap_or("-");
                let role_display = truncate_with_ellipsis(role, role_width);

                // Pad category first, then apply color (ANSI codes break format width)
                let category_padded = format!("{:<cat_width$}", host.category);
                let category_styled = match host.category.as_str() {
                    "Primary" => style(category_padded).green().bold().to_string(),
                    "Same Domain" => style(category_padded).yellow().to_string(),
                    _ => style(category_padded).dim().to_string(),
                };

                println!(
                    "  {}  {:<host_width$}  {:<type_width$}  {:<auth_width$}  {:<cookie_width$}  {:<role_width$}  {:>5}",
                    category_styled,
                    host_display,
                    api_type,
                    auth,
                    cookies,
                    role_display,
                    host.request_count,
                );
            }

            if arch.hosts.len() > 20 {
                println!(
                    "\n  {} more hosts not shown",
                    style(format!("... {} ", arch.hosts.len() - 20)).dim()
                );
            }
        }
    }

    // Authentication section - show detailed output when focused on auth
    let show_auth_details = all || focus.contains(&Focus::Auth);

    if show_auth_details {
        // Enhanced hierarchical output
        if let Some(ref auth_details) = result.auth_details {
            println!("\n{}", style("Authentication").bold());

            // Provider
            if let Some(ref provider) = auth_details.provider {
                println!("  Provider:     {}", style(&provider.name).green());
                let third_party = if provider.is_third_party {
                    " (3rd party)"
                } else {
                    ""
                };
                println!(
                    "                {}{}",
                    style(&provider.host).dim(),
                    style(third_party).dim()
                );
            }

            // Method
            if let Some(ref method) = auth_details.method {
                println!("\n  Method:       {}", style(method).yellow());
            }

            // Flow steps
            if !auth_details.flow_steps.is_empty() {
                println!("\n  Flow:");
                for flow in &auth_details.flow_steps {
                    for (i, step) in flow.steps.iter().enumerate() {
                        let desc = step
                            .description
                            .as_ref()
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default();
                        println!(
                            "    {}. {:4} {}{}",
                            i + 1,
                            step.method,
                            step.path,
                            style(desc).dim()
                        );
                    }
                }
            }

            // Events
            if !auth_details.events.is_empty() {
                println!("\n  Events:");
                for event in &auth_details.events {
                    let status_style = if event.status >= 200 && event.status < 300 {
                        style(format!("({})", event.status)).green()
                    } else if event.status >= 400 {
                        style(format!("({})", event.status)).red()
                    } else {
                        style(format!("({})", event.status)).yellow()
                    };
                    println!(
                        "    - {} {} at {}",
                        event.event_type, status_style, event.time
                    );
                }
            }
        }

        // Authorization section
        if let Some(ref authz) = result.authz_details {
            println!("\n{}", style("Authorization").bold());
            println!("  Session Type: {}", style(&authz.session_type).yellow());

            // Auth headers (JWT details)
            if !authz.auth_headers.is_empty() {
                println!("\n  Authorization Headers:");
                for header in &authz.auth_headers {
                    println!(
                        "    {}: {}",
                        header.header_name,
                        style(&header.header_type).cyan()
                    );

                    if let Some(ref jwt) = header.jwt_details {
                        if let Some(ref alg) = jwt.algorithm {
                            println!("      Algorithm:  {}", alg);
                        }
                        if let Some(ref iss) = jwt.issuer {
                            println!("      Issuer:     {}", iss);
                        }
                        if let Some(ref aud) = jwt.audience {
                            println!("      Audience:   {}", aud);
                        }
                        if let Some(ref exp_in) = jwt.expires_in {
                            if let Some(ref exp_at) = jwt.expires_at {
                                println!("      Expires:    {} ({})", exp_in, exp_at);
                            } else {
                                println!("      Expires:    {}", exp_in);
                            }
                        }

                        // Claims
                        if !jwt.claims.is_empty() {
                            println!("      Claims:");
                            for (key, value) in &jwt.claims {
                                // Truncate long values safely
                                let display_value = truncate_with_ellipsis(value, 50);
                                println!("        {:12} {}", format!("{}:", key), display_value);
                            }
                        }
                    }

                    // Warnings
                    for warning in &header.warnings {
                        println!("      {} {}", style("⚠").yellow(), style(warning).yellow());
                    }
                }
            }

            // Session cookies
            if !authz.session_cookies.is_empty() {
                println!("\n  Session Cookies:");
                for cookie in &authz.session_cookies {
                    let attrs = if cookie.attributes.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", cookie.attributes.join(", "))
                    };
                    println!("    {:<20}{}", cookie.name, style(attrs).dim());

                    for warning in &cookie.warnings {
                        println!("      {} {}", style("⚠").yellow(), style(warning).yellow());
                    }
                }
            }

            // Token refresh
            if let Some(ref refresh) = authz.token_refresh {
                println!("\n  Token Refresh:");
                println!("    Pattern:    {}", refresh.pattern);
                println!("    Observed:   {} refreshes", refresh.count);
                if let Some(ref interval) = refresh.interval {
                    println!("    Interval:   {}", interval);
                }
            }

            // Traced credentials with origins
            if !authz.traced_credentials.is_empty() {
                println!("\n  Credential Sources:");
                for cred in &authz.traced_credentials {
                    let jwt_indicator = if cred.is_jwt {
                        style(" [JWT]").cyan().to_string()
                    } else {
                        String::new()
                    };
                    println!(
                        "    {} {}{}  ({} requests)",
                        style(&cred.credential_type).dim(),
                        style(&cred.name).yellow(),
                        jwt_indicator,
                        cred.usage_count
                    );
                    if let Some(ref origin) = cred.origin {
                        println!(
                            "      {} {} {} ({})  {}",
                            style("←").dim(),
                            origin.method,
                            origin.status,
                            style(&origin.set_via).dim(),
                            style(&origin.url).cyan()
                        );
                    } else {
                        println!(
                            "      {} {}",
                            style("←").dim(),
                            style("Origin not found in HAR").dim()
                        );
                    }
                }
            }
        }
    } else if let Some(ref auth) = result.authentication {
        // Simple summary output (when not focused on auth)
        println!("\n{}", style("Authentication").bold());

        if let Some(ref method) = auth.primary_method {
            println!("  Method:       {}", style(method).yellow());
        } else {
            println!("  Method:       {}", style("None detected").dim());
        }

        if let Some(ref session) = auth.session_type {
            println!("  Session:      {}", session);
        }

        if auth.flow_count > 0 {
            println!("  Flows:        {} detected", auth.flow_count);
        }

        if auth.jwt_count > 0 {
            println!("  JWT Tokens:   {} found", auth.jwt_count);
        }
    }

    // Next steps (only in summary mode)
    if focus.is_empty() && !all {
        println!("\n{}", style("Next Steps").dim());
        println!(
            "  {} for detailed architecture",
            style(format!("harrier analyze {} --focus map", file.display())).cyan()
        );
        println!(
            "  {} for auth flow details",
            style(format!("harrier analyze {} --focus auth", file.display())).cyan()
        );
        println!(
            "  {} for everything",
            style(format!("harrier analyze {} --all", file.display())).cyan()
        );
        println!(
            "  {} for HawkScan config",
            style(format!("harrier export {} --hawkscan", file.display())).cyan()
        );
    }

    println!();
    Ok(())
}

fn output_json(result: &AnalysisResult) -> Result<()> {
    let json_str = serde_json::to_string_pretty(result)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(result: &AnalysisResult) -> Result<()> {
    println!("Metric,Value");
    println!("File,{}", result.file_name);
    println!("Total Entries,{}", result.total_entries);

    if let Some(ref tr) = result.time_range {
        println!("Time Range Start,{}", tr.start);
        println!("Time Range End,{}", tr.end);
        println!("Duration,{}", tr.duration_display);
    }

    if let Some(ref arch) = result.architecture {
        println!();
        println!("Host Count,{}", arch.host_count);
        println!("Same Domain Count,{}", arch.same_domain_count);
        println!("Third Party Count,{}", arch.third_party_count);

        if let Some(ref host) = arch.primary_host {
            println!("Primary Host,{}", host);
        }

        println!();
        println!("Category,Host,Port,Type,Auth,Cookies,Role,Requests");
        for host in &arch.hosts {
            let api_type = host.api_type.as_deref().unwrap_or("");
            let auth = host.auth_method.as_deref().unwrap_or("");
            let cookies = host.session_cookies.join("; ");
            let role = host.role.as_deref().unwrap_or("");
            println!(
                "{},{},{},{},{},\"{}\",\"{}\",{}",
                host.category,
                host.host,
                host.port,
                api_type,
                auth,
                cookies,
                role,
                host.request_count
            );
        }
    }

    if let Some(ref auth) = result.authentication {
        println!();
        if let Some(ref method) = auth.primary_method {
            println!("Auth Method,{}", method);
        }
        if let Some(ref session) = auth.session_type {
            println!("Session Type,{}", session);
        }
        println!("Flow Count,{}", auth.flow_count);
        println!("JWT Count,{}", auth.jwt_count);
    }

    Ok(())
}
