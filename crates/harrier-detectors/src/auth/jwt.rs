use crate::Result;
use harrier_core::har::Har;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a parsed JWT token with its components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    pub raw_token: String,
    pub header: JwtHeader,
    pub claims: JwtClaims,
    pub signature_present: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub usage_count: usize,
    pub entry_indices: Vec<usize>,
}

/// JWT header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: Option<String>,
    pub typ: Option<String>,
    pub kid: Option<String>,
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// JWT claims (payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    // Standard claims
    pub iss: Option<String>, // Issuer
    pub sub: Option<String>, // Subject
    pub aud: Option<String>, // Audience
    pub exp: Option<i64>,    // Expiration time
    pub nbf: Option<i64>,    // Not before
    pub iat: Option<i64>,    // Issued at
    pub jti: Option<String>, // JWT ID

    // Additional claims
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// Security issues found in JWT tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSecurityIssue {
    pub severity: super::security::Severity,
    pub issue_type: JwtIssueType,
    pub message: String,
    pub token_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtIssueType {
    WeakAlgorithm,
    NoAlgorithm,
    Expired,
    MissingExpiration,
    TokenInUrl,
    LongLivedToken,
    MissingSignature,
}

pub struct JwtAnalyzer;

impl JwtAnalyzer {
    /// Analyze all JWT tokens in the HAR file
    pub fn analyze(har: &Har) -> Result<(Vec<JwtToken>, Vec<JwtSecurityIssue>)> {
        let mut tokens_map: HashMap<String, (JwtToken, Vec<usize>)> = HashMap::new();
        let mut security_issues = Vec::new();

        for (idx, entry) in har.log.entries.iter().enumerate() {
            // Check Authorization header
            for header in &entry.request.headers {
                if header.name.to_lowercase() == "authorization"
                    && let Some(token) = Self::extract_bearer_token(&header.value)
                    && Self::is_jwt(token)
                {
                    Self::process_jwt_token(
                        token,
                        idx,
                        &entry.started_date_time,
                        false,
                        &mut tokens_map,
                        &mut security_issues,
                    );
                }
            }

            // Check response body for JWT tokens
            if let Some(ref text) = entry.response.content.text
                && entry
                    .response
                    .content
                    .mime_type
                    .contains("application/json")
            {
                Self::extract_tokens_from_json(
                    text,
                    idx,
                    &entry.started_date_time,
                    &mut tokens_map,
                    &mut security_issues,
                );
            }

            // Check for JWT in URL (security issue)
            if entry.request.url.contains("Bearer%20") || entry.request.url.contains("eyJ") {
                security_issues.push(JwtSecurityIssue {
                    severity: super::security::Severity::Critical,
                    issue_type: JwtIssueType::TokenInUrl,
                    message: format!("JWT token found in URL at entry {}", idx),
                    token_preview: Self::truncate_url(&entry.request.url),
                });
            }
        }

        // Convert map to vector
        let tokens: Vec<JwtToken> = tokens_map
            .into_iter()
            .map(|(_, (mut token, indices))| {
                token.entry_indices = indices;
                token.usage_count = token.entry_indices.len();
                token
            })
            .collect();

        Ok((tokens, security_issues))
    }

    fn process_jwt_token(
        token: &str,
        entry_idx: usize,
        timestamp: &str,
        in_url: bool,
        tokens_map: &mut HashMap<String, (JwtToken, Vec<usize>)>,
        security_issues: &mut Vec<JwtSecurityIssue>,
    ) {
        // Use first 20 chars as key to group same tokens
        let token_key = if token.len() > 20 {
            token[..20].to_string()
        } else {
            token.to_string()
        };

        if let Some((existing_token, indices)) = tokens_map.get_mut(&token_key) {
            // Update existing token
            existing_token.last_seen = timestamp.to_string();
            indices.push(entry_idx);
        } else {
            // Parse new token
            if let Ok(parsed_token) = Self::parse_jwt(token, timestamp) {
                // Analyze security
                let issues = Self::analyze_token_security(&parsed_token, in_url);
                security_issues.extend(issues);

                tokens_map.insert(token_key, (parsed_token, vec![entry_idx]));
            }
        }
    }

    fn parse_jwt(token: &str, timestamp: &str) -> Result<JwtToken> {
        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() != 3 {
            return Err(crate::Error::Parse("Invalid JWT format".to_string()));
        }

        // Parse header
        let header = Self::parse_jwt_header(parts[0])?;

        // Parse claims
        let claims = Self::parse_jwt_claims(parts[1])?;

        // Check signature
        let signature_present = !parts[2].is_empty();

        Ok(JwtToken {
            raw_token: Self::truncate_token(token),
            header,
            claims,
            signature_present,
            first_seen: timestamp.to_string(),
            last_seen: timestamp.to_string(),
            usage_count: 1,
            entry_indices: vec![],
        })
    }

    fn parse_jwt_header(encoded: &str) -> Result<JwtHeader> {
        let decoded = Self::base64_decode(encoded)?;
        let json: serde_json::Value = serde_json::from_str(&decoded)
            .map_err(|e| crate::Error::Parse(format!("Failed to parse JWT header: {}", e)))?;

        let obj = json
            .as_object()
            .ok_or_else(|| crate::Error::Parse("JWT header is not an object".to_string()))?;

        Ok(JwtHeader {
            alg: obj.get("alg").and_then(|v| v.as_str()).map(String::from),
            typ: obj.get("typ").and_then(|v| v.as_str()).map(String::from),
            kid: obj.get("kid").and_then(|v| v.as_str()).map(String::from),
            other: obj
                .iter()
                .filter(|(k, _)| !["alg", "typ", "kid"].contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn parse_jwt_claims(encoded: &str) -> Result<JwtClaims> {
        let decoded = Self::base64_decode(encoded)?;
        let json: serde_json::Value = serde_json::from_str(&decoded)
            .map_err(|e| crate::Error::Parse(format!("Failed to parse JWT claims: {}", e)))?;

        let obj = json
            .as_object()
            .ok_or_else(|| crate::Error::Parse("JWT claims is not an object".to_string()))?;

        Ok(JwtClaims {
            iss: obj.get("iss").and_then(|v| v.as_str()).map(String::from),
            sub: obj.get("sub").and_then(|v| v.as_str()).map(String::from),
            aud: obj.get("aud").and_then(|v| v.as_str()).map(String::from),
            exp: obj.get("exp").and_then(|v| v.as_i64()),
            nbf: obj.get("nbf").and_then(|v| v.as_i64()),
            iat: obj.get("iat").and_then(|v| v.as_i64()),
            jti: obj.get("jti").and_then(|v| v.as_str()).map(String::from),
            other: obj
                .iter()
                .filter(|(k, _)| {
                    !["iss", "sub", "aud", "exp", "nbf", "iat", "jti"].contains(&k.as_str())
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn base64_decode(encoded: &str) -> Result<String> {
        use base64::engine::Engine;
        use base64::engine::general_purpose::STANDARD;

        // JWT uses base64url encoding (no padding)
        let padded = match encoded.len() % 4 {
            2 => format!("{}==", encoded),
            3 => format!("{}=", encoded),
            _ => encoded.to_string(),
        };

        // Replace URL-safe characters
        let standard = padded.replace('-', "+").replace('_', "/");

        let decoded_bytes = STANDARD
            .decode(&standard)
            .map_err(|e| crate::Error::Parse(format!("Base64 decode failed: {}", e)))?;

        String::from_utf8(decoded_bytes)
            .map_err(|e| crate::Error::Parse(format!("UTF-8 decode failed: {}", e)))
    }

    fn analyze_token_security(token: &JwtToken, in_url: bool) -> Vec<JwtSecurityIssue> {
        let mut issues = Vec::new();

        // Check algorithm
        if let Some(ref alg) = token.header.alg {
            let alg_lower = alg.to_lowercase();
            if alg_lower == "none" {
                issues.push(JwtSecurityIssue {
                    severity: super::security::Severity::Critical,
                    issue_type: JwtIssueType::NoAlgorithm,
                    message: "JWT using 'none' algorithm (no signature verification)".to_string(),
                    token_preview: token.raw_token.clone(),
                });
            } else if alg_lower == "hs256" || alg_lower == "hs384" || alg_lower == "hs512" {
                issues.push(JwtSecurityIssue {
                    severity: super::security::Severity::Info,
                    issue_type: JwtIssueType::WeakAlgorithm,
                    message: format!("JWT using symmetric algorithm {} (shared secret)", alg),
                    token_preview: token.raw_token.clone(),
                });
            }
        }

        // Check expiration
        if let Some(exp) = token.claims.exp
            && let Some(iat) = token.claims.iat
        {
            let lifetime = exp - iat;
            // Warn if token lifetime > 24 hours
            if lifetime > 86400 {
                issues.push(JwtSecurityIssue {
                    severity: super::security::Severity::Warning,
                    issue_type: JwtIssueType::LongLivedToken,
                    message: format!("JWT has long lifetime: {} hours", lifetime / 3600),
                    token_preview: token.raw_token.clone(),
                });
            }
        } else if token.claims.exp.is_none() {
            issues.push(JwtSecurityIssue {
                severity: super::security::Severity::Warning,
                issue_type: JwtIssueType::MissingExpiration,
                message: "JWT missing expiration claim (exp)".to_string(),
                token_preview: token.raw_token.clone(),
            });
        }

        // Check signature
        if !token.signature_present {
            issues.push(JwtSecurityIssue {
                severity: super::security::Severity::Critical,
                issue_type: JwtIssueType::MissingSignature,
                message: "JWT missing signature component".to_string(),
                token_preview: token.raw_token.clone(),
            });
        }

        // Token in URL is already handled in main analyze function
        if in_url {
            issues.push(JwtSecurityIssue {
                severity: super::security::Severity::Critical,
                issue_type: JwtIssueType::TokenInUrl,
                message: "JWT token transmitted in URL (visible in logs)".to_string(),
                token_preview: token.raw_token.clone(),
            });
        }

        issues
    }

    fn extract_tokens_from_json(
        json_text: &str,
        entry_idx: usize,
        timestamp: &str,
        tokens_map: &mut HashMap<String, (JwtToken, Vec<usize>)>,
        security_issues: &mut Vec<JwtSecurityIssue>,
    ) {
        // Simple extraction - look for common JWT fields
        let fields = [
            "token",
            "access_token",
            "accessToken",
            "id_token",
            "idToken",
        ];

        for field in &fields {
            if let Some(start) = json_text.find(&format!("\"{}\"", field))
                && let Some(colon) = json_text[start..].find(':')
            {
                let after_colon = &json_text[start + colon + 1..];
                if let Some(quote_start) = after_colon.find('"')
                    && let Some(quote_end) = after_colon[quote_start + 1..].find('"')
                {
                    let token = &after_colon[quote_start + 1..quote_start + 1 + quote_end];
                    if Self::is_jwt(token) {
                        Self::process_jwt_token(
                            token,
                            entry_idx,
                            timestamp,
                            false,
                            tokens_map,
                            security_issues,
                        );
                    }
                }
            }
        }
    }

    fn extract_bearer_token(header_value: &str) -> Option<&str> {
        header_value.strip_prefix("Bearer ").map(|s| s.trim())
    }

    fn is_jwt(token: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| !p.is_empty() || parts[2].is_empty())
    }

    fn truncate_token(token: &str) -> String {
        if token.len() > 50 {
            format!("{}...{}", &token[..25], &token[token.len() - 25..])
        } else {
            token.to_string()
        }
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
    fn test_is_jwt() {
        assert!(JwtAnalyzer::is_jwt("eyJhbGc.eyJzdWI.signature"));
        assert!(!JwtAnalyzer::is_jwt("not.a.jwt.token"));
        assert!(!JwtAnalyzer::is_jwt("only.two"));
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            JwtAnalyzer::extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
        assert_eq!(JwtAnalyzer::extract_bearer_token("Basic abc123"), None);
    }

    #[test]
    fn test_base64_decode() {
        // Standard JWT header: {"alg":"HS256","typ":"JWT"}
        let encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let decoded = JwtAnalyzer::base64_decode(encoded).unwrap();
        assert!(decoded.contains("HS256"));
        assert!(decoded.contains("JWT"));
    }

    #[test]
    fn test_parse_jwt_header() {
        let encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = JwtAnalyzer::parse_jwt_header(encoded).unwrap();
        assert_eq!(header.alg, Some("HS256".to_string()));
        assert_eq!(header.typ, Some("JWT".to_string()));
    }
}
