use crate::Result;
use harrier_core::har::{Entry, Har, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppType {
    Rest,
    GraphQL,
    Soap,
    Grpc,
    WebSocket,
    Mcp,
    Spa,
    Mixed(Vec<AppType>),
    Unknown,
}

impl AppType {
    pub fn as_str(&self) -> &str {
        match self {
            AppType::Rest => "REST API",
            AppType::GraphQL => "GraphQL",
            AppType::Soap => "SOAP",
            AppType::Grpc => "gRPC",
            AppType::WebSocket => "WebSocket",
            AppType::Mcp => "MCP (Model Context Protocol)",
            AppType::Spa => "Single Page Application",
            AppType::Mixed(_) => "Mixed",
            AppType::Unknown => "Unknown",
        }
    }
}

pub struct AppTypeDetector;

impl AppTypeDetector {
    pub fn detect(har: &Har) -> Result<AppType> {
        tracing::debug!("Detecting application type from HAR entries");

        let entries = &har.log.entries;
        if entries.is_empty() {
            return Ok(AppType::Unknown);
        }

        let mut type_scores: HashMap<String, usize> = HashMap::new();

        for entry in entries {
            // Check for GraphQL
            if Self::is_graphql(entry) {
                *type_scores.entry("graphql".to_string()).or_insert(0) += 1;
            }

            // Check for SOAP
            if Self::is_soap(entry) {
                *type_scores.entry("soap".to_string()).or_insert(0) += 1;
            }

            // Check for gRPC
            if Self::is_grpc(entry) {
                *type_scores.entry("grpc".to_string()).or_insert(0) += 1;
            }

            // Check for WebSocket
            if Self::is_websocket(entry) {
                *type_scores.entry("websocket".to_string()).or_insert(0) += 1;
            }

            // Check for MCP
            if Self::is_mcp(entry) {
                *type_scores.entry("mcp".to_string()).or_insert(0) += 1;
            }

            // Check for REST
            if Self::is_rest(entry) {
                *type_scores.entry("rest".to_string()).or_insert(0) += 1;
            }
        }

        // Check for SPA characteristics
        if Self::is_spa(entries) {
            *type_scores.entry("spa".to_string()).or_insert(0) += entries.len() / 2;
        }

        // Determine the dominant type(s)
        if type_scores.is_empty() {
            return Ok(AppType::Unknown);
        }

        let max_score = *type_scores.values().max().unwrap();
        let dominant_types: Vec<_> = type_scores
            .iter()
            .filter(|(_, score)| **score >= max_score / 2)
            .map(|(k, _)| k.as_str())
            .collect();

        let app_type = match dominant_types.len() {
            0 => AppType::Unknown,
            1 => match dominant_types[0] {
                "graphql" => AppType::GraphQL,
                "soap" => AppType::Soap,
                "grpc" => AppType::Grpc,
                "websocket" => AppType::WebSocket,
                "mcp" => AppType::Mcp,
                "rest" => AppType::Rest,
                "spa" => AppType::Spa,
                _ => AppType::Unknown,
            },
            _ => {
                let types: Vec<AppType> = dominant_types
                    .iter()
                    .map(|t| match *t {
                        "graphql" => AppType::GraphQL,
                        "soap" => AppType::Soap,
                        "grpc" => AppType::Grpc,
                        "websocket" => AppType::WebSocket,
                        "mcp" => AppType::Mcp,
                        "rest" => AppType::Rest,
                        "spa" => AppType::Spa,
                        _ => AppType::Unknown,
                    })
                    .collect();
                AppType::Mixed(types)
            }
        };

        tracing::info!("Detected application type: {}", app_type.as_str());
        Ok(app_type)
    }

    fn is_graphql(entry: &Entry) -> bool {
        // Check URL
        if entry.request.url.contains("/graphql") || entry.request.url.contains("/graph") {
            return true;
        }

        // Check content type
        if let Some(content_type) = Self::get_content_type(&entry.request.headers)
            && content_type.contains("application/json")
            && entry.request.method == "POST"
        {
            // TODO: Check body for query/mutation/subscription
            return true;
        }

        false
    }

    fn is_soap(entry: &Entry) -> bool {
        if let Some(content_type) = Self::get_content_type(&entry.request.headers) {
            return content_type.contains("text/xml")
                || content_type.contains("application/soap+xml");
        }
        false
    }

    fn is_grpc(entry: &Entry) -> bool {
        if let Some(content_type) = Self::get_content_type(&entry.request.headers) {
            return content_type.contains("application/grpc");
        }

        // Check for HTTP/2
        entry.request.http_version.contains("HTTP/2")
    }

    fn is_websocket(entry: &Entry) -> bool {
        // Check for upgrade headers
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "upgrade"
                && header.value.to_lowercase().contains("websocket")
            {
                return true;
            }
        }

        // Check for 101 status (Switching Protocols)
        entry.response.status == 101
    }

    fn is_mcp(entry: &Entry) -> bool {
        // Check for JSON-RPC 2.0 structure in content
        if let Some(content_type) = Self::get_content_type(&entry.request.headers)
            && content_type.contains("application/json")
        {
            // TODO: Check body for JSON-RPC structure and MCP methods
            return false;
        }

        false
    }

    fn is_rest(entry: &Entry) -> bool {
        let method = entry.request.method.as_str();
        let restful_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

        if !restful_methods.contains(&method) {
            return false;
        }

        // Check for JSON or XML content type
        if let Some(content_type) = Self::get_content_type(&entry.response.headers) {
            return content_type.contains("application/json")
                || content_type.contains("application/xml");
        }

        // Check for RESTful status codes
        let status = entry.response.status;
        matches!(status, 200..=299 | 400..=499)
    }

    fn is_spa(entries: &[Entry]) -> bool {
        // SPA characteristics:
        // - Single HTML page load
        // - Multiple API calls
        // - JS bundle loading

        let html_count = entries
            .iter()
            .filter(|e| {
                Self::get_content_type(&e.response.headers)
                    .map(|ct| ct.contains("text/html"))
                    .unwrap_or(false)
            })
            .count();

        let api_count = entries
            .iter()
            .filter(|e| {
                Self::get_content_type(&e.response.headers)
                    .map(|ct| ct.contains("application/json"))
                    .unwrap_or(false)
            })
            .count();

        let js_count = entries
            .iter()
            .filter(|e| {
                Self::get_content_type(&e.response.headers)
                    .map(|ct| ct.contains("javascript"))
                    .unwrap_or(false)
            })
            .count();

        // Simple heuristic: 1 HTML, multiple API calls, some JS
        html_count <= 2 && api_count > 5 && js_count > 0
    }

    fn get_content_type(headers: &[Header]) -> Option<String> {
        headers
            .iter()
            .find(|h| h.name.to_lowercase() == "content-type")
            .map(|h| h.value.to_lowercase())
    }
}
