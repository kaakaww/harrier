use crate::Result;
use harrier_core::har::{Entry, Har, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppType {
    Rest,
    RestJson,
    RestXml,
    GraphQL,
    Soap,
    Grpc,
    JsonRpc,
    XmlRpc,
    WebSocket,
    SocketIO,
    SockJS,
    ServerSentEvents,
    Mcp,
    Spa,
    Mixed(Vec<AppType>),
    Unknown,
}

impl AppType {
    pub fn as_str(&self) -> &str {
        match self {
            AppType::Rest => "REST",
            AppType::RestJson => "REST/JSON",
            AppType::RestXml => "REST/XML",
            AppType::GraphQL => "GraphQL",
            AppType::Soap => "SOAP",
            AppType::Grpc => "gRPC",
            AppType::JsonRpc => "JSON-RPC",
            AppType::XmlRpc => "XML-RPC",
            AppType::WebSocket => "WebSocket",
            AppType::SocketIO => "Socket.IO",
            AppType::SockJS => "SockJS",
            AppType::ServerSentEvents => "Server-Sent Events",
            AppType::Mcp => "MCP",
            AppType::Spa => "SPA",
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

            // Check for Socket.IO
            if Self::is_socketio(entry) {
                *type_scores.entry("socketio".to_string()).or_insert(0) += 1;
            }

            // Check for SockJS
            if Self::is_sockjs(entry) {
                *type_scores.entry("sockjs".to_string()).or_insert(0) += 1;
            }

            // Check for Server-Sent Events
            if Self::is_server_sent_events(entry) {
                *type_scores.entry("sse".to_string()).or_insert(0) += 1;
            }

            // Check for MCP
            if Self::is_mcp(entry) {
                *type_scores.entry("mcp".to_string()).or_insert(0) += 1;
            }

            // Check for JSON-RPC
            if Self::is_jsonrpc(entry) {
                *type_scores.entry("jsonrpc".to_string()).or_insert(0) += 1;
            }

            // Check for XML-RPC
            if Self::is_xmlrpc(entry) {
                *type_scores.entry("xmlrpc".to_string()).or_insert(0) += 1;
            }

            // Check for REST with subtypes (prioritize specific over generic)
            if Self::is_rest_json(entry) {
                *type_scores.entry("restjson".to_string()).or_insert(0) += 1;
            } else if Self::is_rest_xml(entry) {
                *type_scores.entry("restxml".to_string()).or_insert(0) += 1;
            } else if Self::is_rest(entry) {
                *type_scores.entry("rest".to_string()).or_insert(0) += 1;
            }
        }

        // Check for SPA characteristics
        let entry_refs: Vec<&Entry> = entries.iter().collect();
        if Self::is_spa(&entry_refs) {
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
                "socketio" => AppType::SocketIO,
                "sockjs" => AppType::SockJS,
                "sse" => AppType::ServerSentEvents,
                "mcp" => AppType::Mcp,
                "jsonrpc" => AppType::JsonRpc,
                "xmlrpc" => AppType::XmlRpc,
                "restjson" => AppType::RestJson,
                "restxml" => AppType::RestXml,
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
                        "socketio" => AppType::SocketIO,
                        "sockjs" => AppType::SockJS,
                        "sse" => AppType::ServerSentEvents,
                        "mcp" => AppType::Mcp,
                        "jsonrpc" => AppType::JsonRpc,
                        "xmlrpc" => AppType::XmlRpc,
                        "restjson" => AppType::RestJson,
                        "restxml" => AppType::RestXml,
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

    /// Detect API types for a specific host with confidence scores
    /// Returns a vector of (AppType, confidence, request_count) tuples
    pub fn detect_for_host(entries: &[&Entry]) -> Vec<(AppType, f64, usize)> {
        if entries.is_empty() {
            return vec![];
        }

        let mut type_scores: HashMap<AppType, usize> = HashMap::new();
        let total_entries = entries.len();

        for &entry in entries {
            // Check for specific API types (order matters - most specific first)
            let mut detected = false;

            // GraphQL
            if Self::is_graphql(entry) {
                *type_scores.entry(AppType::GraphQL).or_insert(0) += 1;
                detected = true;
            }

            // SOAP
            if Self::is_soap(entry) {
                *type_scores.entry(AppType::Soap).or_insert(0) += 1;
                detected = true;
            }

            // gRPC
            if Self::is_grpc(entry) {
                *type_scores.entry(AppType::Grpc).or_insert(0) += 1;
                detected = true;
            }

            // WebSocket variants
            if Self::is_socketio(entry) {
                *type_scores.entry(AppType::SocketIO).or_insert(0) += 1;
                detected = true;
            } else if Self::is_sockjs(entry) {
                *type_scores.entry(AppType::SockJS).or_insert(0) += 1;
                detected = true;
            } else if Self::is_websocket(entry) {
                *type_scores.entry(AppType::WebSocket).or_insert(0) += 1;
                detected = true;
            }

            // Server-Sent Events
            if Self::is_server_sent_events(entry) {
                *type_scores.entry(AppType::ServerSentEvents).or_insert(0) += 1;
                detected = true;
            }

            // RPC variants
            if Self::is_jsonrpc(entry) {
                *type_scores.entry(AppType::JsonRpc).or_insert(0) += 1;
                detected = true;
            } else if Self::is_xmlrpc(entry) {
                *type_scores.entry(AppType::XmlRpc).or_insert(0) += 1;
                detected = true;
            }

            // MCP (Model Context Protocol)
            if Self::is_mcp(entry) {
                *type_scores.entry(AppType::Mcp).or_insert(0) += 1;
                detected = true;
            }

            // REST subtypes (only if not already detected as RPC/SOAP)
            if !detected {
                if Self::is_rest_json(entry) {
                    *type_scores.entry(AppType::RestJson).or_insert(0) += 1;
                } else if Self::is_rest_xml(entry) {
                    *type_scores.entry(AppType::RestXml).or_insert(0) += 1;
                } else if Self::is_rest(entry) {
                    *type_scores.entry(AppType::Rest).or_insert(0) += 1;
                }
            }
        }

        // Check for SPA characteristics (applies to entire host)
        if Self::is_spa(entries) {
            *type_scores.entry(AppType::Spa).or_insert(0) += total_entries / 3;
        }

        // Convert scores to confidence values and sort by count (descending)
        let mut results: Vec<(AppType, f64, usize)> = type_scores
            .into_iter()
            .map(|(api_type, count)| {
                let confidence = count as f64 / total_entries as f64;
                (api_type, confidence, count)
            })
            .collect();

        // Sort by count (descending)
        results.sort_by(|a, b| b.2.cmp(&a.2));

        results
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

    fn is_jsonrpc(entry: &Entry) -> bool {
        // Check for JSON-RPC content type
        if let Some(content_type) = Self::get_content_type(&entry.request.headers)
            && content_type.contains("application/json-rpc")
        {
            return true;
        }

        // Check request body for JSON-RPC 2.0 structure
        if let Some(ref post_data) = entry.request.post_data
            && let Some(ref text) = post_data.text
        {
            // Look for JSON-RPC 2.0 signature
            return text.contains("\"jsonrpc\":\"2.0\"")
                || text.contains("\"jsonrpc\": \"2.0\"")
                || text.contains("'jsonrpc':'2.0'");
        }

        // Check response body for JSON-RPC structure
        if let Some(ref text) = entry.response.content.text {
            return text.contains("\"jsonrpc\":\"2.0\"") || text.contains("\"jsonrpc\": \"2.0\"");
        }

        false
    }

    fn is_xmlrpc(entry: &Entry) -> bool {
        // Check for XML-RPC content type
        if let Some(content_type) = Self::get_content_type(&entry.request.headers)
            && (content_type.contains("text/xml") || content_type.contains("application/xml"))
        {
            // Check request body for methodCall
            if let Some(ref post_data) = entry.request.post_data
                && let Some(ref text) = post_data.text
            {
                return text.contains("<methodCall>") || text.contains("<methodResponse>");
            }
        }

        // Check response content type and body
        if let Some(content_type) = Self::get_content_type(&entry.response.headers)
            && (content_type.contains("text/xml") || content_type.contains("application/xml"))
            && let Some(ref text) = entry.response.content.text
        {
            return text.contains("<methodResponse>") || text.contains("<methodCall>");
        }

        false
    }

    fn is_server_sent_events(entry: &Entry) -> bool {
        // Check for text/event-stream content type
        if let Some(content_type) = Self::get_content_type(&entry.response.headers) {
            return content_type.contains("text/event-stream");
        }
        false
    }

    fn is_socketio(entry: &Entry) -> bool {
        // Check URL for Socket.IO patterns
        if entry.request.url.contains("/socket.io/") || entry.request.url.contains("socket.io") {
            return true;
        }

        // Check for Socket.IO transport query parameters
        if entry.request.url.contains("transport=polling")
            || entry.request.url.contains("transport=websocket")
            || entry.request.url.contains("EIO=")
        // Engine.IO version
        {
            return true;
        }

        false
    }

    fn is_sockjs(entry: &Entry) -> bool {
        // Check URL for SockJS patterns
        if entry.request.url.contains("/sockjs/") || entry.request.url.contains("/sockjs-node/") {
            return true;
        }

        // Check for SockJS endpoints (server/session/transport pattern)
        if entry.request.url.contains("/info?") && entry.request.url.matches('/').count() >= 3 {
            return true;
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

    fn is_rest_json(entry: &Entry) -> bool {
        let method = entry.request.method.as_str();
        let restful_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

        if !restful_methods.contains(&method) {
            return false;
        }

        // Check response content type for JSON
        if let Some(content_type) = Self::get_content_type(&entry.response.headers)
            && content_type.contains("application/json")
        {
            return true;
        }

        // Check request content type for JSON (for POST/PUT/PATCH)
        if ["POST", "PUT", "PATCH"].contains(&method)
            && let Some(ref post_data) = entry.request.post_data
            && post_data
                .mime_type
                .to_lowercase()
                .contains("application/json")
        {
            return true;
        }

        false
    }

    fn is_rest_xml(entry: &Entry) -> bool {
        let method = entry.request.method.as_str();
        let restful_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

        if !restful_methods.contains(&method) {
            return false;
        }

        // Check response content type for XML (but not SOAP)
        if let Some(content_type) = Self::get_content_type(&entry.response.headers)
            && (content_type.contains("application/xml") || content_type.contains("text/xml"))
            && !content_type.contains("soap")
        {
            return true;
        }

        // Check request content type for XML (for POST/PUT/PATCH)
        if ["POST", "PUT", "PATCH"].contains(&method)
            && let Some(ref post_data) = entry.request.post_data
        {
            let mime = post_data.mime_type.to_lowercase();
            if (mime.contains("application/xml") || mime.contains("text/xml"))
                && !mime.contains("soap")
            {
                return true;
            }
        }

        false
    }

    fn is_spa(entries: &[&Entry]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use harrier_core::har::{Cache, Content, PostData, Request, Response, Timings};

    fn create_test_entry(
        url: &str,
        method: &str,
        request_content_type: Option<&str>,
        request_body: Option<&str>,
        response_content_type: Option<&str>,
        response_body: Option<&str>,
    ) -> Entry {
        let mut request_headers = vec![];
        if let Some(ct) = request_content_type {
            request_headers.push(Header {
                name: "Content-Type".to_string(),
                value: ct.to_string(),
                comment: None,
            });
        }

        let mut response_headers = vec![];
        if let Some(ct) = response_content_type {
            response_headers.push(Header {
                name: "Content-Type".to_string(),
                value: ct.to_string(),
                comment: None,
            });
        }

        Entry {
            page_ref: None,
            started_date_time: "2024-01-01T00:00:00Z".to_string(),
            time: 100.0,
            request: Request {
                method: method.to_string(),
                url: url.to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: request_headers,
                query_string: vec![],
                cookies: vec![],
                headers_size: 0,
                body_size: 0,
                post_data: request_body.map(|body| PostData {
                    mime_type: request_content_type.unwrap_or("").to_string(),
                    params: None,
                    text: Some(body.to_string()),
                    comment: None,
                }),
                comment: None,
            },
            response: Response {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: response_headers,
                cookies: vec![],
                content: Content {
                    size: 100,
                    mime_type: response_content_type.unwrap_or("").to_string(),
                    text: response_body.map(|s| s.to_string()),
                    encoding: None,
                    compression: None,
                    comment: None,
                },
                redirect_url: String::new(),
                headers_size: 0,
                body_size: 100,
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

    #[test]
    fn test_detect_rest_json() {
        let entry = create_test_entry(
            "https://api.example.com/users",
            "GET",
            None,
            None,
            Some("application/json"),
            Some(r#"{"users": []}"#),
        );

        assert!(AppTypeDetector::is_rest_json(&entry));
        assert!(!AppTypeDetector::is_rest_xml(&entry));
    }

    #[test]
    fn test_detect_rest_xml() {
        let entry = create_test_entry(
            "https://api.example.com/users",
            "GET",
            None,
            None,
            Some("application/xml"),
            Some("<users></users>"),
        );

        assert!(AppTypeDetector::is_rest_xml(&entry));
        assert!(!AppTypeDetector::is_rest_json(&entry));
    }

    #[test]
    fn test_detect_json_rpc() {
        let entry = create_test_entry(
            "https://api.example.com/rpc",
            "POST",
            Some("application/json"),
            Some(r#"{"jsonrpc":"2.0","method":"test","id":1}"#),
            Some("application/json"),
            Some(r#"{"jsonrpc":"2.0","result":"ok","id":1}"#),
        );

        assert!(AppTypeDetector::is_jsonrpc(&entry));
        assert!(!AppTypeDetector::is_xmlrpc(&entry));
    }

    #[test]
    fn test_detect_xml_rpc() {
        let entry = create_test_entry(
            "https://api.example.com/rpc",
            "POST",
            Some("text/xml"),
            Some("<methodCall><methodName>test</methodName></methodCall>"),
            Some("text/xml"),
            Some("<methodResponse><params></params></methodResponse>"),
        );

        assert!(AppTypeDetector::is_xmlrpc(&entry));
        assert!(!AppTypeDetector::is_jsonrpc(&entry));
    }

    #[test]
    fn test_detect_server_sent_events() {
        let entry = create_test_entry(
            "https://api.example.com/events",
            "GET",
            None,
            None,
            Some("text/event-stream"),
            Some("data: test\n\n"),
        );

        assert!(AppTypeDetector::is_server_sent_events(&entry));
    }

    #[test]
    fn test_detect_socketio() {
        let entry = create_test_entry(
            "https://api.example.com/socket.io/?transport=polling&EIO=4",
            "GET",
            None,
            None,
            Some("application/json"),
            None,
        );

        assert!(AppTypeDetector::is_socketio(&entry));
        assert!(!AppTypeDetector::is_sockjs(&entry));
    }

    #[test]
    fn test_detect_sockjs() {
        let entry = create_test_entry(
            "https://api.example.com/sockjs/123/abc/xhr",
            "POST",
            None,
            None,
            Some("application/json"),
            None,
        );

        assert!(AppTypeDetector::is_sockjs(&entry));
        assert!(!AppTypeDetector::is_socketio(&entry));
    }

    #[test]
    fn test_detect_for_host_multiple_types() {
        let entries = [
            create_test_entry(
                "https://api.example.com/users",
                "GET",
                None,
                None,
                Some("application/json"),
                Some(r#"{"users": []}"#),
            ),
            create_test_entry(
                "https://api.example.com/posts",
                "GET",
                None,
                None,
                Some("application/json"),
                Some(r#"{"posts": []}"#),
            ),
            create_test_entry(
                "https://api.example.com/graphql",
                "POST",
                Some("application/json"),
                Some(r#"{"query":"{ users { id } }"}"#),
                Some("application/json"),
                Some(r#"{"data":{"users":[]}}"#),
            ),
        ];

        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let results = AppTypeDetector::detect_for_host(&entry_refs);

        // Should detect both REST/JSON and GraphQL
        assert!(!results.is_empty());
        let detected_types: Vec<AppType> = results.iter().map(|(t, _, _)| t.clone()).collect();
        assert!(
            detected_types.contains(&AppType::RestJson)
                || detected_types.contains(&AppType::GraphQL)
        );
    }

    #[test]
    fn test_detect_for_host_confidence_scoring() {
        let entries = [
            create_test_entry(
                "https://api.example.com/users",
                "GET",
                None,
                None,
                Some("application/json"),
                Some(r#"{"users": []}"#),
            ),
            create_test_entry(
                "https://api.example.com/posts",
                "GET",
                None,
                None,
                Some("application/json"),
                Some(r#"{"posts": []}"#),
            ),
        ];

        let entry_refs: Vec<&Entry> = entries.iter().collect();
        let results = AppTypeDetector::detect_for_host(&entry_refs);

        // Should have confidence scores
        assert!(!results.is_empty());
        for (_, confidence, count) in results {
            assert!(confidence > 0.0 && confidence <= 1.0);
            assert!(count > 0);
        }
    }
}
