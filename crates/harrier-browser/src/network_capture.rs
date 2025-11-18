use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use harrier_core::har::{
    Cache, Content, Creator, Entry, Har, Header, Log, PostData, Request, Response, Timings,
};

/// Represents a captured network request with optional response
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub request_id: String,
    pub started_at: SystemTime,
    pub method: String,
    pub url: String,
    pub request_headers: HashMap<String, String>,
    pub post_data: Option<String>,
    pub response: Option<NetworkResponse>,
    pub completed: bool,
    pub encoded_data_length: i64,
}

impl NetworkRequest {
    /// Create a new network request
    pub fn new(request_id: String, method: String, url: String) -> Self {
        Self {
            request_id,
            started_at: SystemTime::now(),
            method,
            url,
            request_headers: HashMap::new(),
            post_data: None,
            response: None,
            completed: false,
            encoded_data_length: 0,
        }
    }

    /// Calculate duration from start to now
    pub fn duration(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.started_at)
            .unwrap_or_default()
    }
}

/// Represents a network response
#[derive(Debug, Clone)]
pub struct NetworkResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_base64_encoded: bool,
    pub body_truncated: bool,
    pub original_body_size: Option<i64>,
}

/// Manages network event capture
pub struct NetworkCapture {
    requests: HashMap<String, NetworkRequest>,
}

impl NetworkCapture {
    /// Create a new network capture manager
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Add a new request
    pub fn add_request(&mut self, request_id: String, method: String, url: String) {
        let request = NetworkRequest::new(request_id.clone(), method, url);
        self.requests.insert(request_id, request);
    }

    /// Update request with headers
    pub fn set_request_headers(&mut self, request_id: &str, headers: HashMap<String, String>) {
        if let Some(req) = self.requests.get_mut(request_id) {
            req.request_headers = headers;
        }
    }

    /// Update request with post data
    pub fn set_request_post_data(&mut self, request_id: &str, post_data: String) {
        if let Some(req) = self.requests.get_mut(request_id) {
            req.post_data = Some(post_data);
        }
    }

    /// Add response to request
    pub fn add_response(
        &mut self,
        request_id: &str,
        status: u16,
        status_text: String,
        headers: HashMap<String, String>,
    ) {
        if let Some(req) = self.requests.get_mut(request_id) {
            req.response = Some(NetworkResponse {
                status,
                status_text,
                headers,
                body: None,
                body_base64_encoded: false,
                body_truncated: false,
                original_body_size: None,
            });
        }
    }

    /// Mark request as completed
    pub fn mark_completed(&mut self, request_id: &str, encoded_data_length: i64) {
        if let Some(req) = self.requests.get_mut(request_id) {
            req.completed = true;
            req.encoded_data_length = encoded_data_length;
        }
    }

    /// Set response body with truncation information
    pub fn set_response_body(
        &mut self,
        request_id: &str,
        body: String,
        base64_encoded: bool,
        truncated: bool,
        original_size: Option<i64>,
    ) {
        if let Some(req) = self.requests.get_mut(request_id) {
            if let Some(resp) = &mut req.response {
                resp.body = Some(body);
                resp.body_base64_encoded = base64_encoded;
                resp.body_truncated = truncated;
                resp.original_body_size = original_size;
            }
        }
    }

    /// Get all captured requests
    pub fn requests(&self) -> Vec<NetworkRequest> {
        self.requests.values().cloned().collect()
    }

    /// Get number of captured requests
    pub fn count(&self) -> usize {
        self.requests.len()
    }

    /// Convert captured network events to HAR format
    pub fn to_har(&self) -> Har {
        let entries: Vec<Entry> = self
            .requests
            .values()
            .map(|net_req| self.network_request_to_entry(net_req))
            .collect();

        Har {
            log: Log {
                version: "1.2".to_string(),
                creator: Creator {
                    name: "Harrier".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    comment: None,
                },
                browser: None,
                pages: None,
                entries,
                comment: None,
            },
        }
    }

    /// Convert a NetworkRequest to a HAR Entry
    fn network_request_to_entry(&self, net_req: &NetworkRequest) -> Entry {
        let duration = net_req.duration();

        Entry {
            page_ref: None,
            started_date_time: {
                let datetime: DateTime<Utc> = net_req.started_at.into();
                datetime.to_rfc3339()
            },
            time: duration.as_millis() as f64,
            request: Request {
                method: net_req.method.clone(),
                url: net_req.url.clone(),
                http_version: "HTTP/1.1".to_string(),
                headers: self.convert_headers(&net_req.request_headers),
                query_string: vec![],
                cookies: vec![],
                headers_size: -1,
                body_size: net_req
                    .post_data
                    .as_ref()
                    .map(|s| s.len() as i64)
                    .unwrap_or(-1),
                post_data: net_req.post_data.as_ref().map(|text| PostData {
                    mime_type: net_req
                        .request_headers
                        .get("content-type")
                        .cloned()
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    text: Some(text.clone()),
                    params: None,
                    comment: None,
                }),
                comment: None,
            },
            response: net_req
                .response
                .as_ref()
                .map(|resp| Response {
                    status: resp.status as i64,
                    status_text: resp.status_text.clone(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: self.convert_headers(&resp.headers),
                    cookies: vec![],
                    content: Content {
                        size: net_req.encoded_data_length,
                        compression: None,
                        mime_type: resp
                            .headers
                            .get("content-type")
                            .cloned()
                            .unwrap_or_else(|| "application/octet-stream".to_string()),
                        text: resp.body.clone(),
                        encoding: if resp.body_base64_encoded {
                            Some("base64".to_string())
                        } else {
                            None
                        },
                        comment: if resp.body_truncated {
                            Some(format!(
                                "Body truncated at {} bytes (original size: {} bytes)",
                                MAX_RESPONSE_BODY_SIZE,
                                resp.original_body_size.unwrap_or(0)
                            ))
                        } else {
                            None
                        },
                    },
                    redirect_url: String::new(),
                    headers_size: -1,
                    body_size: net_req.encoded_data_length,
                    comment: None,
                })
                .unwrap_or_else(|| Response {
                    status: 0,
                    status_text: "No Response".to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: vec![],
                    cookies: vec![],
                    content: Content {
                        size: 0,
                        compression: None,
                        mime_type: "application/octet-stream".to_string(),
                        text: None,
                        encoding: None,
                        comment: None,
                    },
                    redirect_url: String::new(),
                    headers_size: -1,
                    body_size: 0,
                    comment: None,
                }),
            cache: Cache {
                before_request: None,
                after_request: None,
                comment: None,
            },
            timings: Timings {
                blocked: None,
                dns: None,
                connect: None,
                send: 0.0,
                wait: duration.as_millis() as f64,
                receive: 0.0,
                ssl: None,
                comment: None,
            },
            server_ip_address: None,
            connection: None,
            comment: None,
        }
    }

    /// Convert HashMap headers to HAR Header format
    fn convert_headers(&self, headers: &HashMap<String, String>) -> Vec<Header> {
        headers
            .iter()
            .map(|(name, value)| Header {
                name: name.clone(),
                value: value.clone(),
                comment: None,
            })
            .collect()
    }
}

impl Default for NetworkCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum response body size before truncation (15 MB for HawkScan compatibility)
pub const MAX_RESPONSE_BODY_SIZE: usize = 15 * 1024 * 1024;

/// Truncate a UTF-8 string at a character boundary
///
/// Ensures the truncation happens at a valid UTF-8 character boundary
/// to avoid corrupting the string.
pub fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }

    // Find valid UTF-8 boundary at or before max_bytes
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    s[..boundary].to_string()
}

/// Truncate a base64 string at a 4-character boundary
///
/// Base64 encoding requires strings to be multiples of 4 characters.
/// This ensures the truncated string is still valid base64.
pub fn truncate_base64(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }

    // Base64 must be multiple of 4 characters
    let boundary = (max_bytes / 4) * 4;
    s[..boundary].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_request_tracks_timing() {
        let req = NetworkRequest::new(
            "req-1".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
        );

        // Just verify duration() doesn't panic and returns a value
        let duration = req.duration();
        assert!(duration.as_millis() < 1000); // Should be under 1 second for this test
    }

    #[test]
    fn test_network_request_stores_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let mut req = NetworkRequest::new(
            "req-1".to_string(),
            "POST".to_string(),
            "https://api.example.com".to_string(),
        );
        req.request_headers = headers.clone();

        assert_eq!(
            req.request_headers.get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_network_request_pairs_with_response() {
        let mut req = NetworkRequest::new(
            "req-1".to_string(),
            "GET".to_string(),
            "https://example.com".to_string(),
        );

        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());

        req.response = Some(NetworkResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers,
            body: None,
            body_base64_encoded: false,
            body_truncated: false,
            original_body_size: None,
        });

        assert!(req.response.is_some());
        assert_eq!(req.response.as_ref().unwrap().status, 200);
    }

    #[test]
    fn test_convert_to_har_empty() {
        let capture = NetworkCapture::new();
        let har = capture.to_har();

        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.creator.name, "Harrier");
        assert_eq!(har.log.entries.len(), 0);
    }

    #[test]
    fn test_convert_to_har_with_request() {
        let mut capture = NetworkCapture::new();
        capture.add_request(
            "req-1".to_string(),
            "GET".to_string(),
            "https://example.com/api".to_string(),
        );

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Test".to_string());
        capture.set_request_headers("req-1", headers);

        capture.add_response("req-1", 200, "OK".to_string(), HashMap::new());
        capture.mark_completed("req-1", 1234);

        let har = capture.to_har();

        assert_eq!(har.log.entries.len(), 1);
        let entry = &har.log.entries[0];
        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.request.url, "https://example.com/api");
        assert_eq!(entry.response.status, 200);
    }

    #[test]
    fn test_convert_to_har_with_post_data() {
        let mut capture = NetworkCapture::new();
        capture.add_request(
            "req-1".to_string(),
            "POST".to_string(),
            "https://api.example.com/data".to_string(),
        );
        capture.set_request_post_data("req-1", r#"{"key":"value"}"#.to_string());

        let har = capture.to_har();

        assert_eq!(har.log.entries.len(), 1);
        let entry = &har.log.entries[0];
        assert!(entry.request.post_data.is_some());
        assert_eq!(
            entry
                .request
                .post_data
                .as_ref()
                .unwrap()
                .text
                .as_ref()
                .unwrap(),
            r#"{"key":"value"}"#
        );
    }

    #[test]
    fn test_truncate_utf8_below_max() {
        let text = "Hello, world!";
        let result = truncate_utf8(text, 100);
        assert_eq!(result, text);
    }

    #[test]
    fn test_truncate_utf8_at_max() {
        let text = "Hello";
        let result = truncate_utf8(text, 5);
        assert_eq!(result, text);
    }

    #[test]
    fn test_truncate_utf8_above_max() {
        let text = "Hello, world!";
        let result = truncate_utf8(text, 5);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_truncate_utf8_multibyte_boundary() {
        // "Hello🌍" - emoji is 4 bytes
        let text = "Hello🌍";
        let result = truncate_utf8(text, 7); // Should truncate before emoji
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_truncate_utf8_multibyte_fits() {
        // "Hello🌍" - emoji is 4 bytes (total 9 bytes)
        let text = "Hello🌍";
        let result = truncate_utf8(text, 10); // Should include emoji
        assert_eq!(result, text);
    }

    #[test]
    fn test_truncate_base64_below_max() {
        let base64 = "SGVsbG8="; // "Hello" in base64 (8 chars)
        let result = truncate_base64(base64, 100);
        assert_eq!(result, base64);
    }

    #[test]
    fn test_truncate_base64_at_boundary() {
        let base64 = "SGVsbG8="; // 8 chars (multiple of 4)
        let result = truncate_base64(base64, 8);
        assert_eq!(result, base64);
    }

    #[test]
    fn test_truncate_base64_not_at_boundary() {
        let base64 = "SGVsbG8gV29ybGQh"; // 16 chars
        let result = truncate_base64(base64, 10); // Should truncate to 8 (multiple of 4)
        assert_eq!(result, "SGVsbG8g"); // First 8 chars
        assert_eq!(result.len(), 8);
    }

    #[test]
    fn test_truncate_base64_zero() {
        let base64 = "SGVsbG8=";
        let result = truncate_base64(base64, 0);
        assert_eq!(result, "");
    }

    #[test]
    fn test_max_response_body_size() {
        assert_eq!(MAX_RESPONSE_BODY_SIZE, 15 * 1024 * 1024);
    }
}
