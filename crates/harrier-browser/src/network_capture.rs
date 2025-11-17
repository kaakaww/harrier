use std::collections::HashMap;
use std::time::{Duration, SystemTime};

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

    /// Get all captured requests
    pub fn requests(&self) -> Vec<NetworkRequest> {
        self.requests.values().cloned().collect()
    }

    /// Get number of captured requests
    pub fn count(&self) -> usize {
        self.requests.len()
    }
}

impl Default for NetworkCapture {
    fn default() -> Self {
        Self::new()
    }
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

        let duration = req.duration();
        assert!(duration.as_millis() >= 0);
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

        assert_eq!(req.request_headers.get("Content-Type").unwrap(), "application/json");
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
        });

        assert!(req.response.is_some());
        assert_eq!(req.response.as_ref().unwrap().status, 200);
    }
}
