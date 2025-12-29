use http::{Request, Response};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// HTTP handler that captures requests and responses for HAR generation
#[derive(Clone)]
pub struct HarCaptureHandler {
    /// Shared buffer for captured entries (will convert to HAR entries later)
    entries: Arc<Mutex<Vec<CapturedEntry>>>,
    /// Pending requests grouped by client connection (FIFO per connection)
    /// Key: client socket address, Value: queue of pending requests
    pending: Arc<Mutex<HashMap<SocketAddr, VecDeque<PendingRequest>>>>,
}

/// Temporary storage for a request waiting for its response
#[derive(Debug, Clone)]
struct PendingRequest {
    url: String,
    method: String,
    request_headers: Vec<(String, String)>,
    started_at: std::time::SystemTime,
}

/// Captured HTTP transaction data
#[derive(Debug, Clone)]
pub struct CapturedEntry {
    pub method: String,
    pub url: String,
    pub request_headers: Vec<(String, String)>,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub started_at: std::time::SystemTime,
    pub completed_at: std::time::SystemTime,
}

impl HarCaptureHandler {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn entries(&self) -> Arc<Mutex<Vec<CapturedEntry>>> {
        Arc::clone(&self.entries)
    }
}

impl Default for HarCaptureHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpHandler for HarCaptureHandler {
    fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl std::future::Future<Output = RequestOrResponse> + Send {
        let method = req.method().to_string();
        let url = req.uri().to_string();
        let started_at = std::time::SystemTime::now();
        let client_addr = ctx.client_addr;

        // Capture request headers
        let request_headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        tracing::debug!(
            "Intercepted request: {} {} (client: {})",
            method,
            url,
            client_addr
        );

        // Store pending request grouped by client connection
        let pending = self.pending.clone();
        let pending_req = PendingRequest {
            url: url.clone(),
            method: method.clone(),
            request_headers,
            started_at,
        };

        async move {
            let mut pending_guard = pending.lock().await;
            // Add to the queue for this client connection (FIFO order)
            pending_guard
                .entry(client_addr)
                .or_insert_with(VecDeque::new)
                .push_back(pending_req);
            drop(pending_guard);

            RequestOrResponse::Request(req)
        }
    }

    fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl std::future::Future<Output = Response<Body>> + Send {
        let status = res.status().as_u16();
        let client_addr = ctx.client_addr;

        // Capture response headers
        let response_headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        tracing::debug!("Intercepted response: {} (client: {})", status, client_addr);

        // Match response with the oldest pending request for this client (FIFO)
        let pending = self.pending.clone();
        let entries = self.entries.clone();

        async move {
            let mut pending_guard = pending.lock().await;
            // Get the queue for this client and pop from the front (FIFO order)
            if let Some(queue) = pending_guard.get_mut(&client_addr)
                && let Some(req) = queue.pop_front()
            {
                let entry = CapturedEntry {
                    method: req.method,
                    url: req.url,
                    request_headers: req.request_headers,
                    response_status: status,
                    response_headers,
                    started_at: req.started_at,
                    completed_at: std::time::SystemTime::now(),
                };

                // Clean up empty queues to prevent memory growth
                if queue.is_empty() {
                    pending_guard.remove(&client_addr);
                }

                let mut entries_guard = entries.lock().await;
                entries_guard.push(entry);
                tracing::trace!("Captured entry (total: {})", entries_guard.len());
                drop(entries_guard);
            }
            drop(pending_guard);

            res
        }
    }
}
