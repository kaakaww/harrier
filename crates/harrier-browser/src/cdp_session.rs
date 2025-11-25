use crate::{
    NetworkCapture, Result,
    network_capture::{MAX_RESPONSE_BODY_SIZE, truncate_base64, truncate_utf8},
};
use chromiumoxide::browser::Browser;
use chromiumoxide::cdp::browser_protocol::network::{
    ClearBrowserCacheParams, EnableParams, EventLoadingFinished, EventRequestWillBeSent,
    EventResponseReceived, GetResponseBodyParams,
};
use chromiumoxide::cdp::browser_protocol::page::{EventLoadEventFired, NavigateParams};
use futures::StreamExt;
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Manages Chrome DevTools Protocol session
pub struct CdpSession {
    debugging_port: u16,
}

impl CdpSession {
    /// Create a new CDP session
    pub fn new(debugging_port: u16) -> Self {
        Self { debugging_port }
    }

    /// Connect to Chrome and return the browser instance
    async fn connect(&self) -> Result<(Browser, chromiumoxide::handler::Handler)> {
        let ws_url = format!("http://localhost:{}", self.debugging_port);
        let mut retries = 20;

        loop {
            tracing::debug!("Attempting CDP connection to {}...", ws_url);
            match Browser::connect(&ws_url).await {
                Ok(result) => {
                    tracing::info!("CDP connection established");
                    return Ok(result);
                }
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        return Err(crate::Error::Cdp(format!(
                            "Failed to connect to Chrome after 10 seconds (20 attempts): {}",
                            e
                        )));
                    }
                    tracing::info!(
                        "CDP connection attempt failed, retrying... ({} left)",
                        retries
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Clear Chrome's browser cache
    pub async fn clear_browser_cache(&self) -> Result<()> {
        tracing::info!("Clearing browser cache...");

        let (browser, mut handler) = self.connect().await?;

        // Spawn handler task
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::debug!("CDP handler event error (continuing): {}", e);
                }
            }
        });

        // Wait for Chrome to be ready
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Get page
        let page = if let Some(page) = browser.pages().await?.first() {
            page.clone()
        } else {
            browser.new_page("about:blank").await?
        };

        // Clear cache
        match page.execute(ClearBrowserCacheParams::default()).await {
            Ok(_) => {
                tracing::info!("Browser cache cleared successfully");
                handler_task.abort();
                Ok(())
            }
            Err(e) => {
                handler_task.abort();
                Err(crate::Error::Cdp(format!(
                    "Failed to clear browser cache: {}",
                    e
                )))
            }
        }
    }

    /// Navigate to a URL
    pub async fn navigate_to(&self, url: &str) -> Result<()> {
        tracing::info!("Navigating to {}...", url);

        // Validate and normalize URL
        let normalized_url = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("https://{}", url)
        };

        let (browser, mut handler) = self.connect().await?;

        // Spawn handler task
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::debug!("CDP handler event error (continuing): {}", e);
                }
            }
        });

        // Wait for Chrome to be ready
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Get page
        let page = if let Some(page) = browser.pages().await?.first() {
            page.clone()
        } else {
            browser.new_page("about:blank").await?
        };

        // Subscribe to load event
        let mut load_events = page.event_listener::<EventLoadEventFired>().await?;

        // Navigate
        let navigate_params = NavigateParams::builder()
            .url(normalized_url.clone())
            .build()
            .map_err(|e| crate::Error::Cdp(format!("Failed to build navigate params: {}", e)))?;

        match page.execute(navigate_params).await {
            Ok(_) => {
                tracing::info!("Navigation initiated to {}", normalized_url);

                // Wait for page load with timeout
                let timeout = tokio::time::sleep(std::time::Duration::from_secs(30));
                tokio::pin!(timeout);

                tokio::select! {
                    _ = load_events.next() => {
                        tracing::info!("Page loaded successfully");
                        handler_task.abort();
                        Ok(())
                    }
                    _ = &mut timeout => {
                        handler_task.abort();
                        Err(crate::Error::Cdp(format!(
                            "Navigation timeout after 30 seconds for {}",
                            normalized_url
                        )))
                    }
                }
            }
            Err(e) => {
                handler_task.abort();
                Err(crate::Error::Cdp(format!(
                    "Failed to navigate to {}: {}",
                    normalized_url, e
                )))
            }
        }
    }

    /// Connect to Chrome and capture network traffic
    ///
    /// Returns a tuple of (shutdown_sender, capture_receiver) where:
    /// - shutdown_sender: Send () to stop capturing and get results
    /// - capture_receiver: Receives the NetworkCapture when shutdown is triggered
    pub async fn capture_traffic(
        &self,
    ) -> Result<(oneshot::Sender<()>, oneshot::Receiver<NetworkCapture>)> {
        tracing::info!(
            "CDP session: connecting to Chrome on port {}",
            self.debugging_port
        );

        // Connect to Chrome via CDP
        let (browser, mut handler) = self.connect().await?;

        // Spawn handler task IMMEDIATELY to process CDP protocol messages
        // This must run for browser.pages() and other commands to work
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    // Log but don't stop - some CDP events may not be fully parseable
                    tracing::debug!("CDP handler event error (continuing): {}", e);
                }
            }
        });

        tracing::info!("CDP: Getting page list...");
        // Get the first page (or create new one)
        // Wait a bit for Chrome to create its initial page
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let page = if let Some(page) = browser.pages().await?.first() {
            tracing::info!("CDP: Using existing page");
            page.clone()
        } else {
            tracing::info!("CDP: No existing pages, creating new page");
            browser.new_page("about:blank").await?
        };

        tracing::info!("CDP session: connected to Chrome, enabling Network domain");

        // Enable Network domain
        page.execute(EnableParams::default()).await?;

        tracing::info!("CDP session: Network domain enabled, starting event capture");

        // Subscribe to network events
        let mut request_events = page.event_listener::<EventRequestWillBeSent>().await?;
        let mut response_events = page.event_listener::<EventResponseReceived>().await?;
        let mut loading_finished_events = page.event_listener::<EventLoadingFinished>().await?;

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let (result_tx, result_rx) = oneshot::channel::<NetworkCapture>();

        // Spawn event processing task
        let page_clone = page.clone();
        tokio::spawn(async move {
            let mut capture = NetworkCapture::new();

            loop {
                tokio::select! {
                    // Check for shutdown signal first
                    _ = &mut shutdown_rx => {
                        tracing::info!("CDP capture: shutdown signal received, stopping capture");
                        break;
                    }
                    Some(event) = request_events.next() => {
                        tracing::debug!("Request: {} {}", event.request.method, event.request.url);
                        let request_id = event.request_id.inner().to_string();
                        capture.add_request(
                            request_id.clone(),
                            event.request.method.clone(),
                            event.request.url.clone(),
                        );

                        // Store headers - deserialize from JSON Value
                        if let Ok(headers) = serde_json::from_value::<HashMap<String, String>>(event.request.headers.inner().clone()) {
                            capture.set_request_headers(&request_id, headers);
                        }

                        // TODO: Fetch POST data if present (has_post_data flag)
                        // This requires calling Network.getRequestPostData separately
                    }
                    Some(event) = response_events.next() => {
                        tracing::debug!("Response: {} - {}", event.response.status, event.response.url);
                        let request_id = event.request_id.inner().to_string();

                        // Store headers - deserialize from JSON Value
                        if let Ok(headers) = serde_json::from_value::<HashMap<String, String>>(event.response.headers.inner().clone()) {
                            capture.add_response(
                                &request_id,
                                event.response.status as u16,
                                event.response.status_text.clone(),
                                headers,
                            );
                        }
                    }
                    Some(event) = loading_finished_events.next() => {
                        tracing::debug!("Loading finished: {}", event.request_id.inner());
                        let request_id = event.request_id.inner().to_string();
                        capture.mark_completed(&request_id, event.encoded_data_length as i64);

                        // Fetch response body
                        let params = GetResponseBodyParams::new(event.request_id.clone());
                        if let Ok(body_result) = page_clone.execute(params).await {
                            let body = body_result.body.clone();
                            let base64_encoded = body_result.base64_encoded;

                            // Truncate body if needed
                            let original_size = body.len();
                            let (truncated_body, was_truncated) = if original_size > MAX_RESPONSE_BODY_SIZE {
                                let truncated = if base64_encoded {
                                    truncate_base64(&body, MAX_RESPONSE_BODY_SIZE)
                                } else {
                                    truncate_utf8(&body, MAX_RESPONSE_BODY_SIZE)
                                };
                                (truncated, true)
                            } else {
                                (body, false)
                            };

                            // Update response with body
                            capture.set_response_body(
                                &request_id,
                                truncated_body,
                                base64_encoded,
                                was_truncated,
                                if was_truncated {
                                    Some(original_size as i64)
                                } else {
                                    None
                                },
                            );
                        }
                    }
                }
            }

            // Send the capture back and cleanup
            let _ = result_tx.send(capture);
            handler_task.abort();
        });

        Ok((shutdown_tx, result_rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cdp_session_creates() {
        let session = CdpSession::new(9222);
        assert_eq!(session.debugging_port, 9222);
    }

    // Note: Full CDP capture tests require a running Chrome instance
    // and are covered by integration tests in harrier-cli
}
