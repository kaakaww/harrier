use crate::{network_capture::{truncate_base64, truncate_utf8, MAX_RESPONSE_BODY_SIZE}, NetworkCapture, Result};
use chromiumoxide::browser::Browser;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventRequestWillBeSent, EventResponseReceived, EventLoadingFinished,
    GetResponseBodyParams,
};
use futures::StreamExt;
use std::collections::HashMap;

/// Manages Chrome DevTools Protocol session
pub struct CdpSession {
    debugging_port: u16,
}

impl CdpSession {
    /// Create a new CDP session
    pub fn new(debugging_port: u16) -> Self {
        Self { debugging_port }
    }

    /// Connect to Chrome and capture network traffic
    pub async fn capture_traffic(&self) -> Result<NetworkCapture> {
        tracing::info!(
            "CDP session: connecting to Chrome on port {}",
            self.debugging_port
        );

        // Connect to Chrome via CDP
        let ws_url = format!("http://localhost:{}", self.debugging_port);
        let (browser, mut handler) = Browser::connect(ws_url).await?;

        // Get the first page (or create new one)
        let page = if let Some(page) = browser.pages().await?.first() {
            page.clone()
        } else {
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

        // Spawn handler task to process CDP protocol messages
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(e) = event {
                    tracing::error!("CDP handler error: {}", e);
                    break;
                }
            }
        });

        // Spawn event processing task
        let page_clone = page.clone();
        let capture_task = tokio::spawn(async move {
            let mut capture = NetworkCapture::new();

            loop {
                tokio::select! {
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
                    else => break,
                }
            }

            capture
        });

        // Wait indefinitely until the function is aborted or Chrome closes
        // In practice, this will be interrupted by the parent task being aborted
        let capture = capture_task.await.map_err(|e| crate::Error::Cdp(e.to_string()))?;

        // Cleanup
        handler_task.abort();

        Ok(capture)
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
