use crate::{NetworkCapture, Result};
use std::time::Duration;
use tokio::time::sleep;

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
    ///
    /// This is a stub implementation for MVP. Full CDP integration
    /// with chromiumoxide will be added in subsequent iterations.
    pub async fn capture_traffic(&self) -> Result<NetworkCapture> {
        tracing::info!(
            "CDP session: connecting to Chrome on port {}",
            self.debugging_port
        );

        // For MVP: just wait and return empty capture
        // Full implementation will:
        // 1. Connect to Chrome via WebSocket
        // 2. Enable Network domain
        // 3. Listen for Network.requestWillBeSent
        // 4. Listen for Network.responseReceived
        // 5. Listen for Network.loadingFinished
        // 6. Call Network.getRequestPostData for POST bodies
        // 7. Build NetworkCapture from events

        // Simulate waiting for Chrome to be ready
        sleep(Duration::from_secs(1)).await;

        tracing::warn!(
            "CDP traffic capture not fully implemented in MVP - returning empty capture"
        );

        Ok(NetworkCapture::new())
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

    #[tokio::test]
    async fn test_cdp_capture_returns_empty() {
        let session = CdpSession::new(9222);
        let capture = session.capture_traffic().await.unwrap();
        assert_eq!(capture.count(), 0);
    }
}
