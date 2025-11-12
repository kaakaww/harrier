use crate::handler::HarCaptureHandler;
use crate::{CertificateAuthority, Error, Result};
use hudsucker::Proxy;
use rustls::crypto::aws_lc_rs::default_provider;
use std::net::SocketAddr;

/// MITM proxy server for capturing HTTP/HTTPS traffic
pub struct ProxyServer {
    port: u16,
    ca: CertificateAuthority,
    handler: HarCaptureHandler,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(port: u16, ca: CertificateAuthority) -> Self {
        Self {
            port,
            ca,
            handler: HarCaptureHandler::new(),
        }
    }

    /// Start the proxy server and return captured entries when it shuts down
    pub async fn start(self) -> Result<HarCaptureHandler> {
        let addr: SocketAddr = ([127, 0, 0, 1], self.port).into();

        tracing::info!("Starting proxy server on {}", addr);

        // Create certificate authority for MITM
        let ca = self.create_hudsucker_ca()?;

        // Set up shutdown signal
        let shutdown_signal = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
            tracing::info!("Received Ctrl+C, shutting down...");
            println!();
            println!("🛑 Shutting down proxy...");
        };

        // Create proxy with our handler and shutdown signal
        let proxy = Proxy::builder()
            .with_addr(addr)
            .with_ca(ca)
            .with_rustls_connector(default_provider())
            .with_http_handler(self.handler.clone())
            .with_graceful_shutdown(shutdown_signal)
            .build()
            .map_err(|e| Error::Proxy(format!("Failed to build proxy: {}", e)))?;

        tracing::info!("✓ Proxy server listening on http://{}", addr);
        println!("✓ Proxy server listening on http://{}", addr);
        println!();
        println!("Configure your browser or application to use this proxy:");
        println!("  HTTP Proxy:  127.0.0.1:{}", self.port);
        println!("  HTTPS Proxy: 127.0.0.1:{}", self.port);
        println!();
        println!("Press Ctrl+C to stop capturing and generate HAR file...");
        println!();

        // Clone the handler before moving proxy
        let handler = self.handler.clone();

        // Start the proxy server (this will run until shutdown)
        proxy
            .start()
            .await
            .map_err(|e| Error::Proxy(format!("Proxy failed: {}", e)))?;

        println!("✅ Proxy stopped gracefully");

        Ok(handler)
    }

    /// Create hudsucker CA from our certificate
    fn create_hudsucker_ca(&self) -> Result<hudsucker::certificate_authority::RcgenAuthority> {
        tracing::debug!("Creating hudsucker certificate authority");

        // Parse our CA certificate and key
        let cert_pem = self.ca.cert_pem();
        let key_pem = self.ca.key_pem();

        // Parse the key pair
        let key_pair = rcgen::KeyPair::from_pem(key_pem)
            .map_err(|e| Error::Tls(format!("Failed to parse private key: {}", e)))?;

        // Create issuer from CA cert and key pair
        let issuer = rcgen::Issuer::from_ca_cert_pem(cert_pem, key_pair)
            .map_err(|e| Error::Tls(format!("Failed to parse CA certificate: {}", e)))?;

        // Create hudsucker authority with issuer and crypto provider
        Ok(hudsucker::certificate_authority::RcgenAuthority::new(
            issuer,
            1_000,
            default_provider(),
        ))
    }

    /// Get the captured entries handler
    pub fn handler(&self) -> &HarCaptureHandler {
        &self.handler
    }
}
