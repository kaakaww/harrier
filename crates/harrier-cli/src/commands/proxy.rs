use anyhow::Result;
use harrier_proxy::{CertificateAuthority, ProxyServer};
use std::path::Path;

pub fn execute(
    port: u16,
    output: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<()> {
    tracing::info!("Starting Harrier MITM proxy on port {}", port);

    // Load or generate CA certificate
    let ca = if let (Some(cert), Some(key)) = (cert_path, key_path) {
        tracing::info!("Loading CA certificate from custom paths");
        CertificateAuthority::load_from_pem(cert, key)?
    } else {
        tracing::info!("Using default CA certificate location");
        CertificateAuthority::load_or_generate()?
    };

    println!("📝 Output will be written to: {}", output.display());
    println!();

    // Create and start proxy server
    let server = ProxyServer::new(port, ca);

    // Run the proxy (this blocks until Ctrl+C)
    let runtime = tokio::runtime::Runtime::new()?;
    let handler = runtime.block_on(async { server.start().await })?;

    println!();
    println!("🛑 Proxy stopped");

    // Get captured entries
    let entries = runtime.block_on(async { handler.entries().lock().await.clone() });

    println!("📊 Captured {} HTTP transactions", entries.len());

    // Generate HAR file
    if !entries.is_empty() {
        use serde_json::json;
        use std::fs;

        // Convert entries to HAR format
        let har_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|entry| {
                let duration = entry
                    .completed_at
                    .duration_since(entry.started_at)
                    .unwrap_or_default();

                json!({
                    "startedDateTime": format!("{:?}", entry.started_at),
                    "time": duration.as_millis() as i64,
                    "request": {
                        "method": entry.method,
                        "url": entry.url,
                        "httpVersion": "HTTP/1.1",
                        "headers": entry.request_headers.iter().map(|(k, v)| {
                            json!({
                                "name": k,
                                "value": v
                            })
                        }).collect::<Vec<_>>(),
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": -1
                    },
                    "response": {
                        "status": entry.response_status,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": entry.response_headers.iter().map(|(k, v)| {
                            json!({
                                "name": k,
                                "value": v
                            })
                        }).collect::<Vec<_>>(),
                        "cookies": [],
                        "content": {
                            "size": -1,
                            "mimeType": "application/octet-stream"
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": -1
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": duration.as_millis() as i64,
                        "receive": 0
                    }
                })
            })
            .collect();

        // Create HAR structure
        let har = json!({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Harrier",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "entries": har_entries
            }
        });

        // Write to file
        let har_json = serde_json::to_string_pretty(&har)?;
        fs::write(output, har_json)?;

        println!("✅ HAR file written to: {}", output.display());
    } else {
        println!("⚠️  No traffic captured, HAR file not generated");
    }

    Ok(())
}
