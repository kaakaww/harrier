use harrier_core::analysis::AnalysisReport;
use harrier_core::har::{Cache, Content, Entry, Request, Response, Timings};
use std::path::PathBuf;

/// Test that analyze_har function reads a HAR file and returns analysis results
#[test]
fn test_analyze_har_returns_summary_stats() {
    // Arrange
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("sample.har");

    // Act - call the analyze_har function that will perform the analysis
    let result = harrier_cli::commands::stats::analyze_har(&fixture_path, false);

    // Assert
    assert!(result.is_ok(), "Should successfully analyze HAR file");

    let report: AnalysisReport = result.unwrap();

    // Verify summary statistics
    assert_eq!(report.summary.total_entries, 3);
    assert_eq!(report.summary.unique_domains, 2);
    assert_eq!(report.summary.total_size, 6400);
}

/// Test that HTTP versions are normalized to standard format
/// This test will FAIL until we implement normalization
#[test]
fn test_analyze_normalizes_http_versions() {
    // Arrange - HAR file with h2, h3, and http/1.1 (Chrome DevTools format)
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("mixed-http-versions.har");

    // Act
    let result = harrier_cli::commands::stats::analyze_har(&fixture_path, false);

    // Assert
    assert!(result.is_ok(), "Should successfully analyze HAR file");

    let report = result.unwrap();

    // Verify HTTP versions are normalized
    assert_eq!(report.summary.http_versions.len(), 3);
    assert!(
        report
            .summary
            .http_versions
            .contains(&"HTTP/1.1".to_string()),
        "Should normalize 'http/1.1' to 'HTTP/1.1'"
    );
    assert!(
        report
            .summary
            .http_versions
            .contains(&"HTTP/2.0".to_string()),
        "Should normalize 'h2' to 'HTTP/2.0'"
    );
    assert!(
        report
            .summary
            .http_versions
            .contains(&"HTTP/3.0".to_string()),
        "Should normalize 'h3' to 'HTTP/3.0'"
    );
}

/// Test that analyze_har includes performance stats when requested
#[test]
fn test_analyze_har_with_timings() {
    // Arrange
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("sample.har");

    // Act - analyze with timings
    let result = harrier_cli::commands::stats::analyze_har(&fixture_path, true);

    // Assert
    assert!(
        result.is_ok(),
        "Should successfully analyze HAR file with timings"
    );

    let report = result.unwrap();

    // Verify performance stats are populated
    assert!(report.performance.total_time > 0.0);
    assert!(report.performance.average_time > 0.0);
    assert!(report.performance.median_time > 0.0);
    assert_eq!(report.performance.slowest_requests.len(), 3);

    // Verify slowest request is first (125.5ms)
    assert_eq!(report.performance.slowest_requests[0].time, 125.5);
}

/// Test that analyze can extract and count hosts from HAR file
/// This test will FAIL until we implement host analysis
#[test]
fn test_analyze_extracts_hosts() {
    // Arrange
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("sample.har");

    let har = harrier_core::har::HarReader::from_file(&fixture_path)
        .expect("Failed to read HAR file");

    // Act - analyze hosts
    let hosts = harrier_cli::commands::stats::analyze_hosts(&har);

    // Assert
    assert_eq!(hosts.len(), 2, "Should find 2 unique hosts");

    // First host should be from the first request (api.example.com)
    assert_eq!(hosts[0].domain, "api.example.com");
    assert_eq!(hosts[0].protocol, "https");
    assert_eq!(hosts[0].port, 443);
    assert_eq!(hosts[0].hit_count, 2); // 2 requests to api.example.com

    // Second host sorted by hit count (cdn.example.com has 1 request)
    assert_eq!(hosts[1].domain, "cdn.example.com");
    assert_eq!(hosts[1].protocol, "https");
    assert_eq!(hosts[1].port, 443);
    assert_eq!(hosts[1].hit_count, 1);
}

/// Test that hosts are sorted by: first host, same root domain by hits, other domains by hits
#[test]
fn test_analyze_hosts_sorting_by_root_domain() {
    use harrier_core::har::*;

    // Create a HAR with multiple hosts from different root domains
    let har = Har {
        log: Log {
            version: "1.2".to_string(),
            creator: Creator {
                name: "test".to_string(),
                version: "1.0".to_string(),
                comment: None,
            },
            browser: None,
            pages: None,
            entries: vec![
                // First request: www.example.com (2 total requests)
                create_entry("https://www.example.com/page1"),
                // Second request: api.different.org (3 requests - should be last despite more hits)
                create_entry("https://api.different.org/v1"),
                // Third request: cdn.example.com (1 request - same root as first)
                create_entry("https://cdn.example.com/asset.js"),
                // Fourth: api.different.org
                create_entry("https://api.different.org/v2"),
                // Fifth: www.example.com
                create_entry("https://www.example.com/page2"),
                // Sixth: api.different.org
                create_entry("https://api.different.org/v3"),
            ],
            comment: None,
        },
    };

    // Act
    let hosts = harrier_cli::commands::stats::analyze_hosts(&har);

    // Assert - should be ordered:
    // 1. www.example.com (2 requests) [first]
    // 2. cdn.example.com (1 request) [same root domain as first]
    // 3. api.different.org (3 requests) [different root domain, sorted by hits]

    assert_eq!(hosts.len(), 3);

    // First host should be www.example.com
    assert_eq!(hosts[0].domain, "www.example.com");
    assert_eq!(hosts[0].hit_count, 2);

    // Second host should be cdn.example.com (same root domain, even though fewer hits)
    assert_eq!(hosts[1].domain, "cdn.example.com");
    assert_eq!(hosts[1].hit_count, 1);

    // Third should be api.different.org (different root domain)
    assert_eq!(hosts[2].domain, "api.different.org");
    assert_eq!(hosts[2].hit_count, 3);
}

// Helper to create a minimal entry for testing
fn create_entry(url: &str) -> Entry {
    Entry {
        page_ref: None,
        started_date_time: "2024-01-01T00:00:00Z".to_string(),
        time: 100.0,
        request: Request {
            method: "GET".to_string(),
            url: url.to_string(),
            http_version: "HTTP/1.1".to_string(),
            cookies: vec![],
            headers: vec![],
            query_string: vec![],
            post_data: None,
            headers_size: 0,
            body_size: 0,
            comment: None,
        },
        response: Response {
            status: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            cookies: vec![],
            headers: vec![],
            content: Content {
                size: 0,
                compression: None,
                mime_type: "text/html".to_string(),
                text: None,
                encoding: None,
                comment: None,
            },
            redirect_url: String::new(),
            headers_size: 0,
            body_size: 0,
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

/// Test that API types are detected for hosts
#[test]
fn test_analyze_hosts_with_api_types() {
    // Arrange
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("sample.har");

    let har = harrier_core::har::HarReader::from_file(&fixture_path)
        .expect("Failed to read HAR file");

    // Act - analyze hosts (now includes API type detection)
    let hosts = harrier_cli::commands::stats::analyze_hosts(&har);

    // Assert - verify hosts have API type information
    assert_eq!(hosts.len(), 2, "Should find 2 unique hosts");

    // Check first host (api.example.com) has API type info
    assert!(!hosts[0].api_types.is_empty(), "First host should have API types detected");

    // Verify API types have proper structure
    for host in &hosts {
        for api_type in &host.api_types {
            // Confidence should be between 0 and 1
            assert!(
                api_type.confidence > 0.0 && api_type.confidence <= 1.0,
                "Confidence for {} should be between 0 and 1, got {}",
                api_type.api_type.as_str(),
                api_type.confidence
            );

            // Request count should be greater than 0
            assert!(
                api_type.request_count > 0,
                "Request count for {} should be > 0, got {}",
                api_type.api_type.as_str(),
                api_type.request_count
            );

            // Request count should not exceed host's total hit count
            assert!(
                api_type.request_count <= host.hit_count,
                "Request count {} for {} should not exceed host hit count {}",
                api_type.request_count,
                api_type.api_type.as_str(),
                host.hit_count
            );
        }
    }
}
