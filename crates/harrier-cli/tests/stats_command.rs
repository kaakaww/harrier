use harrier_core::analysis::AnalysisReport;
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
