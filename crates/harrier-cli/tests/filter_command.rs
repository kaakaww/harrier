use harrier_core::har::HarReader;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to get path to test fixtures
fn fixture_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join(filename)
}

/// Test filtering by exact host match
#[test]
fn test_filter_exact_host_match() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to api.example.com
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["api.example.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify the filtered HAR has the expected entries
    let filtered_har = HarReader::from_file(&output).unwrap();
    assert_eq!(filtered_har.log.entries.len(), 2);

    // All entries should be from api.example.com
    for entry in &filtered_har.log.entries {
        let url = url::Url::parse(&entry.request.url).unwrap();
        assert_eq!(url.host_str().unwrap(), "api.example.com");
    }
}

/// Test filtering with glob pattern
#[test]
fn test_filter_glob_pattern() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to *.example.com (should match both api.example.com and cdn.example.com)
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["*.example.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify the filtered HAR has all example.com domains (all 3 entries)
    let filtered_har = HarReader::from_file(&output).unwrap();
    assert_eq!(filtered_har.log.entries.len(), 3);
}

/// Test filtering with multiple hosts (repeated flags)
#[test]
fn test_filter_multiple_hosts() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to api.example.com OR cdn.example.com
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify the filtered HAR includes entries from both hosts (all 3 entries)
    let filtered_har = HarReader::from_file(&output).unwrap();
    assert_eq!(filtered_har.log.entries.len(), 3);
}

/// Test filtering with comma-separated hosts
#[test]
fn test_filter_comma_separated_hosts() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter with comma-separated hosts
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["api.example.com,cdn.example.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify the filtered HAR includes entries from both hosts (all 3 entries)
    let filtered_har = HarReader::from_file(&output).unwrap();
    assert_eq!(filtered_har.log.entries.len(), 3);
}

/// Test filtering with status code
#[test]
fn test_filter_status_code() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to 2xx status codes
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec![],
        Some("2xx".to_string()),
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify all entries have 2xx status
    let filtered_har = HarReader::from_file(&output).unwrap();
    for entry in &filtered_har.log.entries {
        assert!(entry.response.status >= 200 && entry.response.status < 300);
    }
}

/// Test combined filters (host + status)
#[test]
fn test_filter_combined_host_and_status() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to api.example.com with 2xx status
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["api.example.com".to_string()],
        Some("2xx".to_string()),
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    // Verify entries match both criteria
    let filtered_har = HarReader::from_file(&output).unwrap();
    for entry in &filtered_har.log.entries {
        let url = url::Url::parse(&entry.request.url).unwrap();
        assert_eq!(url.host_str().unwrap(), "api.example.com");
        assert!(entry.response.status >= 200 && entry.response.status < 300);
    }
}

/// Test error when no entries match
#[test]
fn test_filter_no_matches_returns_error() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act - filter to non-existent host
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["nonexistent.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_err(), "Should return error when no entries match");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("No entries matched"),
        "Error message should mention no matches"
    );

    // Output file should not exist
    assert!(
        !output.exists(),
        "Output file should not be created on error"
    );
}

/// Test filtering preserves HAR metadata
#[test]
fn test_filter_preserves_metadata() {
    // Arrange
    let input = fixture_path("sample.har");
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("filtered.har");

    // Act
    let result = harrier_cli::commands::filter::execute(
        &input,
        vec!["api.example.com".to_string()],
        None,
        None,
        None,
        Some(output.clone()),
    );

    // Assert
    assert!(result.is_ok(), "Should successfully filter HAR file");

    let original_har = HarReader::from_file(&input).unwrap();
    let filtered_har = HarReader::from_file(&output).unwrap();

    // Verify metadata is preserved
    assert_eq!(
        filtered_har.log.version, original_har.log.version,
        "HAR version should be preserved"
    );
    assert_eq!(
        filtered_har.log.creator.name, original_har.log.creator.name,
        "Creator name should be preserved"
    );
}
