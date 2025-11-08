use crate::{Error, Result};
use super::types::Har;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct HarReader;

impl HarReader {
    /// Read and parse a HAR file from the given path
    pub fn from_file(path: &Path) -> Result<Har> {
        tracing::debug!("Reading HAR file from: {}", path.display());

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let har: Har = serde_json::from_reader(reader)?;

        tracing::info!(
            "Successfully parsed HAR file with {} entries",
            har.log.entries.len()
        );

        Ok(har)
    }

    /// Parse a HAR file from a JSON string
    pub fn from_str(content: &str) -> Result<Har> {
        tracing::debug!("Parsing HAR from string");

        let har: Har = serde_json::from_str(content)?;

        tracing::info!(
            "Successfully parsed HAR from string with {} entries",
            har.log.entries.len()
        );

        Ok(har)
    }

    /// Validate that a HAR structure is well-formed
    pub fn validate(har: &Har) -> Result<()> {
        tracing::debug!("Validating HAR structure");

        // Check version
        if har.log.version.is_empty() {
            return Err(Error::InvalidStructure("Missing HAR version".to_string()));
        }

        // Check for at least one entry
        if har.log.entries.is_empty() {
            tracing::warn!("HAR file contains no entries");
        }

        // Basic validation of entries
        for (idx, entry) in har.log.entries.iter().enumerate() {
            if entry.request.method.is_empty() {
                return Err(Error::InvalidStructure(format!(
                    "Entry {} has empty request method",
                    idx
                )));
            }
            if entry.request.url.is_empty() {
                return Err(Error::InvalidStructure(format!(
                    "Entry {} has empty request URL",
                    idx
                )));
            }
        }

        tracing::debug!("HAR structure is valid");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_har() {
        let har_json = r#"{
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": []
            }
        }"#;

        let har = HarReader::from_str(har_json).unwrap();
        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.entries.len(), 0);
    }

    #[test]
    fn test_validate_empty_version() {
        let har_json = r#"{
            "log": {
                "version": "",
                "creator": {"name": "test", "version": "1.0"},
                "entries": []
            }
        }"#;

        let har = HarReader::from_str(har_json).unwrap();
        let result = HarReader::validate(&har);
        assert!(result.is_err());
    }
}
