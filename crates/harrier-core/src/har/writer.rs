use crate::Result;
use super::types::Har;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub struct HarWriter;

impl HarWriter {
    /// Write a HAR structure to a file
    pub fn to_file(har: &Har, path: &Path) -> Result<()> {
        tracing::debug!("Writing HAR file to: {}", path.display());

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, har)?;

        tracing::info!(
            "Successfully wrote HAR file with {} entries to {}",
            har.log.entries.len(),
            path.display()
        );

        Ok(())
    }

    /// Convert a HAR structure to a JSON string
    pub fn to_string(har: &Har) -> Result<String> {
        tracing::debug!("Converting HAR to string");

        let json = serde_json::to_string_pretty(har)?;

        tracing::info!("Successfully converted HAR to string");

        Ok(json)
    }

    /// Convert a HAR structure to a compact JSON string
    pub fn to_string_compact(har: &Har) -> Result<String> {
        tracing::debug!("Converting HAR to compact string");

        let json = serde_json::to_string(har)?;

        tracing::info!("Successfully converted HAR to compact string");

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::har::{Log, Creator};

    #[test]
    fn test_har_to_string() {
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
                entries: vec![],
                comment: None,
            },
        };

        let result = HarWriter::to_string(&har);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(json.contains("\"version\": \"1.2\""));
    }
}
