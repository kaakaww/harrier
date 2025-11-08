use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to read HAR file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse HAR file: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Invalid HAR structure: {0}")]
    InvalidStructure(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Analysis error: {0}")]
    Analysis(String),
}

pub type Result<T> = std::result::Result<T, Error>;
