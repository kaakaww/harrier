use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Pattern matching error: {0}")]
    Pattern(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, Error>;
