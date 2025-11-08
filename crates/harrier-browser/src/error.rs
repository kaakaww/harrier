use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Browser error: {0}")]
    Browser(String),

    #[error("CDP error: {0}")]
    Cdp(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
