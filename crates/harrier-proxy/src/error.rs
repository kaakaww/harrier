use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
