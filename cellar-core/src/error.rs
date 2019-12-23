use thiserror::Error;

/// contains all the errors used in cellar-core.
#[derive(Error, Debug)]
pub enum CellarError {
    #[error("{0}")]
    Argon2Error(#[from] argon2::Error),
    #[error("Invalid Nonce: {0}")]
    InvalidChacha20Nonce(String),
    #[error("{0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    #[error("unknown error")]
    Unknown,
}
