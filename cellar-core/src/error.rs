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
    #[error("{0}")]
    ConvertError(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    InvalidKey(String),
    #[error("{0}")]
    InvalidKeypair(#[from] ed25519_compact::Error),
    #[error("Serialize cert error: {0}")]
    CertEncodeError(#[from] bincode::error::EncodeError),
    #[error("Deserialize cert error: {0}")]
    CertDecodeError(#[from] bincode::error::DecodeError),
    #[error("Certify error: {0}")]
    CertifyError(#[from] certify::CertifyError),
    #[error("Rcgen error: {0}")]
    RcgenError(#[from] rcgen::RcgenError),
    #[error("unknown error")]
    Unknown,
}
