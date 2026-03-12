use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidNonceLength { expected: usize, actual: usize },
    InvalidInput(&'static str),
    UnsupportedAlgorithm(&'static str),
    IntegrityCheckFailed,
    DecodeError(&'static str),
    Internal(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {actual} bytes"
                )
            }
            Self::InvalidNonceLength { expected, actual } => {
                write!(
                    f,
                    "invalid nonce length: expected {expected} bytes, got {actual} bytes"
                )
            }
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
            Self::UnsupportedAlgorithm(name) => write!(f, "unsupported algorithm: {name}"),
            Self::IntegrityCheckFailed => write!(f, "integrity check failed"),
            Self::DecodeError(message) => write!(f, "decode error: {message}"),
            Self::Internal(message) => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for CryptoError {}
