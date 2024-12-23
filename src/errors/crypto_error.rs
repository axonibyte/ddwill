use aes_gcm_siv::Error;
use crypto_common::InvalidLength;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    AESError(Error),
    InvalidLength(InvalidLength),
    IOError(std::io::Error),
    WorkflowError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::AESError(err) => write!(f, "AES error: {}", err),
            CryptoError::InvalidLength(err) => write!(f, "Invalid length error: {}", err),
            CryptoError::IOError(err) => write!(f, "STD error: {}", err),
            CryptoError::WorkflowError(msg) => write!(f, "Workflow error: {}", msg),
        }
    }
}

impl From<Error> for CryptoError {
    fn from(err: Error) -> CryptoError {
        CryptoError::AESError(err)
    }
}

impl From<InvalidLength> for CryptoError {
    fn from(err: InvalidLength) -> CryptoError {
        CryptoError::InvalidLength(err)
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> CryptoError {
        CryptoError::IOError(err)
    }
}

impl CryptoError {
    pub fn workflow_error(msg: &str) -> Self {
        CryptoError::WorkflowError(msg.to_string())
    }
}
