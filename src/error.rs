//! Error types for tdata-rs

use std::path::PathBuf;

/// Result type alias for tdata-rs operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during tdata parsing
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// IO error while reading tdata files
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The tdata folder path does not exist
    #[error("tdata folder not found: {path}")]
    FolderNotFound { path: PathBuf },

    /// Required file is missing from tdata folder
    #[error("required file not found: {file} in {folder}")]
    FileNotFound { file: String, folder: PathBuf },

    /// Key file (key_data, key_datas) not found
    #[error("key file not found in tdata folder")]
    KeyFileNotFound,

    /// Failed to decrypt tdata - wrong passcode or corrupted data
    #[error("decryption failed: wrong passcode or corrupted data")]
    DecryptionFailed,

    /// The tdata folder is password-protected but no passcode provided
    #[error("tdata is password-protected, passcode required")]
    PasscodeRequired,

    /// Invalid passcode provided
    #[error("invalid passcode")]
    InvalidPasscode,

    /// QDataStream parsing error
    #[error("QDataStream parse error: {message}")]
    QDataStreamError { message: String },

    /// Unexpected end of data while parsing
    #[error("unexpected end of data at offset {offset}")]
    UnexpectedEof { offset: u64 },

    /// Invalid UTF-16 string data
    #[error("invalid UTF-16 string data")]
    InvalidUtf16,

    /// Invalid data format or structure
    #[error("invalid data format: {message}")]
    InvalidFormat { message: String },

    /// No accounts found in tdata
    #[error("no accounts found in tdata")]
    NoAccounts,

    /// Account index out of range
    #[error("account index {index} out of range (max: {max})")]
    AccountIndexOutOfRange { index: usize, max: usize },

    /// MD5 checksum mismatch in encrypted data
    #[error("checksum mismatch: data may be corrupted")]
    ChecksumMismatch,

    /// Unsupported tdata version
    #[error("unsupported tdata version: {version}")]
    UnsupportedVersion { version: u32 },

    /// Auth key extraction failed
    #[error("failed to extract auth key: {reason}")]
    AuthKeyExtractionFailed { reason: String },
}

impl Error {
    /// Create a QDataStream error with a message
    pub fn qdatastream(msg: impl Into<String>) -> Self {
        Self::QDataStreamError {
            message: msg.into(),
        }
    }

    /// Create an invalid format error with a message
    pub fn invalid_format(msg: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: msg.into(),
        }
    }

    /// Create an auth key extraction error
    pub fn auth_key_failed(reason: impl Into<String>) -> Self {
        Self::AuthKeyExtractionFailed {
            reason: reason.into(),
        }
    }
}
