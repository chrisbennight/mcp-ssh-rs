//! Immutable input and byte publication boundary for mediated transfers.

use crate::action::FileIdentity;
use crate::files::{FileError, MAX_TRANSFER_BYTES};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// Validated bytes remain in the runtime and never serialize into tool arguments.
pub struct PreparedUpload {
    identity: FileIdentity,
    bytes: Arc<[u8]>,
}

impl PreparedUpload {
    pub fn new(uri: String, bytes: Vec<u8>) -> Result<Self, FileError> {
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err(FileError::TooLarge {
                size: bytes.len() as u64,
                max: MAX_TRANSFER_BYTES as u64,
            });
        }
        let identity = identity(uri, &bytes);
        Ok(Self {
            identity,
            bytes: bytes.into(),
        })
    }

    pub fn from_shared(uri: String, bytes: Arc<[u8]>) -> Result<Self, FileError> {
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err(FileError::TooLarge {
                size: bytes.len() as u64,
                max: MAX_TRANSFER_BYTES as u64,
            });
        }
        Ok(Self {
            identity: identity(uri, &bytes),
            bytes,
        })
    }

    pub const fn identity(&self) -> &FileIdentity {
        &self.identity
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Publishes a complete bounded download to the caller's authorized byte store.
/// The implementation owns retention and access checks. It must not return inline content.
pub trait DownloadSink: Send + Sync + 'static {
    fn publish(&self, bytes: Vec<u8>) -> Result<FileIdentity, String>;
}

pub fn identity(uri: String, bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        uri,
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

pub(crate) enum Payload {
    Download(Arc<dyn DownloadSink>),
    Upload(PreparedUpload),
}

/// A bounded failure category safe to return without server or filesystem error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    NotFound,
    PermissionDenied,
    TooLarge,
    SymbolicLink,
    SftpUnavailable,
    RemoteIo,
    PublicationUnavailable,
    TimedOut,
}

impl Failure {
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::TooLarge => "too_large",
            Self::SymbolicLink => "symbolic_link",
            Self::SftpUnavailable => "sftp_unavailable",
            Self::RemoteIo => "remote_io",
            Self::PublicationUnavailable => "publication_unavailable",
            Self::TimedOut => "timed_out",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::NotFound => "The remote file or directory was not found.",
            Self::PermissionDenied => "The remote account was denied file access.",
            Self::TooLarge => "The file exceeds the configured transfer size limit.",
            Self::SymbolicLink => "The remote path resolves through a symbolic link.",
            Self::SftpUnavailable => "The remote SFTP service is unavailable.",
            Self::RemoteIo => "The remote file operation failed.",
            Self::PublicationUnavailable => {
                "The download could not be published to local output storage."
            }
            Self::TimedOut => "The transfer exceeded its time limit.",
        }
    }
}

impl From<FileError> for Failure {
    fn from(error: FileError) -> Self {
        match error {
            FileError::NotFound => Self::NotFound,
            FileError::PermissionDenied => Self::PermissionDenied,
            FileError::TooLarge { .. } => Self::TooLarge,
            FileError::ResolvesElsewhere { .. } => Self::SymbolicLink,
            FileError::Unavailable { .. } => Self::SftpUnavailable,
            FileError::Failed { .. } => Self::RemoteIo,
        }
    }
}
