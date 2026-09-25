//! Immutable input and byte publication boundary for mediated transfers.

use crate::action::FileIdentity;
use crate::files::FileError;
use sha2::{Digest as _, Sha256};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::io::AsyncRead;

pub type Reader = Box<dyn AsyncRead + Unpin + Send>;
pub type TransferFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FileIdentity, Failure>> + Send + 'a>>;

/// A reader of a completed snapshot whose identity was established before review.
pub struct PreparedUpload {
    identity: FileIdentity,
    reader: Reader,
}

impl PreparedUpload {
    /// Adapters supply a completed immutable snapshot, its matching identity, and a reader at byte zero.
    pub fn from_reader(identity: FileIdentity, reader: Reader) -> Self {
        Self { identity, reader }
    }

    #[cfg(test)]
    pub fn new(uri: String, bytes: Vec<u8>) -> Result<Self, FileError> {
        Ok(Self::from_reader(
            identity(uri, &bytes),
            Box::new(std::io::Cursor::new(bytes)),
        ))
    }

    pub const fn identity(&self) -> &FileIdentity {
        &self.identity
    }
    pub(crate) fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut *self.reader
    }
}

/// Receives a stream into reserved storage and publishes only complete content.
pub trait DownloadSink: Send + Sync + 'static {
    fn receive<'a>(&'a self, reader: &'a mut (dyn AsyncRead + Unpin + Send)) -> TransferFuture<'a>;
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
    WorkerStopped,
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
            Self::WorkerStopped => "worker_stopped",
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
            Self::WorkerStopped => "The transfer worker ended unexpectedly.",
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
