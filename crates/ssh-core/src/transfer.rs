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
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl PreparedUpload {
    /// Adapters supply a completed immutable snapshot, its matching identity, and a reader at byte zero.
    pub fn from_reader(identity: FileIdentity, reader: Reader) -> Self {
        Self {
            identity,
            reader,
            release: None,
        }
    }

    /// Frees the source once its content has been written to the target.
    ///
    /// A source is a transfer buffer, not storage: after a successful write
    /// nothing needs it, and keeping it would hold capacity the caller's next
    /// transfer needs. Only success runs this. A failed, refused, or
    /// unapproved upload keeps its source, so an investigated retry does not
    /// have to send the bytes again.
    #[must_use]
    pub fn released_on_success(mut self, release: impl FnOnce() + Send + 'static) -> Self {
        self.release = Some(Box::new(release));
        self
    }

    pub(crate) fn counted(mut self, bytes: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.reader = Box::new(CountingReader {
            inner: self.reader,
            bytes,
        });
        self
    }

    /// Ends an upload whose remote write succeeded and will be reported so.
    ///
    /// The reader is closed before the release runs, so the source is no
    /// longer in use by this upload when it is freed.
    pub fn succeeded(self) -> FileIdentity {
        let Self {
            identity,
            reader,
            release,
        } = self;
        drop(reader);
        if let Some(release) = release {
            release();
        }
        identity
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

pub(crate) struct CountingReader<R> {
    pub inner: R,
    pub bytes: Arc<std::sync::atomic::AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.bytes.fetch_add(
            buf.filled().len().saturating_sub(before) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        result
    }
}

pub(crate) struct CountingSink {
    pub inner: Arc<dyn DownloadSink>,
    pub bytes: Arc<std::sync::atomic::AtomicU64>,
}

impl DownloadSink for CountingSink {
    fn receive<'a>(&'a self, reader: &'a mut (dyn AsyncRead + Unpin + Send)) -> TransferFuture<'a> {
        Box::pin(async move {
            let mut reader = CountingReader {
                inner: reader,
                bytes: Arc::clone(&self.bytes),
            };
            self.inner.receive(&mut reader).await
        })
    }
}

pub(crate) enum Payload {
    Download(Arc<dyn DownloadSink>),
    FileInfo,
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
    Cancelled,
    UnsupportedOperation,
    ReplacementUnknown,
    StagingCleanupFailed,
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
            Self::Cancelled => "cancelled",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::ReplacementUnknown => "replacement_unknown",
            Self::StagingCleanupFailed => "staging_cleanup_failed",
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
            Self::Cancelled => "The transfer was cancelled locally; remote work may be incomplete.",
            Self::UnsupportedOperation => "The SFTP peer does not support the requested operation.",
            Self::ReplacementUnknown => {
                "The replacement acknowledgement was lost; the destination may have been replaced. Investigate before retrying."
            }
            Self::StagingCleanupFailed => {
                "The staged operation failed and temporary file removal was not confirmed; inspect both named paths before retrying."
            }
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
