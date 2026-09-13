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
