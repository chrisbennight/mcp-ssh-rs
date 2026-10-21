//! Bounded metadata and directory reads over the raw SFTP interface.

use std::sync::Arc;

use russh_sftp::{
    client::RawSftpSession,
    protocol::{FileAttributes, StatusCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;

use super::{RemotePath, binary_stream, download, elsewhere, failed, said};
use crate::{
    connect::Connection,
    transfer::{DownloadSink, Failure, TransferFuture},
};

pub const MAX_DIRECTORY_ENTRIES: usize = 128;
pub const MAX_DIRECTORY_BYTES: usize = 64 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InfoOperation {
    Stat,
    List,
    Checksum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub kind: FileKind,
    pub bytes: Option<u64>,
    pub permissions: Option<u32>,
    pub modified: Option<u32>,
}

impl From<FileAttributes> for Metadata {
    fn from(attributes: FileAttributes) -> Self {
        Self {
            kind: match attributes.permissions.map(|mode| mode & 0o170000) {
                Some(0o100000) => FileKind::File,
                Some(0o040000) => FileKind::Directory,
                _ => FileKind::Other,
            },
            bytes: attributes.size,
            permissions: attributes.permissions.map(|mode| mode & 0o7777),
            modified: attributes.mtime,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    /// Recognized secret material in a filename is withheld.
    pub name: Option<String>,
    pub metadata: Metadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileInfo {
    Stat {
        metadata: Metadata,
    },
    List {
        entries: Vec<DirectoryEntry>,
        truncated: bool,
    },
    Checksum {
        bytes: u64,
        sha256: String,
    },
}

impl FileInfo {
    /// Checks metadata recovered from an external audit source.
    pub fn is_bounded(&self) -> bool {
        match self {
            Self::Stat { .. } => true,
            Self::List { entries, .. } => {
                entries.len() <= MAX_DIRECTORY_ENTRIES
                    && entries
                        .iter()
                        .try_fold(128_usize, |charge, entry| {
                            let name = entry.name.as_deref().unwrap_or_default();
                            if name.len() > 4096
                                || name.contains(['/', '\0'])
                                || crate::audit::secret_shape(name).is_some()
                            {
                                return None;
                            }
                            charge.checked_add(name.len().saturating_mul(6).saturating_add(256))
                        })
                        .is_some_and(|charge| charge <= MAX_DIRECTORY_BYTES)
            }
            Self::Checksum { sha256, .. } => {
                sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
        }
    }
}

pub(crate) async fn inspect(
    connection: &Connection,
    path: &RemotePath,
    operation: InfoOperation,
    checksum_limit: u64,
    window: super::DownloadWindow,
    bytes: Arc<std::sync::atomic::AtomicU64>,
) -> Result<FileInfo, Failure> {
    if operation == InfoOperation::Checksum {
        let sink = crate::transfer::CountingSink {
            inner: Arc::new(ChecksumSink(checksum_limit)),
            bytes,
        };
        let digest = download(connection, path, &sink, window).await?;
        return Ok(FileInfo::Checksum {
            bytes: digest.bytes,
            sha256: digest.sha256,
        });
    }
    let raw = RawSftpSession::new(binary_stream(connection).await?);
    raw.init().await.map_err(|_| Failure::SftpUnavailable)?;
    let result = async {
        let resolved = raw
            .realpath(path.parent())
            .await
            .map_err(|source| failed(path, &source))?;
        if resolved
            .files
            .first()
            .is_none_or(|file| file.filename != path.parent())
        {
            return Err(elsewhere(path).into());
        }
        let attributes = raw
            .lstat(path.as_str())
            .await
            .map_err(|source| failed(path, &source))?
            .attrs;
        if attributes.is_symlink() {
            return Err(elsewhere(path).into());
        }
        if operation == InfoOperation::Stat {
            return Ok(FileInfo::Stat {
                metadata: attributes.into(),
            });
        }
        let handle = raw
            .opendir(path.as_str())
            .await
            .map_err(|source| failed(path, &source))?
            .handle;
        let mut entries = Vec::new();
        let mut charge = 128_usize;
        let mut truncated = false;
        let mut packets = 0_usize;
        'read: loop {
            if packets == MAX_DIRECTORY_ENTRIES {
                truncated = true;
                break;
            }
            packets = packets.saturating_add(1);
            let packet = match raw.readdir(&handle).await {
                Ok(packet) => packet,
                Err(source) if said(&source, StatusCode::Eof) => break,
                Err(source) => return Err(failed(path, &source).into()),
            };
            if packet.files.is_empty() {
                return Err(Failure::RemoteIo);
            }
            for file in packet.files {
                if file.filename == "." || file.filename == ".." {
                    continue;
                }
                if file.filename.len() > 4096 || file.filename.contains(['/', '\0']) {
                    return Err(Failure::RemoteIo);
                }
                let name = if crate::audit::secret_shape(&file.filename).is_none() {
                    Some(file.filename)
                } else {
                    None
                };
                let cost = name
                    .as_ref()
                    .map_or(0, String::len)
                    .saturating_mul(6)
                    .saturating_add(256);
                if entries.len() == MAX_DIRECTORY_ENTRIES
                    || charge.saturating_add(cost) > MAX_DIRECTORY_BYTES
                {
                    truncated = true;
                    break 'read;
                }
                charge = charge.saturating_add(cost);
                entries.push(DirectoryEntry {
                    name,
                    metadata: file.attrs.into(),
                });
            }
        }
        // The session owns its directory handle and closes it on teardown.
        Ok(FileInfo::List { entries, truncated })
    }
    .await;
    let _ = raw.close_session();
    result
}

struct ChecksumSink(u64);
impl DownloadSink for ChecksumSink {
    fn receive<'a>(
        &'a self,
        reader: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> TransferFuture<'a> {
        Box::pin(async move {
            let mut digest = Sha256::new();
            let mut bytes = 0_u64;
            let mut buffer = vec![0_u8; 64 << 10];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .await
                    .map_err(|_| Failure::RemoteIo)?;
                if read == 0 {
                    break;
                }
                bytes = bytes.checked_add(read as u64).ok_or(Failure::TooLarge)?;
                if bytes > self.0 {
                    return Err(Failure::TooLarge);
                }
                digest.update(buffer.get(..read).ok_or(Failure::RemoteIo)?);
            }
            Ok(crate::action::FileIdentity {
                uri: String::new(),
                bytes,
                sha256: digest
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            })
        })
    }
}
