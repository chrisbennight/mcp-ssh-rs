//! Explicit upload replacement using the OpenSSH POSIX rename extension.

use russh_sftp::{
    client::RawSftpSession,
    protocol::{FileAttributes, OpenFlags, Packet, StatusCode},
};
use tokio::io::AsyncReadExt as _;

use super::{RemotePath, binary_stream, elsewhere, failed, said};
use crate::{
    connect::Connection,
    transfer::{Failure, PreparedUpload},
};

pub(super) async fn upload(
    connection: &Connection,
    path: &RemotePath,
    stage: &RemotePath,
    input: &mut PreparedUpload,
) -> Result<(), Failure> {
    let mut raw = RawSftpSession::new(binary_stream(connection).await?);
    let version = raw.init().await.map_err(|_| Failure::SftpUnavailable)?;
    if !version
        .extensions
        .get("posix-rename@openssh.com")
        .is_some_and(|version| version == "1")
    {
        let _ = raw.close_session();
        return Err(Failure::UnsupportedOperation);
    }
    let mut chunk_bytes = 64_u64 << 10;
    let mut packet_bytes = None;
    if version
        .extensions
        .get(russh_sftp::extensions::LIMITS)
        .is_some_and(|version| version == "1")
    {
        let limits = russh_sftp::client::rawsession::Limits::from(
            raw.limits().await.map_err(|_| Failure::RemoteIo)?,
        );
        if let Some(write_len) = limits.write_len {
            chunk_bytes = chunk_bytes.min(write_len);
        }
        packet_bytes = limits.packet_len;
        raw.set_limits(limits);
    }
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
        for checked in [path, stage] {
            match raw.lstat(checked.as_str()).await {
                Ok(attributes) if attributes.attrs.is_symlink() => {
                    return Err(elsewhere(checked).into());
                }
                Ok(_) => {}
                Err(source) if said(&source, StatusCode::NoSuchFile) => {}
                Err(source) => return Err(failed(checked, &source).into()),
            }
        }
        let handle = raw
            .open(
                stage.as_str(),
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE,
                FileAttributes {
                    permissions: Some(0o600),
                    ..FileAttributes::empty()
                },
            )
            .await
            .map_err(|source| failed(stage, &source))?
            .handle;
        let written = async {
            if let Some(packet_bytes) = packet_bytes {
                chunk_bytes = chunk_bytes.min(
                    packet_bytes
                        .saturating_sub(handle.len() as u64)
                        .saturating_sub(25),
                );
            }
            if chunk_bytes == 0 {
                return Err(Failure::UnsupportedOperation);
            }
            let mut buffer = vec![0_u8; chunk_bytes as usize];
            let mut offset = 0_u64;
            loop {
                let count = input
                    .reader()
                    .read(&mut buffer)
                    .await
                    .map_err(|_| Failure::RemoteIo)?;
                if count == 0 {
                    break;
                }
                raw.write(
                    &handle,
                    offset,
                    buffer.get(..count).ok_or(Failure::RemoteIo)?.to_vec(),
                )
                .await
                .map_err(|_| Failure::RemoteIo)?;
                offset = offset.checked_add(count as u64).ok_or(Failure::TooLarge)?;
            }
            raw.close(handle).await.map_err(|_| Failure::RemoteIo)?;
            #[derive(serde::Serialize)]
            struct Rename<'a> {
                oldpath: &'a str,
                newpath: &'a str,
            }
            let request = russh_sftp::ser::to_bytes(&Rename {
                oldpath: stage.as_str(),
                newpath: path.as_str(),
            })
            .map_err(|_| Failure::RemoteIo)?;
            match raw
                .extended("posix-rename@openssh.com", request.to_vec())
                .await
            {
                Ok(Packet::Status(status)) if status.status_code == StatusCode::Ok => Ok(()),
                Ok(Packet::Status(_)) => Err(Failure::RemoteIo),
                Ok(_) | Err(_) => Err(Failure::ReplacementUnknown),
            }
        }
        .await;
        if let Err(cause) = written {
            if cause == Failure::ReplacementUnknown {
                return Err(cause);
            }
            if raw.remove(stage.as_str()).await.is_err() {
                tracing::warn!(
                    cause = cause.code(),
                    "staged upload failed and temporary file cleanup was not confirmed"
                );
                return Err(Failure::StagingCleanupFailed);
            }
            return Err(cause);
        }
        Ok(())
    }
    .await;
    let _ = raw.close_session();
    result
}
