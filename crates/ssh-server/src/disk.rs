//! Private anonymous files with bounded asynchronous I/O and independent readers.

use futures_util::stream;
use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use sha2::{Digest as _, Sha256};
use ssh_core::{
    action::FileIdentity,
    transfer::{Failure, Reader},
};
use std::{fs::File, io, os::unix::fs::FileExt as _, path::Path, sync::Arc};
use tokio::{io::AsyncReadExt as _, sync::OwnedSemaphorePermit};
use tokio_util::io::StreamReader;

pub const CHUNK: usize = 256 * 1024;

pub struct DiskFile {
    file: File,
    staging: Option<(Arc<File>, String)>,
    // The permit follows in-flight filesystem work as well as completed readers.
    _permit: Option<OwnedSemaphorePermit>,
}

pub struct Snapshot {
    pub disk: Arc<DiskFile>,
    pub size: u64,
    pub digest: [u8; 32],
}

pub fn directory(path: &Path) -> io::Result<Arc<File>> {
    let directory = Arc::new(File::open(path)?);
    drop(create(Arc::clone(&directory), None, false)?);
    Ok(directory)
}

fn create(
    directory: Arc<File>,
    permit: Option<OwnedSemaphorePermit>,
    publishable: bool,
) -> io::Result<DiskFile> {
    let name = format!(".mcp-ssh-{:032x}.partial", rand::random::<u128>());
    let file = File::from(openat(
        &*directory,
        name.as_str(),
        OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?);
    let staging = if publishable {
        Some((directory, name))
    } else {
        // An unlinked open file retains its contents only for the lifetime of its descriptors.
        unlinkat(&*directory, name.as_str(), UnlinkatFlags::NoRemoveDir)?;
        None
    };
    Ok(DiskFile {
        file,
        staging,
        _permit: permit,
    })
}

pub async fn allocate(
    directory: Arc<File>,
    permit: Option<OwnedSemaphorePermit>,
    publishable: bool,
) -> io::Result<Arc<DiskFile>> {
    tokio::task::spawn_blocking(move || create(directory, permit, publishable).map(Arc::new))
        .await
        .map_err(io::Error::other)?
}

pub async fn receive(
    disk: Arc<DiskFile>,
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    limit: u64,
) -> Result<Arc<Snapshot>, Failure> {
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; CHUNK];
    loop {
        let mut filled = 0_usize;
        while filled < buffer.len() {
            let count = reader
                .read(buffer.get_mut(filled..).ok_or(Failure::RemoteIo)?)
                .await
                .map_err(|_| Failure::RemoteIo)?;
            if count == 0 {
                break;
            }
            filled = filled.checked_add(count).ok_or(Failure::TooLarge)?;
            size.checked_add(filled as u64)
                .filter(|size| *size <= limit)
                .ok_or(Failure::TooLarge)?;
        }
        if filled == 0 {
            break;
        }
        let next = size.checked_add(filled as u64).ok_or(Failure::TooLarge)?;
        let bytes = buffer.get(..filled).ok_or(Failure::RemoteIo)?;
        digest.update(bytes);
        let disk = Arc::clone(&disk);
        buffer = tokio::task::spawn_blocking(move || {
            disk.file.write_all_at(
                buffer
                    .get(..filled)
                    .ok_or_else(|| io::Error::other("invalid write batch"))?,
                size,
            )?;
            Ok::<_, io::Error>(buffer)
        })
        .await
        .map_err(|_| Failure::PublicationUnavailable)?
        .map_err(|_| Failure::PublicationUnavailable)?;
        size = next;
        if filled < CHUNK {
            break;
        }
    }
    Ok(Arc::new(Snapshot {
        disk,
        size,
        digest: digest.finalize().into(),
    }))
}

impl DiskFile {
    pub fn publish(&self, directory: &File, name: &str) -> io::Result<()> {
        let (parent, temporary) = self
            .staging
            .as_ref()
            .ok_or_else(|| io::Error::other("file is not publishable"))?;
        renameat2(
            &**parent,
            temporary.as_str(),
            directory,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )?;
        Ok(())
    }

    pub fn remove(&self) -> io::Result<()> {
        if let Some((directory, name)) = &self.staging {
            match unlinkat(&**directory, name.as_str(), UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(nix::errno::Errno::ENOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
impl Drop for DiskFile {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::warn!(%error, "could not remove staging file");
        }
    }
}

impl Snapshot {
    pub fn identity(&self, uri: String) -> FileIdentity {
        FileIdentity {
            uri,
            bytes: self.size,
            sha256: self
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }

    pub fn reader(self: &Arc<Self>) -> Reader {
        let snapshot = Arc::clone(self);
        let stream = stream::try_unfold((snapshot, 0_u64), |(snapshot, offset)| async move {
            if offset >= snapshot.size {
                return Ok::<_, io::Error>(None);
            }
            let disk = Arc::clone(&snapshot.disk);
            let bytes = tokio::task::spawn_blocking(move || {
                let mut bytes = vec![0; CHUNK];
                let count = disk.file.read_at(&mut bytes, offset)?;
                bytes.truncate(count);
                Ok::<_, io::Error>(bytes)
            })
            .await
            .map_err(io::Error::other)??;
            if bytes.is_empty() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let next = offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("file offset overflow"))?;
            Ok(Some((axum::body::Bytes::from(bytes), (snapshot, next))))
        });
        Box::new(StreamReader::new(Box::pin(stream)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshots_have_independent_readers_and_enforce_the_byte_limit() {
        let directory = directory(&std::env::temp_dir()).unwrap();
        let disk = allocate(Arc::clone(&directory), None, false).await.unwrap();
        let snapshot = receive(disk, &mut std::io::Cursor::new(b"binary\0\xff"), 8)
            .await
            .unwrap();
        let mut first = snapshot.reader();
        let mut second = snapshot.reader();
        let mut prefix = [0; 3];
        first.read_exact(&mut prefix).await.unwrap();
        let mut complete = Vec::new();
        second.read_to_end(&mut complete).await.unwrap();
        assert_eq!(&prefix, b"bin");
        assert_eq!(complete, b"binary\0\xff");
        assert_eq!(
            snapshot.identity(String::new()),
            ssh_core::transfer::identity(String::new(), &complete)
        );
        let disk = allocate(directory, None, false).await.unwrap();
        assert!(matches!(
            receive(disk, &mut std::io::Cursor::new(b"too large"), 8).await,
            Err(Failure::TooLarge)
        ));
    }

    #[tokio::test]
    async fn fragmented_streams_preserve_complete_batches_and_the_final_partial_batch() {
        let bytes: Vec<u8> = (0..CHUNK.saturating_mul(2).saturating_add(17))
            .map(|offset| (offset % 251) as u8)
            .collect();
        let chunks: Vec<_> = bytes
            .chunks(4093)
            .map(|chunk| Ok::<_, io::Error>(axum::body::Bytes::copy_from_slice(chunk)))
            .collect();
        let mut reader = StreamReader::new(stream::iter(chunks));
        let disk = allocate(directory(&std::env::temp_dir()).unwrap(), None, false)
            .await
            .unwrap();
        let snapshot = receive(disk, &mut reader, bytes.len() as u64)
            .await
            .unwrap();
        assert_eq!(
            snapshot.identity(String::new()),
            ssh_core::transfer::identity(String::new(), &bytes)
        );
        let mut received = Vec::new();
        snapshot.reader().read_to_end(&mut received).await.unwrap();
        assert_eq!(received, bytes);
    }

    #[tokio::test]
    #[ignore = "isolated disk batching measurement; run explicitly with --nocapture"]
    async fn disk_batch_benchmark() {
        use std::io::Write as _;
        let bytes: Vec<u8> = (0..4_usize << 20)
            .map(|offset| (offset % 251) as u8)
            .collect();
        for batched in [false, true] {
            let chunks: Vec<_> = bytes
                .chunks(64 << 10)
                .map(|chunk| Ok::<_, io::Error>(axum::body::Bytes::copy_from_slice(chunk)))
                .collect();
            let mut reader = StreamReader::new(stream::iter(chunks));
            let disk = allocate(directory(&std::env::temp_dir()).unwrap(), None, false)
                .await
                .unwrap();
            let started = std::time::Instant::now();
            let snapshot = if batched {
                receive(disk, &mut reader, bytes.len() as u64)
                    .await
                    .unwrap()
            } else {
                let mut size = 0_u64;
                let mut digest = Sha256::new();
                let mut buffer = vec![0; 64 << 10];
                loop {
                    let count = reader.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    let chunk = buffer.get(..count).unwrap();
                    digest.update(chunk);
                    let chunk = chunk.to_vec();
                    let disk = Arc::clone(&disk);
                    tokio::task::spawn_blocking(move || disk.file.write_all_at(&chunk, size))
                        .await
                        .unwrap()
                        .unwrap();
                    size = size.saturating_add(count as u64);
                }
                Arc::new(Snapshot {
                    disk,
                    size,
                    digest: digest.finalize().into(),
                })
            };
            let elapsed = started.elapsed().as_secs_f64();
            assert_eq!(
                snapshot.identity(String::new()),
                ssh_core::transfer::identity(String::new(), &bytes)
            );
            let record = serde_json::json!({"path": if batched { "batched_buffer_reuse" } else { "previous_chunk_copy" }, "bytes": bytes.len(), "seconds": elapsed, "mib_per_second": bytes.len() as f64 / 1048576.0 / elapsed});
            let mut output = std::io::stdout().lock();
            serde_json::to_writer(&mut output, &record).unwrap();
            output.write_all(b"\n").unwrap();
        }
    }

    #[tokio::test]
    async fn disk_full_does_not_produce_a_snapshot() {
        let disk = Arc::new(DiskFile {
            file: std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
            _permit: None,
            staging: None,
        });
        assert!(matches!(
            receive(disk, &mut std::io::Cursor::new(b"data"), 100).await,
            Err(Failure::PublicationUnavailable)
        ));
    }
}
