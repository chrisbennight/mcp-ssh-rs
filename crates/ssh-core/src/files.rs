//! Bounded binary SFTP operations, reachable only through recorded mediation.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{OpenFlags, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use crate::connect::Connection;

// Enough for the result tag, field names, byte count, quotes, and punctuation.

// Fixed entry keys, the largest u64, punctuation, and the list envelope fit
// below these deliberately rounded charges. Counting an upper bound avoids
// allocating the serialized answer merely to learn that it is too large.

// russh-sftp 2.4 accepts response lengths up to u32::MAX and allocates the
// declared length before reading the body. Nothing a bounded operation needs
// is larger than one answer plus ample protocol overhead, so reject a target's
// larger declaration before the dependency sees it.
const MAX_SFTP_FRAME_BYTES: u32 = (1 << 20) + (64 << 10);

/// A transparent SFTP stream that validates each inbound frame before exposing
/// its four-byte length header to the protocol decoder.
///
/// Keeping the header private until it is complete matters: once the decoder
/// sees it, it allocates that declared length before asking for the body.
struct BoundedSftpStream<S> {
    inner: S,
    header: [u8; 4],
    header_read: usize,
    header_exposed: usize,
    body_remaining: usize,
    rejected: bool,
}

impl<S> BoundedSftpStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 4],
            header_read: 0,
            header_exposed: 0,
            body_remaining: 0,
            rejected: false,
        }
    }

    fn invalid_frame() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SFTP response exceeds the operation frame limit",
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BoundedSftpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.rejected {
            return Poll::Ready(Err(Self::invalid_frame()));
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.header_exposed == self.header.len() && self.body_remaining == 0 {
            self.header_read = 0;
            self.header_exposed = 0;
        }

        while self.header_read < self.header.len() {
            let this = &mut *self;
            let offset = this.header_read;
            let (inner, bytes) = (&mut this.inner, &mut this.header);
            let Some(header_bytes) = bytes.get_mut(offset..) else {
                return Poll::Ready(Err(Self::invalid_frame()));
            };
            let mut header = ReadBuf::new(header_bytes);
            match Pin::new(inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(source)) => return Poll::Ready(Err(source)),
                Poll::Ready(Ok(())) if header.filled().is_empty() => {
                    let kind = if self.header_read == 0 {
                        io::ErrorKind::UnexpectedEof
                    } else {
                        io::ErrorKind::InvalidData
                    };
                    return Poll::Ready(Err(io::Error::new(kind, "incomplete SFTP frame header")));
                }
                Poll::Ready(Ok(())) => {
                    let read = header.filled().len();
                    self.header_read = self.header_read.saturating_add(read);
                }
            }
        }

        if self.header_exposed == 0 {
            let declared = u32::from_be_bytes(self.header);
            if declared > MAX_SFTP_FRAME_BYTES {
                self.rejected = true;
                return Poll::Ready(Err(Self::invalid_frame()));
            }
            self.body_remaining = declared as usize;
        }

        if self.header_exposed < self.header.len() {
            let amount = output
                .remaining()
                .min(self.header.len().saturating_sub(self.header_exposed));
            let end = self.header_exposed.saturating_add(amount);
            let Some(header) = self.header.get(self.header_exposed..end) else {
                self.rejected = true;
                return Poll::Ready(Err(Self::invalid_frame()));
            };
            output.put_slice(header);
            self.header_exposed = end;
            return Poll::Ready(Ok(()));
        }

        let amount = output.remaining().min(self.body_remaining).min(32 << 10);
        let mut bytes = [0_u8; 32 << 10];
        let Some(body_bytes) = bytes.get_mut(..amount) else {
            self.rejected = true;
            return Poll::Ready(Err(Self::invalid_frame()));
        };
        let mut body = ReadBuf::new(body_bytes);
        match Pin::new(&mut self.inner).poll_read(cx, &mut body) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(source)) => Poll::Ready(Err(source)),
            Poll::Ready(Ok(())) if body.filled().is_empty() => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete SFTP frame body",
            ))),
            Poll::Ready(Ok(())) => {
                self.body_remaining = self.body_remaining.saturating_sub(body.filled().len());
                output.put_slice(body.filled());
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedSftpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A path on the target.
///
/// Absolute and free of traversal. Not because the target would be confused by
/// `..` — it would resolve it correctly — but because the path is what policy
/// decided about, and a path that resolves elsewhere than it reads is a
/// decision about one file and an operation on another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RemotePath(String);

/// Longest path accepted, which is generous against every filesystem's own
/// limit and bounds what arrives from the wire.
const PATH_MAX: usize = 4096;

impl RemotePath {
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::Empty);
        }
        if raw.len() > PATH_MAX {
            return Err(PathError::TooLong { max: PATH_MAX });
        }
        if !raw.starts_with('/') {
            return Err(PathError::NotAbsolute);
        }
        if raw.contains('\0') {
            return Err(PathError::InteriorNul);
        }
        // One spelling per object, and the one that was written. `..` is the
        // obvious way to name one file and reach another; `.` and an empty
        // component are the quiet ways, because the target resolves
        // `/etc/./shadow` and `/etc//shadow` to exactly what `/etc/shadow`
        // resolves to while a decision, and the record of it, would carry a
        // different string. Refused rather than rewritten: this is what policy
        // will be asked about, and rewriting it here would mean the answer was
        // about something the caller did not say.
        let mut components = raw.split('/');
        // The first is empty because the path is absolute, and a bare "/" ends
        // with an empty last one — neither is a redundant spelling.
        components.next();
        let components: Vec<&str> = components.collect();
        let last_position = components.len().saturating_sub(1);
        for (position, component) in components.iter().enumerate() {
            let last = position == last_position;
            match *component {
                ".." => return Err(PathError::Traversal),
                "." => return Err(PathError::NotOneSpelling),
                "" if !(last && raw == "/") => return Err(PathError::NotOneSpelling),
                _ => {}
            }
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The directory this path names something in.
    ///
    /// The root is its own parent: there is nothing above it to resolve.
    #[must_use]
    pub fn parent(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => parent,
            _ => "/",
        }
    }
}

impl TryFrom<String> for RemotePath {
    type Error = PathError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("a path cannot be empty")]
    Empty,
    #[error("a path may be at most {max} bytes")]
    TooLong { max: usize },
    #[error("a path must be absolute; the working directory is not something this service defines")]
    NotAbsolute,
    #[error("a path containing `..` would be decided about as one file and read as another")]
    Traversal,
    #[error("a path contains a NUL, which cannot cross the wire intact")]
    InteriorNul,
    #[error(
        "a path may be written only one way; `.`, `//` and a trailing `/` name the same file as a different string"
    )]
    NotOneSpelling,
}

/// Upper bound for one binary transfer, enforced again while reading.
pub const MAX_TRANSFER_BYTES: usize = 16 << 20;

async fn binary_session(
    connection: &Connection,
    path: &RemotePath,
) -> Result<SftpSession, FileError> {
    let channel = connection
        .handle()
        .channel_open_session()
        .await
        .map_err(|source| FileError::Unavailable {
            detail: source.to_string(),
        })?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|source| FileError::Unavailable {
            detail: source.to_string(),
        })?;
    let sftp = SftpSession::new(BoundedSftpStream::new(channel.into_stream()))
        .await
        .map_err(|source| FileError::Unavailable {
            detail: source.to_string(),
        })?;
    if let Err(error) = resolves_to_itself(&sftp, path).await {
        let _ = sftp.close().await;
        return Err(error);
    }
    Ok(sftp)
}

/// Bytes remain outside the MCP result and are published only after a complete read.
pub(crate) async fn download(
    connection: &Connection,
    path: &RemotePath,
) -> Result<Vec<u8>, FileError> {
    let sftp = binary_session(connection, path).await?;
    let result = async {
        let mut file = sftp
            .open(path.as_str())
            .await
            .map_err(|source| failed(path, &source))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take((MAX_TRANSFER_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|source| FileError::Failed {
                path: path.as_str().to_owned(),
                detail: source.to_string(),
            })?;
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err(FileError::TooLarge {
                size: bytes.len() as u64,
                max: MAX_TRANSFER_BYTES as u64,
            });
        }
        Ok(bytes)
    }
    .await;
    let _ = sftp.close().await;
    result
}

/// A failed upload may have changed the remote file; callers must never replay it automatically.
pub(crate) async fn upload(
    connection: &Connection,
    path: &RemotePath,
    bytes: &[u8],
    overwrite: bool,
) -> Result<(), FileError> {
    if bytes.len() > MAX_TRANSFER_BYTES {
        return Err(FileError::TooLarge {
            size: bytes.len() as u64,
            max: MAX_TRANSFER_BYTES as u64,
        });
    }
    let sftp = binary_session(connection, path).await?;
    let result = async {
        let mode = if overwrite {
            OpenFlags::TRUNCATE
        } else {
            OpenFlags::EXCLUDE
        };
        let mut file = sftp
            .open_with_flags(path.as_str(), OpenFlags::CREATE | OpenFlags::WRITE | mode)
            .await
            .map_err(|source| failed(path, &source))?;
        file.write_all(bytes)
            .await
            .map_err(|source| FileError::Failed {
                path: path.as_str().to_owned(),
                detail: source.to_string(),
            })?;
        file.shutdown().await.map_err(|source| FileError::Failed {
            path: path.as_str().to_owned(),
            detail: source.to_string(),
        })?;
        Ok(())
    }
    .await;
    let _ = sftp.close().await;
    result
}

/// Whether the target reaches this path without following a link.
///
/// A component of the path may be a link, and then the object opened is not the
/// object named — the same problem as `..`, arriving from the target's side
/// rather than the caller's. Refused rather than followed: what policy decided
/// about is the path as written.
///
/// Asked in two parts rather than by resolving the whole name, because a write
/// may name a file that does not exist yet and a target asked what a missing
/// name resolves to refuses the question. The directory prefix is resolved,
/// which is where a link redirects the whole operation; the last component is
/// asked about with the query that does not follow links, so a link sitting
/// there is seen rather than followed.
///
/// This closes the ordinary case, not a determined race: the target could
/// replace a component between this answer and the open. Making that impossible
/// needs the target's own enforcement, which is where the design puts the
/// boundary that actually holds.
async fn resolves_to_itself(sftp: &SftpSession, path: &RemotePath) -> Result<(), FileError> {
    let resolved = sftp
        .canonicalize(path.parent())
        .await
        .map_err(|source| failed(path, &source))?;
    if resolved != path.parent() {
        return Err(elsewhere(path));
    }
    match sftp.symlink_metadata(path.as_str()).await {
        Ok(attributes) if attributes.is_symlink() => Err(elsewhere(path)),
        Ok(_) => Ok(()),
        // Nothing there to be a link, which is what a write to a new file looks
        // like. Whether the operation needs the path to exist is the
        // operation's own answer, in the target's own words.
        Err(source) if said(&source, StatusCode::NoSuchFile) => Ok(()),
        Err(source) => Err(failed(path, &source)),
    }
}

fn elsewhere(path: &RemotePath) -> FileError {
    FileError::ResolvesElsewhere {
        path: path.as_str().to_owned(),
    }
}

/// Whether the target answered with a particular status rather than failing
/// some other way.
///
/// The protocol says several things through a status that are not failures —
/// the end of a directory, a name that is not there — and telling them apart
/// from a refusal is the difference between an answer and a wrong answer.
fn said(source: &russh_sftp::client::error::Error, code: StatusCode) -> bool {
    matches!(
        source,
        russh_sftp::client::error::Error::Status(status) if status.status_code == code
    )
}

/// One shape of failure for anything the target refused.
///
/// The path is named because the caller supplied it, and the target's own words
/// are carried because "permission denied" and "no such file" are different
/// facts an operator needs. Nothing here reads the file to say more.
fn failed(path: &RemotePath, source: &russh_sftp::client::error::Error) -> FileError {
    if said(source, StatusCode::NoSuchFile) {
        return FileError::NotFound;
    }
    if said(source, StatusCode::PermissionDenied) {
        return FileError::PermissionDenied;
    }
    FileError::Failed {
        path: path.as_str().to_owned(),
        detail: source.to_string(),
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum FileError {
    #[error("the remote file or directory was not found")]
    NotFound,
    #[error("the remote account was denied file access")]
    PermissionDenied,
    #[error("SFTP is unavailable: {detail}")]
    Unavailable { detail: String },
    #[error("{path} could not be operated on: {detail}")]
    Failed { path: String, detail: String },
    #[error("{size} bytes exceeds the transfer limit of {max}")]
    TooLarge { size: u64, max: u64 },
    #[error("{path} resolves through a symbolic link")]
    ResolvesElsewhere { path: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use russh::keys::ssh_key;
    use russh::server::{self, Auth, Msg, Server as _};
    use russh::{Channel, ChannelId, keys};
    use russh_sftp::protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, Status, StatusCode, Version,
    };
    use tokio::net::TcpListener;

    use super::*;
    use crate::connect::{Connector, CredentialError, CredentialSource, Timeouts};
    use crate::registry::{CredentialRef, PinnedHostKey, Registry};
    use crate::secret::Secret;
    use crate::{HostId, RoleId};

    /// A target that serves a real directory over the real protocol.
    ///
    /// The point of using `russh-sftp`'s own server rather than a stub is that
    /// both ends then encode and decode actual SFTP packets. A fake that
    /// returned what this module expected would agree with this module's
    /// reading of the protocol and establish nothing about it.
    #[derive(Clone)]
    struct FileServer {
        root: PathBuf,
        /// Channels kept until their subsystem request arrives, because the
        /// SFTP server takes the channel itself rather than a channel id.
        channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    }

    impl server::Server for FileServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for FileServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _key: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.channels.lock().await.insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if name != "sftp" {
                let _ = session.channel_failure(channel);
                return Ok(());
            }
            let _ = session.channel_success(channel);
            let taken = self.channels.lock().await.remove(&channel).unwrap();
            russh_sftp::server::run(
                taken.into_stream(),
                Files {
                    root: self.root.clone(),
                    open: HashMap::new(),
                },
            )
            .await;
            Ok(())
        }
    }

    /// The directory the target is serving.
    ///
    /// Backed by a real temporary directory rather than a map in memory, so a
    /// read that says a file is 900 bytes is answering from the same place the
    /// bytes come from.
    struct Files {
        root: PathBuf,
        open: HashMap<String, PathBuf>,
    }

    impl Files {
        /// Resolves a client path inside the served directory.
        fn resolve(&self, path: &str) -> PathBuf {
            self.root.join(path.trim_start_matches('/'))
        }

        fn attributes(path: &Path) -> Option<FileAttributes> {
            let meta = std::fs::metadata(path).ok()?;
            let mut attrs = FileAttributes {
                size: Some(meta.len()),
                ..FileAttributes::default()
            };
            attrs.set_dir(meta.is_dir());
            attrs.set_regular(meta.is_file());
            Some(attrs)
        }
    }

    impl russh_sftp::server::Handler for Files {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _version: u32,
            _extensions: HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            pflags: russh_sftp::protocol::OpenFlags,
            _attrs: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            let path = self.resolve(&filename);
            let exists = path.exists();
            if exists && pflags.contains(OpenFlags::EXCLUDE) {
                return Err(StatusCode::Failure);
            }
            if !exists && !pflags.contains(OpenFlags::CREATE) {
                return Err(StatusCode::NoSuchFile);
            }
            // CREATE makes a file that is not there; TRUNCATE is what empties
            // one that is. Conflating them would let a client that asked only
            // to create still pass a test about replacing what was there.
            if !exists || pflags.contains(OpenFlags::TRUNCATE) {
                std::fs::write(&path, b"").map_err(|_| StatusCode::Failure)?;
            }
            let handle = format!("f{id}");
            self.open.insert(handle.clone(), path);
            Ok(Handle { id, handle })
        }

        async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
            self.open.remove(&handle);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en-US".to_owned(),
            })
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> Result<Data, Self::Error> {
            let path = self.open.get(&handle).ok_or(StatusCode::Failure)?;
            let bytes = std::fs::read(path).map_err(|_| StatusCode::Failure)?;
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            if start >= bytes.len() {
                return Err(StatusCode::Eof);
            }
            let end = start
                .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
                .min(bytes.len());
            Ok(Data {
                id,
                data: bytes.get(start..end).unwrap_or_default().to_vec(),
            })
        }

        async fn write(
            &mut self,
            id: u32,
            handle: String,
            _offset: u64,
            data: Vec<u8>,
        ) -> Result<Status, Self::Error> {
            let path = self.open.get(&handle).ok_or(StatusCode::Failure)?;
            let mut existing = std::fs::read(path).unwrap_or_default();
            existing.extend_from_slice(&data);
            std::fs::write(path, &existing).map_err(|_| StatusCode::Failure)?;
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en-US".to_owned(),
            })
        }

        async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let resolved = self.resolve(&path);
            Ok(Attrs {
                id,
                attrs: Files::attributes(&resolved).ok_or(StatusCode::NoSuchFile)?,
            })
        }

        /// Unlike `stat`, this does not follow a link: it describes the link.
        /// That distinction is the whole content of the question the client
        /// asks with it, so answering it with `stat` would answer nothing.
        async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let resolved = self.resolve(&path);
            let meta = std::fs::symlink_metadata(&resolved).map_err(|_| StatusCode::NoSuchFile)?;
            let mut attrs = FileAttributes {
                size: Some(meta.len()),
                ..FileAttributes::default()
            };
            attrs.set_dir(meta.is_dir());
            attrs.set_regular(meta.is_file());
            attrs.set_symlink(meta.file_type().is_symlink());
            Ok(Attrs { id, attrs })
        }

        async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
            let path = self.open.get(&handle).ok_or(StatusCode::Failure)?.clone();
            Ok(Attrs {
                id,
                attrs: Files::attributes(&path).ok_or(StatusCode::NoSuchFile)?,
            })
        }

        async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
            // A target resolving a path to a different one is what a symbolic
            // link looks like from here, so the harness can be one.
            if path.starts_with("/link") {
                return Ok(Name {
                    id,
                    files: vec![File::dummy("/somewhere-else".to_owned())],
                });
            }
            // OpenSSH's own server resolves the whole name and refuses one
            // whose last component is not there. A harness that echoed any path
            // back would agree with a client asking about a file it is about to
            // create, and hide that a real target would refuse the question.
            if !self.resolve(&path).exists() {
                return Err(StatusCode::NoSuchFile);
            }
            Ok(Name {
                id,
                files: vec![File::dummy(path)],
            })
        }
    }

    struct OneKey(String);

    impl CredentialSource for OneKey {
        async fn fetch(&self, _: &CredentialRef) -> Result<Secret<String>, CredentialError> {
            Ok(Secret::new(self.0.clone()))
        }
    }

    /// A connection to a target serving a temporary directory.
    async fn served(root: &Path) -> Connection {
        let host_key =
            keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519).unwrap();
        let pinned =
            PinnedHostKey::parse(&host_key.public_key().to_openssh().unwrap().to_string()).unwrap();
        let config = Arc::new(server::Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            auth_rejection_time: Duration::from_millis(1),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let mut target_server = FileServer {
            root: root.to_path_buf(),
            channels: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };
        tokio::spawn(async move {
            let _ = target_server.run_on_socket(config, &listener).await;
        });

        let client_key = keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let connector = Connector::new(OneKey(client_key), Timeouts::default());
        // Resolved from a registry, as production does: a target names the host
        // and role it was looked up for, and only a lookup can make one.
        let registry = Registry::from_json(&format!(
            r#"{{"testhost": {{"address": "{address}", "host_key": "{key}",
                 "roles": {{"readonly": {{"user": "agent",
                            "access_class": "read_only", "credential": "mcp-ssh/test/readonly"}}}}}}}}"#,
            address = address,
            key = pinned.as_str(),
        ))
        .unwrap();
        let target = registry
            .resolve(
                &HostId::parse("testhost").unwrap(),
                &RoleId::parse("readonly").unwrap(),
            )
            .unwrap();
        connector.connect(&target).await.unwrap()
    }

    /// A directory that goes away with the test.
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-ssh-files-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn transfer_failures_preserve_remote_and_publication_causes() {
        use crate::audit::Ledger;
        use crate::clock::TestClock;
        use crate::policy::{Engine, ReviewMode};
        use crate::run::{Limits, RunState, Runs};
        use crate::session::{Lifetime, Purpose, SessionStore};
        use crate::transfer::{DownloadSink, Failure, Payload};

        struct Unavailable;
        impl DownloadSink for Unavailable {
            fn publish(&self, _: Vec<u8>) -> Result<crate::action::FileIdentity, String> {
                Err("private storage detail must not escape".to_owned())
            }
        }
        let root = scratch();
        std::fs::write(root.join("present"), b"bytes").unwrap();
        let large = std::fs::File::create(root.join("large")).unwrap();
        large.set_len(MAX_TRANSFER_BYTES as u64 + 1).unwrap();
        let connection = Arc::new(served(&root).await);
        let session = SessionStore::new(
            TestClock::at(1000),
            Lifetime {
                idle: 10000,
                max: 60000,
                grace: 5000,
            },
            1,
        )
        .open(
            crate::PrincipalId::parse("alice").unwrap(),
            HostId::parse("testhost").unwrap(),
            RoleId::parse("readonly").unwrap(),
            Purpose::parse("verify file failures").unwrap(),
            crate::AccessClass::ReadOnly,
        )
        .unwrap();
        let ledger = Ledger::new(TestClock::at(1000));
        let runs = Runs::new(Limits::default());
        for (remote, cause) in [
            ("/missing", Failure::NotFound),
            ("/large", Failure::TooLarge),
            ("/present", Failure::PublicationUnavailable),
        ] {
            let action = crate::action::Action::download(path(remote)).unwrap();
            let decision = Engine::new(ReviewMode::Disabled).decide_action(&session, action);
            let receipt = ledger
                .record_intent(
                    decision,
                    crate::command::CommandIntent::parse("verify file failures").unwrap(),
                )
                .unwrap()
                .into_parts()
                .1
                .unwrap();
            let mut outcome = runs
                .transfer(
                    connection.clone(),
                    receipt,
                    Payload::Download(Arc::new(Unavailable)),
                )
                .await
                .unwrap();
            if outcome.still_running() {
                outcome = runs
                    .wait(outcome.run(), Duration::from_secs(10))
                    .await
                    .unwrap();
            }
            assert_eq!(
                outcome.state(),
                RunState::TransferFailed {
                    cause,
                    remote_write_may_be_partial: false
                }
            );
            assert!(outcome.file().is_none());
            assert!(!outcome.stderr().text.contains("private storage"));
            let later = runs.wait(outcome.run(), Duration::ZERO).await.unwrap();
            assert_eq!(later.state(), outcome.state());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn binary_transfer_preserves_bytes_and_requires_explicit_replacement() {
        let root = scratch();
        let connection = served(&root).await;
        let remote = path("/binary");
        let bytes = [0_u8, 255, 254, 128, 10].repeat(15000);
        upload(&connection, &remote, &bytes, false).await.unwrap();
        assert_eq!(download(&connection, &remote).await.unwrap(), bytes);
        assert!(
            upload(&connection, &remote, b"replacement", false)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(root.join("binary")).unwrap(), bytes);
        upload(&connection, &remote, b"replacement", true)
            .await
            .unwrap();
        assert_eq!(
            download(&connection, &remote).await.unwrap(),
            b"replacement"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn path(raw: &str) -> RemotePath {
        RemotePath::parse(raw).unwrap()
    }

    /// The length is rejected before it reaches the SFTP decoder. Testing only
    /// the final listing size would miss the decoder's allocation from this
    /// target-controlled field.
    #[tokio::test]
    async fn an_oversized_sftp_frame_is_rejected_before_its_header_is_exposed() {
        let (mut target, stream) = tokio::io::duplex(64);
        target
            .write_all(&MAX_SFTP_FRAME_BYTES.saturating_add(1).to_be_bytes())
            .await
            .unwrap();
        drop(target);

        let mut guarded = BoundedSftpStream::new(stream);
        let mut header = [0_u8; 4];
        let refused = guarded.read_exact(&mut header).await.unwrap_err();

        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        assert_eq!(header, [0; 4], "the rejected header reached the decoder");
    }

    /// Valid frames cross the guard unchanged, including a second header after
    /// the first body. The guard is a framing boundary, not a new protocol.
    #[tokio::test]
    async fn bounded_sftp_frames_cross_the_guard_unchanged() {
        let (mut target, stream) = tokio::io::duplex(64);
        let expected = [
            3_u32.to_be_bytes().as_slice(),
            b"abc",
            2_u32.to_be_bytes().as_slice(),
            b"de",
        ]
        .concat();
        target.write_all(&expected).await.unwrap();
        drop(target);

        let mut guarded = BoundedSftpStream::new(stream);
        let mut actual = vec![0_u8; expected.len()];
        guarded.read_exact(&mut actual).await.unwrap();

        assert_eq!(actual, expected);
    }

    /// A path is what policy decided about, so anything that could resolve
    /// somewhere else is refused before a decision is made about it.
    #[test]
    fn a_path_that_could_resolve_elsewhere_is_refused() {
        for (raw, expected) in [
            ("", PathError::Empty),
            ("etc/hosts", PathError::NotAbsolute),
            ("../etc/hosts", PathError::NotAbsolute),
            ("/etc/../etc/shadow", PathError::Traversal),
            ("/var/log/..", PathError::Traversal),
            ("/etc/ho\0sts", PathError::InteriorNul),
            // The quiet spellings: the target resolves each of these to
            // exactly what `/etc/shadow` resolves to, while a decision about
            // one of them, and the record of it, would carry a different
            // string. One object, one way to name it.
            ("/etc/./shadow", PathError::NotOneSpelling),
            ("/etc//shadow", PathError::NotOneSpelling),
            ("/etc/shadow/", PathError::NotOneSpelling),
            ("/.", PathError::NotOneSpelling),
        ] {
            assert_eq!(RemotePath::parse(raw), Err(expected), "accepted {raw:?}");
        }
        assert_eq!(
            RemotePath::parse(&"/".repeat(PATH_MAX + 1)),
            Err(PathError::TooLong { max: PATH_MAX })
        );

        // A file whose own name contains dots is not traversal, and the root
        // is the one path whose last component is legitimately empty.
        assert!(RemotePath::parse("/").is_ok());
        assert!(RemotePath::parse("/etc/hosts").is_ok());
        assert!(RemotePath::parse("/etc/.hidden").is_ok());
        assert!(RemotePath::parse("/etc/..hidden").is_ok());
        assert!(RemotePath::parse("/var/log/syslog.1").is_ok());
        assert!(
            serde_json::from_str::<RemotePath>(r#""../etc/passwd""#).is_err(),
            "a traversing path deserialized"
        );
    }
}
