//! Reading and writing files on a target, as operations rather than commands.
//!
//! A file can be reached by running `cat`, and that is how the execution path
//! would do it. Doing it as an operation instead buys three things:
//!
//! - **No shell.** There is no command line, so there is nothing to quote and
//!   no login shell parsing anything. The whole class of defects the command
//!   path spends its care on does not arise here.
//! - **A path policy can bind to.** A decision about `cat /etc/shadow` has to
//!   find the path among a command's arguments; a decision about reading
//!   `/etc/shadow` is about the path itself.
//! - **A bounded answer.** A read says how much it will return before it
//!   returns it, rather than discovering that a log file was a gigabyte.
//!
//! What this does *not* change is who the service is on the target. The role's
//! account is still what the target's own permissions apply to, and it remains
//! the boundary that holds when everything here is wrong.
//!
//! The executor itself is deliberately private until the mediated path can
//! require a recorded policy decision. The compiler keeps dependent crates
//! from reaching the target through this raw layer in the meantime:
//!
//! ```compile_fail
//! use ssh_core::files::perform;
//! ```

#![expect(
    dead_code,
    reason = "the raw executor becomes reachable only through the mediated file surface"
)]
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use russh_sftp::client::SftpSession;
use russh_sftp::client::rawsession::RawSftpSession;
use russh_sftp::protocol::{OpenFlags, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use crate::connect::Connection;

// Enough for the result tag, field names, byte count, quotes, and punctuation.
const READ_ENVELOPE_BYTES: usize = 64;

/// Most encoded bytes any single operation answer can occupy.
const MAX_ANSWER_BYTES: usize = (1 << 20) + READ_ENVELOPE_BYTES;

/// Most bytes a single read returns.
///
/// A file operation answers in one piece, so this is also how much a caller can
/// make the service hold at once. Larger files are what the out-of-band channel
/// is for; until that exists, a read that would exceed this is refused rather
/// than silently truncated, because a truncated configuration file read as if
/// it were whole is worse than no answer.
pub const MAX_READ_BYTES: u64 = 1 << 20;

/// Most bytes a single write accepts.
pub const MAX_WRITE_BYTES: usize = 1 << 20;

/// Most entries a single listing returns.
///
/// Generous for a directory somebody is reading deliberately, and far short of
/// what it takes to make this service hold a directory that is being used as a
/// queue.
pub const MAX_LISTED_ENTRIES: usize = 4096;

/// Most encoded bytes a single listing answer can occupy.
pub const MAX_LISTED_BYTES: usize = MAX_ANSWER_BYTES;

// Fixed entry keys, the largest u64, punctuation, and the list envelope fit
// below these deliberately rounded charges. Counting an upper bound avoids
// allocating the serialized answer merely to learn that it is too large.
const LIST_ENTRY_OVERHEAD: usize = 96;
const LIST_ENVELOPE_BYTES: usize = 64;

/// Bytes this string occupies inside JSON, conservatively.
///
/// Control characters may become `\u00xx`; quote and backslash gain one
/// escape byte; every other scalar stays no larger than its UTF-8 spelling.
fn json_string_weight(value: &str) -> usize {
    value.chars().fold(0_usize, |total, character| {
        let encoded = match character {
            '"' | '\\' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        total.saturating_add(encoded)
    })
}

fn listed_weight(name: &str) -> usize {
    json_string_weight(name).saturating_add(LIST_ENTRY_OVERHEAD)
}

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

/// What is being done to a file.
///
/// Named as its own type rather than passed as a boolean, because this is what
/// a policy decision and an audit record are *about*: "wrote to /etc/hosts" and
/// "read /etc/hosts" are different events and must not be one event with a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOp {
    Read,
    Write,
    List,
    Stat,
}

impl FileOp {
    /// The name this operation is recorded and decided under.
    ///
    /// The prefix distinguishes file operations in the audit record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "file.read",
            Self::Write => "file.write",
            Self::List => "file.list",
            Self::Stat => "file.stat",
        }
    }
}

/// What a file was found to be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub name: String,
    pub directory: bool,
    /// Absent when the target did not say.
    ///
    /// Not zero. A target is allowed to omit it, and reporting an empty file
    /// where the answer was "no answer" is the kind of confident wrongness a
    /// caller cannot detect — it would read a file it was told was empty and
    /// conclude the file was empty.
    pub size: Option<u64>,
}

/// The result of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FileOutcome {
    /// File contents, as text.
    Read { text: String, bytes: u64 },
    /// Bytes written.
    Written { bytes: u64 },
    /// A directory's entries.
    Listed { entries: Vec<Entry> },
    /// What a path is.
    Stated { entry: Entry },
}

/// Performs one file operation over an established connection.
///
/// A fresh SFTP session per operation rather than one held open: a session is
/// cheap next to the SSH handshake the connection already paid for, and holding
/// one means owning its lifetime against a connection that can drop underneath
/// it.
pub(crate) async fn perform(
    connection: &Connection,
    op: FileOp,
    path: &RemotePath,
    content: Option<&str>,
) -> Result<FileOutcome, FileError> {
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
    let stream = BoundedSftpStream::new(channel.into_stream());
    // Listing runs on the raw protocol rather than the convenience wrapper.
    // The wrapper's `read_dir` reads a directory to its end before returning,
    // so a bound applied to its result bounds only what is copied out of it —
    // the service has already taken the whole directory into memory by then,
    // which is the thing the bound exists to prevent.
    if op == FileOp::List {
        return list(stream, path).await;
    }

    let sftp = SftpSession::new(stream)
        .await
        .map_err(|source| FileError::Unavailable {
            detail: source.to_string(),
        })?;
    resolves_to_itself(&sftp, path).await?;

    let outcome = match op {
        FileOp::Read => read(&sftp, path).await,
        FileOp::Write => write(&sftp, path, content.ok_or(FileError::NothingToWrite)?).await,
        FileOp::Stat => stat(&sftp, path).await,
        // Answered above, on the raw protocol, and returned before this point.
        FileOp::List => Err(FileError::Unavailable {
            detail: "listing does not run here".to_owned(),
        }),
    };
    // Closed whichever way the operation went, so a failed operation does not
    // leave a channel open on the target for the life of the session.
    let _ = sftp.close().await;
    outcome
}

async fn read(sftp: &SftpSession, path: &RemotePath) -> Result<FileOutcome, FileError> {
    // Asked about before opened. A read that discovers the size by running out
    // of memory is not a bounded read.
    let metadata = sftp
        .metadata(path.as_str())
        .await
        .map_err(|source| failed(path, &source))?;
    let size = metadata.size.unwrap_or_default();
    if size > MAX_READ_BYTES {
        return Err(FileError::TooLarge {
            size,
            max: MAX_READ_BYTES,
        });
    }

    let mut file = sftp
        .open(path.as_str())
        .await
        .map_err(|source| failed(path, &source))?;
    let mut bytes = Vec::new();
    // Bounded again while reading: the size was read a moment ago and the file
    // may have grown since, and this is the limit that actually holds.
    let mut reader = (&mut file).take(MAX_READ_BYTES.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|source| FileError::Failed {
            path: path.as_str().to_owned(),
            detail: source.to_string(),
        })?;
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read > MAX_READ_BYTES {
        return Err(FileError::TooLarge {
            size: read,
            max: MAX_READ_BYTES,
        });
    }

    // Text, because the answer travels in a tool result. Binary content is what
    // the out-of-band channel is for, and refusing here is better than emitting
    // replacement characters that read as if the file contained them.
    let text = String::from_utf8(bytes).map_err(|_| FileError::NotText {
        path: path.as_str().to_owned(),
    })?;
    let answer_bytes = READ_ENVELOPE_BYTES.saturating_add(json_string_weight(text.as_str()));
    if answer_bytes > MAX_ANSWER_BYTES {
        return Err(FileError::AnswerTooLarge {
            path: path.as_str().to_owned(),
            max: MAX_ANSWER_BYTES,
        });
    }
    Ok(FileOutcome::Read { bytes: read, text })
}

async fn write(
    sftp: &SftpSession,
    path: &RemotePath,
    content: &str,
) -> Result<FileOutcome, FileError> {
    if content.len() > MAX_WRITE_BYTES {
        return Err(FileError::TooLarge {
            size: u64::try_from(content.len()).unwrap_or(u64::MAX),
            max: u64::try_from(MAX_WRITE_BYTES).unwrap_or(u64::MAX),
        });
    }
    let mut file = sftp
        .open_with_flags(
            path.as_str(),
            // Truncating rather than appending: a write replaces the file's
            // contents, which is what was decided about. An append would make
            // the result depend on what was already there.
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|source| failed(path, &source))?;
    file.write_all(content.as_bytes())
        .await
        .map_err(|source| FileError::Failed {
            path: path.as_str().to_owned(),
            detail: source.to_string(),
        })?;
    // Flushed explicitly: dropping the handle would end the operation without
    // anything having established that the bytes arrived.
    file.flush().await.map_err(|source| FileError::Failed {
        path: path.as_str().to_owned(),
        detail: source.to_string(),
    })?;
    Ok(FileOutcome::Written {
        bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
    })
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

async fn list<S>(stream: S, path: &RemotePath) -> Result<FileOutcome, FileError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session = RawSftpSession::new(stream);
    session
        .init()
        .await
        .map_err(|source| FileError::Unavailable {
            detail: source.to_string(),
        })?;

    // The same question the other operations ask, in the raw protocol's words.
    let resolved = session
        .realpath(path.parent())
        .await
        .map_err(|source| failed(path, &source))?;
    let names_itself = resolved
        .files
        .first()
        .is_some_and(|file| file.filename == path.parent());
    if !names_itself {
        return Err(elsewhere(path));
    }
    match session.lstat(path.as_str()).await {
        Ok(attributes) if attributes.attrs.is_symlink() => return Err(elsewhere(path)),
        Ok(_) => {}
        Err(source) if said(&source, StatusCode::NoSuchFile) => {}
        Err(source) => return Err(failed(path, &source)),
    }

    let handle = session
        .opendir(path.as_str())
        .await
        .map_err(|source| failed(path, &source))?
        .handle;
    let mut entries: Vec<Entry> = Vec::new();
    let mut listed_bytes = LIST_ENVELOPE_BYTES;
    let outcome = loop {
        // Read a batch at a time, and stop reading when the answer is full.
        // This is the difference from the convenience wrapper: it reads to the
        // end of the directory before anything can look at what it has, so a
        // bound on its result bounds only the copy.
        match session.readdir(handle.as_str()).await {
            Ok(names) => {
                if names.files.is_empty() {
                    break Err(FileError::ListingMadeNoProgress {
                        path: path.as_str().to_owned(),
                    });
                }
                if entries.len().saturating_add(names.files.len()) > MAX_LISTED_ENTRIES {
                    break Err(FileError::TooManyEntries {
                        path: path.as_str().to_owned(),
                        max: MAX_LISTED_ENTRIES,
                    });
                }
                let batch_bytes = names.files.iter().fold(0_usize, |total, file| {
                    total.saturating_add(listed_weight(file.filename.as_str()))
                });
                let after_batch = listed_bytes.saturating_add(batch_bytes);
                if after_batch > MAX_LISTED_BYTES {
                    break Err(FileError::ListingTooLarge {
                        path: path.as_str().to_owned(),
                        max: MAX_LISTED_BYTES,
                    });
                }
                listed_bytes = after_batch;
                entries.extend(names.files.into_iter().map(|file| Entry {
                    directory: file.attrs.is_dir(),
                    size: file.attrs.size,
                    name: file.filename,
                }));
            }
            // The end of a directory arrives as a status of its own. Anything
            // else the target says is a refusal, and breaking on it as though
            // it were the end would hand back a partial directory that reads
            // as a whole one — the caller acts on what is missing.
            Err(source) if said(&source, StatusCode::Eof) => break Ok(()),
            Err(source) => break Err(failed(path, &source)),
        }
    };
    let _ = session.close(handle).await;
    outcome?;
    // Ordered, so two listings of an unchanged directory are the same answer.
    // A caller comparing them should be told what changed on the target, not
    // what order the target happened to report.
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(FileOutcome::Listed { entries })
}

async fn stat(sftp: &SftpSession, path: &RemotePath) -> Result<FileOutcome, FileError> {
    let metadata = sftp
        .metadata(path.as_str())
        .await
        .map_err(|source| failed(path, &source))?;
    Ok(FileOutcome::Stated {
        entry: Entry {
            name: path.as_str().to_owned(),
            directory: metadata.is_dir(),
            size: metadata.size,
        },
    })
}

/// One shape of failure for anything the target refused.
///
/// The path is named because the caller supplied it, and the target's own words
/// are carried because "permission denied" and "no such file" are different
/// facts an operator needs. Nothing here reads the file to say more.
fn failed(path: &RemotePath, source: &russh_sftp::client::error::Error) -> FileError {
    FileError::Failed {
        path: path.as_str().to_owned(),
        detail: source.to_string(),
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum FileError {
    #[error("the target's file service could not be reached: {detail}")]
    Unavailable { detail: String },
    #[error("a write needs content")]
    NothingToWrite,
    #[error("{path} could not be operated on: {detail}")]
    Failed { path: String, detail: String },
    #[error("{size} bytes exceeds the {max} a single operation carries")]
    TooLarge { size: u64, max: u64 },
    #[error("{path} is not text; bulk and binary content need the out-of-band channel")]
    NotText { path: String },
    #[error("{path} holds more than the {max} entries a single listing carries")]
    TooManyEntries { path: String, max: usize },
    #[error("{path} returned a successful listing batch without entries or EOF")]
    ListingMadeNoProgress { path: String },
    #[error("{path} would make a listing larger than the {max} bytes one answer carries")]
    ListingTooLarge { path: String, max: usize },
    #[error(
        "{path} would make an answer larger than the {max} encoded bytes one operation carries"
    )]
    AnswerTooLarge { path: String, max: usize },
    #[error(
        "{path} is not what the target resolves it to; a link makes it name one file and open another"
    )]
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
                    listed: HashMap::new(),
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
        listed: HashMap<String, bool>,
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
            self.listed.remove(&handle);
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

        async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
            let resolved = self.resolve(&path);
            if !resolved.is_dir() {
                return Err(StatusCode::NoSuchFile);
            }
            let handle = format!("d{id}:{path}");
            self.listed.insert(handle.clone(), false);
            Ok(Handle { id, handle })
        }

        async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
            let path = handle.split_once(':').map(|(_, p)| p).unwrap_or("/");
            // A malicious or broken target can say success without names and
            // without EOF for ever. This fixture never advances its state.
            if path.ends_with("/endless-empty") {
                return Ok(Name {
                    id,
                    files: Vec::new(),
                });
            }
            // A second call must report the end of the directory, or the client
            // reads for ever.
            if self.listed.get(&handle).copied().unwrap_or(true) {
                return Err(StatusCode::Eof);
            }
            self.listed.insert(handle.clone(), true);
            // A directory the target refuses partway through. Real causes are a
            // permission change or a connection dropped mid-listing; what
            // matters to the client is that a refusal is not the end.
            if path.ends_with("/unreadable") {
                return Err(StatusCode::Failure);
            }
            // Fewer entries than the count ceiling, but each expands sixfold
            // when JSON escapes its control bytes. The wire batch stays small
            // enough to arrive; the answer it would produce does not.
            if path.ends_with("/wide") {
                let name = "\u{0001}".repeat(255);
                let files = (0..(MAX_LISTED_ENTRIES / 4))
                    .map(|_| File::dummy(name.clone()))
                    .collect();
                return Ok(Name { id, files });
            }
            let resolved = self.resolve(path);
            let mut files = Vec::new();
            for entry in std::fs::read_dir(&resolved).map_err(|_| StatusCode::Failure)? {
                let entry = entry.map_err(|_| StatusCode::Failure)?;
                let attrs = Files::attributes(&entry.path()).ok_or(StatusCode::Failure)?;
                files.push(File::new(entry.file_name().to_string_lossy(), attrs));
            }
            Ok(Name { id, files })
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

    fn path(raw: &str) -> RemotePath {
        RemotePath::parse(raw).unwrap()
    }

    /// The round trip that matters: bytes written through the protocol are the
    /// bytes read back through it, and a listing sees what was written.
    #[tokio::test]
    async fn a_file_written_through_the_protocol_reads_back_the_same() {
        let root = scratch();
        let connection = served(&root).await;

        let written = perform(
            &connection,
            FileOp::Write,
            &path("/hosts"),
            Some("127.0.0.1 localhost\n"),
        )
        .await
        .unwrap();
        assert_eq!(written, FileOutcome::Written { bytes: 20 });

        let read = perform(&connection, FileOp::Read, &path("/hosts"), None)
            .await
            .unwrap();
        assert_eq!(
            read,
            FileOutcome::Read {
                text: "127.0.0.1 localhost\n".to_owned(),
                bytes: 20
            }
        );

        let FileOutcome::Stated { entry } =
            perform(&connection, FileOp::Stat, &path("/hosts"), None)
                .await
                .unwrap()
        else {
            panic!("stat did not describe the file");
        };
        assert_eq!(entry.size, Some(20));
        assert!(!entry.directory);

        let FileOutcome::Listed { entries } = perform(&connection, FileOp::List, &path("/"), None)
            .await
            .unwrap()
        else {
            panic!("list did not return entries");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries.first().map(|e| e.name.as_str()), Some("hosts"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A write replaces the file rather than adding to it. Appending would make
    /// the result depend on what was already there, which is not what a caller
    /// asked for or what policy decided about.
    #[tokio::test]
    async fn a_write_replaces_what_was_there() {
        let root = scratch();
        let connection = served(&root).await;
        let target = path("/motd");

        perform(&connection, FileOp::Write, &target, Some("first"))
            .await
            .unwrap();
        perform(&connection, FileOp::Write, &target, Some("second"))
            .await
            .unwrap();

        let read = perform(&connection, FileOp::Read, &target, None)
            .await
            .unwrap();
        assert_eq!(
            read,
            FileOutcome::Read {
                text: "second".to_owned(),
                bytes: 6
            }
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A path can name one file and open another without any `..` in it: a
    /// link resolves on the target's side, where nothing the parser reads can
    /// see it. What policy decided about is the path as written, so an
    /// operation whose path resolves to something else is refused rather than
    /// followed — on every operation, since a link in a directory's path is
    /// the same problem as one in a file's.
    #[tokio::test]
    async fn a_path_the_target_resolves_elsewhere_is_refused() {
        let root = scratch();
        std::fs::write(root.join("hosts"), b"127.0.0.1 localhost\n").unwrap();
        let connection = served(&root).await;

        for op in [FileOp::Read, FileOp::Stat, FileOp::List] {
            let refused = perform(&connection, op, &path("/link/hosts"), None)
                .await
                .expect_err("a path resolving elsewhere was operated on anyway");
            assert!(
                matches!(refused, FileError::ResolvesElsewhere { .. }),
                "unexpected error for {op:?}: {refused:?}"
            );
        }

        // And a link as the *last* component, which resolving the prefix does
        // not cover: the path names one file and opens another just the same,
        // and a write through one would land on the file it points at.
        std::os::unix::fs::symlink(root.join("hosts"), root.join("shadow")).unwrap();
        for op in [FileOp::Read, FileOp::Stat, FileOp::Write] {
            let refused = perform(&connection, op, &path("/shadow"), Some("x"))
                .await
                .expect_err("a link as the last component was operated on anyway");
            assert!(
                matches!(refused, FileError::ResolvesElsewhere { .. }),
                "unexpected error for {op:?}: {refused:?}"
            );
        }

        // And a path the target resolves to itself is untouched by the check.
        assert!(
            perform(&connection, FileOp::Read, &path("/hosts"), None)
                .await
                .is_ok(),
            "an ordinary path was refused"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A listing the target cuts short is not a short directory. Reporting a
    /// refusal as a complete answer hands a caller something it reads as the
    /// whole directory and acts on for what is missing — the same wrongness as
    /// a truncated file read, arriving by a different route.
    #[tokio::test]
    async fn a_listing_the_target_cuts_short_is_refused_not_reported_as_complete() {
        let root = scratch();
        std::fs::create_dir(root.join("unreadable")).unwrap();
        std::fs::write(root.join("unreadable").join("present"), b"x").unwrap();
        let connection = served(&root).await;

        let refused = perform(&connection, FileOp::List, &path("/unreadable"), None)
            .await
            .expect_err("a refused listing was reported as a complete one");
        assert!(
            matches!(refused, FileError::Failed { .. }),
            "unexpected error: {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A listing is an answer, so it is bounded like one. A directory used as
    /// a queue is a normal thing to find, and returning as much of it as fits
    /// would hand back something a caller reads as the whole directory and
    /// acts on for what is missing.
    #[tokio::test]
    async fn a_directory_larger_than_a_single_answer_is_refused_not_truncated() {
        let root = scratch();
        for which in 0..=MAX_LISTED_ENTRIES {
            std::fs::write(root.join(format!("entry-{which:05}")), b"x").unwrap();
        }
        let connection = served(&root).await;

        let refused = perform(&connection, FileOp::List, &path("/"), None)
            .await
            .expect_err("an oversized directory was listed anyway");
        assert!(
            matches!(
                refused,
                FileError::TooManyEntries {
                    max: MAX_LISTED_ENTRIES,
                    ..
                }
            ),
            "unexpected error: {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A listing below the entry ceiling can still be too large to answer with.
    /// The target's names expand when encoded, so counting vector slots alone
    /// would accept an outcome beyond the same response budget reads observe.
    #[tokio::test]
    async fn a_listing_larger_than_one_answer_is_refused_below_the_entry_ceiling() {
        let root = scratch();
        std::fs::create_dir(root.join("wide")).unwrap();
        let connection = served(&root).await;

        let result = perform(&connection, FileOp::List, &path("/wide"), None).await;
        let Err(refused) = result else {
            panic!("an encoded listing beyond the answer budget was returned");
        };
        assert!(
            matches!(
                refused,
                FileError::ListingTooLarge {
                    max: MAX_LISTED_BYTES,
                    ..
                }
            ),
            "unexpected error: {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Successful empty batches are not EOF and do not advance the entry or
    /// answer-size counters. Refusing the first one means every successful
    /// batch advances the entry bound, which then bounds the whole operation.
    #[tokio::test]
    async fn successful_empty_batches_do_not_keep_a_listing_alive() {
        let root = scratch();
        std::fs::create_dir(root.join("endless-empty")).unwrap();
        let connection = served(&root).await;

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            perform(&connection, FileOp::List, &path("/endless-empty"), None),
        )
        .await
        .expect("the listing did not stop within its round-trip budget");
        let Err(refused) = result else {
            panic!("empty successful batches produced a complete listing");
        };
        assert!(
            matches!(refused, FileError::ListingMadeNoProgress { .. }),
            "unexpected error: {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Raw bytes are not the answer size: JSON expands control characters to
    /// six bytes each. This file is below the read ceiling but its complete
    /// encoded answer is not.
    #[tokio::test]
    async fn a_read_larger_only_after_encoding_is_refused() {
        let root = scratch();
        let control_bytes = vec![1_u8; (MAX_ANSWER_BYTES / 6).saturating_add(1)];
        std::fs::write(root.join("escaped"), control_bytes).unwrap();
        let connection = served(&root).await;

        let result = perform(&connection, FileOp::Read, &path("/escaped"), None).await;
        let Err(refused) = result else {
            panic!("an answer beyond the encoded budget was returned");
        };
        assert!(
            matches!(
                refused,
                FileError::AnswerTooLarge {
                    max: MAX_ANSWER_BYTES,
                    ..
                }
            ),
            "unexpected error: {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A file too large to answer with is refused rather than truncated. A
    /// configuration file read as though it were whole, when it was not, is
    /// worse than no answer at all.
    #[tokio::test]
    async fn a_file_larger_than_a_single_answer_is_refused_not_truncated() {
        let root = scratch();
        std::fs::write(
            root.join("huge"),
            vec![b'x'; usize::try_from(MAX_READ_BYTES).unwrap() + 1],
        )
        .unwrap();
        let connection = served(&root).await;

        let refused = perform(&connection, FileOp::Read, &path("/huge"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, FileError::TooLarge { .. }),
            "got {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Content that is not text is refused rather than mangled. Replacement
    /// characters would read as though the file contained them.
    #[tokio::test]
    async fn content_that_is_not_text_is_refused_rather_than_mangled() {
        let root = scratch();
        std::fs::write(root.join("binary"), [0xff_u8, 0xfe, 0x00, 0x01]).unwrap();
        let connection = served(&root).await;

        let refused = perform(&connection, FileOp::Read, &path("/binary"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, FileError::NotText { .. }),
            "got {refused:?}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A path the target will not give up is a refusal naming the path, not a
    /// silence and not an empty answer.
    #[tokio::test]
    async fn a_path_the_target_refuses_is_reported_as_such() {
        let root = scratch();
        let connection = served(&root).await;

        let refused = perform(&connection, FileOp::Read, &path("/absent"), None)
            .await
            .unwrap_err();
        let FileError::Failed { path: named, .. } = refused else {
            panic!("expected a refusal naming the path, got {refused:?}");
        };
        assert_eq!(named, "/absent");

        std::fs::remove_dir_all(&root).unwrap();
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

    /// Reading and writing are different events. A record that said "file
    /// operation on /etc/hosts" with a flag would make an audit reader work out
    /// which one happened.
    #[test]
    fn each_operation_is_named_as_itself() {
        assert_eq!(FileOp::Read.name(), "file.read");
        assert_eq!(FileOp::Write.name(), "file.write");

        // File operations have a distinct audit namespace.
        for op in [FileOp::Read, FileOp::Write, FileOp::List, FileOp::Stat] {
            assert!(op.name().starts_with("file."), "{:?}", op);
        }
    }
}
