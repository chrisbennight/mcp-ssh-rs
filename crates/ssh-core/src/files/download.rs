//! Ordered, bounded reads over the dependency's raw request interface.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use russh_sftp::{client::RawSftpSession, protocol::StatusCode};
use tokio::io::{AsyncRead, ReadBuf};

pub(super) const CHUNK_BYTES: u32 = 64 << 10;
pub(super) const READ_AHEAD: usize = 8;

type ReadFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;

struct Request {
    size: u32,
    future: Option<ReadFuture>,
    result: Option<io::Result<Vec<u8>>>,
}

pub(super) struct Reader {
    session: Arc<RawSftpSession>,
    handle: String,
    chunk_bytes: u32,
    window: usize,
    next: u64,
    limit: u64,
    requests: VecDeque<Request>,
    current: std::io::Cursor<Vec<u8>>,
    eof: bool,
}

impl Reader {
    pub(super) fn new(
        session: Arc<RawSftpSession>,
        handle: String,
        chunk_bytes: u32,
        window: usize,
    ) -> io::Result<Self> {
        if chunk_bytes == 0
            || chunk_bytes > CHUNK_BYTES
            || super::DownloadWindow::new(window).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SFTP read budget",
            ));
        }
        Ok(Self {
            session,
            handle,
            chunk_bytes,
            window,
            next: 0,
            limit: u64::MAX,
            requests: VecDeque::new(),
            current: std::io::Cursor::new(Vec::new()),
            eof: false,
        })
    }

    pub(super) fn bounded(mut self, bytes: u64) -> Self {
        self.limit = bytes;
        self
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.current.position() < self.current.get_ref().len() as u64 {
            return Pin::new(&mut self.current).poll_read(cx, output);
        }
        self.current = std::io::Cursor::new(Vec::new());
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        while self.requests.len() < self.window {
            let offset = self.next;
            let size = u64::from(self.chunk_bytes).min(self.limit.saturating_sub(offset)) as u32;
            if size == 0 {
                break;
            }
            let Some(next) = offset.checked_add(u64::from(size)) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SFTP offset overflow",
                )));
            };
            self.next = next;
            let session = Arc::clone(&self.session);
            let handle = self.handle.clone();
            self.requests.push_back(Request {
                size,
                future: Some(Box::pin(read_chunk(session, handle, offset, size))),
                result: None,
            });
        }
        if self.requests.is_empty() {
            self.eof = true;
            return Poll::Ready(Ok(()));
        }
        // Poll every request so later offsets can cross the wire before the
        // first reply. Delivery still consumes only the oldest offset.
        for request in &mut self.requests {
            if let Some(future) = &mut request.future
                && let Poll::Ready(result) = future.as_mut().poll(cx)
            {
                request.result = Some(result);
                request.future = None;
            }
        }
        let Some(result) = self
            .requests
            .front_mut()
            .and_then(|request| request.result.take())
        else {
            return Poll::Pending;
        };
        let requested = self.requests.pop_front().map(|request| request.size);
        match result {
            Ok(bytes) => {
                if requested.is_some_and(|size| bytes.len() < size as usize) {
                    self.eof = true;
                    self.requests.clear();
                }
                self.current = std::io::Cursor::new(bytes);
                Pin::new(&mut self.current).poll_read(cx, output)
            }
            Err(error) => {
                self.eof = true;
                self.requests.clear();
                Poll::Ready(Err(error))
            }
        }
    }
}

async fn read_chunk(
    session: Arc<RawSftpSession>,
    handle: String,
    offset: u64,
    size: u32,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < size as usize {
        let remaining = size.saturating_sub(bytes.len() as u32);
        let at = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SFTP offset overflow"))?;
        match session.read(handle.as_str(), at, remaining).await {
            Ok(data) => {
                if data.data.is_empty() || data.data.len() > remaining as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SFTP data length",
                    ));
                }
                if bytes.is_empty() && data.data.len() == size as usize {
                    return Ok(data.data);
                }
                if bytes.is_empty() {
                    bytes.reserve_exact(size as usize);
                }
                bytes.extend_from_slice(&data.data);
            }
            Err(error) if super::said(&error, StatusCode::Eof) => break,
            Err(_) => return Err(io::Error::other("SFTP read failed")),
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
