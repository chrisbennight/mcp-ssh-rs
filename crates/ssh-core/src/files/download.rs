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
    future: Option<ReadFuture>,
    result: Option<io::Result<Vec<u8>>>,
}

pub(super) struct Reader {
    session: Arc<RawSftpSession>,
    handle: String,
    chunk_bytes: u32,
    window: usize,
    next: u64,
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
        if chunk_bytes == 0 || chunk_bytes > CHUNK_BYTES || window == 0 || window > READ_AHEAD {
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
            requests: VecDeque::new(),
            current: std::io::Cursor::new(Vec::new()),
            eof: false,
        })
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
            let Some(next) = offset.checked_add(u64::from(self.chunk_bytes)) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SFTP offset overflow",
                )));
            };
            self.next = next;
            let session = Arc::clone(&self.session);
            let handle = self.handle.clone();
            let size = self.chunk_bytes;
            self.requests.push_back(Request {
                future: Some(Box::pin(read_chunk(session, handle, offset, size))),
                result: None,
            });
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
        self.requests.pop_front();
        match result {
            Ok(bytes) => {
                if bytes.len() < self.chunk_bytes as usize {
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
