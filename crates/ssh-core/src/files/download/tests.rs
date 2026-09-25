#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use russh::keys::ssh_encoding::bytes::{Bytes, BytesMut};
use russh_sftp::protocol::{Data, Packet, Version};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Copy, Debug)]
enum Reply {
    Ordinary,
    Short,
    Oversized,
    Empty,
    Malformed,
    Disconnect,
}

struct Peer {
    bytes: Arc<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    written: Arc<AtomicUsize>,
    job: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.job.abort();
    }
}

async fn packet(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Packet> {
    let size = stream.read_u32().await? as usize;
    assert!(size <= 128 << 10, "fixture received an unbounded request");
    let mut bytes = BytesMut::zeroed(size);
    stream.read_exact(&mut bytes).await?;
    let mut bytes = bytes.freeze();
    Ok(Packet::try_from(&mut bytes).unwrap())
}

async fn reply(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    packet: Packet,
) -> io::Result<()> {
    stream.write_all(&Bytes::try_from(packet).unwrap()).await
}

async fn fixture(
    size: usize,
    latency: Duration,
    mode: Reply,
    reorder: bool,
) -> (Arc<RawSftpSession>, Peer) {
    let (client, peer) = fixture_stream(size, latency, mode, reorder);
    let session = Arc::new(RawSftpSession::new(super::super::BoundedSftpStream::new(
        client,
    )));
    session.init().await.unwrap();
    (session, peer)
}

fn fixture_stream(
    size: usize,
    latency: Duration,
    mode: Reply,
    reorder: bool,
) -> (tokio::io::DuplexStream, Peer) {
    let bytes = Arc::new(
        (0..size)
            .map(|offset| (offset % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let reads = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let written = Arc::new(AtomicUsize::new(0));
    let (client, server) = tokio::io::duplex(128 << 10);
    let source = Arc::clone(&bytes);
    let seen = Arc::clone(&reads);
    let peak = Arc::clone(&maximum);
    let write_bytes = Arc::clone(&written);
    let job = tokio::spawn(async move {
        let (mut input, mut server) = tokio::io::split(server);
        let (send, mut incoming) = tokio::sync::mpsc::channel(READ_AHEAD);
        let mut readers = tokio::task::JoinSet::new();
        readers.spawn(async move {
            while let Ok(packet) = packet(&mut input).await {
                if send.send(packet).await.is_err() {
                    break;
                }
            }
        });
        let mut answers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                request = incoming.recv() => {
                    let Some(request) = request else { break };
                    match request {
                        Packet::Init(_) => { if reply(&mut server, Version::new().into()).await.is_err() { break; } },
                        Packet::Open(request) => { if reply(&mut server, russh_sftp::protocol::Handle {id: request.id, handle: "fixture".into()}.into()).await.is_err() { break; } },
                        Packet::Close(request) => { if reply(&mut server, Packet::error(request.id, StatusCode::Ok)).await.is_err() { break; } },
                        Packet::Write(request) => {
                            let start = request.offset as usize;
                            assert_eq!(source.get(start..start.saturating_add(request.data.len())).unwrap(), request.data);
                            write_bytes.fetch_add(request.data.len(), Ordering::SeqCst);
                            peak.fetch_max(answers.len().saturating_add(1), Ordering::SeqCst);
                            answers.spawn(async move {
                                tokio::time::sleep(latency).await;
                                Packet::error(request.id, StatusCode::Ok)
                            });
                        },
                        Packet::Read(request) => {
                            seen.fetch_add(1, Ordering::SeqCst);
                            peak.fetch_max(answers.len().saturating_add(1), Ordering::SeqCst);
                            if matches!(mode, Reply::Disconnect) { break; }
                            let source = Arc::clone(&source);
                            answers.spawn(async move {
                                let delay = if reorder && request.offset == 0 { latency.saturating_mul(2) } else { latency };
                                tokio::time::sleep(delay).await;
                                if matches!(mode, Reply::Malformed) { return russh_sftp::protocol::Handle { id: request.id, handle: "unexpected".into() }.into(); }
                                let offset = request.offset as usize;
                                if offset >= source.len() { return Packet::error(request.id, StatusCode::Eof); }
                                let length = match mode {
                                    Reply::Oversized => (request.len as usize).saturating_add(1),
                                    Reply::Empty => 0,
                                    Reply::Short => (request.len as usize).min(7),
                                    _ => request.len as usize,
                                };
                                let data = if matches!(mode, Reply::Oversized) { vec![0; length] } else { source.get(offset..offset.saturating_add(length).min(source.len())).unwrap().to_vec() };
                                Data { id: request.id, data }.into()
                            });
                        },
                        _ => panic!("unexpected fixture request"),
                    }
                },
                response = answers.join_next(), if !answers.is_empty() => {
                    let response = response.unwrap().unwrap();
                    if reply(&mut server, response).await.is_err() { break; }
                }
            }
        }
    });
    (
        client,
        Peer {
            bytes,
            reads,
            maximum,
            written,
            job,
        },
    )
}

#[tokio::test]
async fn ordered_delivery_preserves_short_reads_and_binary_data() {
    for (mode, size) in [
        (Reply::Ordinary, 511),
        (Reply::Short, 511),
        (Reply::Ordinary, 0),
        (Reply::Ordinary, 248),
    ] {
        let (session, peer) = fixture(size, Duration::from_millis(1), mode, true).await;
        let mut reader = Reader::new(session, "fixture".into(), 31, READ_AHEAD).unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, &*peer.bytes);
        assert!(peer.maximum.load(Ordering::SeqCst) <= READ_AHEAD);
    }
}

#[tokio::test]
async fn invalid_responses_fail_without_panicking_or_publishing_bytes() {
    for mode in [
        Reply::Oversized,
        Reply::Empty,
        Reply::Malformed,
        Reply::Disconnect,
    ] {
        let (session, _peer) = fixture(1024, Duration::ZERO, mode, false).await;
        // A disconnected raw session settles pending reads at its existing
        // request deadline. Shorten that deadline for this synthetic fixture.
        session.set_timeout(1);
        let mut reader = Reader::new(session, "fixture".into(), 31, READ_AHEAD).unwrap();
        let mut received = Vec::new();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut received))
                .await
                .unwrap_or_else(|_| panic!("response {mode:?} did not settle"))
                .is_err()
        );
        assert!(received.is_empty());
    }
}

#[tokio::test]
async fn slow_consumers_do_not_expand_the_window() {
    let (session, peer) = fixture(4 << 20, Duration::from_millis(1), Reply::Ordinary, true).await;
    let mut reader = Reader::new(session, "fixture".into(), CHUNK_BYTES, READ_AHEAD).unwrap();
    let mut byte = [0];
    reader.read_exact(&mut byte).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(peer.reads.load(Ordering::SeqCst), READ_AHEAD);
    assert_eq!(reader.requests.len().saturating_add(1), READ_AHEAD);
    let buffered = reader
        .requests
        .iter()
        .filter_map(|request| request.result.as_ref())
        .filter_map(|result| result.as_ref().ok())
        .map(Vec::len)
        .sum::<usize>()
        .saturating_add(reader.current.get_ref().len());
    assert!(buffered <= (CHUNK_BYTES as usize).saturating_mul(READ_AHEAD));
    let started = Instant::now();
    drop(reader);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !peer.job.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn read_budgets_reject_zero_and_excess() {
    let (session, _peer) = fixture(1, Duration::ZERO, Reply::Ordinary, false).await;
    for (size, window) in [
        (0, 1),
        (CHUNK_BYTES.saturating_add(1), 1),
        (CHUNK_BYTES, 0),
        (CHUNK_BYTES, READ_AHEAD.saturating_add(1)),
    ] {
        assert!(Reader::new(Arc::clone(&session), "fixture".into(), size, window).is_err());
    }
}

fn cpu_seconds() -> f64 {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID).unwrap();
    time.tv_sec() as f64 + time.tv_nsec() as f64 / 1_000_000_000.0
}

fn peak_rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

fn report(measurement: serde_json::Value) {
    use std::io::Write as _;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &measurement).unwrap();
    output.write_all(b"\n").unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
#[ignore = "latency-controlled SFTP throughput measurement; run explicitly with --nocapture"]
async fn latency_benchmark() {
    use sha2::{Digest as _, Sha256};
    for size in [256 << 10, 4 << 20] {
        for rtt_ms in [0, 10, 50, 100] {
            for sink_ms in [0, 5] {
                for window in [1, READ_AHEAD] {
                    let (session, peer) =
                        fixture(size, Duration::from_millis(rtt_ms), Reply::Ordinary, false).await;
                    let mut reader =
                        Reader::new(session, "fixture".into(), CHUNK_BYTES, window).unwrap();
                    let mut buffer = vec![0; CHUNK_BYTES as usize];
                    let mut digest = Sha256::new();
                    let mut total = 0_usize;
                    let started = Instant::now();
                    let cpu = cpu_seconds();
                    loop {
                        let read = reader.read(&mut buffer).await.unwrap();
                        if read == 0 {
                            break;
                        }
                        digest.update(buffer.get(..read).unwrap());
                        total = total.saturating_add(read);
                        if sink_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(sink_ms)).await;
                        }
                    }
                    let elapsed = started.elapsed().as_secs_f64();
                    let cpu = cpu_seconds() - cpu;
                    let digest = digest.finalize();
                    assert_eq!(total, size);
                    assert_eq!(digest, Sha256::digest(&*peer.bytes));
                    assert!(peer.maximum.load(Ordering::SeqCst) <= window);
                    report(
                        serde_json::json!({"direction":"download", "bytes":size, "response_delay_ms":rtt_ms, "sink_delay_ms":sink_ms, "window":window, "seconds":elapsed, "mib_per_second":size as f64 / 1048576.0 / elapsed, "process_cpu_seconds":cpu, "process_peak_rss_kib":peak_rss_kib(), "max_requests":peer.maximum.load(Ordering::SeqCst), "scheduled_byte_budget":(CHUNK_BYTES as usize).saturating_mul(window), "sha256":hex(&digest)}),
                    );
                }
                // Use the unchanged high-level upload writer, as production does.
                let (stream, peer) = fixture_stream(
                    size,
                    Duration::from_millis(rtt_ms.saturating_add(sink_ms)),
                    Reply::Ordinary,
                    false,
                );
                let session = russh_sftp::client::SftpSession::new(
                    super::super::BoundedSftpStream::new(stream),
                )
                .await
                .unwrap();
                let mut file = session.create("/fixture").await.unwrap();
                let started = Instant::now();
                let cpu = cpu_seconds();
                tokio::time::timeout(Duration::from_secs(60), async {
                    // Match production's copy buffer and acknowledgement path.
                    let mut input = std::io::Cursor::new(peer.bytes.as_slice());
                    tokio::io::copy(&mut input, &mut file).await.unwrap();
                    file.shutdown().await.unwrap();
                })
                .await
                .expect("synthetic upload must settle");
                let elapsed = started.elapsed().as_secs_f64();
                let cpu = cpu_seconds() - cpu;
                assert_eq!(peer.written.load(Ordering::SeqCst), size);
                report(
                    serde_json::json!({"direction":"upload", "bytes":size, "response_delay_ms":rtt_ms, "sink_delay_ms":sink_ms, "seconds":elapsed, "mib_per_second":size as f64 / 1048576.0 / elapsed, "process_cpu_seconds":cpu, "process_peak_rss_kib":peak_rss_kib(), "max_requests":peer.maximum.load(Ordering::SeqCst), "sha256":hex(&Sha256::digest(&*peer.bytes))}),
                );
                session.close().await.unwrap();
            }
        }
    }
    let (session, peer) =
        fixture(4 << 20, Duration::from_millis(100), Reply::Ordinary, false).await;
    let mut reader = Reader::new(session, "fixture".into(), CHUNK_BYTES, READ_AHEAD).unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(1), reader.read(&mut byte))
            .await
            .is_err()
    );
    let started = Instant::now();
    drop(reader);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !peer.job.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    report(
        serde_json::json!({"direction":"cancel_download", "seconds":started.elapsed().as_secs_f64(), "max_requests":peer.maximum.load(Ordering::SeqCst)}),
    );
}
