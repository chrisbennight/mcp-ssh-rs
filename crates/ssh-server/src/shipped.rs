//! Required audit recording, independent of diagnostic logging.
//!
//! A bounded writer acknowledges a complete JSON line only after write and
//! flush succeed. Failure or backpressure prevents new effects. A file flush
//! does not promise disk synchronization, remote collection, or retention;
//! those remain deployment responsibilities.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

use ssh_core::audit::{Entry, NotRecorded, Records};

/// Most complete entries waiting for the output writer.
///
/// Memory stays bounded under a burst, and a full queue fails closed rather
/// than turning audit pressure into unbounded process growth.
const OUTPUT_QUEUE: usize = 8;
/// Long enough for an ordinary write, short enough that output
/// backpressure cannot consume the service's shutdown window.
const WRITE_WITHIN: Duration = Duration::from_millis(250);

struct Line {
    bytes: Vec<u8>,
    answered: SyncSender<bool>,
}

/// Writes complete audit lines through one bounded process-scoped worker.
///
/// The worker exclusively owns its sink. A caller receives success only after
/// its complete line was written and flushed, and never waits indefinitely for
/// a pipe or logging consumer that stopped draining.
pub struct ToAuditOutput {
    to: SyncSender<Line>,
    within: Duration,
    poisoned: AtomicBool,
}

impl ToAuditOutput {
    pub fn to<W>(sink: W) -> io::Result<Self>
    where
        W: Write + Send + 'static,
    {
        Self::to_within(sink, WRITE_WITHIN)
    }

    fn to_within<W>(sink: W, within: Duration) -> io::Result<Self>
    where
        W: Write + Send + 'static,
    {
        let (to, from) = sync_channel(OUTPUT_QUEUE);
        std::thread::Builder::new()
            .name("audit-output".to_owned())
            .spawn(move || write_lines(sink, from))?;
        Ok(Self {
            to,
            within,
            poisoned: AtomicBool::new(false),
        })
    }
}

fn write_lines<W>(mut sink: W, from: Receiver<Line>)
where
    W: Write,
{
    while let Ok(line) = from.recv() {
        let written = sink
            .write_all(&line.bytes)
            .and_then(|()| sink.flush())
            .is_ok();
        // The caller may already have reached its deadline. That only means
        // this answer has nobody left to receive it.
        let _ = line.answered.send(written);
    }
}

impl Records for ToAuditOutput {
    fn wrote(&self, entry: &Entry) -> Result<(), NotRecorded> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(NotRecorded);
        }

        // Build the newline into the same buffer. The worker owns the output,
        // so neither another audit entry nor a diagnostic event can split it.
        let mut bytes = serde_json::to_vec(entry).map_err(|_| NotRecorded)?;
        bytes.push(b'\n');

        let (answered, answer) = sync_channel(0);
        if self.to.try_send(Line { bytes, answered }).is_err() {
            self.poisoned.store(true, Ordering::Release);
            return Err(NotRecorded);
        }
        if matches!(answer.recv_timeout(self.within), Ok(true)) {
            return Ok(());
        }

        // A timed-out write may finish later. Refuse the rest of this process's
        // entries so that late line can only be the terminal link, never a link
        // followed by a second entry built from the same predecessor.
        self.poisoned.store(true, Ordering::Release);
        Err(NotRecorded)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ssh_core::audit::Ledger;
    use ssh_core::clock::TestClock;
    use ssh_core::session::{Lifetime, Purpose, Session, SessionStore};
    use ssh_core::{AccessClass, HostId, PrincipalId, RoleId};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// A sink that fails on demand, so a test can say what happens when the
    /// record cannot leave.
    struct RefusesWrite;

    impl Write for RefusesWrite {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("nowhere to write"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct RefusesFlush;

    impl Write for RefusesFlush {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("nowhere to flush"))
        }
    }

    struct BlocksOutput(Arc<AtomicUsize>);

    impl Write for BlocksOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::Release);
            std::thread::sleep(Duration::from_millis(100));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Shared so a test can read what the adapter wrote.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn a_session() -> Session {
        SessionStore::new(
            TestClock::at(1_000),
            Lifetime {
                idle: 10_000,
                max: 60_000,
                grace: 5_000,
            },
            8,
        )
        .open(
            PrincipalId::parse("alice").unwrap(),
            HostId::parse("dns1").unwrap(),
            RoleId::parse("readonly").unwrap(),
            Purpose::parse("find out why the deploy did nothing").unwrap(),
            AccessClass::ReadOnly,
        )
        .unwrap()
    }

    /// The production adapter, not a stand-in for it: what has to be true here is
    /// that a real entry becomes a complete line at the adapter's output
    /// boundary.
    #[test]
    fn an_entry_becomes_a_line_that_says_what_it_was() {
        let captured = Captured::default();
        let ledger = Ledger::recording_to(
            TestClock::at(1_000),
            Arc::new(ToAuditOutput::to(captured.clone()).unwrap()),
        );

        let session = a_session();
        ledger.record_session_opened(&session).unwrap();

        let written = captured.0.lock().unwrap().clone();
        let written = String::from_utf8(written).unwrap();
        assert_eq!(written.lines().count(), 1, "not one line: {written}");

        let line: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
        let field = |name: &str| line.get(name).cloned().unwrap_or(serde_json::Value::Null);
        assert_eq!(field("session"), session.id.as_str());
        assert_eq!(field("principal"), "alice");
        assert!(
            field("digest").is_string() && field("event").is_object(),
            "the line does not carry the entry: {line}"
        );
    }

    /// An entry that could not leave is not an entry anything may run on. The
    /// record refuses it rather than letting an effect begin without a complete
    /// entry beyond the process boundary.
    #[test]
    fn an_entry_that_cannot_leave_is_not_recorded_at_all() {
        let ledger = Ledger::recording_to(
            TestClock::at(1_000),
            Arc::new(ToAuditOutput::to(RefusesWrite).unwrap()),
        );

        let refused = ledger.record_session_opened(&a_session()).unwrap_err();
        assert!(
            matches!(refused, ssh_core::audit::AuditError::NotRecorded),
            "unexpected error: {refused:?}"
        );
        assert!(
            ledger.entries().is_empty(),
            "the record kept an entry it could not ship"
        );
        assert!(
            ledger.verify().is_ok(),
            "refusing to record broke the chain"
        );
    }

    /// Writing is not enough: the selected boundary is crossed only after the
    /// complete line has also been flushed.
    #[test]
    fn an_entry_that_cannot_be_flushed_is_not_recorded_at_all() {
        let ledger = Ledger::recording_to(
            TestClock::at(1_000),
            Arc::new(ToAuditOutput::to(RefusesFlush).unwrap()),
        );

        let refused = ledger.record_session_opened(&a_session()).unwrap_err();
        assert!(
            matches!(refused, ssh_core::audit::AuditError::NotRecorded),
            "unexpected error: {refused:?}"
        );
        assert!(
            ledger.entries().is_empty(),
            "the record kept an entry that was not flushed"
        );
        assert!(
            ledger.verify().is_ok(),
            "refusing to record broke the chain"
        );
    }

    /// A stopped stdout consumer may refuse an effect, but may not hang the
    /// service until the container's shutdown deadline expires or let a late
    /// write fork the process-local chain.
    #[test]
    fn output_backpressure_is_bounded_and_fails_closed() {
        let writes = Arc::new(AtomicUsize::new(0));
        let ledger = Ledger::recording_to(
            TestClock::at(1_000),
            Arc::new(
                ToAuditOutput::to_within(
                    BlocksOutput(Arc::clone(&writes)),
                    Duration::from_millis(10),
                )
                .unwrap(),
            ),
        );

        let started = Instant::now();
        let refused = ledger.record_session_opened(&a_session()).unwrap_err();

        assert!(
            matches!(refused, ssh_core::audit::AuditError::NotRecorded),
            "unexpected error: {refused:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "output backpressure exceeded the bounded recording deadline"
        );
        assert!(ledger.entries().is_empty());
        assert!(ledger.verify().is_ok());

        std::thread::sleep(Duration::from_millis(150));
        let refused_again = ledger.record_session_opened(&a_session()).unwrap_err();
        assert!(matches!(
            refused_again,
            ssh_core::audit::AuditError::NotRecorded
        ));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            writes.load(Ordering::Acquire),
            1,
            "a timed-out writer accepted another entry and forked the chain"
        );
    }
}
