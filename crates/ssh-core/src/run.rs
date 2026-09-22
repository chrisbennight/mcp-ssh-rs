//! Running a command, and not losing it when it takes longer than expected.
//!
//! One execution path, not a fast one and a slow one. An agent cannot predict
//! whether a command will return immediately or grind for minutes, so asking it
//! to choose up front guarantees wrong guesses in both directions — and two
//! paths would mean two authorization paths and two
//! audit shapes that drift apart.
//!
//! So every command is started the same way and waited on for a bounded time.
//! If it finishes, the caller gets its outcome. If it does not, the caller gets
//! the same outcome shape with the work still identified, and can ask again.
//! Nothing is orphaned by being slow.
//!
//! Output is bounded, because a command's output arrives on a connection this
//! service holds and a caller cannot be trusted to have picked a command that
//! produces a sensible amount of it. When the bound is reached the response says
//! so and reports how much was produced, rather than handing back a prefix that
//! looks complete.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::audit::{Authorization, LONGEST_SECRET_SHAPE, Receipt, secret_shape};
use crate::connect::Connection;
use crate::session::SessionId;

/// Opaque handle to one execution.
///
/// Every identifier this store mints is the store's own name followed by the
/// run's, both in lowercase hex. Anything else cannot name a run, so it is
/// refused before it is copied, hashed, or quoted back in an answer — a handle
/// arrives as a string a caller typed, and its length is otherwise the
/// caller's to choose.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RunId(String);

/// Hex characters naming the store that minted a run.
const STORE_CHARS: usize = 16;

/// Hex characters naming the run within it.
const RUN_CHARS: usize = 32;

impl RunId {
    /// Reads an identifier a caller supplied.
    ///
    /// Shape only. A well-formed identifier for a run that never existed, and
    /// one for a run belonging to another session, are still answered alike:
    /// what a caller may ask about is decided by the session that owns the run,
    /// never by holding its name.
    pub fn parse(raw: &str) -> Result<Self, MalformedRunId> {
        let Some((store, run)) = raw.split_once('-') else {
            return Err(MalformedRunId);
        };
        let hex = |part: &str, chars: usize| {
            part.len() == chars
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        };
        if !hex(store, STORE_CHARS) || !hex(run, RUN_CHARS) {
            return Err(MalformedRunId);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Names a run from a raw identifier, for tests that need one without
    /// starting a process. Compiled out of every non-test build; identifiers
    /// are minted by the store and read from callers by `parse`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_raw(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RunId {
    type Error = MalformedRunId;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("that is not the shape of a run identifier")]
pub struct MalformedRunId;

/// What a single execution is allowed to consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes retained per stream before output is truncated.
    pub output_bytes: usize,
    /// Maximum elapsed time for one file operation.
    pub transfer_timeout: Duration,
    /// How long a caller waits before a run is handed back as still running.
    pub wait: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            output_bytes: 1 << 20,
            transfer_timeout: Duration::from_secs(1800),
            wait: Duration::from_secs(30),
        }
    }
}

/// One output stream, as much of it as was kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stream {
    pub text: String,
    /// Whether the target produced more than was kept.
    pub truncated: bool,
    /// How much the target produced, including what was discarded.
    pub bytes: u64,
    /// What this stream looked like, if it looked like credential material.
    ///
    /// Decided as the output arrives rather than from what survived the bound,
    /// because that is the only moment all of it exists. A stream can carry a
    /// key past the point where retention of its bytes stops, and a reader of
    /// the record has to be told that whether or not the bytes were kept.
    pub matched: Option<&'static str>,
}

/// Where an execution has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RunState {
    /// Still going. The same run can be asked about again.
    Running,
    Exited {
        code: u32,
    },
    /// The target closed the channel without reporting an exit status.
    ///
    /// Distinct from an exit code, because "the command ended somehow" and "the
    /// command succeeded" are different facts and conflating them would report
    /// a killed process as a clean run.
    Ended,
    /// Nothing ran, and the target said so.
    ///
    /// The exec request is made with a reply asked for, and this is the
    /// negative one. A caller can send the command somewhere else, or send a
    /// different command, knowing this one did not happen.
    Refused,
    /// Nobody said whether it ran.
    ///
    /// The channel ended without the target answering the request, producing
    /// output, reporting a status, or naming a signal — or the request could
    /// not be sent at all, which is the same silence one step earlier. The
    /// command may have run; it may never have started.
    ///
    /// This exists because the alternatives are both claims nobody can support.
    /// Calling it ended says the work happened, and a caller then does not
    /// redo work that may still be undone. Calling it refused says the work did
    /// not happen, and a caller then repeats a command that may have already
    /// changed the target — the worse of the two, which is why silence is not
    /// quietly folded into either.
    Indeterminate,
    /// The transfer failed; a remote write may already have changed its target.
    TransferFailed {
        cause: crate::transfer::Failure,
        remote_write_may_be_partial: bool,
    },
}

impl RunState {
    /// What this state says about whether the command ran, in words an answer
    /// can carry.
    ///
    /// Anything reporting a run to somebody who has to decide what to do next
    /// needs this phrase rather than the state's name, and it belongs here so
    /// that the answer cannot drift from the state it describes.
    #[must_use]
    pub const fn what_happened(self) -> &'static str {
        match self {
            Self::Running => "is still running",
            Self::Exited { .. } | Self::Ended => "ran",
            Self::Refused => "did not run",
            Self::Indeterminate => "may or may not have run",
            Self::TransferFailed { .. } => "failed to transfer",
        }
    }
}

/// What a caller learns about an execution.
///
/// Every field is read-only, and not `Clone`: this is the report of what a
/// target did, and the record hashes it as fact. A settable state or stream
/// would let whoever holds one rewrite what happened before it is written down,
/// and the chain would still verify — it proves entries were not edited
/// afterwards, not that they were true when written. So the only thing that can
/// say what a run did is the store that watched it.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Outcome {
    run: RunId,
    /// What permitted this run: which entry, in which record, for whom. Copied
    /// from the receipt when the run is registered, so recording what happened
    /// never has to look the decision back up or be told who it was for.
    authorization: Authorization,
    state: RunState,
    /// Kept separate rather than interleaved: a caller checking whether a
    /// command complained cannot do so if the complaint is mixed into its
    /// output, and the interleaving order is not reproducible anyway.
    stdout: Stream,
    stderr: Stream,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<crate::action::FileIdentity>,
    #[serde(skip)]
    stdout_bytes: Vec<u8>,
    #[serde(skip)]
    stderr_bytes: Vec<u8>,
}

impl Outcome {
    pub fn stdout_bytes(&self) -> &[u8] {
        &self.stdout_bytes
    }
    pub fn stderr_bytes(&self) -> &[u8] {
        &self.stderr_bytes
    }

    pub const fn file(&self) -> Option<&crate::action::FileIdentity> {
        self.file.as_ref()
    }

    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// What permitted this run.
    #[must_use]
    pub const fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    /// The record entry that authorized this run.
    #[must_use]
    pub const fn decided(&self) -> u64 {
        self.authorization.sequence()
    }

    #[must_use]
    pub const fn state(&self) -> RunState {
        self.state
    }

    #[must_use]
    pub const fn stdout(&self) -> &Stream {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &Stream {
        &self.stderr
    }

    /// An outcome for a run authorized by a given record entry, for tests that
    /// need one without starting a process. Compiled out of every non-test
    /// build: outside them this is minted by the store from a receipt, and
    /// nothing else has business asserting what a run did.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn authorized_by(
        authorization: Authorization,
        run: RunId,
        state: RunState,
        stdout: Stream,
    ) -> Self {
        Self {
            run,
            authorization,
            state,
            stdout_bytes: stdout.text.as_bytes().to_vec(),
            stderr_bytes: Vec::new(),
            stdout,
            file: None,
            stderr: Stream {
                text: String::new(),
                truncated: false,
                bytes: 0,
                matched: None,
            },
        }
    }

    /// Whether this execution outlived the wait it was given.
    ///
    /// Policy needs this distinct from a finished run: work that outlives its
    /// caller can also outlive the window that authorized it.
    #[must_use]
    pub fn still_running(&self) -> bool {
        self.state == RunState::Running
    }
}

/// Told when a command finishes, so its completion can be written then rather
/// than when somebody next happens to look.
///
/// A finished command is owed an entry at the moment it finishes. Anything that
/// discovers completions by being asked - a caller polling, housekeeping
/// passing by - leaves an idle service holding an unrecorded fact, and idle is
/// exactly when nobody is asking.
pub trait Settled: Send + Sync {
    fn settled(&self, outcome: Outcome);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Executions this service has started.
pub struct Runs {
    limits: Limits,
    /// Told the moment a command finishes. Optional because a store can be used
    /// without a record - the tests in this module do - and because the store
    /// must not need to know what a record is.
    watcher: Option<Arc<dyn Settled>>,
    /// What every identifier from this store begins with.
    ///
    /// A record can be fed by more than one store, and two of them numbering
    /// their runs from the same place would collide: the record would take the
    /// second store's first run for a repeat of the first store's and refuse to
    /// account for it.
    minted_by: String,
    records: Mutex<HashMap<String, Arc<Live>>>,
    /// Set when the service is stopping.
    ///
    /// Read while the records are held, so refusing and registering cannot
    /// interleave: a stop landing between a caller's check and its start would
    /// otherwise still put a command on a target that nothing is waiting to
    /// record.
    stopping: AtomicBool,
    /// Runs whose reader has not finished, by identifier.
    ///
    /// Held rather than derived from the records, because a run stops being
    /// `Running` a moment before its reader has told the watcher about it, and
    /// something waiting for work to be *recorded* must not be told it is done
    /// in that gap. An identifier leaves this only after the reader has
    /// announced.
    ///
    /// Identifiers rather than a count, because something that gives up
    /// waiting has to be able to say *which* commands it is giving up on:
    /// those are the ones whose outcome the record will not have, and a number
    /// tells whoever reads that log nothing they can act on.
    reading: Arc<Mutex<BTreeSet<String>>>,
}

/// Takes a run out of the reading set however its reader ends.
struct Reading {
    reading: Arc<Mutex<BTreeSet<String>>>,
    id: String,
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// The shared state one execution's reader task writes and callers read.
struct Live {
    record: Mutex<Record>,
    /// What permitted this run. Fixed when the run is registered, so asking
    /// about it later still says what permitted it and which record said so.
    authorization: Authorization,
    /// Signalled when the execution reaches a terminal state.
    settled: Notify,
}

struct Record {
    file: Option<crate::action::FileIdentity>,
    stdout: Collected,
    stderr: Collected,
    state: RunState,
}

/// A bounded view of one stream.
struct Collected {
    kept: Vec<u8>,
    seen: u64,
    limit: usize,
    /// What the whole stream looked like, decided as it went past.
    matched: Option<&'static str>,
    /// The tail of the last piece, so a shape falling across the join between
    /// two of them is still seen.
    carried: Vec<u8>,
}

impl Collected {
    fn new(limit: usize) -> Self {
        Self {
            kept: Vec::new(),
            seen: 0,
            limit,
            matched: None,
            carried: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.seen = self.seen.saturating_add(data.len() as u64);
        // Every byte is looked at here, kept or not: this is the only point at
        // which the whole stream exists.
        if self.matched.is_none() {
            let mut window = std::mem::take(&mut self.carried);
            window.extend_from_slice(data);
            self.matched = secret_shape(&String::from_utf8_lossy(&window));
            let overlap = window.len().saturating_sub(LONGEST_SECRET_SHAPE);
            self.carried = window.split_off(overlap.min(window.len()));
        }
        let room = self.limit.saturating_sub(self.kept.len());
        if room > 0 {
            self.kept
                .extend_from_slice(data.get(..room).unwrap_or(data));
        }
    }

    fn snapshot(&self) -> Stream {
        Stream {
            // Lossy because command output is bytes, not text, and truncating
            // at a byte bound can split a character. Refusing to report output
            // that is not valid UTF-8 would lose the output entirely.
            text: String::from_utf8_lossy(&self.kept).into_owned(),
            truncated: self.seen > self.kept.len() as u64,
            bytes: self.seen,
            matched: self.matched,
        }
    }
}

impl Runs {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self::watched(limits, None)
    }

    /// The same, telling `watcher` whenever a command finishes.
    #[must_use]
    pub fn watched(limits: Limits, watcher: Option<Arc<dyn Settled>>) -> Self {
        let mut bytes = [0_u8; 8];
        rand::fill(&mut bytes);
        Self {
            limits,
            watcher,
            minted_by: hex(&bytes),
            records: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
            reading: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    /// Names one execution, unguessably.
    ///
    /// Numbering runs within a store would make an identifier a position: see
    /// one and you can name the rest by counting. An identifier is the only
    /// thing a caller presents to ask about a run, so anything derivable from
    /// another identifier is a starting point for probing runs that are not
    /// yours. Random bytes from the platform's generator leave nothing to
    /// derive, and 128 bits of them make a collision within a store no more
    /// likely than the store failing outright.
    fn mint(&self) -> RunId {
        let mut bytes = [0_u8; 16];
        rand::fill(&mut bytes);
        RunId(format!("{}-{}", self.minted_by, hex(&bytes)))
    }

    /// An identifier of the shape this store mints, for tests that need one
    /// without a target to run against. Compiled out of every non-test build:
    /// identifiers are minted by starting a command and nothing else has
    /// business inventing one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn mint_id(&self) -> RunId {
        self.mint()
    }

    /// Runs a command and waits for it, up to the configured wait.
    ///
    /// A command that has not finished by then is returned as still running
    /// rather than abandoned or reported as failed.
    ///
    /// The receipt says what to run. There is no separate command argument,
    /// because two of them could disagree and only one of them was authorized.
    pub async fn run(
        &self,
        connection: &Connection,
        recorded: Receipt,
    ) -> Result<Outcome, RunError> {
        if recorded.action().kind() != crate::action::ActionKind::Execute {
            return Err(RunError::WrongOperation);
        }
        let started = Instant::now();
        let id = self.start(connection, recorded).await?;
        let left = self.limits.wait.saturating_sub(started.elapsed());
        self.wait(&id, left).await
    }

    /// Registers an audited transfer before any remote file effect. The task survives caller cancellation.
    pub(crate) async fn transfer(
        &self,
        connection: Arc<Connection>,
        recorded: Receipt,
        payload: crate::transfer::Payload,
    ) -> Result<Outcome, RunError> {
        use crate::action::Operation;
        use crate::transfer::{Failure, Payload};
        if recorded.host() != connection.host() || recorded.role() != connection.role() {
            return Err(RunError::WrongTarget {
                recorded: recorded.sequence(),
                host: connection.host().to_string(),
                role: connection.role().to_string(),
            });
        }
        match (recorded.action().operation(), &payload) {
            (Operation::Download { .. }, Payload::Download(_)) => {}
            (Operation::Upload { source, .. }, Payload::Upload(input))
                if source.bytes == input.identity().bytes
                    && source.sha256 == input.identity().sha256 => {}
            _ => return Err(RunError::WrongOperation),
        }
        let operation = recorded.action().operation().clone();
        let is_upload = matches!(operation, Operation::Upload { .. });
        let id = self.mint();
        let live = Arc::new(Live {
            record: Mutex::new(Record {
                file: None,
                stdout: Collected::new(self.limits.output_bytes),
                stderr: Collected::new(self.limits.output_bytes),
                state: RunState::Running,
            }),
            authorization: recorded.authorization().clone(),
            settled: Notify::new(),
        });
        {
            let mut records = self
                .records
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if self.stopping.load(Ordering::SeqCst) {
                return Err(RunError::Stopping);
            }
            records.insert(id.0.clone(), Arc::clone(&live));
            self.reading
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(id.0.clone());
        }
        let reading = Reading {
            reading: Arc::clone(&self.reading),
            id: id.0.clone(),
        };
        let watcher = self.watcher.clone();
        let settled_id = id.clone();
        let transfer_timeout = self.limits.transfer_timeout;
        tokio::spawn(async move {
            let _reading = reading;
            let work = async {
                match (operation, payload) {
                    (Operation::Download { path }, Payload::Download(sink)) => {
                        crate::files::download(&connection, &path, &*sink).await
                    }
                    (
                        Operation::Upload {
                            path,
                            source: _,
                            overwrite,
                        },
                        Payload::Upload(mut input),
                    ) => {
                        crate::files::upload(&connection, &path, &mut input, overwrite)
                            .await
                            .map_err(Failure::from)?;
                        Ok(input.identity().clone())
                    }
                    _ => unreachable!("transfer payload was validated before registration"),
                }
            };
            let result = tokio::time::timeout(transfer_timeout, work).await;
            {
                let mut record = live
                    .record
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                match result {
                    Ok(Ok(file)) => {
                        record.file = Some(file);
                        record.state = RunState::Exited { code: 0 };
                    }
                    failure => {
                        let cause = match failure {
                            Ok(Err(cause)) => cause,
                            Err(_) => Failure::TimedOut,
                            Ok(Ok(_)) => unreachable!(),
                        };
                        record.state = RunState::TransferFailed {
                            cause,
                            remote_write_may_be_partial: is_upload,
                        };
                        record.stderr.push(cause.message().as_bytes());
                        if is_upload {
                            record.stderr.push(
                                b" A remote write may be partial; do not automatically retry.",
                            );
                        }
                    }
                }
            }
            live.settled.notify_waiters();
            if let Some(watcher) = watcher {
                watcher.settled(snapshot_of(&settled_id, &live));
            }
        });
        self.wait(&id, self.limits.wait).await
    }

    /// The receipt fixes the command and target; registration precedes the exec request.
    async fn start(&self, connection: &Connection, recorded: Receipt) -> Result<RunId, RunError> {
        if recorded.host() != connection.host() || recorded.role() != connection.role() {
            return Err(RunError::WrongTarget {
                recorded: recorded.sequence(),
                host: connection.host().to_string(),
                role: connection.role().to_string(),
            });
        }
        // Taken by value, so one authorization is one execution: a receipt that
        // could be kept would run a second command on the first one's record.
        let command = recorded.command().clone();
        // One deadline for the whole call, not one per await. Two awaits with a
        // budget each can spend twice what the caller was told.
        let started = Instant::now();
        let left = || self.limits.wait.saturating_sub(started.elapsed());
        let opening = connection.handle().channel_open_session();
        let mut channel = match tokio::time::timeout(left(), opening).await {
            Ok(Ok(channel)) => channel,
            Ok(Err(source)) => {
                return Err(RunError::Channel {
                    detail: source.to_string(),
                });
            }
            Err(_) => {
                return Err(RunError::Channel {
                    detail: "the target did not accept the command within the wait".to_owned(),
                });
            }
        };
        // Registered before the command is sent, and nothing sends it except
        // the task that owns the record.
        //
        // The order is the whole point. A command reaches the target the moment
        // its bytes leave, whatever this call then learns about the send: a
        // timeout, a transport error or a cancellation after that point would
        // leave something running on a host with no record to find it by, no
        // way to settle it and no outcome to join to the decision that
        // permitted it. Registering first can at worst leave a record for a
        // command that never started - which is visible, settled, and
        // releasable, and says plainly that nothing ran.
        let id = self.mint();
        let live = Arc::new(Live {
            record: Mutex::new(Record {
                file: None,
                stdout: Collected::new(self.limits.output_bytes),
                stderr: Collected::new(self.limits.output_bytes),
                state: RunState::Running,
            }),
            authorization: recorded.authorization().clone(),
            settled: Notify::new(),
        });
        {
            // Refusing, registering the run, and registering its reader happen
            // under one hold. Split apart, a stop arriving between any two of
            // them lets a command reach the target with nothing waiting to
            // write down what it did — which is the one thing this is for.
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if self.stopping.load(Ordering::SeqCst) {
                return Err(RunError::Stopping);
            }
            records.insert(id.0.clone(), Arc::clone(&live));
            self.reading
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.0.clone());
        }

        // The reader outlives the caller on purpose. It is what makes a slow
        // command retrievable instead of orphaned: output keeps accumulating
        // and the exit status is recorded whenever it arrives.
        let watcher = self.watcher.clone();
        let settled_id = id.clone();
        let reading = Reading {
            reading: Arc::clone(&self.reading),
            id: id.0.clone(),
        };
        tokio::spawn(async move {
            // Held for the reader's whole life, including the announcing: the
            // count says "still to be recorded", not "still running".
            let _reading = reading;
            // Whoever is watching is told once, at the moment this run reaches
            // a terminal state, whatever brought it there.
            let announce = |live: &Arc<Live>| {
                live.settled.notify_waiters();
                if let Some(watcher) = &watcher {
                    watcher.settled(snapshot_of(&settled_id, live));
                }
            };
            // The vector becomes one string here and nowhere else: SSH carries
            // a command string, and `Command::to_wire` is what makes a shell
            // parse it back into the vector that was authorized.
            if let Err(source) = channel.exec(true, command.to_wire()).await {
                {
                    // Not a refusal: a send that reports a failure may still
                    // have put bytes on the wire, and the target may be running
                    // them. Nobody said it did not happen, so nothing here says
                    // so either.
                    let mut record = live.record.lock().unwrap_or_else(|e| e.into_inner());
                    record.state = RunState::Indeterminate;
                }
                drop(source);
                announce(&live);
                return;
            }
            let mut code = None;
            // Whether anything says the command began.
            //
            // The request is made with a reply asked for, so a target that
            // takes it says so — but the reply is not the only evidence, and
            // treating it as the only evidence would report a command that
            // produced output as one that never started. Anything only a
            // running command can produce counts: its output, its exit status,
            // the signal that killed it.
            let mut began = false;
            while let Some(message) = channel.wait().await {
                let mut record = live.record.lock().unwrap_or_else(|e| e.into_inner());
                match message {
                    // The positive reply to the exec request.
                    ChannelMsg::Success => began = true,
                    ChannelMsg::Data { data } => {
                        began = true;
                        record.stdout.push(&data);
                    }
                    // Extended data type 1 is stderr; the protocol allows
                    // others, and anything else is not this stream.
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        began = true;
                        record.stderr.push(&data);
                    }
                    // Only a process that ran is killed by a signal. The state
                    // stays `Ended` — there is no exit status to report — but
                    // this is not a command that failed to start.
                    ChannelMsg::ExitSignal { .. } => began = true,
                    // Recorded, not settled. Output can still arrive after the
                    // status does, and reporting a finished run whose streams
                    // are still filling would hand back an outcome that looks
                    // complete and is not.
                    ChannelMsg::ExitStatus { exit_status } => {
                        began = true;
                        code = Some(exit_status);
                    }
                    // The negative reply to the exec request. Discarding it
                    // leaves a command that never started looking like one that
                    // is merely slow. Nothing further is coming on this channel
                    // and a refused request does not oblige the target to close
                    // it, so the reader stops here rather than holding a task
                    // and a channel open for a run that is already settled.
                    //
                    // Only a refusal if nothing has said the command began. A
                    // target that produces output and then declines the request
                    // is contradicting itself, and the evidence is the half that
                    // cannot be taken back: bytes came from somewhere.
                    //
                    // And in that case the reading continues. Stopping here
                    // would settle the run while the channel is still open,
                    // which says the stream is complete when more of it may be
                    // coming — including the bytes that would have shown it to
                    // be a credential. What is withheld is decided from a whole
                    // stream, so the stream has to be whole first.
                    ChannelMsg::Failure if !began => {
                        record.state = RunState::Refused;
                        break;
                    }
                    _ => {}
                }
            }
            // The channel is closed, and what to call the run is decided by
            // what arrived on it rather than by guessing.
            //
            // An exit status settles it: only a command that ran has one.
            // Anything else a running command produces — its output, the reply
            // taking the request, the signal that killed it — says it began,
            // and it ended without saying how. If none of that arrived, nobody
            // said anything: the target may have started the command and lost
            // the connection before its reply left, or may never have taken it.
            // That is not a fact this can supply, so it does not.
            {
                let mut record = live.record.lock().unwrap_or_else(|e| e.into_inner());
                if record.state == RunState::Running {
                    record.state = match (code, began) {
                        (Some(code), _) => RunState::Exited { code },
                        (None, true) => RunState::Ended,
                        (None, false) => RunState::Indeterminate,
                    };
                }
            }
            announce(&live);
        });

        Ok(id)
    }

    /// Whether this run was granted to `session`.
    ///
    /// Separate from `wait` because whoever decides *whether* a caller may ask
    /// about a run must be able to do so before spending the caller's wait on
    /// it — otherwise how long the answer takes says whether the run exists and
    /// whether it is still going.
    ///
    /// Answered here rather than by handing back the authorization, so that a
    /// caller asking about a run it does not own never receives another
    /// session's authorization, and so that "not yours" and "no such run" cost
    /// one lookup either way.
    #[must_use]
    pub fn belongs_to(&self, id: &RunId, session: &SessionId) -> bool {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id.as_str())
            .is_some_and(|live| live.authorization.session() == session)
    }

    /// What authorized a run, without waiting for it.
    ///
    /// For reconciliation, which needs to know whose a run was in order to tell
    /// whether anyone can still ask about it. Not for answering a caller: see
    /// `belongs_to`.
    #[must_use]
    pub fn authorization(&self, id: &RunId) -> Option<Authorization> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id.as_str())
            .map(|live| live.authorization.clone())
    }

    /// This run's outcome if it has finished, without waiting.
    ///
    /// For a caller that has to decide something about settled work — whether
    /// it can be collected, say — and must not spend a wait finding out.
    #[must_use]
    pub fn finished(&self, id: &RunId) -> Option<Outcome> {
        let live = self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id.as_str())
            .map(Arc::clone)?;
        let outcome = snapshot_of(id, &live);
        (!outcome.still_running()).then_some(outcome)
    }

    /// Asks about a run, waiting up to `how_long` for it to settle.
    pub async fn wait(&self, id: &RunId, how_long: Duration) -> Result<Outcome, RunError> {
        let live = self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id.as_str())
            .map(Arc::clone)
            .ok_or_else(|| RunError::Unknown {
                run: id.as_str().to_owned(),
            })?;

        // Registered before the state is read, so a run that settles between
        // the check and the wait is not missed.
        let settled = live.settled.notified();
        if !snapshot_of(id, &live).still_running() {
            return Ok(snapshot_of(id, &live));
        }
        let _ = tokio::time::timeout(how_long, settled).await;
        Ok(snapshot_of(id, &live))
    }

    /// Drops a finished run's retained output, and reports whether it did.
    ///
    /// A run that is still going is kept. Releasing it would free the slot
    /// while its reader and the remote command carry on, and asking about it
    /// afterwards would say no such run exists - which is the one answer that
    /// is untrue, because it is still running on the target.
    ///
    /// Records are held until asked for, so something has to release them; that
    /// belongs to whatever owns the run's lifetime rather than to this store.
    pub fn forget(&self, id: &RunId) -> bool {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let settled = records.get(id.as_str()).is_some_and(|held| {
            held.record.lock().unwrap_or_else(|e| e.into_inner()).state != RunState::Running
        });
        if settled {
            records.remove(id.as_str());
        }
        settled
    }

    /// Every run this store is holding.
    ///
    /// A caller that never received an identifier has one way back to a run
    /// that is nonetheless real: `run` can be abandoned after the command has
    /// been sent, and the command is running on the target whether or not
    /// anything is still waiting for it. Without this, such a record would be
    /// unreachable rather than merely unclaimed - nothing could ask about it,
    /// and nothing could release it.
    /// Refuses runs that have not started yet.
    ///
    /// One way: a store that could be told to carry on would owe an answer
    /// about everything refused in between.
    pub fn stop(&self) {
        // Under the same hold a start takes. Setting the flag beside that lock
        // rather than inside it leaves a start that has already read `false`
        // free to register afterwards, so a stop could return while work was
        // still arriving — which is the one thing this is for.
        let _records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// How many runs are still being read, and so still to be recorded.
    ///
    /// Deliberately not the length of `outstanding`: that is every record still
    /// held, and a record that has settled is being kept only until whoever
    /// asked comes back for it. Something waiting for work to finish — stopping
    /// the process, say — has to be able to tell those apart, or it waits on
    /// results that were recorded long ago.
    ///
    /// Equally deliberately not the count of records still `Running`: a reader
    /// leaves that state a moment before it tells the record what happened, and
    /// stopping in that moment would lose exactly the completion the waiting
    /// was for.
    #[must_use]
    pub fn unfinished(&self) -> Vec<RunId> {
        self.reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|id| RunId(id.clone()))
            .collect()
    }

    /// Readers still in flight, paired with the entry that authorized each.
    ///
    /// Both sets are held together so every returned identifier has the
    /// correlation metadata shutdown needs to join it to the audit record.
    pub(crate) fn unfinished_authorized(&self) -> Vec<(RunId, Authorization)> {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        self.reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|id| {
                records
                    .get(id)
                    .map(|live| (RunId(id.clone()), live.authorization.clone()))
            })
            .collect()
    }

    #[must_use]
    pub fn outstanding(&self) -> Vec<RunId> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .map(|name| RunId(name.clone()))
            .collect()
    }
}

/// What a run looks like right now.
///
/// Free of the store because the reader task holds only the run it is reading,
/// and has to be able to say what that run did without reaching back into
/// something that also holds it.
fn snapshot_of(id: &RunId, live: &Live) -> Outcome {
    let record = live.record.lock().unwrap_or_else(|e| e.into_inner());
    Outcome {
        run: id.clone(),
        authorization: live.authorization.clone(),
        state: record.state,
        stdout: record.stdout.snapshot(),
        stderr: record.stderr.snapshot(),
        file: record.file.clone(),
        stdout_bytes: record.stdout.kept.clone(),
        stderr_bytes: record.stderr.kept.clone(),
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RunError {
    #[error("the recorded operation does not authorize command execution")]
    WrongOperation,
    #[error("the service is stopping and is not starting new work")]
    Stopping,
    #[error("no run named {run}")]
    Unknown { run: String },
    #[error("the record at entry {recorded} did not authorize {role} on {host}")]
    WrongTarget {
        recorded: u64,
        host: String,
        role: String,
    },
    #[error("the target would not run the command: {detail}")]
    Channel { detail: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;

    use russh::keys::ssh_encoding::bytes::Bytes;
    use russh::keys::ssh_key;
    use russh::server::{self, Auth, Msg, Server as _};
    use russh::{Channel, ChannelId, keys};
    use tokio::net::TcpListener;

    use super::*;
    use crate::command::Command;
    use crate::connect::{Connector, CredentialError, CredentialSource, Timeouts};
    use crate::registry::{CredentialRef, PinnedHostKey, Registry};
    use crate::secret::Secret;
    use crate::{HostId, RoleId};

    /// A target that runs what it is asked to run.
    ///
    /// The point of a real shell here is that it closes the loop: an argument
    /// vector is quoted, crosses a real SSH channel, and is parsed by a real
    /// shell. A server that echoed back what we sent would agree with our own
    /// reading of the wire format and prove nothing about it.
    /// How the test target answers an exec request.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Exec {
        /// Run it in a real shell.
        Shell,
        /// Answer the request negatively, which is a target declining to run a
        /// command at all.
        Refuse,
        /// Accepts the channel promptly and then never answers the exec
        /// request. The command may or may not have reached the target, which
        /// is exactly the state a caller has to be able to find it in.
        Silent,
        /// Hold the channel-open request without answering it, which is where
        /// a silent target actually holds a caller: opening the channel is the
        /// first thing that waits on the target.
        Stall,
        /// Never answers the exec request, then closes the channel. Nothing
        /// ever said the command was taken, and now nothing more is coming.
        Vanish,
        /// Never answers the exec request either, but produces output and then
        /// closes. Only a command that ran produces output, whatever the target
        /// did or did not say about taking it.
        Unheralded,
        /// Produces output and *then* answers the request negatively, which is
        /// a target contradicting itself. Nothing obliges a target to be
        /// coherent, and a caller still has to be told something true.
        Recants,
        /// The same contradiction, with a secret split across it: half a key,
        /// the negative reply, then the rest. Neither half is recognisable
        /// alone, so only a reader that kept going sees what the stream is.
        RecantsMidSecret,
    }

    #[derive(Clone)]
    struct ShellServer(Exec, Arc<Mutex<Vec<String>>>);

    impl server::Server for ShellServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for ShellServer {
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
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if self.0 == Exec::Stall {
                // Neither accepted nor refused, for far longer than any caller
                // is willing to wait. Returning without accepting is not the
                // same thing: russh answers that promptly, and a prompt answer
                // is not the case the budget exists for.
                tokio::time::sleep(Duration::from_secs(30)).await;
                return Ok(());
            }
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if let Ok(mut asked) = self.1.lock() {
                asked.push(String::from_utf8_lossy(data).into_owned());
            }
            match self.0 {
                Exec::Shell => {}
                Exec::Refuse => {
                    let _ = session.channel_failure(channel);
                    return Ok(());
                }
                // No reply of either kind, and the channel stays open.
                Exec::Stall | Exec::Silent => return Ok(()),
                Exec::Vanish => {
                    // No reply either, and then the channel goes away: the
                    // caller is left with a command nothing ever said was
                    // taken.
                    let handle = session.handle();
                    tokio::spawn(async move {
                        let _ = handle.close(channel).await;
                    });
                    return Ok(());
                }
                Exec::Unheralded => {
                    // Output but no reply, and no exit status: everything the
                    // caller has says the command ran, except the one message
                    // that would have said so.
                    let handle = session.handle();
                    tokio::spawn(async move {
                        let _ = handle.data(channel, Bytes::from_static(b"hello")).await;
                        let _ = handle.close(channel).await;
                    });
                    return Ok(());
                }
                Exec::Recants => {
                    // Output first, then the negative reply. Both cannot be
                    // true, and only one of them is evidence.
                    let handle = session.handle();
                    tokio::spawn(async move {
                        let _ = handle.data(channel, Bytes::from_static(b"hello")).await;
                        let _ = handle.channel_failure(channel).await;
                        let _ = handle.close(channel).await;
                    });
                    return Ok(());
                }
                Exec::RecantsMidSecret => {
                    // Half a key, the negative reply, then the rest. A reader
                    // that stopped at the reply would keep the half it had and
                    // never learn what it was holding.
                    let handle = session.handle();
                    tokio::spawn(async move {
                        // Split so that neither half is a shape on its own:
                        // only the join is one, so recognising it is proof the
                        // whole stream was read rather than proof the first
                        // piece happened to look alarming.
                        let _ = handle
                            .data(channel, Bytes::from_static(b"aws_secret_"))
                            .await;
                        let _ = handle.channel_failure(channel).await;
                        // Long enough that a reader which stopped at the reply
                        // has already settled the run: the rest arrives after,
                        // so having it is proof the reading continued rather
                        // than proof it was buffered in time.
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        let _ = handle
                            .data(channel, Bytes::from_static(b"access_key = AKIAEXAMPLE"))
                            .await;
                        let _ = handle.close(channel).await;
                    });
                    return Ok(());
                }
            }
            let command = String::from_utf8_lossy(data).into_owned();
            let handle = session.handle();
            let _ = session.channel_success(channel);
            tokio::spawn(async move {
                let output = tokio::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(&command)
                    .output()
                    .await;
                let (stdout, stderr, code) = match output {
                    Ok(output) => (
                        output.stdout,
                        output.stderr,
                        output.status.code().unwrap_or(255),
                    ),
                    Err(err) => (Vec::new(), err.to_string().into_bytes(), 255),
                };
                if !stdout.is_empty() {
                    let _ = handle.data(channel, Bytes::from(stdout)).await;
                }
                if !stderr.is_empty() {
                    let _ = handle.extended_data(channel, 1, Bytes::from(stderr)).await;
                }
                let _ = handle
                    .exit_status_request(channel, u32::try_from(code).unwrap_or(255))
                    .await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
            Ok(())
        }
    }

    struct OneKey(String);

    impl CredentialSource for OneKey {
        async fn fetch(&self, _: &CredentialRef) -> Result<Secret<String>, CredentialError> {
            Ok(Secret::new(self.0.clone()))
        }
    }

    struct Harness {
        connection: Connection,
        /// Every command the target was actually asked to run, so a test can
        /// tell "refused" from "never sent".
        asked: Arc<Mutex<Vec<String>>>,
    }

    async fn harness() -> Harness {
        harness_answering(Exec::Shell).await
    }

    async fn harness_answering(answer: Exec) -> Harness {
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
        let asked = Arc::new(Mutex::new(Vec::new()));
        let mut server = ShellServer(answer, Arc::clone(&asked));
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
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
        .expect("the test registry is well formed");
        let target = registry
            .resolve(
                &HostId::parse("testhost").unwrap(),
                &RoleId::parse("readonly").unwrap(),
            )
            .expect("the test registry resolves");
        let connection = connector
            .connect(&target)
            .await
            .expect("connecting to the shell server");

        Harness { connection, asked }
    }

    /// A target that declines to run a command has said something, and it is
    /// not "still going". Reporting it as running would have the caller wait
    /// out its budget and then retry what was already refused.
    #[tokio::test]
    async fn a_refused_command_is_refused_rather_than_slow() {
        let harness = harness_answering(Exec::Refuse).await;
        let outcome = runs(Limits::default())
            .run(&harness.connection, recorded(&["echo", "hello"]))
            .await
            .expect("the run is reported, not an error");

        assert_eq!(outcome.state, RunState::Refused);
        assert!(!outcome.still_running());

        // Refused by the target, not never sent: the two are different facts
        // and only one of them is this state.
        let asked = harness.asked.lock().unwrap().clone();
        assert!(
            asked.iter().any(|sent| sent.contains("hello")),
            "the command never reached the target: {asked:?}"
        );
    }

    /// A target that produces output and then declines the request is
    /// contradicting itself. The output is the half that cannot be taken back:
    /// bytes came from somewhere, so the command ran, and reporting a refusal
    /// would tell a caller it is safe to send a destructive command again.
    #[tokio::test]
    async fn a_refusal_after_output_does_not_unrun_the_command() {
        let harness = harness_answering(Exec::Recants).await;
        let outcome = runs(Limits::default())
            .run(&harness.connection, recorded(&["echo", "hello"]))
            .await
            .expect("the run is reported, not an error");

        assert_ne!(
            outcome.state,
            RunState::Refused,
            "output arrived and the command was still reported as never started"
        );
        assert_eq!(outcome.stdout().text, "hello");
    }

    /// What a stream is gets decided from the whole stream, so the reader has
    /// to see the whole stream. A target that declines the request halfway
    /// through a key would otherwise stop the reading there, and the half
    /// already collected — unrecognisable on its own — would be released as
    /// ordinary output while the rest, and what it proves, never arrives.
    #[tokio::test]
    async fn a_secret_split_across_a_refusal_is_still_recognised() {
        let harness = harness_answering(Exec::RecantsMidSecret).await;
        let outcome = runs(Limits::default())
            .run(&harness.connection, recorded(&["cat", "credentials"]))
            .await
            .expect("the run is reported, not an error");

        assert!(
            outcome.stdout().matched.is_some(),
            "the stream was not recognised as a secret: {:?}",
            outcome.stdout()
        );
    }

    /// A channel that ends having carried nothing back leaves the question
    /// open, and the answer is to say so.
    ///
    /// Calling it ended claims the work happened, and a caller then leaves
    /// undone work undone. Calling it refused claims it did not, and a caller
    /// then repeats a command that may have already changed the target. Neither
    /// is a fact anyone here has.
    #[tokio::test]
    async fn silence_from_the_target_is_reported_as_silence() {
        let harness = harness_answering(Exec::Vanish).await;
        let outcome = runs(Limits::default())
            .run(&harness.connection, recorded(&["echo", "hello"]))
            .await
            .expect("the run is reported, not an error");

        assert_eq!(
            outcome.state,
            RunState::Indeterminate,
            "got {:?}",
            outcome.state
        );
        assert!(!outcome.still_running());
    }

    /// Output is a command running. A target that produced some and never got
    /// round to saying it had taken the request has still run it, and telling a
    /// caller otherwise invites it to send a destructive command a second time
    /// — which is the worse of the two mistakes, and the one this guards.
    #[tokio::test]
    async fn output_is_proof_enough_that_a_command_ran() {
        let harness = harness_answering(Exec::Unheralded).await;
        let outcome = runs(Limits::default())
            .run(&harness.connection, recorded(&["echo", "hello"]))
            .await
            .expect("the run is reported, not an error");

        // `Ended` specifically, not merely "not refused": output proves the
        // command ran, so reporting it as something nobody knows about would
        // fail the caller in the same direction, just more politely.
        assert_eq!(
            outcome.state,
            RunState::Ended,
            "output did not settle whether the command ran: {:?}",
            outcome.state
        );
        assert_eq!(outcome.stdout().text, "hello");
    }

    /// The wait a caller is given covers the whole call. A target that accepts
    /// the connection and then never answers would otherwise hold it for the
    /// connection's inactivity timeout, which is a different and much longer
    /// number than the one the limit advertises.
    #[tokio::test]
    async fn setting_up_the_command_is_inside_the_caller_s_wait() {
        let harness = harness_answering(Exec::Stall).await;
        let limits = Limits {
            wait: Duration::from_millis(300),
            ..Limits::default()
        };
        let attempts = runs(limits);
        let started = Instant::now();
        let answered = attempts
            .run(&harness.connection, recorded(&["sleep", "60"]))
            .await;

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the call outlived its budget by {:?}",
            started.elapsed()
        );
        // What comes back is the budget expiring rather than a run identifier:
        // the target never accepted the channel, so there is nothing running to
        // hand back and saying otherwise would invent one.
        assert!(matches!(answered, Err(RunError::Channel { .. })));

        // And the slot the abandoned setup took is back. A record registered
        // before the target answered, with no reader that can ever settle it,
        // would sit in the store forever and take a place with it.
        assert!(
            attempts.outstanding().is_empty(),
            "a run that never started is still being held"
        );
    }

    /// A call abandoned after the command was sent leaves a run behind, because
    /// the command is running on the target whether or not anything is waiting
    /// for it. What must not happen is that the run becomes unreachable: the
    /// caller never received an identifier, so the store is the only way back
    /// to it.
    #[tokio::test]
    async fn an_abandoned_call_leaves_a_run_that_can_still_be_found() {
        let harness = harness().await;
        let runs = runs(Limits::default());

        // Cancelled while the command is running, so the identifier the call
        // would have returned is never handed over.
        let abandoned = runs.run(&harness.connection, recorded(&["sleep", "30"]));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), abandoned)
                .await
                .is_err(),
            "the call was supposed to be cancelled, not to finish"
        );

        let outstanding = runs.outstanding();
        assert_eq!(
            outstanding.len(),
            1,
            "the run is unreachable: {outstanding:?}"
        );
        let found = outstanding.first().expect("just asserted there is one");
        assert!(
            runs.wait(found, Duration::from_millis(10)).await.is_ok(),
            "the run was found but cannot be asked about"
        );
    }

    /// A run that is still going stays addressable. Releasing it would free the
    /// slot while its reader and the remote command carry on, and asking after
    /// that would answer that no such run exists - which is untrue.
    #[tokio::test]
    async fn a_running_run_is_not_released() {
        let harness = harness().await;
        let runs = runs(Limits {
            wait: Duration::from_millis(50),
            ..Limits::default()
        });
        let outcome = runs
            .run(&harness.connection, recorded(&["sleep", "30"]))
            .await
            .expect("the slow run starts");
        assert!(outcome.still_running());

        assert!(!runs.forget(&outcome.run), "a running run was released");
        assert!(
            runs.wait(&outcome.run, Duration::from_millis(10))
                .await
                .is_ok(),
            "the run stopped being addressable"
        );
    }

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    /// A receipt for a command, minted the way production mints one: classify,
    /// decide, write the record, and take what writing it returns. There is no
    /// stand-in - a test that could conjure a receipt would not be exercising
    /// the gate this module's signature exists to enforce.
    fn recorded(argv: &[&str]) -> Receipt {
        recorded_for("testhost", argv)
    }

    /// The same, for a session against some other host. The harness connects to
    /// `testhost`, so this is how a test gets an authorization that belongs
    /// somewhere else.
    fn recorded_for(host: &str, argv: &[&str]) -> Receipt {
        use crate::audit::Ledger;
        use crate::clock::TestClock;
        use crate::policy::Engine;
        use crate::session::{Lifetime, Purpose, SessionStore};

        let session = SessionStore::new(
            TestClock::at(1_000),
            Lifetime {
                idle: 10_000,
                max: 60_000,
                grace: 5_000,
            },
            8,
        )
        .open(
            crate::PrincipalId::parse("alice").unwrap(),
            crate::HostId::parse(host).unwrap(),
            crate::RoleId::parse("readonly").unwrap(),
            Purpose::parse("exercise the execution path").unwrap(),
            crate::AccessClass::Privileged,
        )
        .unwrap();
        let decision =
            Engine::new(crate::policy::ReviewMode::Disabled).decide(&session, command(argv));
        Ledger::new(TestClock::at(1_000))
            .record_intent(
                decision,
                crate::command::CommandIntent::parse("exercise the run path").unwrap(),
            )
            .unwrap()
            .into_parts()
            .1
            .expect("these test commands are permitted to run")
    }

    fn runs(limits: Limits) -> Runs {
        Runs::new(limits)
    }

    /// A caller hands an identifier back as a string, so what a caller may hand
    /// back has to be what this mints — and nothing else, since the length of
    /// anything else is the caller's to choose and every rejected string is
    /// otherwise copied, hashed and quoted back.
    ///
    /// Minting and reading are separate code; this is what keeps them agreeing.
    #[test]
    fn what_a_store_mints_is_what_a_caller_may_present() {
        let store = runs(Limits::default());
        let minted = store.mint_id();
        assert_eq!(
            RunId::parse(minted.as_str()).expect("a minted identifier"),
            minted
        );

        let unusable = [
            "",
            "no-hyphens",
            minted.as_str().trim_end_matches(|c: char| c != '-'),
            &minted.as_str().to_uppercase(),
            &format!("{}0", minted.as_str()),
            &"a".repeat(4096),
        ];
        for raw in unusable {
            assert!(
                RunId::parse(raw).is_err(),
                "{raw:?} was accepted as a run identifier"
            );
        }
    }

    /// An identifier is the only thing a caller presents to ask about a run, so
    /// one identifier must not let a caller name another. Numbering runs makes
    /// every other one derivable by arithmetic from any single one — which is
    /// where probing runs you do not own starts.
    ///
    /// A position is what counting produces, so what this looks for is
    /// counting: names that are all numbers and that climb in the order they
    /// were handed out.
    #[test]
    fn an_identifier_does_not_name_a_position() {
        const MINTED: usize = 64;
        let store = runs(Limits::default());
        let names: Vec<String> = (0..MINTED)
            .map(|_| {
                let id = store.mint_id();
                let (_, names) = id
                    .as_str()
                    .rsplit_once('-')
                    .expect("an identifier says which store minted it");
                names.to_owned()
            })
            .collect();

        let distinct: HashSet<&String> = names.iter().collect();
        assert_eq!(
            distinct.len(),
            MINTED,
            "a store gave two runs the same name"
        );

        let counted: Option<Vec<u128>> = names.iter().map(|name| name.parse().ok()).collect();
        assert!(
            counted.is_none_or(|values| !values.is_sorted_by(|earlier, later| earlier < later)),
            "the names climb, so holding one names the rest: {names:?}"
        );
    }

    /// An authorization is for a target, not just for a command. The connection
    /// is dialled independently of the record being written, so this is the one
    /// part of an authorization the execution path cannot take from the receipt
    /// and has to check against it.
    #[tokio::test]
    async fn a_receipt_for_another_host_does_not_run_here() {
        let harness = harness().await;
        let err = runs(Limits::default())
            .run(
                &harness.connection,
                recorded_for("dns1", &["printf", "%s", "hello"]),
            )
            .await
            .expect_err("a receipt written for another host should not run on this one");

        assert!(
            matches!(err, RunError::WrongTarget { .. }),
            "unexpected error: {err:?}"
        );
        assert!(
            harness.asked.lock().unwrap().is_empty(),
            "the command reached the target anyway"
        );
    }

    /// Once the channel is open, the command may reach the target at any
    /// moment, so from that point on it must be findable whatever the caller
    /// learns next. The run is registered before anything is sent, which is
    /// what makes an execution nobody heard back about recoverable rather than
    /// invisible.
    #[tokio::test]
    async fn a_command_that_may_have_reached_the_target_is_always_findable() {
        let harness = harness_answering(Exec::Silent).await;
        let runs = runs(Limits {
            wait: Duration::from_millis(100),
            ..Limits::default()
        });

        let outcome = runs
            .run(&harness.connection, recorded(&["printf", "%s", "hello"]))
            .await
            .expect("the run is reported, not lost");
        assert!(outcome.still_running());

        let outstanding = runs.outstanding();
        assert_eq!(
            outstanding.len(),
            1,
            "the run is unreachable: {outstanding:?}"
        );
        assert!(
            runs.wait(outcome.run(), Duration::from_millis(10))
                .await
                .is_ok(),
            "the run cannot be asked about"
        );
    }

    /// Output arrives in pieces and a shape can fall across the join between
    /// two of them. Reading each piece on its own would miss every credential
    /// that did not happen to arrive whole - which is most of them, since the
    /// pieces are however the transport chose to split the bytes.
    #[test]
    fn a_shape_split_across_two_arrivals_is_one_shape() {
        // Split so that neither piece is a shape on its own - otherwise the
        // second piece would match by itself and the join would go untested.
        let mut collected = Collected::new(1 << 20);
        collected.push(b"region=us-east-1\naws_secret_");
        assert!(collected.matched.is_none(), "half a shape is not a shape");
        collected.push(b"access_key = wJalrXUtnFEMI\n");

        assert!(
            collected.matched.is_some(),
            "a shape arriving in two pieces was missed"
        );
    }

    /// The output bound decides what is *kept*, not what is *seen*. A key that
    /// appears past the bound is still a key, and a record that called that
    /// stream ordinary output which happens to be short would be wrong about
    /// the one thing this pass exists to be right about.
    #[tokio::test]
    async fn a_secret_past_the_output_bound_is_still_recognised() {
        let harness = harness().await;
        let runs = runs(Limits {
            output_bytes: 16,
            ..Limits::default()
        });

        let outcome = runs
            .run(
                &harness.connection,
                recorded(&[
                    "sh",
                    "-c",
                    "printf 'x%.0s' $(seq 1 200); printf -- '-----BEGIN OPENSSH PRIVATE KEY-----'",
                ]),
            )
            .await
            .unwrap();

        assert!(outcome.stdout().truncated, "the bound should have applied");
        assert!(
            !outcome.stdout().text.contains("BEGIN"),
            "the key should be past the retained prefix: {:?}",
            outcome.stdout().text
        );
        assert!(
            outcome.stdout().matched.is_some(),
            "output past the bound was not recognised"
        );
    }

    /// What ran and what was decided are two entries in the record, and the
    /// outcome carries the link between them so nothing has to remember it.
    #[tokio::test]
    async fn an_outcome_names_the_entry_that_authorized_it() {
        let harness = harness().await;
        let receipt = recorded(&["printf", "%s", "hello"]);
        let authorized = receipt.sequence();
        let runs = runs(Limits::default());

        let outcome = runs.run(&harness.connection, receipt).await.unwrap();
        assert_eq!(outcome.decided(), authorized);

        // And it survives being asked about later, when whoever asks no longer
        // holds the receipt.
        let again = runs
            .wait(&outcome.run, Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(again.decided(), authorized);
    }

    /// The whole path: an argument vector is quoted, crosses a real SSH
    /// channel, is parsed by a real shell, and its outcome comes back with the
    /// two streams distinguishable and the exit status intact.
    #[tokio::test]
    async fn a_command_runs_and_its_outcome_comes_back() {
        let harness = harness().await;
        let runs = runs(Limits::default());

        let outcome = runs
            .run(&harness.connection, recorded(&["printf", "%s", "hello"]))
            .await
            .unwrap();
        assert_eq!(outcome.state, RunState::Exited { code: 0 });
        assert_eq!(outcome.stdout.text, "hello");
        assert_eq!(outcome.stderr.text, "");
    }

    /// A caller asking whether a command complained cannot find out if the
    /// complaint was mixed into its output.
    #[tokio::test]
    async fn the_two_streams_stay_apart() {
        let harness = harness().await;
        let runs = runs(Limits::default());

        let outcome = runs
            .run(
                &harness.connection,
                recorded(&["sh", "-c", "printf out; printf err >&2; exit 3"]),
            )
            .await
            .unwrap();
        assert_eq!(outcome.stdout.text, "out");
        assert_eq!(outcome.stderr.text, "err");
        assert_eq!(outcome.state, RunState::Exited { code: 3 });
    }

    /// An argument that is itself shell syntax must arrive as an argument. This
    /// is the quoting contract, checked where it actually matters: after a real
    /// shell on a real target has parsed it.
    #[tokio::test]
    async fn arguments_survive_the_target_s_shell() {
        let harness = harness().await;
        let runs = runs(Limits::default());

        let outcome = runs
            .run(
                &harness.connection,
                recorded(&["printf", "%s|", "a b", "$HOME", "; echo pwned", "*"]),
            )
            .await
            .unwrap();
        assert_eq!(outcome.stdout.text, "a b|$HOME|; echo pwned|*|");
    }

    /// Output is bounded, and a bounded response says so rather than handing
    /// back a prefix that looks complete.
    #[tokio::test]
    async fn output_beyond_the_bound_is_reported_as_truncated() {
        let harness = harness().await;
        let runs = runs(Limits {
            output_bytes: 16,
            ..Limits::default()
        });

        let outcome = runs
            .run(
                &harness.connection,
                recorded(&["sh", "-c", "printf 'x%.0s' $(seq 1 500)"]),
            )
            .await
            .unwrap();
        assert!(outcome.stdout.truncated, "should be marked truncated");
        assert_eq!(outcome.stdout.text.len(), 16);
        assert_eq!(outcome.stdout.bytes, 500, "the full size is still reported");
    }

    /// The promise that makes one execution path workable: a command that
    /// outlives the caller's wait is handed back still identified, and asking
    /// again later returns its result. Nothing is orphaned by being slow.
    #[tokio::test]
    async fn a_command_that_outlives_its_wait_stays_retrievable() {
        let harness = harness().await;
        let runs = runs(Limits {
            wait: Duration::from_millis(50),
            ..Limits::default()
        });

        let outcome = runs
            .run(
                &harness.connection,
                recorded(&["sh", "-c", "sleep 1; printf done"]),
            )
            .await
            .unwrap();
        assert!(outcome.still_running(), "should not have finished yet");
        assert_eq!(outcome.stdout.text, "");

        let later = runs
            .wait(&outcome.run, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(later.run, outcome.run, "the same run, asked about again");
        assert_eq!(later.state, RunState::Exited { code: 0 });
        assert_eq!(later.stdout.text, "done");
    }

    #[tokio::test]
    async fn asking_about_a_run_that_does_not_exist_is_refused() {
        let runs = runs(Limits::default());
        assert_eq!(
            runs.wait(&RunId("r-nonexistent".to_owned()), Duration::from_millis(1))
                .await
                .unwrap_err(),
            RunError::Unknown {
                run: "r-nonexistent".to_owned()
            }
        );
    }

    /// Refusing and registering happen under one hold, so a stop arriving
    /// between a caller's check and its start cannot still put a command on a
    /// target. Anywhere else and the store can grow after shutdown has said it
    /// will not.
    #[tokio::test]
    async fn a_stopping_store_registers_nothing() {
        let harness = harness().await;
        let runs = runs(Limits::default());

        runs.stop();

        let refused = runs
            .run(&harness.connection, recorded(&["printf", "hi"]))
            .await
            .expect_err("a stopping store ran a command");
        assert!(
            matches!(refused, RunError::Stopping),
            "unexpected error: {refused:?}"
        );
        assert!(
            runs.outstanding().is_empty(),
            "a stopping store kept a record of what it refused"
        );
    }

    /// A run that has finished is kept until whoever asked collects it, so
    /// counting held records answers "what is this store keeping", not "what is
    /// still happening". Anything waiting for work to end — stopping the
    /// process, say — needs the second question, or it waits out its whole
    /// deadline on a result recorded long ago and then reports it as lost.
    #[tokio::test]
    async fn a_finished_run_is_kept_without_still_being_in_flight() {
        let harness = harness().await;
        let runs = runs(Limits::default());
        let outcome = runs
            .run(&harness.connection, recorded(&["printf", "hi"]))
            .await
            .unwrap();

        assert!(!outcome.still_running(), "the command should have finished");
        assert_eq!(runs.outstanding().len(), 1, "the result was not kept");

        // Once its reader has finished telling the record what happened. The
        // caller is woken just before that last step, so a count taken the
        // instant `run` returns can still include this one — which is the
        // point of counting readers rather than states: what it answers is
        // "still to be recorded", and stopping while that is nonzero is what
        // keeps a completion from being lost.
        for _ in 0..100 {
            if runs.unfinished().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("a finished command was still counted as unrecorded");
    }

    #[tokio::test]
    async fn a_forgotten_run_releases_its_output() {
        let harness = harness().await;
        let runs = runs(Limits::default());
        let outcome = runs
            .run(&harness.connection, recorded(&["printf", "hi"]))
            .await
            .unwrap();
        assert_eq!(runs.outstanding().len(), 1);
        runs.forget(&outcome.run);
        assert!(runs.outstanding().is_empty());
    }

    /// Connecting is a precondition for running, so a broken connection has to
    /// surface as a failure to run rather than as an empty success.
    #[tokio::test]
    async fn a_closed_connection_cannot_start_a_run() {
        let harness = harness().await;
        harness.connection.close().await.ok();
        let runs = runs(Limits::default());
        let err = runs
            .run(&harness.connection, recorded(&["printf", "hi"]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RunError::Channel { .. }),
            "unexpected error: {err:?}"
        );
    }
}
