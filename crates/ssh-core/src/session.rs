//! Sessions: the unit of work, audit, and approval.
//!
//! A session binds a principal, one host, and one role, carries the purpose the
//! work was opened for, and expires on its own. Everything a command does
//! happens inside one, so that a record of what happened has something to
//! attribute it to and a human approving work has something to approve.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::clock::{Clock, Millis};
use crate::{AccessClass, HostId, PrincipalId, RoleId};

/// Handle to a session: shaped, not merely opaque.
///
/// What authorizes a session is its principal, so a malformed identifier is
/// harmless to *authorization* — but it still arrives from the wire, is
/// allocated, and is hashed in full on every lookup, and nothing else bounds
/// it. Every identifier this service issues is `ID_BYTES` bytes of randomness
/// in lowercase hex, so anything else cannot name a session and is refused
/// before it costs anything.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SessionId(String);

/// Bytes of randomness behind a session identifier.
const ID_BYTES: usize = 16;

/// Characters in a session identifier: two hex digits per random byte.
const ID_CHARS: usize = ID_BYTES * 2;

impl SessionId {
    /// Reads an identifier a caller supplied.
    pub fn parse(raw: &str) -> Result<Self, MalformedSessionId> {
        let shaped = raw.len() == ID_CHARS
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !shaped {
            return Err(MalformedSessionId);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SessionId {
    type Error = MalformedSessionId;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// The identifier cannot be one this service issued.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("that is not the shape of a session identifier")]
pub struct MalformedSessionId;

/// Mints an identifier that no previous session has held.
///
/// Random from a CSPRNG rather than a counter. A counter restarts at zero with
/// the process, so the first session after a restart reuses the identifier the
/// first session before it had — and a delayed or retried request carrying that
/// stale handle would land on a *different* session belonging to the same
/// principal, inheriting its host, role, purpose and account class. Restarting is
/// supposed to invalidate sessions, not silently re-point them.
///
/// Ownership is still what authorizes, so this is not a bearer token. It is
/// simply the cheapest way to make reuse impossible in practice, and it
/// removes guessability as a question at the same time.
fn new_identifier() -> String {
    let mut bytes = [0_u8; ID_BYTES];
    rand::fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Why a session was opened, in the operator's words.
///
/// A session is the unit a human approves, and "approve this" is unanswerable
/// without it. An empty purpose would produce a record that says work happened
/// and nothing about what it was for, so a blank one is refused rather than
/// stored.
///
/// Bounded as well as non-empty. Limiting how *many* sessions a principal holds
/// bounds nothing if one of them can carry an unlimited string: the value is
/// stored, cloned into the record, and cloned again into every lapse context. A
/// purpose is a sentence for a human to read, and this is more than generous
/// for one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Purpose(String);

/// Longest purpose accepted.
const PURPOSE_MAX: usize = 512;

impl Purpose {
    pub fn parse(raw: &str) -> Result<Self, PurposeError> {
        if raw.trim().is_empty() {
            return Err(PurposeError::Blank);
        }
        if raw.len() > PURPOSE_MAX {
            return Err(PurposeError::TooLong { max: PURPOSE_MAX });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Purpose {
    type Error = PurposeError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PurposeError {
    #[error("a session needs a purpose; a human is asked to approve it")]
    Blank,
    #[error("a purpose is a sentence, not a document; at most {max} bytes")]
    TooLong { max: usize },
}

/// One principal already holds as many live sessions as it may.
///
/// Close one, or let one lapse. Refusing is the point: a caller that can open
/// sessions without limit can consume the service's memory without ever running
/// a command.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("this principal already holds {limit} live sessions")]
pub struct TooManySessions {
    pub limit: usize,
}

/// How long a session may live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifetime {
    /// Closed after this long without use.
    pub idle: Millis,
    /// Closed after this long regardless of use.
    pub max: Millis,
    /// How long a lapsed session survives collection by other callers.
    ///
    /// Not extra life: from the instant a session expires, this store refuses
    /// every request made through it, so nothing can reach a command by way of
    /// a lapsed session. (An authorization already minted from a live session
    /// is a separate question, answered where a request is assembled into a
    /// command rather than here.) What survives is the ability to *say so
    /// usefully* —
    /// the owner who comes back is told the session lapsed and what it was for,
    /// rather than being told it never existed and left to reconstruct the
    /// host, role, purpose and account class from memory.
    ///
    /// It does not gate that answer, only how long the entry outlives an
    /// unrelated caller's collection: an owner who returns to a session still
    /// held is told what happened to it whatever this is set to, including
    /// zero. Longer values widen the window in which that is still true after
    /// somebody else has opened or swept.
    ///
    /// Bounded, because remembering forever is the unbounded growth this is
    /// collected to avoid. A caller returning long after the fact does not need
    /// the context; a caller returning immediately does.
    pub grace: Millis,
}

/// A live session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub principal: PrincipalId,
    pub host: HostId,
    pub role: RoleId,
    pub purpose: Purpose,
    pub access_class: AccessClass,
    opened_at: Millis,
    last_used: Millis,
    lifetime: Lifetime,
}

impl Session {
    /// Whether the session has aged out, and why.
    fn expiry(&self, now: Millis) -> Option<Expiry> {
        if now.saturating_sub(self.opened_at) >= self.lifetime.max {
            return Some(Expiry::MaxLifetime);
        }
        if now.saturating_sub(self.last_used) >= self.lifetime.idle {
            return Some(Expiry::Idle);
        }
        None
    }

    /// When this session stopped being usable, whichever bound came first.
    fn lapsed_at(&self) -> Millis {
        let by_age = self.opened_at.saturating_add(self.lifetime.max);
        let by_idleness = self.last_used.saturating_add(self.lifetime.idle);
        by_age.min(by_idleness)
    }

    /// Whether the session is old enough to stop remembering.
    fn forgettable(&self, now: Millis) -> bool {
        self.expiry(now).is_some() && now >= self.lapsed_at().saturating_add(self.lifetime.grace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    Idle,
    MaxLifetime,
}

/// Operational state of a session at the instant a snapshot was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Live,
    Lapsed(Expiry),
}

/// A read-only operational view of a held session.
///
/// Taking a snapshot does not count as use and therefore cannot extend the
/// session it observes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session: Session,
    pub status: SessionStatus,
    pub opened_at: Millis,
    pub last_used: Millis,
    pub idle_by: Millis,
    pub ends_by: Millis,
}

/// What a caller needs to open an equivalent session after one lapses.
///
/// Carried on the error rather than left for the caller to reconstruct: an
/// agent that has to guess the host, role, purpose, and account class it was using will
/// guess differently, and the replacement session will not be the one a human
/// approved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LapsedContext {
    pub host: HostId,
    pub role: RoleId,
    pub purpose: Purpose,
    pub access_class: AccessClass,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    /// No live session with that identifier belongs to this principal.
    ///
    /// Deliberately the same answer whether the session never existed, belongs
    /// to somebody else, or was closed: a caller must not be able to probe for
    /// other principals' sessions by comparing error messages.
    #[error("no such session")]
    Unknown,
    #[error("session expired")]
    Expired {
        why: Expiry,
        context: Box<LapsedContext>,
    },
}

/// Live sessions.
pub struct SessionStore<C: Clock> {
    clock: C,
    lifetime: Lifetime,
    per_principal: usize,
    sessions: Mutex<HashMap<String, Session>>,
}

impl<C: Clock> SessionStore<C> {
    /// Checks immutable session identity without extending its lifetime.
    pub fn check_binding(
        &self,
        id: &SessionId,
        principal: &PrincipalId,
        host: &HostId,
        role: &RoleId,
    ) -> Result<(), SessionError> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let session = sessions.get(id.as_str()).ok_or(SessionError::Unknown)?;
        if &session.principal != principal || &session.host != host || &session.role != role {
            return Err(SessionError::Unknown);
        }
        Ok(())
    }

    /// `per_principal` is the most entries one principal may occupy, counting
    /// both live sessions and lapsed ones still being remembered.
    ///
    /// Expiry bounds how *long* a session lives, not how many exist. Without a
    /// count as well, a caller can open sessions faster than they age out and
    /// the store grows for as long as it keeps asking — each open also scanning
    /// everything already there.
    #[must_use]
    pub fn new(clock: C, lifetime: Lifetime, per_principal: usize) -> Self {
        Self {
            clock,
            lifetime,
            per_principal,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Opens a session for a principal.
    ///
    /// Collects along the way, so opening pays for forgetting what earlier
    /// callers abandoned. Without that, a session nobody ever touches again is
    /// never noticed by anything: expiry is observed when the owner comes back,
    /// and an owner who has gone away by definition does not come back.
    pub fn open(
        &self,
        principal: PrincipalId,
        host: HostId,
        role: RoleId,
        purpose: Purpose,
        access_class: AccessClass,
    ) -> Result<Session, TooManySessions> {
        let id = SessionId(new_identifier());
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // Read under the lock. A reading taken before waiting for it can be
        // older than one another caller already wrote.
        let now = self.clock.now();
        sessions.retain(|_, held| !held.forgettable(now));

        // Counted over everything still held for this principal, not only what
        // is still usable. A lapsed session occupies an entry until its grace
        // period ends, so a quota that ignored those would bound nothing: open,
        // let lapse, open again, and every one of them is retained.
        let held = sessions
            .values()
            .filter(|held| held.principal == principal)
            .count();
        if held >= self.per_principal {
            // A lapsed session gives up its slot rather than denying one.
            // Remembering what a session was for is worth keeping; it is not
            // worth refusing the replacement session it exists to help open.
            // The oldest goes first, because it is the one whose owner is least
            // likely to still be coming back for it.
            let stale = sessions
                .values()
                .filter(|held| held.principal == principal && held.expiry(now).is_some())
                .min_by_key(|held| held.lapsed_at())
                .map(|held| held.id.0.clone());
            let Some(stale) = stale else {
                return Err(TooManySessions {
                    limit: self.per_principal,
                });
            };
            sessions.remove(&stale);
        }
        let session = Session {
            id: id.clone(),
            principal,
            host,
            role,
            purpose,
            access_class,
            opened_at: now,
            last_used: now,
            lifetime: self.lifetime,
        };
        sessions.insert(id.0, session.clone());
        Ok(session)
    }

    /// Forgets every session that lapsed longer ago than the grace period.
    ///
    /// Expired sessions are *not* dropped the moment they expire. They refuse
    /// every command from that instant, but they are kept briefly so the owner
    /// who returns is told the session lapsed and what it was for, rather than
    /// being told it never existed. Dropping immediately would satisfy
    /// collection and break the lapse context that makes reopening possible.
    ///
    /// Exposed because a deployment that opens sessions rarely still should not
    /// hold an abandoned one indefinitely.
    ///
    pub fn sweep(&self) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        sessions.retain(|_, held| !held.forgettable(now));
    }

    /// Every session that can still be used.
    ///
    /// For whoever holds something *per* session — a connection, most
    /// obviously — and needs to let go of it when a session stops being usable.
    /// Sessions stop by several routes: lapsed by age or idleness, swept,
    /// dropped when their owner returns after the grace, evicted to make room
    /// at the per-principal limit. Reporting what is left rather than what each
    /// route removed is what makes that reconciliation total; a holder
    /// subscribing to removals has to be told about every route, and will
    /// eventually miss one.
    ///
    /// A lapsed session is still *held* — that is what tells its owner it
    /// lapsed and what it was for — but it refuses every command from the
    /// instant it expires, so anything held on its behalf is already
    /// unreachable and this does not report it as a reason to keep it.
    #[must_use]
    pub fn live(&self) -> Vec<SessionId> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // Read under the lock: a reading taken before waiting for it can be
        // older than one another caller already wrote.
        let now = self.clock.now();
        sessions
            .values()
            .filter(|held| held.expiry(now).is_none())
            .map(|held| held.id.clone())
            .collect()
    }
    /// A bounded newest-first view of held sessions and their lifecycle state.
    ///
    /// Read under one lock and without changing `last_used`, so an operations
    /// page cannot keep abandoned sessions alive by looking at them. Selection
    /// retains at most `limit` references and clones only the returned
    /// sessions, so response memory is independent of the total principal set.
    #[must_use]
    pub fn recent_snapshots(&self, limit: usize) -> Vec<SessionSnapshot> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        let mut newest = Vec::with_capacity(limit.min(sessions.len()));
        for held in sessions.values() {
            let position = newest.partition_point(|candidate: &&Session| {
                candidate.opened_at > held.opened_at
                    || (candidate.opened_at == held.opened_at
                        && candidate.id.as_str() <= held.id.as_str())
            });
            if position < limit {
                newest.insert(position, held);
                newest.truncate(limit);
            }
        }
        newest
            .into_iter()
            .map(|held| SessionSnapshot {
                session: held.clone(),
                status: held
                    .expiry(now)
                    .map_or(SessionStatus::Live, SessionStatus::Lapsed),
                opened_at: held.opened_at,
                last_used: held.last_used,
                idle_by: held.last_used.saturating_add(held.lifetime.idle),
                ends_by: held.opened_at.saturating_add(held.lifetime.max),
            })
            .collect()
    }

    /// Whether this one session can still be used.
    ///
    /// The same question `live` answers, asked about one session rather than
    /// all of them — for a holder working through what it holds, which cannot
    /// use a set read before it started without that set going stale under it.
    ///
    /// Does not refresh the idle timer: asking whether a session is usable is
    /// not using it, and housekeeping that renewed what it looked at would keep
    /// alive exactly the sessions nobody is using.
    #[must_use]
    pub fn holds(&self, id: &SessionId) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // Read under the lock, as in `live`.
        let now = self.clock.now();
        sessions
            .get(id.as_str())
            .is_some_and(|held| held.expiry(now).is_none())
    }

    /// When a session's age alone will end it, if the store still holds it.
    ///
    /// The idle bound is deliberately not part of the answer: idleness resets
    /// with use, so the age bound is the only end a caller can plan against -
    /// which is what an agreement about the session's remaining life needs.
    #[must_use]
    pub fn ends_by(&self, id: &SessionId) -> Option<Millis> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        sessions
            .get(id.as_str())
            .filter(|held| held.expiry(now).is_none())
            .map(|held| held.opened_at.saturating_add(held.lifetime.max))
    }

    /// Retrieves a session for use, refreshing its idle timer.
    ///
    /// The principal is required rather than optional. A session identifier is
    /// not a capability: knowing one must not be enough to use it, or one
    /// caller could drive another's session and spend approvals granted to
    /// them.
    pub fn use_session(
        &self,
        id: &SessionId,
        principal: &PrincipalId,
    ) -> Result<Session, SessionError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        // Under the lock, for the same reason as `open`: a reading taken before
        // waiting for the lock can be older than one a concurrent caller has
        // already recorded, and writing it back would move `last_used`
        // backwards and expire a session that was just used.
        let now = self.clock.now();

        let session = sessions.get(id.as_str()).ok_or(SessionError::Unknown)?;
        if &session.principal != principal {
            return Err(SessionError::Unknown);
        }
        if let Some(why) = session.expiry(now) {
            let context = Box::new(LapsedContext {
                host: session.host.clone(),
                role: session.role.clone(),
                purpose: session.purpose.clone(),
                access_class: session.access_class,
            });
            // Answered before forgetting, so reaching a session that is still
            // held always tells its owner what happened to it — the whole
            // reason lapsed sessions are kept at all. Deciding that from the
            // grace period instead would make the answer depend on a duration,
            // and a deployment that set it to zero would get a store that
            // remembers a session precisely long enough to refuse to explain
            // it.
            //
            // Forgetting here as well as in `open` and `sweep` matters: a store
            // that nothing else touches would otherwise keep answering
            // `Expired` from a session past its grace period, and keep its
            // context in memory, forever.
            if session.forgettable(now) {
                sessions.remove(id.as_str());
            }
            return Err(SessionError::Expired { why, context });
        }

        let session = sessions.get_mut(id.as_str()).ok_or(SessionError::Unknown)?;
        session.last_used = now;
        Ok(session.clone())
    }

    /// Ends a session early.
    pub fn close(&self, id: &SessionId, principal: &PrincipalId) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get(id.as_str()) {
            Some(session) if &session.principal == principal => {
                sessions.remove(id.as_str());
                Ok(())
            }
            _ => Err(SessionError::Unknown),
        }
    }

    /// Number of sessions the store is holding.
    ///
    /// Deliberately does not sweep. If reading the count were what collected
    /// expired sessions, a process that never read it would still grow without
    /// bound, and this would report a bound it was itself creating. Collection
    /// belongs to [`SessionStore::open`] and [`SessionStore::sweep`]; this
    /// reports what those have left behind.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    const LIFETIME: Lifetime = Lifetime {
        idle: 10_000,
        max: 60_000,
        grace: 5_000,
    };
    const PER_PRINCIPAL: usize = 16;

    fn store() -> SessionStore<TestClock> {
        SessionStore::new(TestClock::at(1_000), LIFETIME, PER_PRINCIPAL)
    }

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::parse(name).unwrap()
    }

    fn open(store: &SessionStore<TestClock>, who: &str) -> Session {
        store
            .open(
                principal(who),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("readonly").unwrap(),
                Purpose::parse("check why the deploy did not take effect").unwrap(),
                AccessClass::ReadOnly,
            )
            .expect("within the per-principal limit")
    }

    #[test]
    fn session_binding_rejects_a_different_caller_host_or_account() {
        let store = store();
        let session = open(&store, "alice");
        store.clock.advance(LIFETIME.idle / 2);
        for (caller, host, role) in [
            ("bob", "dns1", "readonly"),
            ("alice", "dns2", "readonly"),
            ("alice", "dns1", "operator"),
        ] {
            assert_eq!(
                store.check_binding(
                    &session.id,
                    &principal(caller),
                    &HostId::parse(host).unwrap(),
                    &RoleId::parse(role).unwrap()
                ),
                Err(SessionError::Unknown)
            );
        }
        store
            .check_binding(
                &session.id,
                &principal("alice"),
                &session.host,
                &session.role,
            )
            .unwrap();
        store.clock.advance(LIFETIME.idle / 2);
        assert!(matches!(
            store.use_session(&session.id, &principal("alice")),
            Err(SessionError::Expired { .. })
        ));
    }

    #[test]
    fn a_session_is_usable_by_the_principal_that_opened_it() {
        let store = store();
        let session = open(&store, "alice");
        let used = store.use_session(&session.id, &principal("alice")).unwrap();
        assert_eq!(used.host.as_str(), "dns1");
        assert_eq!(
            used.purpose.as_str(),
            "check why the deploy did not take effect"
        );
    }

    #[test]
    fn operational_snapshots_are_newest_first_and_bounded_before_clone() {
        let store = store();
        let first = open(&store, "alice");
        store.clock.advance(1);
        let second = open(&store, "bob");
        store.clock.advance(1);
        let third = open(&store, "carol");

        let snapshots = store.recent_snapshots(2);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots.first().map(|item| &item.session.id),
            Some(&third.id)
        );
        assert_eq!(
            snapshots.get(1).map(|item| &item.session.id),
            Some(&second.id)
        );
        assert!(!snapshots.iter().any(|item| item.session.id == first.id));
        assert!(store.recent_snapshots(0).is_empty());
    }

    /// Invariant 3. Without this, one authenticated caller could drive
    /// another's session, or spend an approval granted to them, by guessing or
    /// observing an identifier.
    #[test]
    fn another_principal_cannot_use_or_close_a_session() {
        let store = store();
        let session = open(&store, "alice");

        assert_eq!(
            store.use_session(&session.id, &principal("bob")),
            Err(SessionError::Unknown)
        );
        assert_eq!(
            store.close(&session.id, &principal("bob")),
            Err(SessionError::Unknown)
        );

        store
            .use_session(&session.id, &principal("alice"))
            .expect("the owner is unaffected by the refusal");
    }

    /// A session that exists but is not yours must be indistinguishable from
    /// one that does not exist, or the error itself becomes a way to enumerate
    /// other principals' sessions.
    #[test]
    fn a_foreign_session_is_indistinguishable_from_a_missing_one() {
        let store = store();
        let session = open(&store, "alice");
        let foreign = store.use_session(&session.id, &principal("bob"));
        let missing = store.use_session(
            &SessionId::parse(&"0".repeat(ID_CHARS)).unwrap(),
            &principal("bob"),
        );
        assert_eq!(foreign, missing);
    }

    #[test]
    fn an_idle_session_expires_and_says_so() {
        let store = store();
        let session = open(&store, "alice");
        store.clock.advance(LIFETIME.idle);

        let err = store
            .use_session(&session.id, &principal("alice"))
            .unwrap_err();
        let SessionError::Expired { why, context } = err else {
            panic!("expected expiry, got {err:?}");
        };
        assert_eq!(why, Expiry::Idle);
        assert_eq!(context.host.as_str(), "dns1");
        assert_eq!(context.role.as_str(), "readonly");
        assert_eq!(context.access_class, AccessClass::ReadOnly);
        assert_eq!(
            context.purpose.as_str(),
            "check why the deploy did not take effect"
        );
    }

    /// Use refreshes the idle timer, so a session in continuous use does not
    /// lapse mid-task.
    #[test]
    fn use_refreshes_the_idle_timer() {
        let store = store();
        let session = open(&store, "alice");
        for _ in 0..5 {
            store.clock.advance(LIFETIME.idle - 1);
            store
                .use_session(&session.id, &principal("alice"))
                .expect("still live");
        }
    }

    /// The maximum lifetime is what stops continuous use from extending a
    /// session forever, which would turn a bounded window into a standing one.
    #[test]
    fn continuous_use_cannot_outlive_the_maximum() {
        let store = store();
        let session = open(&store, "alice");
        let mut last = Ok(());
        // Stepped by less than the grace period as well as less than the idle
        // timeout, so the session is observed in the window where it has
        // expired but is still remembered. A coarser step would jump straight
        // past that window to `Unknown`, which is also a dead session but says
        // less about why.
        let step = LIFETIME.idle.min(LIFETIME.grace) - 1;
        for _ in 0..100 {
            store.clock.advance(step);
            if let Err(err) = store.use_session(&session.id, &principal("alice")) {
                last = Err(err);
                break;
            }
        }
        let Err(SessionError::Expired { why, .. }) = last else {
            panic!("a session in continuous use never hit its maximum lifetime");
        };
        assert_eq!(why, Expiry::MaxLifetime);
    }

    /// Expiry and forgetting are separate events, and collapsing them is what
    /// destroys the lapse context. The session stops working the instant it
    /// expires; it stops being *remembered* only once nobody plausibly needs to
    /// be told what happened to it.
    #[test]
    fn a_lapsed_session_answers_usefully_before_it_is_forgotten() {
        let store = store();
        let session = open(&store, "alice");
        store.clock.advance(LIFETIME.idle);

        // Collection by another caller must preserve the owner's expiry context.
        open(&store, "bob");

        let err = store
            .use_session(&session.id, &principal("alice"))
            .unwrap_err();
        let SessionError::Expired { context, .. } = err else {
            panic!("the owner was told the session never existed: {err:?}");
        };
        assert_eq!(context.host.as_str(), "dns1");
        assert_eq!(context.role.as_str(), "readonly");

        // Past the grace period it is gone, and the answer becomes the one
        // given for anything unknown.
        store.clock.advance(LIFETIME.grace);
        store.sweep();
        assert_eq!(
            store.use_session(&session.id, &principal("alice")),
            Err(SessionError::Unknown),
            "a long-lapsed session was still remembered"
        );
    }

    /// Being told what a session was for is a property of reaching it, not of
    /// how long it is kept. A deployment that keeps nothing still owes its
    /// owner an answer on the way out — otherwise the store remembers a lapsed
    /// session exactly long enough to refuse to explain it.
    #[test]
    fn a_returning_owner_is_told_why_even_when_nothing_is_kept() {
        const NO_GRACE: Lifetime = Lifetime {
            idle: 10_000,
            max: 60_000,
            grace: 0,
        };
        let store = SessionStore::new(TestClock::at(1_000), NO_GRACE, PER_PRINCIPAL);
        let session = open(&store, "alice");
        store.clock.advance(NO_GRACE.idle);

        let err = store
            .use_session(&session.id, &principal("alice"))
            .unwrap_err();
        let SessionError::Expired { context, .. } = err else {
            panic!("the owner was told the session never existed: {err:?}");
        };
        assert_eq!(context.host.as_str(), "dns1");
        assert_eq!(
            context.purpose.as_str(),
            "check why the deploy did not take effect"
        );

        // And with nothing kept, the entry does not outlive that answer.
        assert_eq!(
            store.use_session(&session.id, &principal("alice")),
            Err(SessionError::Unknown)
        );
        assert!(
            store.is_empty(),
            "a session was kept by a store keeping none"
        );
    }

    /// A quota over live sessions alone bounds nothing, because a lapsed
    /// session still occupies memory until its grace period ends: open, let
    /// lapse, open again, and the store grows by an entry per cycle for as long
    /// as a caller keeps that up.
    #[test]
    fn lapsed_sessions_count_against_the_quota_that_bounds_memory() {
        // A long memory over a short life, which is the shape that accumulates:
        // each session lapses immediately and is then remembered for an hour.
        const CHURN: Lifetime = Lifetime {
            idle: 1_000,
            max: 60_000,
            grace: 3_600_000,
        };
        let store = SessionStore::new(TestClock::at(1_000), CHURN, PER_PRINCIPAL);
        for _ in 0..PER_PRINCIPAL * 4 {
            open(&store, "alice");
            store.clock.advance(CHURN.idle);
        }
        assert!(
            store.len() <= PER_PRINCIPAL,
            "a principal accumulated {} entries under a limit of {PER_PRINCIPAL}",
            store.len()
        );
    }

    #[test]
    fn closing_ends_the_session() {
        let store = store();
        let session = open(&store, "alice");
        store.close(&session.id, &principal("alice")).unwrap();
        assert_eq!(
            store.use_session(&session.id, &principal("alice")),
            Err(SessionError::Unknown)
        );
    }

    #[test]
    fn sessions_do_not_share_identifiers() {
        let store = store();
        let first = open(&store, "alice");
        let second = open(&store, "alice");
        assert_ne!(first.id, second.id);
    }

    /// An identifier that cannot be one this service issued is refused before
    /// it is allocated or hashed. Authorization does not depend on this — the
    /// principal does that — but nothing else bounds what arrives on the wire.
    #[test]
    fn an_identifier_of_the_wrong_shape_is_refused() {
        let good = "0123456789abcdef0123456789abcdef";
        assert!(SessionId::parse(good).is_ok());
        assert_eq!(good.len(), ID_CHARS);

        for bad in [
            "",
            "s-1",
            "0123456789abcdef0123456789abcde",   // one short
            "0123456789abcdef0123456789abcdef0", // one long
            "0123456789ABCDEF0123456789abcdef",  // upper case is not what we mint
            "0123456789abcdef0123456789abcdeg",  // not hex
        ] {
            assert_eq!(
                SessionId::parse(bad),
                Err(MalformedSessionId),
                "accepted {bad:?}"
            );
        }
        assert!(
            serde_json::from_str::<SessionId>(r#""not-an-identifier""#).is_err(),
            "deserialization accepted a malformed identifier"
        );
    }

    /// Identifiers do not collide across stores.
    ///
    /// **This does not demonstrate the property it is nearest to.** What
    /// matters is that an identifier issued before a restart does not name a
    /// session after one, and a fresh store in the same process cannot show
    /// that: a process-global counter would keep counting across these
    /// instances and pass anyway.
    ///
    /// That property is structural instead. `new_identifier` reads a CSPRNG and
    /// holds no state, so there is no sequence for a restart to resume — and no
    /// test can demonstrate the absence of process state. What this covers is
    /// the weaker, checkable claim, named honestly.
    #[test]
    fn identifiers_do_not_collide_across_stores() {
        let before = open(&store(), "alice");
        for _ in 0..50 {
            let after = open(&store(), "alice");
            assert_ne!(
                before.id, after.id,
                "a restart reissued a previous identifier"
            );
        }
    }

    /// Expiry is only noticed when an owner comes back, and an owner who has
    /// abandoned a session by definition does not. Without collection the store
    /// grows for as long as the process runs.
    #[test]
    fn abandoned_sessions_are_collected_without_anyone_returning_for_them() {
        let abandoned = store();
        for _ in 0..10 {
            open(&abandoned, "alice");
        }
        assert_eq!(abandoned.len(), 10);

        // Nobody touches any of them again.
        abandoned.clock.advance(LIFETIME.max);
        abandoned.sweep();
        assert!(abandoned.is_empty(), "abandoned sessions were retained");

        // And opening collects, so a store nothing else calls still cannot grow
        // without bound.
        // Nothing here calls sweep or len between opens, so a store that only
        // collected when asked for its size would hold all ten.
        let churning = store();
        for _ in 0..10 {
            churning.clock.advance(LIFETIME.max);
            open(&churning, "alice");
        }
        assert_eq!(churning.len(), 1, "opening did not collect the expired");
    }

    /// Expiry bounds how long a session lives, not how many exist. A caller
    /// that can open them faster than they age out grows the store for as long
    /// as it keeps asking, without ever running a command.
    #[test]
    fn one_principal_cannot_hold_unboundedly_many_sessions() {
        let store = store();
        for _ in 0..PER_PRINCIPAL {
            open(&store, "alice");
        }
        assert!(
            matches!(
                store.open(
                    principal("alice"),
                    HostId::parse("dns1").unwrap(),
                    RoleId::parse("readonly").unwrap(),
                    Purpose::parse("one too many").unwrap(),
                    AccessClass::ReadOnly,
                ),
                Err(TooManySessions { .. })
            ),
            "the limit did not hold"
        );

        // Another principal is unaffected: the bound is per principal, so one
        // caller cannot deny the service to everyone else.
        open(&store, "bob");

        // And letting one lapse frees the slot, so the limit is a bound on
        // concurrency rather than on how much work a principal may ever do.
        store.clock.advance(LIFETIME.idle);
        open(&store, "alice");
    }

    /// A session is the unit a human approves, and "approve this" cannot be
    /// answered about work with no stated purpose — nor about a purpose nobody
    /// will read.
    #[test]
    fn a_session_cannot_be_opened_without_a_usable_purpose() {
        for blank in ["", "   ", "\t\n"] {
            assert_eq!(
                Purpose::parse(blank),
                Err(PurposeError::Blank),
                "accepted {blank:?}"
            );
        }
        assert!(
            serde_json::from_str::<Purpose>(r#""""#).is_err(),
            "a blank purpose deserialized"
        );

        // Counting sessions bounds nothing if one can carry an unlimited
        // string: it is stored, cloned into the record, and cloned again into
        // every lapse context.
        assert!(matches!(
            Purpose::parse(&"x".repeat(PURPOSE_MAX + 1)),
            Err(PurposeError::TooLong { .. })
        ));
        assert!(Purpose::parse(&"x".repeat(PURPOSE_MAX)).is_ok());

        assert!(Purpose::parse("check why the deploy did not take effect").is_ok());
    }
}
