//! Approval: a recorded decision a second party can verify.
//!
//! When policy says a command needs a human, the command **waits**. It does not
//! fail, and it certainly does not proceed. A human then decides, and if they
//! agree the *service* runs the command — the agent is never handed anything it
//! keeps.
//!
//! That last distinction is the whole point, and it is enforced by the shape of
//! this module rather than by convention:
//!
//! - Approving produces a [`Grant`], which is consumed by running the command
//!   and cannot be produced any other way.
//! - A grant is bound to **one exact argument vector**. A different command
//!   cannot be substituted under an approval a human gave for this one.
//! - A grant redeems **once**. A second attempt is refused.
//! - A grant **expires**. Standing session approvals have their own explicit,
//!   bounded lifetime and can be revoked.
//!
//! # Break-glass
//!
//! An outage is the moment approval matters most and is hardest to obtain, so
//! there is an override. It produces exactly the same kind of grant, subject to
//! the same single-use, single-command, expiring rules, and differs in only one
//! way: who approved it. That is carried in the same field a human's name would
//! be, so override use appears in the record wherever approvals appear —
//! nobody has to know to look for it.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::action::{Action, ActionKind};
use crate::audit::{DecisionProof, Intended};
use crate::clock::{Clock, Millis};
use crate::command::{Command, CommandIntent};
use crate::policy::Verdict;
use crate::session::{Purpose, SessionId};
use crate::{AccessClass, HostId, PrincipalId, RoleId};

/// Opaque handle to an approval request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RequestId(String);

impl RequestId {
    /// Reads an identifier a caller supplied.
    ///
    /// Shape-checked for the same reason a session identifier is: it arrives
    /// from outside - a form submission on the approval surface - and is
    /// allocated and hashed on every lookup, and nothing else bounds it. Every
    /// identifier this service issues is `ID_BYTES` bytes of randomness in
    /// lowercase hex, so anything else cannot name a request.
    pub fn parse(raw: &str) -> Result<Self, MalformedRequestId> {
        let shaped = raw.len() == ID_CHARS
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !shaped {
            return Err(MalformedRequestId);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Names a request from a raw identifier, for tests that need one without
    /// asking anybody. Compiled out of every non-test build: identifiers are
    /// minted when a command is held, and nothing else has business inventing
    /// one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_raw(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Opaque handle to one standing agreement.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct AgreementId(String);

impl AgreementId {
    /// Reads an identifier supplied by the dashboard.
    pub fn parse(raw: &str) -> Result<Self, MalformedAgreementId> {
        let shaped = raw.len() == ID_CHARS
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !shaped {
            return Err(MalformedAgreementId);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The identifier cannot be one this service issued.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("that is not the shape of an agreement identifier")]
pub struct MalformedAgreementId;

/// The identifier cannot be one this service issued.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("that is not the shape of a request identifier")]
pub struct MalformedRequestId;

/// Bytes of randomness behind a request identifier.
const ID_BYTES: usize = 16;

/// Characters in a request identifier: two hex digits per random byte.
const ID_CHARS: usize = ID_BYTES * 2;

fn new_identifier() -> String {
    let mut bytes = [0_u8; ID_BYTES];
    rand::fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Who agreed.
///
/// One field for both, so that an override is recorded in exactly the place a
/// reader already looks for the approver. A separate flag would be something to
/// remember to check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "approver", rename_all = "snake_case")]
pub enum Approver {
    /// A person, identified as the dashboard authenticated them.
    Human { who: String },
    /// Nobody. Used when a human could not be reached, and said so.
    Override { who: String, because: String },
    /// A person's standing agreement for one session, given once on the
    /// approval surface and answering in their name until it expires, is
    /// revoked, or the session ends. Its own variant so a reader can tell a
    /// command somebody clicked for from one their standing answer covered,
    /// in the same place they already look for the approver.
    SessionStanding { who: String, agreement: AgreementId },
}

impl Approver {
    /// Whether this says who agreed and, for an override, why.
    ///
    /// The record's account of a break-glass is a name and a reason. An empty
    /// one is the record failing at the moment it matters most, so it is
    /// refused where the answer arrives rather than written down blank and
    /// discovered later by somebody reading the log.
    fn is_stated(&self) -> bool {
        match self {
            Self::Human { who } | Self::SessionStanding { who, .. } => !who.trim().is_empty(),
            Self::Override { who, because } => !who.trim().is_empty() && !because.trim().is_empty(),
        }
    }
}

/// What a human is shown, and what the record keeps.
///
/// Everything needed to decide is here, because a decision made from a command
/// alone is not a decision: the same command means different things on different
/// hosts, under different roles, in work opened for different reasons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Asked {
    pub operation: ActionKind,
    pub id: RequestId,
    pub session: SessionId,
    /// Whom the work is being done for, as the caller was authenticated.
    ///
    /// One identity, not two: nothing here distinguishes the agent making the
    /// call from the person it acts for, so a reader must not take this for a
    /// chain. Whether that distinction should exist, and reach a person
    /// deciding, is a question for the surface that shows requests.
    pub principal: PrincipalId,
    pub host: HostId,
    pub role: RoleId,
    pub purpose: Purpose,
    pub access_class: AccessClass,
    /// The exact command, as an argument vector.
    pub command: Vec<String>,
    /// The calling agent's own explanation. It is evidence, not trusted user
    /// intent or an authorization fact.
    pub agent_intent: CommandIntent,
    /// The record entry holding the decision this request is about.
    pub decided: u64,
    /// That entry's digest, so an agreement can be checked against the entry
    /// itself rather than against a position anything could name.
    pub decided_digest: String,
    /// Why local review is required for this account.
    pub why: String,
    pub asked_at: Millis,
    pub decide_by: Millis,
}

/// What asking produced: a request nobody has seen yet, or one already waiting.
///
/// The distinction exists because asking is idempotent and telling a human is
/// not. An agent that retries a held command every few seconds joins the
/// request it already made; anything that announces a request needs to know
/// which of those two happened, and reconstructing it afterwards from a set of
/// identifiers already announced is bookkeeping that this makes unnecessary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    /// Newly created by this call.
    New(Asked),
    /// The same command, already waiting for the same session.
    Pending(Asked),
}

impl Ask {
    #[must_use]
    pub const fn asked(&self) -> &Asked {
        match self {
            Self::New(asked) | Self::Pending(asked) => asked,
        }
    }

    #[must_use]
    pub fn into_asked(self) -> Asked {
        match self {
            Self::New(asked) | Self::Pending(asked) => asked,
        }
    }

    /// Whether this call is what created the request.
    #[must_use]
    pub const fn is_new(&self) -> bool {
        matches!(self, Self::New(_))
    }
}

/// A human's answer, as the store took it.
///
/// Minted only by [`Approvals::decide`], with private fields for the same
/// reason a grant has them: what the record can say about an answer rests on
/// the answer being about a request somebody actually made, and an answer
/// anybody could assemble would let the record be told about a deliberation
/// that never happened.
#[derive(Debug)]
pub struct Answer {
    asked: Asked,
    approver: Approver,
    agreed: bool,
    _proof: Option<DecisionProof>,
}

impl Answer {
    /// The request that was answered.
    pub(crate) const fn asked(&self) -> &Asked {
        &self.asked
    }

    /// Who answered.
    pub(crate) const fn approver(&self) -> &Approver {
        &self.approver
    }

    /// Whether they agreed.
    pub(crate) const fn agreed(&self) -> bool {
        self.agreed
    }

    /// Builds one without anybody answering, for tests in this crate that need
    /// to present an answer rather than collect one. Compiled out of every
    /// non-test build.
    #[cfg(test)]
    pub(crate) const fn answered_for(asked: Asked, approver: Approver, agreed: bool) -> Self {
        Self {
            asked,
            approver,
            agreed,
            _proof: None,
        }
    }
}

/// Permission to run one command, once, before it expires.
///
/// Only [`Approvals::redeem`] produces one, and only [`crate::mediate`] consumes
/// one. It is deliberately not `Clone`: a grant that could be copied would be a
/// capability, and approval authorizes an action.
#[derive(Debug, PartialEq, Eq)]
pub struct Grant {
    _proof: Option<DecisionProof>,
    request: RequestId,
    /// Whose work this agreement was given for.
    ///
    /// Carried by the grant itself rather than read back from the record, so
    /// that whose agreement this is stays answerable after retention has
    /// removed what the deliberation said.
    session: SessionId,
    approver: Approver,
    /// The argument vector this was granted for, by digest.
    ///
    /// Carried so that whoever writes the agreement down can check it is
    /// writing it against the command a human actually saw. A grant and a
    /// decision arrive at the record separately, and without this the two
    /// could be paired: an agreement given for one command, presented
    /// alongside a held decision about another, would authorize the other.
    action: String,
    /// The decision entry the human was answering.
    ///
    /// Recorded when the request is made, so the agreement names the
    /// deliberation that was actually put in front of somebody rather than
    /// whichever entry the retry happened to write. The digest comes with it,
    /// because a sequence number names a position and a digest names an entry.
    decided: u64,
    decided_digest: String,
}

impl Grant {
    /// Which request was answered.
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }

    /// Who agreed, and whether they were overriding.
    #[must_use]
    pub const fn approver(&self) -> &Approver {
        &self.approver
    }

    /// The command this was granted for, by digest.
    pub(crate) fn action(&self) -> &str {
        &self.action
    }

    /// The decision entry the human was answering.
    pub(crate) const fn decided(&self) -> u64 {
        self.decided
    }

    /// That entry's digest.
    pub(crate) fn decided_digest(&self) -> &str {
        &self.decided_digest
    }

    /// The session this agreement was given for.
    pub(crate) const fn session(&self) -> &SessionId {
        &self.session
    }

    /// Spends the grant, handing back who agreed.
    ///
    /// Consuming rather than reading: a grant is permission to do one thing
    /// once, so taking the approver out of it is the moment that permission is
    /// used up. What is left afterwards is a name, which authorizes nothing.
    pub(crate) fn spend(self) -> Approver {
        self.approver
    }

    /// Builds one without an approval flow, for tests in this crate that need
    /// to present a grant rather than earn one. Compiled out of every non-test
    /// build: outside them, redeeming is the only way to obtain a grant, which
    /// is what makes holding one mean something.
    #[cfg(test)]
    pub(crate) const fn granted_for(
        request: RequestId,
        session: SessionId,
        approver: Approver,
        action: String,
        decided: u64,
        decided_digest: String,
    ) -> Self {
        Self {
            request,
            session,
            approver,
            action,
            decided,
            decided_digest,
            _proof: None,
        }
    }
}

/// Where a command stands with the humans.
///
/// Asking is not always a question: a command somebody has already refused is
/// answered rather than asked about again, which is what stops an agent from
/// putting the same request in front of people until one of them agrees.
#[derive(Debug)]
pub enum Standing<R = Grant> {
    /// Somebody has already agreed, and the agreement was consumed successfully.
    ///
    /// Asking and collecting an answer are the same act — an agent retries the
    /// command — so they are one operation on the store. Two operations would
    /// leave a window in which an answer arriving between them looks like
    /// neither a waiting request nor an agreement, and the retry would queue a
    /// second request for a command somebody has already decided.
    Ready(Box<R>),
    /// Waiting on a person — and whether this call is what created the
    /// request, because asking is idempotent and telling a human is not.
    Waiting(Box<Ask>),
    /// Somebody agreed to this exact command, and the agreement expired before
    /// anything collected it. Nothing ran on it, and the request named here is
    /// the fresh one now waiting in its place.
    ///
    /// Distinct from `Waiting` because a caller that cannot tell the two apart
    /// reads a lapsed agreement as one that was never given: it asks again
    /// without ever telling whoever agreed that what they allowed did not
    /// happen. Said once, by the attempt that finds it — the request is swept
    /// with everything else afterwards.
    Lapsed { asked: Box<Ask>, by: Approver },
    /// Somebody said no, and it still stands.
    Refused { by: Approver },
}

/// A request in flight.
#[derive(Clone, Debug)]
struct Held {
    proof: Option<DecisionProof>,
    asked: Asked,
    /// Digest of the argument vector this was asked about.
    action: String,
    state: State,
    /// When the approval itself stops being redeemable.
    redeem_by: Millis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Waiting,
    /// Agreed to - and collectable only once `recorded` says the answer
    /// crossed the recording boundary. Born unrecorded, so the window between
    /// applying an answer and the record accepting it can never hand out a
    /// grant the record has no entry for.
    Approved {
        by: Approver,
        recorded: bool,
    },
    Refused {
        by: Approver,
    },
    Redeemed,
}

/// How long requests and approvals live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    /// How long a request waits for a human before it lapses.
    pub decide_within: Millis,
    /// How long an approval stays redeemable after it is given.
    ///
    /// Short on purpose. This is the window in which the approved action
    /// happens, not a period during which the agent holds extra privilege.
    pub redeem_within: Millis,
}

/// What one standing agreement may answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "coverage", rename_all = "snake_case")]
pub enum StandingCoverage {
    /// Every held command in the session.
    Session,
}

/// A human's standing agreement for one session, as the store keeps it.
///
/// Not a grant: nothing here can be redeemed. When a command in the session
/// is held, the agreement answers the request in the operator's name, and the
/// answer is recorded and redeemed exactly like a clicked one - single-use,
/// bound to the exact argument vector. What stands is who answers, never what
/// the agent holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StandingApproval {
    pub id: AgreementId,
    pub session: SessionId,
    pub who: String,
    /// When the agreement stops answering, whatever the session is doing.
    pub until: Millis,
    pub coverage: StandingCoverage,
}

/// Requests waiting on, or answered by, a human.
pub struct Approvals<C: Clock> {
    /// Most commands one session may have waiting on a human at once.
    ///
    /// A queue a person reads is the scarce thing here, not memory: an agent
    /// that can hold an unbounded number of commands can bury the one that
    /// mattered. Bounding it per session also bounds what a lookup walks.
    waiting_per_session: usize,
    clock: C,
    windows: Windows,
    requests: Mutex<HashMap<String, Held>>,
    /// Individually keyed standing agreements.
    ///
    /// Standing use takes this lock before `requests`; no path may take them
    /// in the opposite order. That ordering serializes use with withdrawal.
    standing: Mutex<HashMap<String, StandingApproval>>,
}

impl<C: Clock> Approvals<C> {
    #[must_use]
    pub fn new(clock: C, windows: Windows, waiting_per_session: usize) -> Self {
        Self {
            waiting_per_session,
            clock,
            windows,
            requests: Mutex::new(HashMap::new()),
            standing: Mutex::new(HashMap::new()),
        }
    }

    /// Records an individually revocable standing agreement.
    ///
    /// A newer agreement replaces the previous agreement for the session.
    pub fn grant_standing(
        &self,
        session: &SessionId,
        who: String,
        until: Millis,
        coverage: StandingCoverage,
    ) -> AgreementId {
        let id = AgreementId(new_identifier());
        let agreement = StandingApproval {
            id: id.clone(),
            session: session.clone(),
            who,
            until,
            coverage,
        };
        let now = self.clock.now();
        let mut standing = self.standing.lock().unwrap_or_else(|e| e.into_inner());
        standing
            .retain(|_, existing| now < existing.until && existing.session != agreement.session);
        standing.insert(id.as_str().to_owned(), agreement);
        id
    }

    /// Withdraws one standing agreement, saying whether there was one.
    ///
    /// Withdrawing is not a refusal: the next held command simply waits for a
    /// person again.
    pub fn revoke_standing(&self, agreement: &AgreementId) -> bool {
        self.standing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(agreement.as_str())
            .is_some()
    }

    /// Holds session agreement selection and redemption against withdrawal.
    pub(crate) fn use_standing<R>(
        &self,
        session: &SessionId,
        use_approval: impl FnOnce(Approver) -> R,
    ) -> Option<R> {
        let standing = self.standing.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        let agreement = standing
            .values()
            .find(|agreement| agreement.session == *session && now < agreement.until)?;
        let result = use_approval(Approver::SessionStanding {
            who: agreement.who.clone(),
            agreement: agreement.id.clone(),
        });
        drop(standing);
        Some(result)
    }

    /// The standing agreements still answering, for the surface that shows
    /// and withdraws them.
    #[must_use]
    pub fn standing(&self) -> Vec<StandingApproval> {
        let now = self.clock.now();
        self.standing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|agreement| now < agreement.until)
            .cloned()
            .collect()
    }

    /// Records that a command is waiting for a human.
    ///
    /// Returns the existing request when this session has already asked about
    /// this exact command under the same agent intent and it has not lapsed. An
    /// agent that retries — which is how it discovers the answer — must not
    /// create a queue of identical requests for a human to wade through.
    pub fn ask(&self, held: &Intended) -> Result<Standing, ApprovalError> {
        self.ask_with(held, Ok)
    }

    /// Consume an existing approval only after its recording step succeeds.
    /// The callback runs under the request lock and must not retain a grant or
    /// issue a receipt when returning an error.
    pub(crate) fn ask_with<R, E: From<ApprovalError>>(
        &self,
        held: &Intended,
        consume: impl FnOnce(Grant) -> Result<R, E>,
    ) -> Result<Standing<R>, E> {
        if held.decision().verdict() != Verdict::NeedsApproval {
            return Err(ApprovalError::NotHeld.into());
        }
        let session = held.decision().session();
        let command = held.decision().command();
        let why = held.decision().explanation().to_owned();
        let agent_intent = held.agent_intent().clone();
        // Taken from the entry rather than from a caller, so a request cannot
        // name a deliberation other than the one it is about. What an
        // agreement is later checked against is this pair, and everything the
        // record can prove about it rests on them having arrived together.
        let decided = held.deliberation().sequence;
        let decided_digest = held.deliberation().digest.as_str().to_owned();
        let action = digest_action(held.decision().action(), &agent_intent);
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        requests.retain(|_, held| !held.forgettable(now));

        // Looked for among what survived that sweep, so remembrance is decided
        // in one place. An agreement outlives the window it was collectable in
        // so that the attempt which comes for it can be told; past remembrance
        // it is gone here too, and this finds nothing.
        //
        // Only an agreement the record can account for is named: an answer that
        // never crossed the recording boundary is not something to tell a
        // caller a person gave.
        //
        // Nothing is removed here. The record is what remembers, and it is
        // released only once the answer has actually been handed back — every
        // path between this point and that one can still refuse, and giving up
        // the record first would spend the lapse on a call that never reported
        // it.
        let lapsed = requests.iter().find_map(|(id, held)| match &held.state {
            State::Approved { by, recorded: true }
                if held.asked.session == session.id
                    && held.asked.principal == session.principal
                    && held.action == action
                    && now >= held.redeem_by =>
            {
                Some((id.clone(), by.clone()))
            }
            _ => None,
        });

        // An agreement already given for this exact command is spent here. The
        // caller does not have to have kept the request identifier: an agent
        // discovers the answer by retrying the command, and the command is what
        // the approval was given for, so the command is enough to find it.
        let agreed = requests
            .iter()
            .find(|(_, held)| {
                held.asked.session == session.id
                    && held.asked.principal == session.principal
                    && held.action == action
                    && matches!(held.state, State::Approved { recorded: true, .. })
                    && now < held.redeem_by
            })
            .map(|(id, _)| id.clone());
        if let Some(id) = agreed
            && let Some(held) = requests.get_mut(&id)
            && let State::Approved { by, .. } = &held.state
        {
            let ready = consume(Grant {
                _proof: held.proof.clone(),
                request: RequestId(id),
                session: held.asked.session.clone(),
                approver: by.clone(),
                action: held.action.clone(),
                decided: held.asked.decided,
                decided_digest: held.asked.decided_digest.clone(),
            })?;
            held.state = State::Redeemed;
            held.proof = None;
            return Ok(Standing::Ready(Box::new(ready)));
        }

        // A standing refusal is the answer, not an invitation to ask again.
        if let Some(refused) = requests.values().find(|held| {
            held.asked.session == session.id
                && held.action == action
                && matches!(held.state, State::Refused { .. })
        }) {
            let State::Refused { by } = &refused.state else {
                unreachable!("just matched on a refusal")
            };
            return Ok(Standing::Refused { by: by.clone() });
        }

        // An agreement whose answer is not yet in the record reads as still
        // waiting: collectable it is not, and telling the caller anything else
        // would either run a command the record has no entry for or queue a
        // duplicate request in front of a human.
        if let Some(existing) = requests.values().find(|held| {
            held.asked.session == session.id
                && held.action == action
                && matches!(
                    held.state,
                    State::Waiting
                        | State::Approved {
                            recorded: false,
                            ..
                        }
                )
        }) {
            if matches!(
                existing.state,
                State::Approved {
                    recorded: false,
                    ..
                }
            ) {
                tracing::warn!(
                    request = existing.asked.id.as_str(),
                    "an agreement was asked for before its answer was recorded; withheld"
                );
            }
            return Ok(Standing::Waiting(Box::new(Ask::Pending(
                existing.asked.clone(),
            ))));
        }

        // Counted after the retry path above: asking again about something
        // already waiting hands back that request, and an agent collecting its
        // answer must never be the one turned away.
        let waiting = requests
            .values()
            .filter(|held| held.asked.session == session.id && matches!(held.state, State::Waiting))
            .count();
        if waiting >= self.waiting_per_session {
            return Err(ApprovalError::TooManyWaiting.into());
        }

        let asked = Asked {
            operation: held.decision().action().kind(),
            id: RequestId(new_identifier()),
            session: session.id.clone(),
            principal: session.principal.clone(),
            host: session.host.clone(),
            role: session.role.clone(),
            purpose: session.purpose.clone(),
            access_class: session.access_class,
            command: command.argv().to_vec(),
            agent_intent,
            decided,
            decided_digest,
            why,
            asked_at: now,
            decide_by: now.saturating_add(self.windows.decide_within),
        };
        requests.insert(
            asked.id.0.clone(),
            Held {
                proof: held.decision_proof(),
                asked: asked.clone(),
                action,
                state: State::Waiting,
                redeem_by: 0,
            },
        );
        // The request just made is what a person answers next either way. What
        // changes is whether the caller is told why it is being asked again.
        if let Some((id, by)) = lapsed {
            // Handing the answer back is also letting go of it: the record
            // outlived its window so that one attempt could be told, and
            // keeping it now would answer every later ask with the same stale
            // lapse. Done here, past every refusal above, so a call that never
            // reported it cannot spend it.
            requests.remove(&id);
            return Ok(Standing::Lapsed {
                asked: Box::new(Ask::New(asked)),
                by,
            });
        }
        Ok(Standing::Waiting(Box::new(Ask::New(asked))))
    }

    /// Records a decision.
    ///
    /// Only a request that is still waiting can be decided: an answered request
    /// cannot be answered again, and one that has lapsed has to be asked afresh
    /// so the human sees current context rather than yesterday's.
    ///
    /// Told, like [`Self::sweep`], which sessions can still redeem: a request
    /// whose session cannot is refused as lapsed, because a decision about it
    /// could not take effect either way, and recording agreement for it would
    /// put an answer in the record that governs nothing.
    ///
    /// The agreement this may apply is born unrecorded; see
    /// [`Self::mark_recorded`] for when it becomes collectable.
    pub fn decide(
        &self,
        id: &RequestId,
        approver: Approver,
        agreed: bool,
        redeemable: impl Fn(&SessionId) -> bool,
    ) -> Result<Answer, ApprovalError> {
        if !approver.is_stated() {
            return Err(ApprovalError::Unattributed);
        }
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        let held = requests
            .get_mut(id.as_str())
            .ok_or(ApprovalError::Unknown)?;

        if !matches!(held.state, State::Waiting) {
            return Err(ApprovalError::AlreadyDecided);
        }
        if now >= held.asked.decide_by {
            return Err(ApprovalError::Lapsed);
        }
        if !redeemable(&held.asked.session) {
            return Err(ApprovalError::Lapsed);
        }

        held.state = if agreed {
            held.redeem_by = now.saturating_add(self.windows.redeem_within);
            State::Approved {
                by: approver.clone(),
                recorded: false,
            }
        } else {
            State::Refused {
                by: approver.clone(),
            }
        };
        // Handed back so the answer can be written down. What a human decided
        // is a fact about the request, and the request is what says whose work
        // it was about.
        Ok(Answer {
            asked: held.asked.clone(),
            approver,
            agreed,
            _proof: if agreed {
                held.proof.clone()
            } else {
                held.proof.take()
            },
        })
    }

    /// Spends an approval on the command and agent intent it was given for.
    ///
    /// Every condition here is one of the ways an approval could otherwise
    /// become more than it was: a different command, a changed agent intent, a
    /// different principal, a second use, or a later use.
    pub fn redeem(
        &self,
        id: &RequestId,
        principal: &PrincipalId,
        command: &Command,
        agent_intent: &CommandIntent,
    ) -> Result<Grant, ApprovalError> {
        self.redeem_action(
            id,
            principal,
            &Action::execute(command.clone()),
            agent_intent,
        )
    }

    pub fn redeem_action(
        &self,
        id: &RequestId,
        principal: &PrincipalId,
        action: &Action,
        agent_intent: &CommandIntent,
    ) -> Result<Grant, ApprovalError> {
        self.redeem_action_with(id, principal, action, agent_intent, Ok)
    }

    /// Record and consume under the same lock, retaining approval on failure.
    /// The callback has the same no-effect-on-error contract as `ask_with`.
    pub(crate) fn redeem_action_with<R, E: From<ApprovalError>>(
        &self,
        id: &RequestId,
        principal: &PrincipalId,
        action: &Action,
        agent_intent: &CommandIntent,
        consume: impl FnOnce(Grant) -> Result<R, E>,
    ) -> Result<R, E> {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        let held = requests
            .get_mut(id.as_str())
            .ok_or(ApprovalError::Unknown)?;

        // The principal is checked first and answers as if the request did not
        // exist, so one caller cannot probe for another's pending approvals.
        if &held.asked.principal != principal {
            return Err(ApprovalError::Unknown.into());
        }
        match &held.state {
            State::Waiting => return Err(ApprovalError::StillWaiting.into()),
            State::Refused { .. } => return Err(ApprovalError::Refused.into()),
            State::Redeemed => return Err(ApprovalError::AlreadyRedeemed.into()),
            State::Approved {
                recorded: false, ..
            } => {
                tracing::warn!(
                    request = id.as_str(),
                    "an agreement was asked for before its answer was recorded; withheld"
                );
                return Err(ApprovalError::Unrecorded.into());
            }
            State::Approved { .. } => {}
        }
        if now >= held.redeem_by {
            return Err(ApprovalError::Lapsed.into());
        }
        // The approval names one action. Anything else is a different decision
        // than the one that was made.
        if held.action != digest_action(action, agent_intent) {
            return Err(ApprovalError::DifferentAction.into());
        }

        let State::Approved { by, .. } = &held.state else {
            return Err(ApprovalError::AlreadyRedeemed.into());
        };
        let ready = consume(Grant {
            _proof: held.proof.clone(),
            request: id.clone(),
            session: held.asked.session.clone(),
            approver: by.clone(),
            action: held.action.clone(),
            decided: held.asked.decided,
            decided_digest: held.asked.decided_digest.clone(),
        })?;
        held.state = State::Redeemed;
        held.proof = None;
        Ok(ready)
    }

    /// Marks an agreement's answer as accepted by the recording boundary.
    ///
    /// An agreement is born unrecorded and cannot be collected or redeemed
    /// until this says otherwise: between applying an answer and the record
    /// accepting it there is a window, and a retry landing inside it must not
    /// run a command whose approval the record has no entry for. When the
    /// record refuses the entry, this is never called and the agreement
    /// expires unredeemable at its own window. A refusal needs no such gate,
    /// because a refusal grants nothing.
    ///
    /// Says whether there was an unrecorded agreement to mark; `false` means
    /// it lapsed or was never there, and there is nothing to unlock.
    pub fn mark_recorded(&self, id: &RequestId) -> bool {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        match requests.get_mut(id.as_str()) {
            Some(held) => match &mut held.state {
                State::Approved { recorded, .. } => {
                    *recorded = true;
                    true
                }
                _ => false,
            },
            None => false,
        }
    }

    /// Requests still waiting on a human, for the surface that shows them.
    ///
    /// Told, like [`Self::sweep`], which sessions can still redeem: a request
    /// whose session cannot is not shown, because offering it asks somebody to
    /// decide something that could not take effect either way.
    #[must_use]
    pub fn waiting(&self, redeemable: impl Fn(&SessionId) -> bool) -> Vec<Asked> {
        let now = self.clock.now();
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|held| {
                matches!(held.state, State::Waiting)
                    && now < held.asked.decide_by
                    && redeemable(&held.asked.session)
            })
            .map(|held| held.asked.clone())
            .collect()
    }

    /// Drops requests nobody can act on any more.
    ///
    /// What stops one being worth keeping depends on what became of it: an
    /// unanswered request by its own window closing, a recorded agreement by
    /// having been reported to the attempt it was owed to. The session is the
    /// bound they all share, and it is asked of the caller, because the store
    /// deliberately knows nothing about sessions beyond which one a request
    /// named — and a request whose session has gone can never be redeemed, so
    /// leaving it offers somebody a decision that could not take effect.
    pub fn sweep(&self, lives: impl Fn(&SessionId) -> bool) {
        let now = self.clock.now();
        {
            let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
            requests.retain(|_, held| !held.forgettable(now) && lives(&held.asked.session));
        }
        let mut standing = self.standing.lock().unwrap_or_else(|e| e.into_inner());
        standing.retain(|_, agreement| now < agreement.until && lives(&agreement.session));
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Held {
    /// Whether nothing further can happen to this request.
    ///
    /// A refusal never becomes forgettable on its own. Forgetting it would make
    /// asking again produce a fresh request, and an agent that asks repeatedly
    /// would eventually find somebody who says yes — which is not a workflow a
    /// service that asks humans for permission should support. It goes when the
    /// session it was about goes, so a no stands for the whole of the work it
    /// was said about, and a later session asking again is somebody stating a
    /// fresh purpose rather than the same agent asking twice.
    ///
    /// A recorded agreement is kept on the same terms, and for the mirror of
    /// that reason: it is the only thing that knows a person said yes and that
    /// nothing came for it. It goes when the attempt it is owed to is told, or
    /// with the session it was about — never on a clock of its own, because a
    /// clock is a length of silence during which an agent is told its command
    /// was never answered, and no such length is defensible when the whole
    /// point is that a person's decision is not lost quietly.
    ///
    /// What bounds it is the session, exactly as for a refusal. Within one,
    /// what accumulates is one record per agreement a person actually gave and
    /// nothing collected, and how fast requests can be raised at all is capped
    /// by the waiting-per-session limit.
    ///
    /// Outliving the window is not the same as still being redeemable: what
    /// may be spent is decided by `redeem_by` where an agreement is redeemed,
    /// never by whether the record is still here.
    ///
    /// An answer the record never accepted is not an agreement anybody can be
    /// told a person gave, so it is kept no longer than it was collectable —
    /// which is also what lets its command be asked about afresh once it goes.
    fn forgettable(&self, now: Millis) -> bool {
        match self.state {
            State::Waiting => now >= self.asked.decide_by,
            State::Approved { recorded: true, .. } => false,
            State::Approved {
                recorded: false, ..
            } => now >= self.redeem_by,
            State::Refused { .. } => false,
            State::Redeemed => true,
        }
    }
}

/// Identifies the exact argument vector and agent explanation an approval was
/// given for.
///
/// A digest rather than the vector itself, so comparison cannot be fooled by
/// how the arguments are joined: `["a b"]` and `["a", "b"]` are different
/// commands and produce different digests, where any flattening would make them
/// the same. The intent is length-delimited and domain-separated for the same
/// reason.
#[cfg(test)]
pub(crate) fn digest_of(command: &Command, agent_intent: &CommandIntent) -> String {
    digest_parts(ActionKind::Execute, command, agent_intent)
}

pub(crate) fn digest_action(action: &Action, agent_intent: &CommandIntent) -> String {
    digest_parts(action.kind(), action.command(), agent_intent)
}

fn digest_parts(kind: ActionKind, command: &Command, agent_intent: &CommandIntent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-ssh-action-v3");
    hasher.update(kind.as_str().len().to_le_bytes());
    hasher.update(kind.as_str().as_bytes());
    hasher.update(agent_intent.as_str().len().to_le_bytes());
    hasher.update(agent_intent.as_str().as_bytes());
    for argument in command.argv() {
        hasher.update(argument.len().to_le_bytes());
        hasher.update(argument.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApprovalError {
    /// No request with that identifier belongs to this principal.
    #[error("no such approval request")]
    Unknown,
    #[error("nobody has decided this yet")]
    StillWaiting,
    #[error("this was refused")]
    Refused,
    #[error("this approval has already been used")]
    AlreadyRedeemed,
    #[error("this approval was for a different command")]
    DifferentAction,
    #[error("the request or its approval has lapsed; ask again")]
    Lapsed,
    #[error("the answer to this is not yet in the record, so it cannot be acted on; retry")]
    Unrecorded,
    #[error("this request has already been decided")]
    AlreadyDecided,
    #[error("an answer must say who gave it, and an override why")]
    Unattributed,
    #[error("that decision did not ask for a human")]
    NotHeld,
    #[error("too many commands from this session are already waiting for a human")]
    TooManyWaiting,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::audit::Ledger;
    use crate::clock::TestClock;
    use crate::policy::Engine;
    use crate::session::{Lifetime, Session, SessionStore};
    use crate::{HostId, RoleId};
    use std::sync::Arc;

    const LIFETIME: Lifetime = Lifetime {
        idle: 600_000,
        max: 3_600_000,
        grace: 60_000,
    };
    /// Small on purpose: a test that has to queue a realistic number of
    /// commands to reach the limit is testing arithmetic, not the rule.
    const WAITING_PER_SESSION: usize = 3;
    const WINDOWS: Windows = Windows {
        decide_within: 300_000,
        redeem_within: 60_000,
    };

    fn session(who: &str) -> Session {
        SessionStore::new(TestClock::at(1_000), LIFETIME, 8)
            .open(
                PrincipalId::parse(who).unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse("restart traefik after the config change").unwrap(),
                AccessClass::Privileged,
            )
            .unwrap()
    }

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    fn approvals() -> Approvals<TestClock> {
        Approvals::new(TestClock::at(1_000), WINDOWS, WAITING_PER_SESSION)
    }

    fn human() -> Approver {
        Approver::Human {
            who: "chris".to_owned(),
        }
    }

    #[derive(Debug)]
    struct GatedClock {
        millis: std::sync::atomic::AtomicU64,
        gate: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    }

    impl GatedClock {
        fn at(millis: Millis) -> Self {
            Self {
                millis: std::sync::atomic::AtomicU64::new(millis),
                gate: Mutex::new(None),
            }
        }

        fn arm(&self, entered: Arc<std::sync::Barrier>, release: Arc<std::sync::Barrier>) {
            *self.gate.lock().unwrap_or_else(|e| e.into_inner()) = Some((entered, release));
        }

        fn set(&self, millis: Millis) {
            self.millis
                .store(millis, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Clock for GatedClock {
        fn now(&self) -> Millis {
            let gate = self.gate.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some((entered, release)) = gate {
                entered.wait();
                release.wait();
            }
            self.millis.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A recorded deliberation that held a command for a human, which is what
    /// a request is asked about. Built through policy and the record rather
    /// than assembled, because a request that could be asked about parts
    /// picked out by hand is exactly what these tests must not be able to set
    /// up when production cannot.
    fn held(session: &Session, command: &Command) -> crate::audit::Intended {
        let decision =
            Engine::new(crate::policy::ReviewMode::Privileged).decide(session, (command).clone());
        assert_eq!(
            decision.verdict(),
            Verdict::NeedsApproval,
            "this test needs a command policy holds for a human"
        );
        Ledger::new(TestClock::at(1_000))
            .record_intent(
                decision,
                CommandIntent::parse("exercise the approval flow").unwrap(),
            )
            .unwrap()
    }

    /// Asks, and takes the request. Tests about what happens while somebody is
    /// deciding need the request itself; a refusal here means the test set up
    /// something other than what it meant to.
    fn asking(approvals: &Approvals<TestClock>, session: &Session, command: &Command) -> Asked {
        match approvals.ask(&held(session, command)).unwrap() {
            Standing::Waiting(asked) => asked.into_asked(),
            other => panic!("expected a request, got {other:?}"),
        }
    }

    /// Asking and collecting an answer are the same act, so an answer arriving
    /// while a retry is in flight must not fall between them. Answered before
    /// the retry looks up, the request is no longer waiting and not yet spent —
    /// and a store that only recognised those two states would queue a second
    /// request for a command somebody had just decided, leaving a duplicate in
    /// front of a person and a second way to run it.
    #[test]
    fn an_answer_arriving_before_a_retry_is_collected_rather_than_asked_again() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        // The moment the race turns on: decided, not yet collected.
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Ready(grant) => assert_eq!(grant.approver(), &human()),
            other => panic!("an answer already given was not collected: {other:?}"),
        }
        assert!(
            approvals.waiting(|_| true).is_empty(),
            "a command already agreed to was queued for somebody again"
        );

        // And the agreement was spent by collecting it, not left to be spent
        // twice by asking twice.
        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Waiting(again) => assert_ne!(again.asked().id, asked.id),
            other => panic!("a spent agreement was collected a second time: {other:?}"),
        }
    }

    /// Asking is idempotent and telling a human is not: whatever announces a
    /// request needs to know whether this call created it, or an agent
    /// retrying every few seconds would page somebody on every retry.
    #[test]
    fn only_the_ask_that_created_a_request_is_new() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);

        let first = match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Waiting(ask) => ask,
            other => panic!("expected a request, got {other:?}"),
        };
        assert!(first.is_new());

        let again = match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Waiting(ask) => ask,
            other => panic!("expected the same request, got {other:?}"),
        };
        assert!(
            !again.is_new(),
            "a retry claimed to have created the request"
        );
        assert_eq!(again.asked().id, first.asked().id);
    }

    /// An answer takes effect when it is applied, but an agreement is worth
    /// nothing until the record has accepted it: a command must never run on
    /// an approval the record has no entry for. Until then a retry reads as
    /// still waiting, and if the record never accepts the answer, the
    /// agreement expires without ever having been collectable.
    #[test]
    fn an_agreement_is_not_collectable_until_its_answer_is_recorded() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();

        // Applied, not yet recorded: a retry is told to keep waiting, on the
        // same request rather than a duplicate...
        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Waiting(again) => assert_eq!(again.asked().id, asked.id),
            other => panic!("an unrecorded agreement was handed out: {other:?}"),
        }
        // ...and redeeming outright is refused by name.
        assert_eq!(
            approvals
                .redeem(&asked.id, &session.principal, &command, &asked.agent_intent)
                .unwrap_err(),
            ApprovalError::Unrecorded
        );

        // The record accepts the answer, and only now is it collectable.
        assert!(approvals.mark_recorded(&asked.id));
        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Ready(grant) => assert_eq!(grant.approver(), &human()),
            other => panic!("a recorded agreement was not collectable: {other:?}"),
        }
    }

    /// A request whose session can no longer redeem is not offered and not
    /// decidable: the decision could not take effect either way, so recording
    /// one would put an answer in the record that governs nothing.
    #[test]
    fn a_request_whose_session_cannot_redeem_is_neither_shown_nor_decidable() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        assert_eq!(approvals.waiting(|_| true).len(), 1);
        assert!(approvals.waiting(|_| false).is_empty());
        assert_eq!(
            approvals
                .decide(&asked.id, human(), true, |_| false)
                .unwrap_err(),
            ApprovalError::Lapsed
        );
        // Refused without being consumed: liveness said no, but the request
        // itself still stands for a caller whose answer can take effect.
        assert_eq!(approvals.waiting(|_| true).len(), 1);
    }

    /// A no does not become a question again by waiting. The window a person
    /// had to answer in is not how long their answer is worth: an agent that
    /// could outlast a refusal and ask again would eventually reach somebody
    /// who says yes, which is the workflow the refusal existed to prevent. It
    /// stands for the work it was said about — a later session asking is
    /// somebody stating a fresh purpose, not the same agent asking twice.
    #[test]
    fn a_refusal_does_not_expire_into_a_fresh_question() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);
        approvals
            .decide(&asked.id, human(), false, |_| true)
            .unwrap();

        // Long past the window a person had to answer in.
        approvals.clock.advance(WINDOWS.decide_within * 10);

        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Refused { by } => assert_eq!(by, human()),
            other => panic!("waiting out a refusal turned it back into something else: {other:?}"),
        }
    }

    /// An answer is worth what the record can say about it, and a break-glass
    /// with nobody's name or no reason says nothing. Refused where it arrives,
    /// because by the time it is in the log it is too late to ask who.
    #[test]
    fn an_answer_that_names_nobody_is_not_an_answer() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);

        let asked = asking(&approvals, &session, &command);

        for nameless in [
            Approver::Human {
                who: "  ".to_owned(),
            },
            Approver::Override {
                who: String::new(),
                because: "the pager did not answer".to_owned(),
            },
            Approver::Override {
                who: "chris".to_owned(),
                because: "   ".to_owned(),
            },
        ] {
            assert_eq!(
                approvals
                    .decide(&asked.id, nameless.clone(), true, |_| true)
                    .unwrap_err(),
                ApprovalError::Unattributed,
                "recorded an answer nobody is accountable for: {nameless:?}"
            );
        }

        // And the request is still there for somebody who will say who they
        // are, rather than having been used up by an answer that said nothing.
        assert_eq!(approvals.waiting(|_| true).len(), 1);
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));
        assert!(
            approvals
                .redeem(&asked.id, &session.principal, &command, &asked.agent_intent)
                .is_ok()
        );
    }

    /// What a queue of held commands costs is a person's attention, and an
    /// agent that can fill it without limit can bury the command that
    /// mattered under ones nobody meant to be asked about. Collecting the
    /// answer to something already waiting is never what gets turned away.
    #[test]
    fn one_session_cannot_fill_the_queue_a_human_reads() {
        let approvals = approvals();
        let mine = session("agent-a");
        let elsewhere = session("agent-b");
        let first = command(&["docker", "restart", "traefik"]);

        let waiting = asking(&approvals, &mine, &first);
        for target in ["postgres", "redis"] {
            asking(&approvals, &mine, &command(&["docker", "restart", target]));
        }

        let one_too_many = command(&["docker", "restart", "grafana"]);
        assert_eq!(
            approvals.ask(&held(&mine, &one_too_many)).unwrap_err(),
            ApprovalError::TooManyWaiting
        );

        // Asking again about something already waiting still answers with that
        // request: an agent collecting its answer is not the one queueing work.
        match approvals.ask(&held(&mine, &first)).unwrap() {
            Standing::Waiting(again) => assert_eq!(again.asked().id, waiting.id),
            other => panic!("a waiting request stopped being answerable: {other:?}"),
        }

        // Another session is unaffected: the limit is on what one session can
        // put in front of somebody, not on how much anybody may be asked.
        asking(&approvals, &elsewhere, &one_too_many);
    }

    /// A refusal is an answer, and asking again does not turn it into a
    /// question. Otherwise an agent that retries reaches somebody else, and
    /// eventually somebody agrees — which is not what a person refusing a
    /// command meant to be signing up for.
    #[test]
    fn a_refusal_stands_rather_than_becoming_a_fresh_request() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        approvals
            .decide(&asked.id, human(), false, |_| true)
            .unwrap();

        match approvals.ask(&held(&session, &command)).unwrap() {
            Standing::Refused { by } => assert_eq!(by, human()),
            other => panic!("a refused command became something else: {other:?}"),
        }
        assert!(
            approvals.waiting(|_| true).is_empty(),
            "a refused command is waiting on somebody"
        );
    }

    /// A human deciding needs the whole picture: the same command means
    /// different things on different hosts, under different roles, in work
    /// opened for different reasons.
    #[test]
    fn a_request_carries_everything_needed_to_decide() {
        let approvals = approvals();
        let session = session("agent-a");
        let asked = asking(
            &approvals,
            &session,
            &command(&["docker", "restart", "traefik"]),
        );

        assert_eq!(asked.host.as_str(), "dns1");
        assert_eq!(asked.role.as_str(), "operator");
        assert_eq!(asked.principal.as_str(), "agent-a");
        assert_eq!(
            asked.purpose.as_str(),
            "restart traefik after the config change"
        );
        assert_eq!(asked.command, ["docker", "restart", "traefik"]);
        assert_eq!(asked.agent_intent.as_str(), "exercise the approval flow");
        assert_eq!(asked.access_class, AccessClass::Privileged);
        assert_eq!(approvals.waiting(|_| true).len(), 1);
    }

    /// The approved action happens, and the grant is what makes it happen.
    #[test]
    fn approving_lets_the_command_run_once() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));
        let grant = approvals
            .redeem(&asked.id, &session.principal, &command, &asked.agent_intent)
            .expect("an approved request redeems");
        assert_eq!(grant.approver, human());

        // Approval authorizes an action, not a capability.
        assert_eq!(
            approvals.redeem(&asked.id, &session.principal, &command, &asked.agent_intent),
            Err(ApprovalError::AlreadyRedeemed)
        );
    }

    /// The explanation is part of what the operator agreed to. Replaying the
    /// same argv with a different story must not collect that answer.
    #[test]
    fn a_different_agent_intent_cannot_redeem_the_approval() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        let changed = CommandIntent::parse("inspect logs without changing the service").unwrap();
        assert_eq!(
            approvals.redeem(&asked.id, &session.principal, &command, &changed),
            Err(ApprovalError::DifferentAction),
            "the same command under a different stated intent spent the approval"
        );
    }

    /// The approval names one action. Substituting another under it would make
    /// the human's decision meaningless.
    #[test]
    fn a_different_command_cannot_be_run_under_the_approval() {
        let approvals = approvals();
        let session = session("agent-a");
        let asked = asking(
            &approvals,
            &session,
            &command(&["docker", "restart", "traefik"]),
        );
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        for substitute in [
            &["docker", "restart", "postgres"][..],
            &["docker", "exec", "traefik", "sh"][..],
            &["docker", "restart"][..],
            &["docker restart traefik"][..],
        ] {
            assert_eq!(
                approvals.redeem(
                    &asked.id,
                    &session.principal,
                    &command(substitute),
                    &asked.agent_intent
                ),
                Err(ApprovalError::DifferentAction),
                "accepted {substitute:?} under an approval for something else"
            );
        }
    }

    /// A queue with no room must not spend the lapse it could not report.
    ///
    /// Reporting one is the store letting go of the record that remembers it,
    /// so a refusal issued after that point would take with it the last thing
    /// that knew a person had answered. The refusal has to leave the lapse
    /// exactly where it found it.
    #[test]
    fn a_full_queue_does_not_spend_the_lapse_it_could_not_report() {
        let approvals = approvals();
        let session = session("agent-clawde");
        let subject = command(&["systemctl", "restart", "unbound"]);

        let asked = asking(&approvals, &session, &subject);
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        // Nothing collects it, and by the time the agent comes back the
        // session's queue is full of other questions.
        approvals.clock.advance(WINDOWS.redeem_within + 1);
        let mut queued = Vec::new();
        for other in [
            command(&["systemctl", "restart", "traefik"]),
            command(&["systemctl", "restart", "grafana"]),
            command(&["systemctl", "restart", "loki"]),
        ] {
            queued.push(asking(&approvals, &session, &other));
        }

        let refused = approvals.ask(&held(&session, &subject));
        assert!(
            matches!(refused, Err(ApprovalError::TooManyWaiting)),
            "a full queue answered with something other than a refusal: {refused:?}"
        );

        // A place frees up, and the answer somebody gave is still there to be
        // handed back.
        approvals
            .decide(&queued[0].id, human(), false, |_| true)
            .unwrap();
        match approvals.ask(&held(&session, &subject)).unwrap() {
            Standing::Lapsed { by, .. } => assert_eq!(by, human()),
            other => panic!("a refusal took the lapse with it: {other:?}"),
        }
    }

    /// An answer the record never accepted does not strand its command.
    ///
    /// Nothing can be redeemed against such an entry and nobody can be told a
    /// person gave it, so it is no agreement and must not outlive the window
    /// it was collectable in. Kept, it would answer every later ask with the
    /// same request nothing can act on, for the rest of the session.
    #[test]
    fn an_answer_the_record_never_took_does_not_strand_its_command() {
        let approvals = approvals();
        let session = session("agent-clawde");
        let subject = command(&["systemctl", "restart", "unbound"]);

        let asked = asking(&approvals, &session, &subject);
        // Agreed to, but the recording boundary never accepted the answer, so
        // it was never marked.
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();

        approvals.clock.advance(WINDOWS.redeem_within + 1);
        match approvals.ask(&held(&session, &subject)).unwrap() {
            Standing::Waiting(ask) => assert_ne!(
                ask.asked().id,
                asked.id,
                "the command is stuck behind an answer nothing can act on"
            ),
            other => panic!("expected a fresh request to be asked, got {other:?}"),
        }
    }

    /// An expired approval cannot authorize execution.
    #[test]
    fn an_approval_expires_rather_than_becoming_standing_privilege() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        approvals.clock.advance(WINDOWS.redeem_within);
        assert_eq!(
            approvals.redeem(&asked.id, &session.principal, &command, &asked.agent_intent),
            Err(ApprovalError::Lapsed)
        );
    }

    /// A request nobody answers lapses, and a late answer is refused: a human
    /// deciding must be looking at current context, not yesterday's.
    #[test]
    fn an_unanswered_request_lapses() {
        let approvals = approvals();
        let session = session("agent-a");
        let asked = asking(
            &approvals,
            &session,
            &command(&["docker", "restart", "traefik"]),
        );

        approvals.clock.advance(WINDOWS.decide_within);
        assert!(
            approvals.waiting(|_| true).is_empty(),
            "a lapsed request is not shown"
        );
        assert_eq!(
            approvals
                .decide(&asked.id, human(), true, |_| true)
                .unwrap_err(),
            ApprovalError::Lapsed
        );
    }

    /// Refusal is final. Asking a human twice until they say yes is not a
    /// workflow this should support.
    #[test]
    fn a_refusal_stands() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        approvals
            .decide(&asked.id, human(), false, |_| true)
            .unwrap();
        assert_eq!(
            approvals.redeem(&asked.id, &session.principal, &command, &asked.agent_intent),
            Err(ApprovalError::Refused)
        );
        assert_eq!(
            approvals
                .decide(&asked.id, human(), true, |_| true)
                .unwrap_err(),
            ApprovalError::AlreadyDecided,
            "a refusal cannot be reversed by deciding again"
        );
    }

    /// An agent discovers the answer by retrying, so retrying must not queue
    /// identical requests for a human to wade through.
    #[test]
    fn asking_again_about_the_same_command_does_not_queue_a_second_request() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);

        let first = asking(&approvals, &session, &command);
        let second = asking(&approvals, &session, &command);
        assert_eq!(first.id, second.id);
        assert_eq!(approvals.waiting(|_| true).len(), 1);
    }

    /// A changed explanation is new evidence for the reviewer, not an
    /// identical retry that may silently inherit an earlier answer.
    #[test]
    fn changing_agent_intent_queues_a_distinct_request() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);

        let first = asking(&approvals, &session, &command);
        let decision =
            Engine::new(crate::policy::ReviewMode::Privileged).decide(&session, (command).clone());
        let changed = Ledger::new(TestClock::at(1_000))
            .record_intent(
                decision,
                CommandIntent::parse("restore service after checking its logs").unwrap(),
            )
            .unwrap();
        let second = match approvals.ask(&changed).unwrap() {
            Standing::Waiting(asked) => asked.into_asked(),
            other => panic!("expected a distinct request, got {other:?}"),
        };

        assert_ne!(first.id, second.id);
        assert_eq!(approvals.waiting(|_| true).len(), 2);
    }

    /// Another principal holding the identifier gets the answer given for a
    /// request that does not exist, so pending approvals cannot be probed for.
    #[test]
    fn another_principal_cannot_redeem_or_discover_the_approval() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);
        approvals
            .decide(&asked.id, human(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        let other = PrincipalId::parse("agent-b").unwrap();
        assert_eq!(
            approvals.redeem(&asked.id, &other, &command, &asked.agent_intent),
            Err(ApprovalError::Unknown),
            "a foreign redeemer should not learn the request exists"
        );

        // And the owner is unaffected.
        assert!(
            approvals
                .redeem(&asked.id, &session.principal, &command, &asked.agent_intent)
                .is_ok()
        );
    }

    /// An outage is when approval matters most and is hardest to get. The
    /// override produces the same grant under the same rules and differs only
    /// in who approved — which is recorded where a reader already looks.
    #[test]
    fn an_override_is_a_grant_that_says_who_took_it() {
        let approvals = approvals();
        let session = session("agent-a");
        let command = command(&["docker", "restart", "traefik"]);
        let asked = asking(&approvals, &session, &command);

        let broke_glass = Approver::Override {
            who: "chris".to_owned(),
            because: "pager is down and traefik is wedged".to_owned(),
        };
        approvals
            .decide(&asked.id, broke_glass.clone(), true, |_| true)
            .unwrap();
        assert!(approvals.mark_recorded(&asked.id));

        let grant = approvals
            .redeem(&asked.id, &session.principal, &command, &asked.agent_intent)
            .unwrap();
        assert_eq!(grant.approver, broke_glass);

        // It is in the approver field, not a flag beside it, so anything that
        // reports who approved reports this without being taught to.
        let rendered = serde_json::to_string(&grant.approver).unwrap();
        assert!(rendered.contains("override"), "got {rendered}");
        assert!(rendered.contains("pager is down"), "the reason travels too");

        // And it is not a shortcut past the other rules.
        assert_eq!(
            approvals.redeem(&asked.id, &session.principal, &command, &asked.agent_intent),
            Err(ApprovalError::AlreadyRedeemed)
        );
    }

    #[test]
    fn only_service_shaped_agreement_ids_are_accepted() {
        assert!(
            AgreementId::parse("0123456789abcdef0123456789abcdef").is_ok(),
            "a service-shaped ID was refused"
        );
        for bad in [
            "",
            "short",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "gggggggggggggggggggggggggggggggg",
            "0123456789abcdef/123456789abcdef",
        ] {
            assert!(
                AgreementId::parse(bad).is_err(),
                "an unshaped agreement ID was accepted: {bad:?}"
            );
        }
    }

    /// Withdrawal and standing use have one ordering: if use wins, it becomes
    /// an exact one-shot grant before withdrawal can return; if withdrawal
    /// wins, no later use can see the agreement.
    #[test]
    fn standing_use_holds_the_withdrawal_boundary_until_it_finishes() {
        let approvals = Arc::new(approvals());
        let mine = session("agent-a");
        let agreement = approvals.grant_standing(
            &mine.id,
            "chris".to_owned(),
            10_000,
            StandingCoverage::Session,
        );
        let session = mine.id.clone();
        let using = Arc::clone(&approvals);
        let (entered, wait_until_released) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let use_thread = std::thread::spawn(move || {
            using.use_standing(&session, |approver| {
                entered.send(()).unwrap();
                released.recv().unwrap();
                approver
            })
        });

        wait_until_released.recv().unwrap();
        assert!(
            approvals.standing.try_lock().is_err(),
            "standing use released the withdrawal lock before its operation finished"
        );
        release.send(()).unwrap();
        assert!(use_thread.join().unwrap().is_some());

        assert!(approvals.revoke_standing(&agreement));
        assert_eq!(
            approvals.use_standing(&mine.id, std::convert::identity),
            None,
            "an agreement remained usable after withdrawal returned"
        );
    }

    /// A caller waiting to select an agreement must read expiry only after it
    /// enters the same boundary that serializes use with withdrawal.
    #[test]
    fn standing_expiry_is_read_inside_the_use_boundary() {
        let clock = Arc::new(GatedClock::at(1_000));
        let approvals = Arc::new(Approvals::new(
            Arc::clone(&clock),
            WINDOWS,
            WAITING_PER_SESSION,
        ));
        let mine = session("agent-a");
        approvals.grant_standing(
            &mine.id,
            "chris".to_owned(),
            2_000,
            StandingCoverage::Session,
        );

        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        clock.arm(Arc::clone(&entered), Arc::clone(&release));
        let using = Arc::clone(&approvals);
        let session = mine.id.clone();
        let use_thread =
            std::thread::spawn(move || using.use_standing(&session, std::convert::identity));

        entered.wait();
        let expiry_read_holds_the_boundary = approvals.standing.try_lock().is_err();
        clock.set(2_000);
        release.wait();
        let result = use_thread.join().unwrap();

        assert!(
            expiry_read_holds_the_boundary,
            "expiry was sampled before the standing-use boundary"
        );
        assert_eq!(result, None, "an agreement answered at its expiry");
    }

    /// Requests nobody can act on any more do not accumulate.
    #[test]
    fn spent_and_lapsed_requests_are_collected() {
        let approvals = approvals();
        let session = session("agent-a");
        for target in ["traefik", "postgres", "redis"] {
            asking(
                &approvals,
                &session,
                &command(&["docker", "restart", target]),
            );
        }
        assert_eq!(approvals.len(), 3);

        approvals.clock.advance(WINDOWS.decide_within);
        approvals.sweep(|_| true);
        assert!(approvals.is_empty(), "lapsed requests were retained");
    }
    #[test]
    fn upload_approval_binds_content_and_replacement_choice() {
        let path = crate::files::RemotePath::parse("/tmp/report").unwrap();
        let input =
            crate::transfer::PreparedUpload::new("mcp-file://input/one".to_owned(), vec![1, 2])
                .unwrap();
        let changed =
            crate::transfer::PreparedUpload::new("mcp-file://input/one".to_owned(), vec![1, 3])
                .unwrap();
        let original = Action::upload(path.clone(), input.identity().clone(), false).unwrap();
        let remapped = crate::transfer::PreparedUpload::new(
            "mcp-file://input/remapped".to_owned(),
            vec![1, 2],
        )
        .unwrap();
        let remapped = Action::upload(path.clone(), remapped.identity().clone(), false).unwrap();
        let replacement = Action::upload(path.clone(), input.identity().clone(), true).unwrap();
        let changed = Action::upload(path, changed.identity().clone(), false).unwrap();
        let intent = CommandIntent::parse("place the report").unwrap();
        assert_eq!(
            digest_action(&original, &intent),
            digest_action(&remapped, &intent)
        );
        assert_ne!(
            digest_action(&original, &intent),
            digest_action(&replacement, &intent)
        );
        assert_ne!(
            digest_action(&original, &intent),
            digest_action(&changed, &intent)
        );
    }

    #[test]
    fn file_transfer_and_execution_have_distinct_approval_identity() {
        let transfer =
            Action::download(crate::files::RemotePath::parse("/tmp/report").unwrap()).unwrap();
        let execution = Action::execute(transfer.command().clone());
        let intent = CommandIntent::parse("inspect the report").unwrap();
        assert_ne!(
            digest_action(&transfer, &intent),
            digest_action(&execution, &intent)
        );
    }
}
