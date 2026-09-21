//! The record: what was run, on whose behalf, what was decided, what happened.
//!
//! This is the product for most of the use cases the design lists. Structured
//! per-command records can be *queried* — "every mutating command that touched
//! this path on this host last month" is a query rather than an afternoon of
//! replaying a terminal capture — which is the whole reason execution is
//! preferred over terminal capture wherever there is a choice.
//!
//! # Written before the command runs
//!
//! An execution nobody can account for is worse than an execution that did not
//! happen, so the record comes first and a failure to write one stops the
//! command. That is not a convention here: [`Ledger::record_intent`] returns a
//! [`Receipt`], the execution path requires one, and there is no way to obtain
//! a `Receipt` except by successfully appending. Forgetting to record is a
//! compile error rather than an audit gap discovered later.
//!
//! # Tamper-evident across retention
//!
//! Each entry carries the digest of the one before it, so altering or dropping
//! one breaks every link after it. A plain hash chain has an awkward
//! consequence, though: it makes retention impossible, because deleting old
//! entries breaks the chain that proves the recent ones.
//!
//! So retention *seals* rather than deletes. A sealed entry keeps its sequence
//! number and both digests and loses its content. The chain still verifies end
//! to end, and verification reports which entries can no longer be read — which
//! is honest, where a chain that silently verified over a gap would not be.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::approval::{Answer, Approver, Asked, Grant};
use crate::clock::{Clock, Millis};
use crate::command::{Command, CommandIntent};
use crate::policy::{Decision, Verdict};
use crate::run::{Outcome, RunId, Stream};
use crate::session::{Session, SessionId};
use crate::{AccessClass, HostId, PrincipalId, RoleId};

/// A digest, as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Digest(String);

impl Digest {
    /// The digest a chain starts from, unique to that chain.
    ///
    /// A fixed genesis would make two records that wrote the same first entry
    /// at the same moment produce the same digests all the way down, and a
    /// digest is how an authorization proves which record it came from. Random
    /// bytes from the platform's generator make one record's entries name
    /// nothing in another.
    fn genesis() -> Self {
        let mut bytes = [0_u8; 32];
        rand::fill(&mut bytes);
        Self(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Output as it was recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recorded {
    /// Stored as produced, with what the target actually emitted.
    ///
    /// `truncated` is the execution path's bound rather than this module's, and
    /// carrying it is the difference between a record that is short and a
    /// record that says it is short.
    Kept {
        text: String,
        truncated: bool,
        bytes: u64,
    },
    /// Recognised as secret-shaped and deliberately not stored.
    ///
    /// `bytes` is what the target produced, which is not always what was read:
    /// a stream can be both bounded and secret-shaped, and reporting only the
    /// retained part would understate what is missing.
    ///
    /// The record says what was withheld and why rather than appearing
    /// complete. A record that quietly dropped the bytes would be a record
    /// nobody could trust, and one that stored them would put credential
    /// material into the audit output.
    Withheld { bytes: u64, matched: &'static str },
}

/// How an approval answer was supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Direct,
    Override,
    Session,
}

/// What an external evaluator concluded about one recorded command decision.
///
/// Evaluations are evidence only. No value in this type is read by policy,
/// approval matching, or execution, and recording one mints no receipt.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationVerdict {
    SupportsIntent,
    DoesNotSupportIntent,
    Uncertain,
}

/// Untrusted JSON accepted from the separately authenticated evaluator.
///
/// Conversion to [`EvaluationArtifact`] applies all storage and display bounds
/// before anything joins the audit chain.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationDraft {
    pub evaluation_id: String,
    pub decision_digest: String,
    pub model: String,
    pub prompt_version: String,
    pub verdict: EvaluationVerdict,
    pub confidence: u8,
    pub rationale: String,
    #[serde(default)]
    pub side_effects: Vec<String>,
}

/// A validated, immutable advisory evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvaluationArtifact {
    evaluation_id: String,
    decision_digest: String,
    evaluator: String,
    model: String,
    prompt_version: String,
    verdict: EvaluationVerdict,
    confidence: u8,
    rationale: String,
    side_effects: Vec<String>,
}

impl EvaluationArtifact {
    pub fn from_draft(draft: EvaluationDraft, evaluator: String) -> Result<Self, EvaluationError> {
        bounded("evaluation_id", &draft.evaluation_id, 128)?;
        if !draft
            .evaluation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
        {
            return Err(EvaluationError::InvalidId);
        }
        if draft.decision_digest.len() != 64
            || !draft
                .decision_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvaluationError::InvalidDigest);
        }
        bounded("evaluator", &evaluator, 128)?;
        bounded("model", &draft.model, 128)?;
        bounded("prompt_version", &draft.prompt_version, 128)?;
        bounded("rationale", &draft.rationale, 2_048)?;
        if draft.confidence > 100 {
            return Err(EvaluationError::InvalidConfidence);
        }
        if draft.side_effects.len() > 16 {
            return Err(EvaluationError::TooManySideEffects);
        }
        for effect in &draft.side_effects {
            bounded("side_effect", effect, 256)?;
        }
        Ok(Self {
            evaluation_id: draft.evaluation_id,
            decision_digest: draft.decision_digest,
            evaluator,
            model: draft.model,
            prompt_version: draft.prompt_version,
            verdict: draft.verdict,
            confidence: draft.confidence,
            rationale: draft.rationale,
            side_effects: draft.side_effects,
        })
    }

    #[must_use]
    pub fn evaluation_id(&self) -> &str {
        &self.evaluation_id
    }
    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
    #[must_use]
    pub fn evaluator(&self) -> &str {
        &self.evaluator
    }
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
    #[must_use]
    pub fn prompt_version(&self) -> &str {
        &self.prompt_version
    }
    #[must_use]
    pub const fn verdict(&self) -> EvaluationVerdict {
        self.verdict
    }
    #[must_use]
    pub const fn confidence(&self) -> u8 {
        self.confidence
    }
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
    #[must_use]
    pub fn side_effects(&self) -> &[String] {
        &self.side_effects
    }
}

fn bounded(field: &'static str, value: &str, max: usize) -> Result<(), EvaluationError> {
    if value.trim().is_empty() {
        return Err(EvaluationError::Blank { field });
    }
    if value.len() > max {
        return Err(EvaluationError::TooLong { field, max });
    }
    Ok(())
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvaluationError {
    #[error("{field} must not be blank")]
    Blank { field: &'static str },
    #[error("{field} is bounded to at most {max} bytes")]
    TooLong { field: &'static str, max: usize },
    #[error("evaluation_id contains characters outside the service-safe alphabet")]
    InvalidId,
    #[error("decision_digest must be 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("confidence must be between 0 and 100")]
    InvalidConfidence,
    #[error("an evaluation may name at most 16 side effects")]
    TooManySideEffects,
}

/// What happened, at one point in a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    SessionOpened {
        purpose: String,
        access_class: AccessClass,
    },
    /// A command was submitted, and this is what was decided before any run.
    Decided {
        /// The calling agent's own explanation, not authenticated user intent.
        agent_intent: String,
        argv: Vec<String>,
        program: String,
        access_class: AccessClass,
        /// The session's own inputs to the answer. Policy is asked about a
        /// command *in a session*, so an entry without these records the
        /// verdict and not everything the verdict was based on.
        purpose: String,
        verdict: Verdict,
        policies: Vec<String>,
    },
    /// A human agreed to a command policy would not permit on its own.
    ///
    /// Its own entry rather than a field on the decision, because it is a
    /// second fact arriving later and from somebody else: policy said this
    /// needed a person, and this is the person. `decided` names the entry that
    /// said so, so the two halves join without guessing from timing.
    ///
    /// This entry is what authorizes the run. A decision that needs approval
    /// mints no receipt — it permitted nothing — and the agreement does,
    /// which keeps the rule that running requires an entry that allowed it.
    Approved {
        decided: u64,
        /// Which held request was answered.
        request: String,
        /// Who agreed, and whether they were overriding.
        approver: String,
        /// True when the agreement was an override rather than the ordinary
        /// approval path. Recorded as a fact of its own so a reader counting
        /// overrides does not have to parse a name.
        override_of: Option<String>,
        /// True when a standing agreement answered, rather than a click for
        /// this command. A fact of its own
        /// for the same reason as `override_of`: a reader separating the two
        /// must not have to parse a name.
        standing: bool,
        /// Direct, override, or session-wide.
        mode: ApprovalMode,
        /// The standing agreement that answered, if one did.
        agreement: Option<String>,
    },
    /// A human answered a request for approval, either way.
    ///
    /// Separate from `Approved`, which is the moment an agreement is spent to
    /// authorize a run. Most answers never become that: a refusal never does,
    /// and an approval nobody comes back for lapses. Those are exactly the
    /// answers that would otherwise leave no trace, which is the opposite of
    /// what a record of who decided what is for.
    ///
    /// This entry authorizes nothing. Running still requires the entry that
    /// allowed it.
    Answered {
        decided: u64,
        /// Which request was answered.
        request: String,
        /// Who answered, and whether they were overriding.
        approver: String,
        override_of: Option<String>,
        /// True when a standing agreement answered, rather than a click for
        /// this command.
        standing: bool,
        mode: ApprovalMode,
        agreement: Option<String>,
        /// Whether they agreed.
        agreed: bool,
    },
    /// What the command did.
    Completed {
        run: RunId,
        /// The entry that authorized this run, so the two halves of a command
        /// join without guessing from timing.
        decided: u64,
        state: String,
        stdout: Recorded,
        stderr: Recorded,
    },
    SessionClosed,
    /// An external, advisory assessment of a recorded decision.
    ///
    /// This entry authorizes nothing and cannot change an earlier verdict.
    Evaluated {
        artifact: EvaluationArtifact,
        /// The exact decision sequence and bounded context copied when the
        /// artifact joins the chain. Keeping this with the evaluation makes
        /// durable evaluation history self-contained and source-filterable;
        /// none of these repeated facts are consulted for authorization.
        decided: u64,
        argv: Vec<String>,
        agent_intent: String,
        purpose: String,
        access_class: AccessClass,
    },
}

/// Who an entry is about.
///
/// Every entry is attributed from something the ledger produced or was given
/// as a whole — a session for the events that are about a session, and the
/// [`Authorization`] the ledger itself minted for the completion of a command.
/// Nothing writes an entry from an identity supplied beside the thing being
/// recorded, which is what would let one session's work be recorded as
/// another's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Attribution {
    session: SessionId,
    principal: PrincipalId,
    host: HostId,
    role: RoleId,
}

impl Attribution {
    /// From the request a human answered.
    ///
    /// Attributed to the work it is about rather than to whoever answered: a
    /// human deciding somebody else's command does not make it their session,
    /// and by the time they answer that session may not exist to be asked.
    fn about(asked: &Asked) -> Self {
        Self {
            session: asked.session.clone(),
            principal: asked.principal.clone(),
            host: asked.host.clone(),
            role: asked.role.clone(),
        }
    }

    fn of(session: &Session) -> Self {
        Self {
            session: session.id.clone(),
            principal: session.principal.clone(),
            host: session.host.clone(),
            role: session.role.clone(),
        }
    }
}

/// What a decision entry permitted, in a form that travels.
///
/// Minted only by [`Ledger::record_intent`], from the entry it just wrote. It
/// names the entry twice — by position and by digest — because a position
/// repeats across records and a digest does not, and it carries who the
/// decision was for so that recording what happened never has to read the
/// decision back. That last part is what lets retention be unconditional: a
/// completion can be attributed after its decision's content is gone, because
/// the attribution travelled with the authorization rather than staying behind
/// in the entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Authorization {
    sequence: u64,
    digest: Digest,
    who: Attribution,
}

impl Authorization {
    /// Which entry recorded this, so what ran can be joined to what was decided.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// That entry's digest, so a record can tell the entry is its own.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.who.session
    }

    #[must_use]
    pub const fn host(&self) -> &HostId {
        &self.who.host
    }

    #[must_use]
    pub const fn role(&self) -> &RoleId {
        &self.who.role
    }

    /// The same authorization aimed at a different entry, for tests that need
    /// to present one the record should refuse. Compiled out of every non-test
    /// build: outside them an authorization names the entry it was minted from
    /// and nothing can move it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pointed_at(mut self, sequence: u64, digest: Digest) -> Self {
        self.sequence = sequence;
        self.digest = digest;
        self
    }
}

/// One entry, with its place in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub sequence: u64,
    pub at: Millis,
    pub session: SessionId,
    pub principal: PrincipalId,
    pub host: HostId,
    pub role: RoleId,
    pub event: Event,
    pub previous: Digest,
    pub digest: Digest,
}

/// An entry as the ledger holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Held {
    Intact(Arc<Entry>),
    /// Content removed by retention; the links survive.
    ///
    /// Nothing is kept here that the chain cannot vouch for. A fact retained
    /// beside a sealed entry and excluded from its digest is a fact that can be
    /// changed without verification noticing, which would make the chain verify
    /// after something load-bearing had been altered — so a sealed entry keeps
    /// its place and its two digests and nothing else.
    Sealed {
        sequence: u64,
        previous: Digest,
        digest: Digest,
    },
}

impl Held {
    fn sequence(&self) -> u64 {
        match self {
            Self::Intact(entry) => entry.sequence,
            Self::Sealed { sequence, .. } => *sequence,
        }
    }

    fn previous(&self) -> &Digest {
        match self {
            Self::Intact(entry) => &entry.previous,
            Self::Sealed { previous, .. } => previous,
        }
    }

    fn digest(&self) -> &Digest {
        match self {
            Self::Intact(entry) => &entry.digest,
            Self::Sealed { digest, .. } => digest,
        }
    }
}

/// Proof that a command was recorded before it ran.
///
/// Obtainable only from [`Ledger::record_intent`], and required by the
/// execution path. This is what makes "a failure to write the record prevents
/// the command from running" a property of the types rather than a rule someone
/// has to remember.
///
/// Not `Clone`, and consumed by whoever runs the command: one authorization is
/// one execution. A receipt that could be copied would let a second command run
/// on the first one's record, which is the thing this type exists to prevent.
///
/// It names the whole of what was authorized: this command, in this session,
/// against this host as this role. Any part left out is a part the execution
/// path would have to take from somewhere else, and a receipt that authorized
/// "some command, somewhere" would let one session's permission run on another
/// session's connection.
#[derive(Debug, PartialEq, Eq)]
pub struct Receipt {
    authorization: Authorization,
    command: Command,
}

impl Receipt {
    /// What this authorizes, apart from the command: which entry, in which
    /// record, for whom, on which host and as which role.
    #[must_use]
    pub const fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    /// The command this authorizes.
    ///
    /// The execution path runs *this*, rather than being handed a command
    /// alongside a receipt and comparing the two: a comparison can be got wrong
    /// or skipped, and there is no second command here to disagree with.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.authorization.sequence()
    }

    #[must_use]
    pub const fn digest(&self) -> &Digest {
        self.authorization.digest()
    }

    #[must_use]
    pub const fn session(&self) -> &SessionId {
        self.authorization.session()
    }

    #[must_use]
    pub const fn host(&self) -> &HostId {
        self.authorization.host()
    }

    #[must_use]
    pub const fn role(&self) -> &RoleId {
        self.authorization.role()
    }
}

/// The record.
/// Told about every entry as the record writes it.
///
/// The ledger this service keeps is process-local. Before an entry joins that
/// ledger, it is handed to the recording boundary selected by the deployment.
/// This fleet selects a flushed write to the service's standard output.
///
/// Able to fail, and its failure stops the entry.
///
/// A command does not run unless that boundary has accepted its complete entry.
/// An entry that could not cross the boundary must not become one a command
/// runs on. A service that cannot record is a service that cannot mediate, and
/// refusing is the whole point of it. What acceptance guarantees beyond the
/// boundary belongs to the supplied recorder; collector acknowledgement and
/// external durability are not properties of this trait.
pub trait Records: Send + Sync {
    /// # Errors
    ///
    /// When the entry could not cross the required recording boundary.
    fn wrote(&self, entry: &Entry) -> Result<(), NotRecorded>;
}

/// An entry could not cross the required recording boundary.
///
/// Carries no detail from the sink on purpose: what a caller does about it is
/// the same whatever it was, and an entry's content has already been through
/// the record's own rules about what may be repeated.
#[derive(Debug, thiserror::Error)]
#[error("the entry could not cross the recording boundary")]
pub struct NotRecorded;

pub struct Ledger<C: Clock> {
    clock: C,
    /// Where entries must be written before they join this process-local chain.
    ///
    /// Optional because a record is useful without one — every test in this
    /// crate uses a ledger that keeps entries and sends them nowhere — and
    /// because the boundary and its guarantees are deployment policy, not this
    /// type's business.
    records_to: Option<Arc<dyn Records>>,
    /// What this record's first entry commits to, and what makes its digests
    /// its own. Minted once, when the record is created.
    genesis: Digest,
    entries: Mutex<Vec<Held>>,
    /// What the ledger has written, and the digest it ended on.
    ///
    /// A chain proves each entry follows the one before it, and says nothing
    /// about the entries that are no longer there: remove the last one, or the
    /// last ten, and everything remaining still links. Verification compares
    /// what is present against what was issued, so losing the tail is a break
    /// rather than a shorter chain that happens to be consistent.
    issued: Mutex<Issued>,
    /// Runs this record has already accounted for.
    ///
    /// Kept beside the chain rather than inside it, like `issued`, because it
    /// has to answer after retention has taken the entries it would otherwise
    /// be read from. A run asked about twice hands back two outcomes, and
    /// without this the second one becomes a second completion once the first
    /// has been retired.
    ///
    /// This is why an identifier has to name one execution rather than one
    /// position in one store: a record can be fed by more than one, and two
    /// stores numbering from the same place would have the second store's first
    /// run mistaken for a repeat of the first store's.
    completed: Mutex<HashSet<String>>,
    /// Bounded-look-up state for advisory evaluations.
    ///
    /// Issued identifiers and evaluated decision digests survive retention so
    /// sealing cannot reopen either append surface. Readable decisions and
    /// artifacts are indexed only while their corresponding ledger entries
    /// remain intact; keeping those lookups here prevents a credentialed miss
    /// from scanning the complete record while blocking audit appends.
    evaluations: Mutex<EvaluationIndex>,
}

#[derive(Debug, Default)]
struct EvaluationIndex {
    issued_ids: HashSet<String>,
    evaluated_decisions: HashSet<String>,
    readable_decisions: HashMap<String, ReadableDecision>,
    readable_artifacts: HashMap<String, Entry>,
}

#[derive(Clone, Debug)]
struct ReadableDecision {
    sequence: u64,
    attribution: Attribution,
    argv: Vec<String>,
    agent_intent: String,
    purpose: String,
    access_class: AccessClass,
}

/// What this record has written, in order.
///
/// One digest per entry, kept for the life of the record. A digest is the
/// entry: recomputing it is how an intact entry is checked, and after retention
/// there is nothing left to recompute — so the commitment has to have been kept
/// somewhere retention does not reach, or a sealed entry's own digest is
/// whatever the last writer left there. Two adjacent sealed entries could
/// otherwise be changed together, one's digest and the next one's link, and
/// every later entry and the head would still agree.
///
/// The cost is thirty-two bytes an entry, against the argument vectors and
/// command output that retention exists to shed. Keeping proof is cheap;
/// keeping content is not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Issued {
    digests: Vec<Digest>,
}

impl Issued {
    fn entries(&self) -> u64 {
        u64::try_from(self.digests.len()).unwrap_or(u64::MAX)
    }
}

impl<C: Clock> Ledger<C> {
    #[must_use]
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            records_to: None,
            genesis: Digest::genesis(),
            entries: Mutex::new(Vec::new()),
            issued: Mutex::new(Issued::default()),
            completed: Mutex::new(HashSet::new()),
            evaluations: Mutex::new(EvaluationIndex::default()),
        }
    }

    /// A record that also hands every entry to something that outlives it.
    #[must_use]
    pub fn recording_to(clock: C, records_to: Arc<dyn Records>) -> Self {
        Self {
            records_to: Some(records_to),
            ..Self::new(clock)
        }
    }

    /// Records that a command is about to run, and what was decided about it.
    ///
    /// Returns the receipt the execution path needs. Recording the decision
    /// *and* the argument vector before execution is what makes a later
    /// disagreement about what ran resolvable.
    ///
    /// The decision and typed agent intent are consumed together. The decision
    /// carries the session and command, so trusted authorization facts cannot be transposed while
    /// the separately provenanced agent explanation remains attached to that
    /// exact deliberation. Taking both by value keeps the count right too: one
    /// answer from the decision point is one recorded intent and one receipt,
    /// where a borrowed decision could be presented again for a second
    /// execution nobody asked policy about.
    pub fn record_intent(
        &self,
        decision: Decision,
        agent_intent: CommandIntent,
    ) -> Result<Intended, AuditError> {
        let session = decision.session();
        let command = decision.command();
        let argv = command.argv().to_vec();
        let recorded_agent_intent = agent_intent.as_str().to_owned();
        let purpose = session.purpose.as_str().to_owned();
        let access_class = session.access_class;
        // The evaluation index is held before the ledger so retention and an
        // evaluator cannot observe the decision in only one of the two. This
        // is the same lock order used by evaluation append and sealing.
        let mut evaluations = self.evaluations.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let attribution = Attribution::of(session);
        let entry = self.append_to(
            &mut entries,
            attribution.clone(),
            Event::Decided {
                argv: argv.clone(),
                agent_intent: recorded_agent_intent.clone(),
                program: command.program().to_owned(),
                access_class,
                // The session's own inputs to the answer. Without them the
                // entry says what policy decided and not everything policy was
                // told, so a reader cannot check the verdict against the facts.
                purpose: purpose.clone(),
                verdict: decision.verdict(),
                policies: decision.policies().to_vec(),
            },
        )?;
        evaluations.readable_decisions.insert(
            entry.digest.as_str().to_owned(),
            ReadableDecision {
                sequence: entry.sequence,
                attribution,
                argv,
                agent_intent: recorded_agent_intent,
                purpose,
                access_class,
            },
        );

        // A refusal is recorded and authorizes nothing. Minting a receipt for
        // one would make the record of the refusal into permission to run the
        // command it refused.
        let receipt = (decision.verdict() == Verdict::Permit).then(|| Receipt {
            authorization: Authorization {
                sequence: entry.sequence,
                digest: entry.digest.clone(),
                who: Attribution::of(decision.session()),
            },
            command: command.clone(),
        });
        Ok(Intended {
            entry,
            decision,
            agent_intent,
            receipt,
        })
    }

    /// Records that a human agreed to a command policy held.
    ///
    /// Takes the decision that was held, so the agreement cannot be attached to
    /// a command nobody deliberated about, and hands back a receipt: a held
    /// decision authorized nothing, and this is what authorizes the run. The
    /// receipt names *this* entry, so a completion joins to the agreement that
    /// allowed it rather than to the deliberation that did not.
    ///
    /// Refuses a decision that did not need approval. Recording an agreement
    /// about a command policy already permitted, or already refused, would put
    /// a human's name against a choice they were never asked to make.
    ///
    /// Refuses, too, an agreement that is not about *this* recorded intent. The
    /// capability already keeps decision, command, agent intent, session, and
    /// audit entry together; the grant must name that same action and entry
    /// before it can mint a receipt.
    pub fn record_approval(
        &self,
        intended: &Intended,
        grant: Grant,
    ) -> Result<(Receipt, Approver), AuditError> {
        let decided = grant.decided();
        let decision = intended.decision();
        if decision.verdict() != Verdict::NeedsApproval {
            return Err(AuditError::NotHeldForApproval { sequence: decided });
        }
        if grant.action() != crate::approval::digest_of(decision.command(), intended.agent_intent())
        {
            return Err(AuditError::NotItsApproval { sequence: decided });
        }
        let session = decision.session();
        // Whose agreement this is, against whose work is being decided. Both
        // halves say so themselves, so this holds whatever the record still
        // keeps: an agreement given for one session cannot be presented
        // alongside another session's deliberation, even after retention has
        // removed what that deliberation said.
        if grant.session() != &session.id {
            return Err(AuditError::NotItsApproval { sequence: decided });
        }
        self.this_deliberation(decided, grant.decided_digest(), &session.id)?;

        let (approver, override_of, standing, mode, agreement) = match grant.approver() {
            Approver::Human { who } => (who.clone(), None, false, ApprovalMode::Direct, None),
            Approver::Override { who, because } => (
                who.clone(),
                Some(because.clone()),
                false,
                ApprovalMode::Override,
                None,
            ),
            Approver::SessionStanding { who, agreement } => (
                who.clone(),
                None,
                true,
                ApprovalMode::Session,
                Some(agreement.as_str().to_owned()),
            ),
        };
        let entry = self.append(
            Attribution::of(session),
            Event::Approved {
                decided,
                request: grant.request().as_str().to_owned(),
                approver,
                override_of,
                standing,
                mode,
                agreement,
            },
        )?;
        // The grant is spent here: it was taken by value, it does not copy, and
        // the caller no longer has one. Minting a second receipt from the same
        // agreement would need a second agreement.
        let approver = grant.spend();
        Ok((
            Receipt {
                authorization: Authorization {
                    sequence: entry.sequence,
                    digest: entry.digest.clone(),
                    who: Attribution::of(session),
                },
                command: decision.command().clone(),
            },
            approver,
        ))
    }

    /// Checks that an entry is the deliberation an answer claims to answer.
    ///
    /// A sequence number names a position, and positions repeat between
    /// records, so the digest is what identifies which entry is meant. What
    /// the entry has to be is a deliberation that asked for a human, about
    /// this session's work — an answer against anything else describes a
    /// choice nobody was offered.
    ///
    /// Retention removes an entry's content and keeps its digest, so the
    /// checks that need the content apply while there is content. What does
    /// not depend on them is the authorization itself: an agreement carries
    /// the session it was given for, and that is compared before this is
    /// reached.
    fn this_deliberation(
        &self,
        decided: u64,
        digest: &str,
        session: &SessionId,
    ) -> Result<(), AuditError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let held = usize::try_from(decided)
            .ok()
            .and_then(|index| entries.get(index))
            .ok_or(AuditError::NoSuchDecision { sequence: decided })?;
        if held.digest().as_str() != digest {
            return Err(AuditError::NotItsApproval { sequence: decided });
        }
        if let Held::Intact(entry) = held {
            if !matches!(
                entry.event,
                Event::Decided {
                    verdict: Verdict::NeedsApproval,
                    ..
                }
            ) {
                return Err(AuditError::NotHeldForApproval { sequence: decided });
            }
            if &entry.session != session {
                return Err(AuditError::NotItsApproval { sequence: decided });
            }
        }
        Ok(())
    }

    /// Records a human's answer to a request for approval.
    ///
    /// Written after the answer has been taken rather than before, because an
    /// answer the store refuses — one already decided, or lapsed — is not an
    /// answer, and recording it would say a decision was made that was not.
    /// Nothing rests on the ordering: this entry authorizes no run, and the
    /// entry that does is written before anything happens.
    pub fn record_answer(&self, answer: &Answer) -> Result<Entry, AuditError> {
        let asked = answer.asked();
        self.this_deliberation(asked.decided, &asked.decided_digest, &asked.session)?;
        let (who, override_of, standing, mode, agreement) = match answer.approver() {
            Approver::Human { who } => (who.clone(), None, false, ApprovalMode::Direct, None),
            Approver::Override { who, because } => (
                who.clone(),
                Some(because.clone()),
                false,
                ApprovalMode::Override,
                None,
            ),
            Approver::SessionStanding { who, agreement } => (
                who.clone(),
                None,
                true,
                ApprovalMode::Session,
                Some(agreement.as_str().to_owned()),
            ),
        };
        self.append(
            Attribution::about(asked),
            Event::Answered {
                decided: asked.decided,
                request: asked.id.as_str().to_owned(),
                approver: who,
                override_of,
                standing,
                mode,
                agreement,
                agreed: answer.agreed(),
            },
        )
    }

    /// Records what a command did.
    ///
    /// The outcome names the entry that authorized it, and everything else
    /// about the completion is read from *that* entry: who, on which host, as
    /// which role, in which session. Nothing is supplied alongside, so a
    /// completion cannot be attributed to a session that did not make the
    /// decision — there is no second session to attribute it to.
    ///
    /// The entry it names must be *this* record's decision, identified by
    /// digest rather than by position: entry seven of one record is not entry
    /// seven of another, so a number alone would let a run be recorded against
    /// an unrelated same-numbered decision somewhere else. And it must be a
    /// decision that permitted running — a completion hanging off a refusal,
    /// off a session opening, or off nothing would be a transcript that
    /// verifies and misstates what authorized the run.
    ///
    /// A run that has not finished has no completion to record. `Completed`
    /// means completed; writing one for a command still going would leave the
    /// record saying a command ended in a state it had not reached, and its
    /// real ending unrecorded. Ask again when it settles.
    ///
    /// One execution is one completion entry. The outcome is consumed, but a
    /// run can be asked about as many times as a caller likes and each answer
    /// is a fresh outcome, so consuming is not enough on its own — the record
    /// refuses a second completion for a run it has already accounted for. A
    /// chain that verified while saying one command finished three times would
    /// be worse than no record, because it would look like evidence.
    ///
    /// Both checks and the append happen under one hold of the record. Looking
    /// and then writing are two operations, and a record that answered "no
    /// completion yet" to two callers at once would let both write one - a
    /// chain that verifies while saying one execution finished twice. The whole
    /// question is asked and answered without letting go.
    pub fn record_outcome(&self, outcome: Outcome) -> Result<Accounted, AuditError> {
        if outcome.still_running() {
            return Err(AuditError::StillRunning {
                run: outcome.run().as_str().to_owned(),
            });
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut completed = self.completed.lock().unwrap_or_else(|e| e.into_inner());
        if completed.contains(outcome.run().as_str()) {
            return Err(AuditError::AlreadyCompleted {
                run: outcome.run().as_str().to_owned(),
            });
        }
        let authorized = outcome.authorization();
        this_records_decision(&entries, authorized)?;
        let written = self.append_to(
            &mut entries,
            authorized.who.clone(),
            Event::Completed {
                run: outcome.run().clone(),
                decided: authorized.sequence(),
                state: format!("{:?}", outcome.state()),
                stdout: record_output(outcome.stdout()),
                stderr: record_output(outcome.stderr()),
            },
        )?;
        completed.insert(outcome.run().as_str().to_owned());
        Ok(Accounted {
            entry: written,
            outcome,
        })
    }

    /// Appends an immutable advisory evaluation for an exact decision digest.
    ///
    /// One decision accepts one artifact. The same evaluator retry is
    /// idempotent while its entry is readable; reusing that identifier for
    /// different content, using another identifier for the same decision, or
    /// retrying after retention has sealed its content is refused. The issued
    /// identifier, evaluated-decision, and entry locks span the lookup and
    /// append, so concurrent submissions cannot both claim either name.
    pub fn record_evaluation(&self, artifact: EvaluationArtifact) -> Result<Entry, AuditError> {
        let id = artifact.evaluation_id().to_owned();
        let decision_digest = artifact.decision_digest().to_owned();
        let mut evaluations = self.evaluations.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if evaluations.issued_ids.contains(&id) {
            if let Some(entry) = evaluations.readable_artifacts.get(&id)
                && let Event::Evaluated {
                    artifact: existing, ..
                } = &entry.event
                && existing == &artifact
            {
                return Ok(entry.clone());
            }
            return Err(AuditError::EvaluationConflict { id });
        }
        if evaluations.evaluated_decisions.contains(&decision_digest) {
            return Err(AuditError::DecisionAlreadyEvaluated {
                digest: decision_digest,
            });
        }
        let Some(decision) = evaluations.readable_decisions.get(&decision_digest) else {
            return Err(AuditError::EvaluationDecisionUnknown {
                digest: artifact.decision_digest().to_owned(),
            });
        };
        let entry = self.append_to(
            &mut entries,
            decision.attribution.clone(),
            Event::Evaluated {
                artifact,
                decided: decision.sequence,
                argv: decision.argv.clone(),
                agent_intent: decision.agent_intent.clone(),
                purpose: decision.purpose.clone(),
                access_class: decision.access_class,
            },
        )?;
        evaluations.issued_ids.insert(id.clone());
        evaluations.evaluated_decisions.insert(decision_digest);
        evaluations.readable_artifacts.insert(id, entry.clone());
        Ok(entry)
    }

    pub fn record_session_opened(&self, session: &Session) -> Result<Entry, AuditError> {
        self.append(
            Attribution::of(session),
            Event::SessionOpened {
                purpose: session.purpose.as_str().to_owned(),
                access_class: session.access_class,
            },
        )
    }

    pub fn record_session_closed(&self, session: &Session) -> Result<Entry, AuditError> {
        self.append(Attribution::of(session), Event::SessionClosed)
    }

    fn append(&self, who: Attribution, event: Event) -> Result<Entry, AuditError> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.append_to(&mut entries, who, event)
    }

    /// Appends to a record already being held, so a caller that had to look
    /// before writing can do both without letting go in between.
    fn append_to(
        &self,
        entries: &mut Vec<Held>,
        who: Attribution,
        event: Event,
    ) -> Result<Entry, AuditError> {
        let at = self.clock.now();
        let sequence = u64::try_from(entries.len()).map_err(|_| AuditError::Full)?;
        let previous = entries
            .last()
            .map_or_else(|| self.genesis.clone(), |held| held.digest().clone());

        let mut entry = Entry {
            sequence,
            at,
            session: who.session,
            principal: who.principal,
            host: who.host,
            role: who.role,
            event,
            previous,
            digest: self.genesis.clone(),
        };
        entry.digest = digest_of(&entry)?;
        // Before the chain, not after. An entry that could not cross the
        // configured recording boundary is not one anything may run on, and
        // the way to mean that is for it never to become part of the record at
        // all — rather than to be acted upon while the boundary has no complete
        // entry for it.
        if let Some(records_to) = &self.records_to {
            records_to
                .wrote(&entry)
                .map_err(|_| AuditError::NotRecorded)?;
        }
        entries.push(Held::Intact(Arc::new(entry.clone())));
        {
            let mut issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
            issued.digests.push(entry.digest.clone());
        }
        Ok(entry)
    }

    /// Entries still readable, oldest first.
    #[must_use]
    pub fn entries(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|held| match held {
                Held::Intact(entry) => Some((**entry).clone()),
                Held::Sealed { .. } => None,
            })
            .collect()
    }

    /// Newest readable entries, sharing their immutable storage with the
    /// ledger rather than copying retained command output.
    ///
    /// The caller supplies the complete read window up front. This makes a
    /// human-facing view's memory cost independent of the age of the process,
    /// while the recording boundary remains the complete durable history.
    #[must_use]
    pub fn recent_entries(&self, limit: usize) -> Vec<Arc<Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .filter_map(|held| match held {
                Held::Intact(entry) => Some(Arc::clone(entry)),
                Held::Sealed { .. } => None,
            })
            .take(limit)
            .collect()
    }

    /// Removes the content of everything before `sequence`, keeping the links.
    ///
    /// This is what retention looks like on a chain: the bytes go, the proof
    /// stays. Deleting outright would break verification of everything that
    /// came after, which would mean choosing between keeping records forever
    /// and being able to trust them.
    ///
    /// One kind of entry is left alone: one whose content no longer matches its
    /// own digest. Sealing it would copy the digest of the entry it used to be
    /// and discard the only thing that could contradict it, so retention would
    /// quietly launder an alteration into a chain that verifies.
    ///
    /// Nothing else is exempt, including a decision whose command has not
    /// finished. That costs nothing, because an authorization carries what it
    /// permitted and who for, so a completion arriving after its decision has
    /// been retired is still attributable and still checkable against the
    /// sealed entry's digest.
    pub fn seal_before(&self, sequence: u64) {
        let mut evaluations = self.evaluations.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for held in entries.iter_mut() {
            if held.sequence() < sequence
                && let Held::Intact(entry) = held
                && digest_of(entry).is_ok_and(|recomputed| recomputed == entry.digest)
            {
                *held = Held::Sealed {
                    sequence: entry.sequence,
                    previous: entry.previous.clone(),
                    digest: entry.digest.clone(),
                };
            }
        }
        let remains_readable = |entry_sequence: u64| {
            usize::try_from(entry_sequence)
                .ok()
                .and_then(|index| entries.get(index))
                .is_some_and(|held| matches!(held, Held::Intact(_)))
        };
        evaluations
            .readable_decisions
            .retain(|_, decision| remains_readable(decision.sequence));
        evaluations
            .readable_artifacts
            .retain(|_, entry| remains_readable(entry.sequence));
    }

    /// Checks the chain end to end.
    ///
    /// Verifies over sealed entries as well as intact ones, and says how many
    /// could no longer be read — a verification that quietly passed over a gap
    /// would be worth less than none.
    pub fn verify(&self) -> Result<Verified, Broken> {
        self.verify_window(None)
    }

    /// Verifies at most the newest `limit` entries and the record's head.
    ///
    /// Sequence and link checks still anchor the window to the entry just
    /// before it, and the issued count still detects a missing tail. Content
    /// before the window is deliberately not re-hashed: this is the bounded
    /// check suitable for a request path, not a claim about the complete
    /// retained history.
    pub fn verify_recent(&self, limit: usize) -> Result<Verified, Broken> {
        self.verify_window(Some(limit))
    }

    fn verify_window(&self, limit: Option<usize>) -> Result<Verified, Broken> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let issued = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        let start = limit.map_or(0, |limit| entries.len().saturating_sub(limit));
        let mut expected_previous = start
            .checked_sub(1)
            .and_then(|before| entries.get(before))
            .map_or_else(|| self.genesis.clone(), |before| before.digest().clone());
        let mut sealed = 0_usize;

        for (index, held) in entries.iter().enumerate().skip(start) {
            let position = u64::try_from(index).unwrap_or(u64::MAX);
            if held.sequence() != position {
                return Err(Broken::OutOfOrder {
                    at: position,
                    found: held.sequence(),
                });
            }
            if held.previous() != &expected_previous {
                return Err(Broken::LinkMismatch {
                    at: held.sequence(),
                });
            }
            // Every entry against the digest it was written with. An intact
            // one is also recomputed from its content, which is what catches an
            // edit; a sealed one has no content left to recompute, so what was
            // issued is the only thing that can contradict a digest someone
            // changed after the fact.
            if issued.digests.get(index) != Some(held.digest()) {
                return Err(Broken::ContentAltered {
                    at: held.sequence(),
                });
            }
            match held {
                Held::Intact(entry) => {
                    let recomputed =
                        digest_of(entry).map_err(|_| Broken::Unreadable { at: entry.sequence })?;
                    if recomputed != entry.digest {
                        return Err(Broken::ContentAltered { at: entry.sequence });
                    }
                }
                Held::Sealed { .. } => sealed = sealed.saturating_add(1),
            }
            expected_previous = held.digest().clone();
        }

        // What is present, against what was written. A chain cannot notice its
        // own missing tail: every remaining link is still correct.
        let present = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        if present != issued.entries() {
            return Err(Broken::EntriesMissing {
                issued: issued.entries(),
                present,
            });
        }

        Ok(Verified {
            entries: entries.len().saturating_sub(start),
            sealed,
        })
    }
}

/// A recorded intent, and what it hands back.
///
/// Recording consumes the decision, because one answer from the decision point
/// is one recorded intent and one execution. A caller still has to *answer*
/// with that decision — what was decided and why is most of what it has to say
/// — so the decision comes back rather than being swallowed. The receipt is
/// present only when the decision permitted running.
/// The entry and the decision are held together and privately: what makes this
/// worth anything to a caller is that the record produced both halves at once,
/// and fields anybody could set would let a decision be presented beside an
/// entry that is not its own.
#[derive(Debug)]
pub struct Intended {
    entry: Entry,
    decision: Decision,
    agent_intent: CommandIntent,
    receipt: Option<Receipt>,
}

impl Intended {
    /// The entry this deliberation was recorded as.
    #[must_use]
    pub const fn deliberation(&self) -> &Entry {
        &self.entry
    }

    /// What was decided.
    #[must_use]
    pub const fn decision(&self) -> &Decision {
        &self.decision
    }

    /// What the calling agent said this command was meant to accomplish.
    #[must_use]
    pub const fn agent_intent(&self) -> &CommandIntent {
        &self.agent_intent
    }

    /// Takes the decision, and the receipt if the decision permitted running.
    ///
    /// The entry is not handed out: everything that needs to name it does so
    /// through this pairing, which is the only thing that says the two belong
    /// together.
    #[must_use]
    pub fn into_parts(self) -> (Decision, Option<Receipt>) {
        (self.decision, self.receipt)
    }
}

/// A recorded completion, and the outcome it was written from.
///
/// The same shape and the same reason: recording consumes the outcome so that
/// one execution is one completion, and hands it back because the caller's
/// answer is what the command did.
#[derive(Debug)]
pub struct Accounted {
    pub entry: Entry,
    pub outcome: Outcome,
}

/// The result of a successful verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub entries: usize,
    /// How many entries verified but can no longer be read.
    pub sealed: usize,
}

/// Shapes that mean the text is credential material.
///
/// **Deliberately incomplete, and it always will be.** Recognising a secret in
/// arbitrary command output is a heuristic: this withholds what it matches and
/// nothing more, and it is not a guarantee that credentials never reach the
/// record. What actually bounds the exposure is that the role credential limits
/// what can be read at all. Nothing identifies which files a command names -
/// which part of an argument is a path is a question about the option that
/// carried it - so this pass is the whole of the recognition rather than a
/// second line behind a first.
///
/// Stated here because a list like this invites being read as complete.
pub(crate) const SECRET_SHAPES: &[(&str, &str)] = &[
    ("-----BEGIN", "a PEM private key block"),
    ("ssh-rsa AAAA", "an SSH public key line"),
    ("ssh-ed25519 AAAA", "an SSH public key line"),
    ("PRIVATE KEY", "private key material"),
    ("aws_secret_access_key", "an AWS credential"),
];

/// The longest shape above, in bytes.
///
/// Output arrives in pieces, and a shape can fall across the join between two
/// of them, so whatever scans a stream as it flows has to carry this much of
/// the previous piece forward.
pub(crate) const LONGEST_SECRET_SHAPE: usize = 21;

/// What a piece of output looks like, if it looks like anything.
pub(crate) fn secret_shape(text: &str) -> Option<&'static str> {
    SECRET_SHAPES
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|(_, what)| *what)
}

/// Whether the entry this authorization names belongs to this record.
///
/// By digest, not by position. A position repeats — entry seven of one record
/// is not entry seven of another — so a run authorized somewhere else would
/// otherwise land on whatever this record happens to hold at the same number,
/// and the entry would hash correctly while naming a decision that was about
/// something else entirely. A digest is the entry.
///
/// A sealed entry passes on its digest alone, which is all retention leaves and
/// all that is needed: the digest commits to the whole entry, so matching it is
/// proof of which decision this was. What the entry said is not read here,
/// because the authorization already carries it.
fn this_records_decision(entries: &[Held], authorized: &Authorization) -> Result<(), AuditError> {
    let sequence = authorized.sequence();
    let held = usize::try_from(sequence)
        .ok()
        .and_then(|index| entries.get(index))
        .ok_or(AuditError::NoSuchDecision { sequence })?;
    if held.digest() != authorized.digest() {
        return Err(AuditError::NotItsDecision { sequence });
    }
    // An intact entry can still say what it was, so it is asked. A sealed one
    // cannot, and does not need to: an `Authorization` is minted only for an
    // entry that allowed a run, names one entry, and cannot be aimed elsewhere
    // — so holding one that matches this digest is itself the proof that this
    // entry allowed this run.
    //
    // Two kinds of entry allow one, and they are the two that mint a receipt: a
    // decision that permitted the command outright, and a human's agreement to
    // one policy would not permit on its own. A decision that *held* a command
    // allowed nothing, which is why the agreement is a separate entry rather
    // than a flag on it.
    if let Held::Intact(entry) = held
        && !matches!(
            entry.event,
            Event::Decided {
                verdict: Verdict::Permit,
                ..
            } | Event::Approved { .. }
        )
    {
        return Err(AuditError::NotItsDecision { sequence });
    }
    Ok(())
}

/// What the record keeps of one stream.
///
/// The stream says whether it looked like a secret, because only the stream
/// saw all of it. Deciding that here from what survived the output bound would
/// mean a credential appearing past the bound is stored as ordinary output that
/// merely says it is short — the record would be wrong about the one thing this
/// pass exists to be right about.
fn record_output(stream: &Stream) -> Recorded {
    if let Some(what) = stream.matched {
        return Recorded::Withheld {
            // What the target produced, not what survived the bound: a count
            // describing only the retained prefix understates what was withheld
            // whenever the stream was also truncated.
            bytes: stream.bytes,
            matched: what,
        };
    }
    Recorded::Kept {
        text: stream.text.clone(),
        truncated: stream.truncated,
        bytes: stream.bytes,
    }
}

/// Hashes an entry over everything except its own digest.
fn digest_of(entry: &Entry) -> Result<Digest, AuditError> {
    let mut without = entry.clone();
    // Hashed over a fixed placeholder rather than the record's genesis, so the
    // digest of an entry depends on the entry and the link before it and not on
    // where the placeholder happened to come from.
    without.digest = Digest(String::new());
    let canonical = serde_json::to_vec(&without).map_err(|source| AuditError::Unserializable {
        detail: source.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(Digest(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("the record could not cross the recording boundary")]
    NotRecorded,
    #[error("the record could not be serialized: {detail}")]
    Unserializable { detail: String },
    #[error("the record is full")]
    Full,
    #[error("entry {sequence} is not a decision that was held for a human")]
    NotHeldForApproval { sequence: u64 },
    #[error("the agreement recorded at entry {sequence} was given for another command")]
    NotItsApproval { sequence: u64 },
    #[error("no entry {sequence} to attribute this outcome to")]
    NoSuchDecision { sequence: u64 },
    #[error("entry {sequence} is not a decision that permitted running")]
    NotItsDecision { sequence: u64 },
    #[error("run {run} has not finished, so there is no completion to record")]
    StillRunning { run: String },
    #[error("run {run} has already been recorded as completed")]
    AlreadyCompleted { run: String },
    #[error("no readable command decision has digest {digest}")]
    EvaluationDecisionUnknown { digest: String },
    #[error("evaluation id {id} was already used for different evidence")]
    EvaluationConflict { id: String },
    #[error("decision digest {digest} already has evaluation evidence")]
    DecisionAlreadyEvaluated { digest: String },
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Broken {
    #[error("entry {at} does not commit to the one before it")]
    LinkMismatch { at: u64 },
    #[error("entry {at} has been altered since it was written")]
    ContentAltered { at: u64 },
    #[error("expected entry {at} but found {found}")]
    OutOfOrder { at: u64, found: u64 },
    #[error("entry {at} could not be read")]
    Unreadable { at: u64 },
    #[error("{issued} entries were written and {present} are present")]
    EntriesMissing { issued: u64, present: u64 },
    #[error("the last entry is not the one this record ended on")]
    HeadMismatch,
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
    use crate::clock::TestClock;
    use crate::policy::Engine;
    use crate::run::{Limits, RunState, Runs, Stream};
    use crate::session::{Lifetime, Purpose, SessionStore};

    const LIFETIME: Lifetime = Lifetime {
        idle: 10_000,
        max: 60_000,
        grace: 5_000,
    };

    /// A privileged account subject to the fixture's local review setting.
    fn session_that_can_be_asked_about() -> Session {
        SessionStore::new(TestClock::at(1_000), LIFETIME, 8)
            .open(
                PrincipalId::parse("alice").unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("readonly").unwrap(),
                Purpose::parse("restart the proxy after the config change").unwrap(),
                AccessClass::Privileged,
            )
            .expect("within the per-principal limit")
    }

    fn session() -> Session {
        SessionStore::new(TestClock::at(1_000), LIFETIME, 8)
            .open(
                PrincipalId::parse("alice").unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("readonly").unwrap(),
                Purpose::parse("find out why the deploy did not take effect").unwrap(),
                AccessClass::ReadOnly,
            )
            .expect("within the per-principal limit")
    }

    fn ledger() -> Ledger<TestClock> {
        Ledger::new(TestClock::at(1_000))
    }

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    fn intent() -> CommandIntent {
        CommandIntent::parse("exercise the recorded command").unwrap()
    }

    fn recorded_run(ledger: &Ledger<TestClock>, session: &Session, argv: &[&str]) -> Receipt {
        recorded_decision(ledger, session, argv).expect("this command is permitted to run")
    }

    fn recorded_decision(
        ledger: &Ledger<TestClock>,
        session: &Session,
        argv: &[&str],
    ) -> Option<Receipt> {
        let decision =
            Engine::new(crate::policy::ReviewMode::Privileged).decide(session, command(argv));
        ledger.record_intent(decision, intent()).unwrap().receipt
    }

    /// A finished outcome for the run this receipt authorized.
    ///
    /// The run is named after the authorization, so two commands in one record
    /// are two runs - as they are in production, where the store mints an
    /// identifier per execution.
    fn outcome_for(receipt: &Receipt, stdout: &str) -> Outcome {
        Outcome::authorized_by(
            receipt.authorization().clone(),
            RunId::from_raw(format!("r-{}", receipt.sequence())),
            RunState::Exited { code: 0 },
            kept(stdout),
        )
    }

    /// The same, for a test that has to name an entry the receipt does not.
    ///
    /// Built by taking a real authorization apart and pointing it somewhere
    /// else, which is what forging one would look like.
    fn outcome_naming(receipt: &Receipt, at: u64, digest: Digest, stdout: Stream) -> Outcome {
        Outcome::authorized_by(
            receipt.authorization().clone().pointed_at(at, digest),
            RunId::from_raw("r-1"),
            RunState::Exited { code: 0 },
            stdout,
        )
    }

    /// A finished outcome for a run that store would have started.
    fn outcome_from(runs: &Runs, receipt: &Receipt, stdout: &str) -> Outcome {
        Outcome::authorized_by(
            receipt.authorization().clone(),
            runs.mint_id(),
            RunState::Exited { code: 0 },
            kept(stdout),
        )
    }

    /// A stream as the execution path would hand it over, having already
    /// decided whether what went past looked like credential material.
    fn kept(text: &str) -> Stream {
        Stream {
            text: text.to_owned(),
            truncated: false,
            bytes: text.len() as u64,
            matched: crate::audit::secret_shape(text),
        }
    }

    /// The decision and the exact argument vector are recorded before the
    /// command runs, so a later disagreement about what ran is resolvable.
    #[test]
    fn what_was_decided_is_recorded_before_the_command_runs() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);

        let entries = ledger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(&entries[0].digest, receipt.digest());
        let Event::Decided {
            agent_intent,
            argv,
            verdict,
            ..
        } = &entries[0].event
        else {
            panic!("expected a decision, got {:?}", entries[0].event);
        };
        assert_eq!(agent_intent, intent().as_str());
        assert_eq!(argv, &["docker", "ps"]);
        assert_eq!(*verdict, Verdict::Permit);
    }

    /// Every entry is attributable without looking anywhere else: who, on which
    /// host, as which role, in which session.
    #[test]
    fn every_entry_carries_who_and_where() {
        let ledger = ledger();
        let session = session();
        ledger.record_session_opened(&session).unwrap();

        let entry = &ledger.entries()[0];
        assert_eq!(entry.principal.as_str(), "alice");
        assert_eq!(entry.host.as_str(), "dns1");
        assert_eq!(entry.role.as_str(), "readonly");
        assert_eq!(entry.session, session.id);
    }

    /// A held decision must be recorded without authorizing execution.
    #[test]
    fn a_held_decision_is_recorded_and_authorizes_nothing() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();
        let refused = recorded_decision(&ledger, &session, &["docker", "exec", "web", "ls"]);
        assert!(refused.is_none(), "a refusal handed back permission to run");

        let Event::Decided { verdict, .. } = &ledger.entries()[0].event else {
            panic!("the refusal was not recorded");
        };
        assert_eq!(*verdict, Verdict::NeedsApproval);
    }

    /// A receipt names the whole of what was authorized. Anything it left out
    /// would be a part the execution path had to take from somewhere else, and
    /// "somewhere else" is what an authorization exists to rule out.
    #[test]
    fn a_receipt_names_the_command_and_the_target_it_was_written_for() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);

        assert_eq!(receipt.command(), &command(&["docker", "ps"]));
        assert_eq!(receipt.session(), &session.id);
        assert_eq!(receipt.host(), &session.host);
        assert_eq!(receipt.role(), &session.role);
    }

    /// An outcome joins to the decision that authorized it. A completion that
    /// could name any entry would let a transcript attribute what happened to a
    /// decision that permitted something else - and it would hash correctly,
    /// because the chain proves entries were not edited, not that they are true.
    #[test]
    fn an_outcome_cannot_be_attributed_to_a_decision_that_did_not_authorize_it() {
        let ledger = ledger();
        let session = session();
        ledger.record_session_opened(&session).unwrap();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);

        // Entry 0 is the session opening, which authorized nothing - named
        // with its own digest, so what refuses it is what kind of entry it is.
        let opening = ledger.entries()[0].digest.clone();
        let err = ledger
            .record_outcome(outcome_naming(&receipt, 0, opening, kept("ok")))
            .expect_err("an outcome attached to a non-decision was accepted");
        assert!(
            matches!(err, AuditError::NotItsDecision { .. }),
            "unexpected error: {err:?}"
        );

        // Nor an entry that does not exist at all.
        let err = ledger
            .record_outcome(outcome_naming(
                &receipt,
                99,
                receipt.digest().clone(),
                kept("ok"),
            ))
            .expect_err("an outcome attached to nothing was accepted");
        assert!(
            matches!(err, AuditError::NoSuchDecision { .. }),
            "unexpected error: {err:?}"
        );

        ledger
            .record_outcome(outcome_for(&receipt, "ok"))
            .expect("the decision that authorized this run is its own");
    }

    /// Positions repeat across records; digests do not. A run authorized
    /// somewhere else must not land on whatever this record holds at the same
    /// number, because the resulting entry would hash correctly while naming a
    /// decision that was about something else.
    #[test]
    fn a_run_authorized_in_another_record_does_not_complete_in_this_one() {
        let session = session();
        let mine = ledger();
        let elsewhere = ledger();
        let here = recorded_run(&mine, &session, &["docker", "ps"]);
        let there = recorded_run(&elsewhere, &session, &["docker", "logs", "web"]);
        assert_eq!(
            here.sequence(),
            there.sequence(),
            "both records start at the same place, which is the point"
        );

        let err = mine
            .record_outcome(outcome_for(&there, "ok"))
            .expect_err("another record's authorization completed here");
        assert!(
            matches!(err, AuditError::NotItsDecision { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// One execution is one completion. A run stays addressable after it
    /// settles and answers with a fresh outcome every time it is asked, so
    /// consuming the outcome is not enough on its own - a record saying one
    /// command finished twice would verify cleanly and be worse than none.
    #[test]
    fn a_run_is_recorded_as_completed_once() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();

        // The same run, asked about again: a second answer, not a second run.
        let err = ledger
            .record_outcome(outcome_for(&receipt, "ok"))
            .expect_err("one execution was recorded as completing twice");
        assert!(
            matches!(err, AuditError::AlreadyCompleted { .. }),
            "unexpected error: {err:?}"
        );
        assert_eq!(ledger.entries().len(), 2, "a second completion was written");
    }

    /// Looking and then writing are two operations. Callers racing to record
    /// the same settled run must not both be told there is no completion yet
    /// and both write one, because the resulting chain verifies while saying
    /// one execution finished more than once.
    #[test]
    fn racing_callers_cannot_both_complete_one_run() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);

        // A barrier, so the callers arrive together rather than one after
        // another: without it the threads finish in turn and the window
        // between looking and writing is never actually contended.
        const CALLERS: usize = 16;
        let ready = std::sync::Barrier::new(CALLERS);
        let wrote = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|threads| {
            for _ in 0..CALLERS {
                threads.spawn(|| {
                    let outcome = outcome_for(&receipt, "ok");
                    ready.wait();
                    if ledger.record_outcome(outcome).is_ok() {
                        wrote.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(
            wrote.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "more than one caller recorded the same run as completed"
        );
        assert_eq!(ledger.entries().len(), 2, "{:?}", ledger.entries());
        assert!(ledger.verify().is_ok());
    }

    /// `Completed` means completed. Writing one for a command still going would
    /// leave the record asserting an ending the command had not reached, and
    /// its real ending unrecorded.
    #[test]
    fn a_command_still_running_has_no_completion_to_record() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        let still_going = Outcome::authorized_by(
            receipt.authorization().clone(),
            RunId::from_raw("r-1"),
            RunState::Running,
            kept("so far"),
        );

        let err = ledger
            .record_outcome(still_going)
            .expect_err("a running command was recorded as completed");
        assert!(
            matches!(err, AuditError::StillRunning { .. }),
            "unexpected error: {err:?}"
        );
        assert_eq!(ledger.entries().len(), 1, "a completion was written anyway");
    }

    /// A completion is attributed from the decision that authorized it, not
    /// from an identity handed in beside it. With several sessions in one
    /// record, what ran still belongs to whoever was permitted to run it.
    #[test]
    fn a_completion_is_attributed_to_the_session_that_was_decided_for() {
        let ledger = ledger();
        let mine = session();
        let theirs = session();
        // Another session's work either side, so a completion attributed by
        // position or by recency would land on the wrong one.
        recorded_run(&ledger, &theirs, &["docker", "ps"]);
        let receipt = recorded_run(&ledger, &mine, &["docker", "ps"]);
        recorded_run(&ledger, &theirs, &["docker", "ps"]);

        let completion = ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();
        assert_eq!(completion.entry.session, mine.id);
        assert_ne!(completion.entry.session, theirs.id);
    }

    /// A held decision cannot be used as a completed run's authorization.
    #[test]
    fn nothing_completes_against_an_unapproved_decision() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();
        assert!(recorded_decision(&ledger, &session, &["docker", "exec", "web", "ls"]).is_none());
        let permitted = ledger
            .record_intent(
                Engine::new(crate::policy::ReviewMode::Disabled)
                    .decide(&session, command(&["docker", "ps"])),
                intent(),
            )
            .unwrap()
            .receipt
            .unwrap();

        let refusal = ledger.entries()[0].digest.clone();
        let err = ledger
            .record_outcome(outcome_naming(&permitted, 0, refusal, kept("ok")))
            .expect_err("a completion was attached to a refusal");
        assert!(
            matches!(err, AuditError::NotItsDecision { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// An agreement is about a command somebody was asked about. Recording one
    /// against a decision that permitted the command outright, or refused it,
    /// would put a human's name against a choice they were never offered.
    #[test]
    fn an_agreement_is_only_recorded_against_a_decision_that_asked_for_one() {
        let ledger = ledger();
        let session = session();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);

        // A command policy permitted outright needs nobody's agreement, and
        // recording one would put a human's name against a choice they were
        // never asked to make.
        let permitted = engine.decide(&session, (command(&["docker", "ps"])).clone());
        let entry = ledger.record_intent(permitted, intent()).unwrap();
        let grant = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            session.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(entry.decision.command(), entry.agent_intent()),
            entry.entry.sequence,
            entry.entry.digest.as_str().to_owned(),
        );
        let err = ledger
            .record_approval(&entry, grant)
            .expect_err("an agreement was recorded about a command nobody was asked about");
        assert!(
            matches!(err, AuditError::NotHeldForApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// A decision that held a command permitted nothing, and mints no receipt.
    /// The agreement is what allows the run, so it is the entry a completion
    /// names — and until somebody agrees there is nothing to name.
    #[test]
    fn a_held_decision_authorizes_nothing_until_somebody_agrees() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();
        let held = recorded_decision(&ledger, &session, &["systemctl", "restart", "nginx"]);
        assert!(
            held.is_none(),
            "a held decision handed back something to run with"
        );
    }

    /// A grant and a decision reach the record separately, so the record checks
    /// they are about the same thing. Otherwise an agreement given for one
    /// command, presented alongside a held decision about another, would mint a
    /// receipt for the other — a human's yes spent on something they never saw.
    #[test]
    fn an_agreement_cannot_be_spent_on_a_command_it_was_not_given_for() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);

        // A decision that was held for a human, about one command.
        let held = engine.decide(
            &session,
            (command(&["systemctl", "restart", "nginx"])).clone(),
        );
        let entry = ledger.record_intent(held, intent()).unwrap();

        // An agreement given for a different one.
        let elsewhere = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            session.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(
                &command(&["systemctl", "restart", "postgres"]),
                entry.agent_intent(),
            ),
            entry.entry.sequence,
            entry.entry.digest.as_str().to_owned(),
        );

        let err = ledger
            .record_approval(&entry, elsewhere)
            .expect_err("an agreement was spent on a command it was not given for");
        assert!(
            matches!(err, AuditError::NotItsApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// Two sessions can be held over the very same command, and their
    /// deliberations differ only in whose they are. An agreement given about
    /// one of them must not mint a receipt against the other: a human agreed
    /// that *this* person may run it, for the purpose they gave, and the record
    /// is what makes that specific.
    #[test]
    fn an_agreement_cannot_be_spent_on_another_sessions_deliberation() {
        let ledger = ledger();
        let mine = session_that_can_be_asked_about();
        let theirs = session_that_can_be_asked_about();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);
        let restart = (command(&["systemctl", "restart", "nginx"])).clone();

        // The same command held for two people. Their deliberation is recorded
        // first, so the agreement about it names a real entry of this record.
        let held_for_them = ledger
            .record_intent(engine.decide(&theirs, restart.clone()), intent())
            .unwrap();
        let held_for_me = ledger
            .record_intent(engine.decide(&mine, restart), intent())
            .unwrap();

        // An agreement about their deliberation, presented alongside mine.
        let theirs_agreed = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            // Their agreement, and so their session: it is the deliberation it
            // names that belongs to somebody else.
            mine.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(
                held_for_them.decision.command(),
                held_for_them.agent_intent(),
            ),
            held_for_them.entry.sequence,
            held_for_them.entry.digest.as_str().to_owned(),
        );

        let err = ledger
            .record_approval(&held_for_me, theirs_agreed)
            .expect_err("one session's agreement was spent on another's deliberation");
        assert!(
            matches!(err, AuditError::NotItsApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// An agreement names the deliberation it answers, and that deliberation
    /// has to be one that asked for a human. A record that will attach a
    /// person's yes to an entry which permitted the command outright is a
    /// record that can be made to say somebody approved something nobody put
    /// to them.
    #[test]
    fn an_agreement_cannot_name_an_entry_that_asked_nobody() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);

        // Two entries of the same session: one policy permitted outright, one
        // it held for a person.
        let permitted = ledger
            .record_intent(
                Engine::new(crate::policy::ReviewMode::Disabled)
                    .decide(&session, command(&["docker", "ps"])),
                intent(),
            )
            .unwrap();
        let held = ledger
            .record_intent(
                engine.decide(
                    &session,
                    (command(&["systemctl", "restart", "nginx"])).clone(),
                ),
                intent(),
            )
            .unwrap();

        // An agreement about the held command, but naming the entry that
        // needed nobody.
        let misnamed = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            session.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(held.decision.command(), held.agent_intent()),
            permitted.entry.sequence,
            permitted.entry.digest.as_str().to_owned(),
        );

        let err = ledger
            .record_approval(&held, misnamed)
            .expect_err("an agreement named a deliberation that asked nobody");
        assert!(
            matches!(err, AuditError::NotHeldForApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// The trail of who answered what is worth what it can be checked against.
    /// An answer naming an entry that never asked for a person would make the
    /// record say somebody decided about a deliberation that never happened.
    #[test]
    fn an_answer_cannot_name_a_deliberation_that_never_asked() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();

        let permitted = ledger
            .record_intent(
                Engine::new(crate::policy::ReviewMode::Disabled)
                    .decide(&session, command(&["docker", "ps"])),
                intent(),
            )
            .unwrap();

        let asked = Asked {
            id: crate::approval::RequestId::from_raw("a-request"),
            session: session.id.clone(),
            principal: session.principal.clone(),
            host: session.host.clone(),
            role: session.role.clone(),
            purpose: session.purpose.clone(),
            access_class: session.access_class,
            command: vec!["systemctl".to_owned(), "restart".to_owned()],
            agent_intent: intent(),
            decided: permitted.entry.sequence,
            decided_digest: permitted.entry.digest.as_str().to_owned(),
            why: "held for a test".to_owned(),
            asked_at: 1_000,
            decide_by: 2_000,
        };

        let err = ledger
            .record_answer(&Answer::answered_for(
                asked,
                Approver::Human {
                    who: "chris".to_owned(),
                },
                false,
            ))
            .expect_err("an answer named a deliberation that never asked for one");
        assert!(
            matches!(err, AuditError::NotHeldForApproval { .. }),
            "unexpected error: {err:?}"
        );
        assert!(
            !ledger
                .entries()
                .iter()
                .any(|entry| matches!(entry.event, Event::Answered { .. })),
            "the record kept an answer it had refused"
        );
    }

    /// Retention removes what a deliberation said, and an agreement has to
    /// stay bound to whose work it was given for after that. The grant says
    /// whose it is, so the check does not depend on the record still holding
    /// the entry's content — otherwise sealing an entry would quietly widen
    /// what an old agreement could be spent on.
    #[test]
    fn an_agreement_stays_bound_to_its_session_after_retention() {
        let ledger = ledger();
        let mine = session_that_can_be_asked_about();
        let theirs = session_that_can_be_asked_about();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);
        let restart = (command(&["systemctl", "restart", "nginx"])).clone();

        let held_for_them = ledger
            .record_intent(engine.decide(&theirs, restart.clone()), intent())
            .unwrap();
        let held_for_me = ledger
            .record_intent(engine.decide(&mine, restart), intent())
            .unwrap();

        // Their deliberation is retired, keeping only its digest.
        ledger.seal_before(held_for_me.entry.sequence);

        let theirs_agreed = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            theirs.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(
                held_for_them.decision.command(),
                held_for_them.agent_intent(),
            ),
            held_for_them.entry.sequence,
            held_for_them.entry.digest.as_str().to_owned(),
        );

        let err = ledger
            .record_approval(&held_for_me, theirs_agreed)
            .expect_err("a sealed deliberation let one session's agreement answer another's");
        assert!(
            matches!(err, AuditError::NotItsApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// A grant names the deliberation it answers by sequence and by digest.
    /// Sequence alone names a position, and positions repeat between records,
    /// so an agreement pointing at a position that now holds something else is
    /// not an agreement about what is there.
    #[test]
    fn an_agreement_naming_the_wrong_entry_is_refused() {
        let ledger = ledger();
        let session = session_that_can_be_asked_about();

        let engine = Engine::new(crate::policy::ReviewMode::Privileged);

        let held = ledger
            .record_intent(
                engine.decide(
                    &session,
                    (command(&["systemctl", "restart", "nginx"])).clone(),
                ),
                intent(),
            )
            .unwrap();

        let misnamed = Grant::granted_for(
            crate::approval::RequestId::from_raw("a-request"),
            session.id.clone(),
            Approver::Human {
                who: "chris".to_owned(),
            },
            crate::approval::digest_of(held.decision.command(), held.agent_intent()),
            held.entry.sequence,
            "not the digest of that entry".to_owned(),
        );

        let err = ledger
            .record_approval(&held, misnamed)
            .expect_err("an agreement named an entry it does not describe");
        assert!(
            matches!(err, AuditError::NotItsApproval { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// A command outliving the retention of its own decision is the case that
    /// makes retention and attribution pull against each other. It resolves
    /// because the authorization carries who it was for: the sealed entry still
    /// has its digest, which is enough to prove it was that decision, and
    /// nothing has to read back what the decision said.
    #[test]
    fn a_completion_still_lands_after_its_decision_is_retired() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        let slow = outcome_for(&receipt, "eventually");

        ledger.seal_before(99);
        assert!(ledger.entries().is_empty(), "the decision should be sealed");

        let completion = ledger
            .record_outcome(slow)
            .expect("a run outlived the retention of its decision");
        assert_eq!(completion.entry.session, session.id);
        assert!(ledger.verify().is_ok());
    }

    /// The digest identifies the entry, and that survives sealing. Another
    /// record's authorization is refused here whether or not this record has
    /// been retired, so retention does not turn sealed entries into somewhere
    /// anything can be attached.
    #[test]
    fn a_retired_record_still_refuses_another_records_authorization() {
        let session = session();
        let mine = ledger();
        let elsewhere = ledger();
        let here = recorded_run(&mine, &session, &["docker", "ps"]);
        let there = recorded_run(&elsewhere, &session, &["docker", "ps"]);
        assert_eq!(here.sequence(), there.sequence());

        mine.seal_before(99);
        assert!(mine.entries().is_empty(), "the decision should be sealed");

        let err = mine
            .record_outcome(outcome_for(&there, "ok"))
            .expect_err("a sealed entry accounted for another record's run");
        assert!(
            matches!(err, AuditError::NotItsDecision { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// Two adjacent sealed entries can be changed together - one's digest and
    /// the next one's link to it - leaving every later entry and the head still
    /// agreeing. What contradicts that is the digest each entry was written
    /// with, kept where retention does not reach.
    #[test]
    fn coordinated_alteration_of_sealed_entries_is_detected() {
        let ledger = ledger();
        let session = session();
        for _ in 0..4 {
            let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
            ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();
        }
        ledger.seal_before(4);
        assert!(ledger.verify().is_ok());

        // Reach past the API, as anyone rewriting retained records would, and
        // keep the chain self-consistent while doing it.
        {
            let mut entries = ledger.entries.lock().unwrap();
            let forged = Digest("f".repeat(64));
            if let Held::Sealed { digest, .. } = &mut entries[1] {
                *digest = forged.clone();
            }
            if let Held::Sealed { previous, .. } = &mut entries[2] {
                *previous = forged;
            }
        }

        assert_eq!(
            ledger.verify(),
            Err(Broken::ContentAltered { at: 1 }),
            "a rewritten sealed entry passed verification"
        );
    }

    /// One record can be fed by more than one run store. An identifier that
    /// numbered runs within a store would have the second store's first run
    /// taken for a repeat of the first store's, and a real command's outcome
    /// would go unrecorded.
    #[test]
    fn two_run_stores_feeding_one_record_do_not_collide() {
        let ledger = ledger();
        let session = session();
        let here = recorded_run(&ledger, &session, &["docker", "ps"]);
        let there = recorded_run(&ledger, &session, &["docker", "logs", "web"]);

        let first = Runs::new(Limits::default());
        let second = Runs::new(Limits::default());
        let one = outcome_from(&first, &here, "ok");
        let two = outcome_from(&second, &there, "ok");
        assert_ne!(one.run(), two.run(), "two stores minted one identifier");

        ledger.record_outcome(one).unwrap();
        ledger
            .record_outcome(two)
            .expect("a second store's first run was taken for a repeat");
    }

    /// Retention must not erase the fact that a run was already accounted for.
    /// A settled run answers with a fresh outcome every time it is asked, so a
    /// record that forgot its completions along with their entries would accept
    /// a second one and verify cleanly while saying a command finished twice.
    #[test]
    fn retention_does_not_reopen_a_run_that_was_already_completed() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();

        ledger.seal_before(99);
        assert!(ledger.entries().is_empty(), "everything should be sealed");

        let err = ledger
            .record_outcome(outcome_for(&receipt, "ok"))
            .expect_err("retention reopened a run that had already completed");
        assert!(
            matches!(err, AuditError::AlreadyCompleted { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// A decision records its command and configured account context.
    #[test]
    fn a_decision_records_the_facts_behind_it() {
        let ledger = ledger();
        let session = session();
        recorded_run(&ledger, &session, &["docker", "ps"]);

        let Event::Decided {
            argv,
            purpose,
            access_class,
            ..
        } = &ledger.entries()[0].event
        else {
            panic!("expected a decision");
        };
        assert_eq!(argv, &["docker", "ps"]);
        assert_eq!(purpose, session.purpose.as_str());
        assert_eq!(*access_class, session.access_class);
    }

    /// What happened joins to what was decided. Reading a transcript by
    /// guessing from timing is not reading a transcript.
    #[test]
    fn an_outcome_names_the_decision_that_authorized_it() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();

        let Event::Completed { decided, .. } = &ledger.entries()[1].event else {
            panic!("expected a completion");
        };
        assert_eq!(*decided, receipt.sequence());
    }

    /// A chain cannot notice its own missing tail: cut the last entry off and
    /// every remaining link is still correct. What catches it is the record
    /// knowing what it wrote.
    #[test]
    fn removing_the_last_entry_is_detected() {
        let ledger = ledger();
        let session = session();
        ledger.record_session_opened(&session).unwrap();
        recorded_run(&ledger, &session, &["docker", "ps"]);
        assert!(ledger.verify().is_ok());

        // Reach past the API, as anyone dropping records would.
        {
            let mut entries = ledger.entries.lock().unwrap();
            entries.pop();
        }
        assert!(
            matches!(ledger.verify(), Err(Broken::EntriesMissing { .. })),
            "a truncated record verified as whole"
        );
    }

    /// A stream that was cut short says so. A record that is quietly short
    /// reads as complete, which is worse than one that is obviously partial.
    #[test]
    fn a_bounded_stream_is_recorded_as_bounded() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        let bounded = outcome_naming(
            &receipt,
            receipt.sequence(),
            receipt.digest().clone(),
            Stream {
                text: "the part that was kept".to_owned(),
                truncated: true,
                bytes: 100_000,
                matched: None,
            },
        );
        ledger.record_outcome(bounded).unwrap();

        let Event::Completed { stdout, .. } = &ledger.entries()[1].event else {
            panic!("expected a completion");
        };
        let Recorded::Kept {
            truncated, bytes, ..
        } = stdout
        else {
            panic!("expected kept output: {stdout:?}");
        };
        assert!(truncated, "the record does not say it is short");
        assert_eq!(*bytes, 100_000);
    }

    /// Altering a written entry has to be detectable, which is the entire point
    /// of the chain.
    #[test]
    fn an_altered_entry_breaks_verification() {
        let ledger = ledger();
        let session = session();
        ledger.record_session_opened(&session).unwrap();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();
        assert!(ledger.verify().is_ok());

        // Reach past the API, as anyone tampering with stored records would.
        {
            let mut entries = ledger.entries.lock().unwrap();
            if let Held::Intact(entry) = &mut entries[1] {
                Arc::make_mut(entry).event = Event::SessionClosed;
            }
        }
        assert_eq!(ledger.verify(), Err(Broken::ContentAltered { at: 1 }));
    }

    /// Removing an entry outright breaks every link after it, which is why
    /// retention seals instead.
    #[test]
    fn removing_an_entry_outright_breaks_the_chain() {
        let ledger = ledger();
        let session = session();
        for _ in 0..3 {
            recorded_run(&ledger, &session, &["docker", "ps"]);
        }
        {
            let mut entries = ledger.entries.lock().unwrap();
            entries.remove(1);
        }
        assert!(
            ledger.verify().is_err(),
            "a deleted entry should be detectable"
        );
    }

    /// Retention destroys the only evidence an entry was altered, so it must
    /// not run on an entry that has been. Sealing one would copy the digest of
    /// the entry it used to be and discard the content that contradicts it,
    /// turning an alteration into a chain that verifies clean.
    #[test]
    fn retention_does_not_seal_over_an_alteration() {
        let ledger = ledger();
        let session = session();
        for _ in 0..3 {
            recorded_run(&ledger, &session, &["docker", "ps"]);
        }
        {
            let mut entries = ledger.entries.lock().unwrap();
            if let Held::Intact(entry) = &mut entries[0] {
                Arc::make_mut(entry).event = Event::SessionClosed;
            }
        }

        ledger.seal_before(3);

        assert_eq!(
            ledger.verify(),
            Err(Broken::ContentAltered { at: 0 }),
            "retention laundered an altered entry into a verifying chain"
        );
    }

    /// The constraint that shapes this design: retention has to be possible
    /// *and* the chain has to keep verifying. Sealing keeps the links and drops
    /// the content, and verification says how much can no longer be read rather
    /// than passing silently over the gap.
    #[test]
    fn the_chain_still_verifies_after_retention_removes_content() {
        let ledger = ledger();
        let session = session();
        // Finished work: retention retires what has been accounted for.
        for _ in 0..2 {
            let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
            ledger.record_outcome(outcome_for(&receipt, "ok")).unwrap();
        }
        ledger.record_session_closed(&session).unwrap();
        assert_eq!(ledger.verify().unwrap().sealed, 0);

        ledger.seal_before(3);

        let verified = ledger.verify().expect("the chain should still verify");
        assert_eq!(verified.entries, 5);
        assert_eq!(verified.sealed, 3, "verification should admit what it lost");
        assert_eq!(
            ledger.entries().len(),
            2,
            "sealed entries are no longer readable"
        );
    }

    /// Secret-shaped output is withheld and *said* to be withheld. A record
    /// that dropped it silently would be untrustworthy; one that stored it
    /// would put credential material in the log store.
    #[test]
    fn secret_shaped_output_is_withheld_and_the_record_says_so() {
        let ledger = ledger();
        let session = session();
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE\n";
        let recorded = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.record_outcome(outcome_for(&recorded, key)).unwrap();

        // The decision comes first, then what it did.
        let entry = &ledger.entries()[1];
        let Event::Completed { stdout, .. } = &entry.event else {
            panic!("expected a completion");
        };
        let Recorded::Withheld { bytes, matched } = stdout else {
            panic!("credential material was stored: {stdout:?}");
        };
        assert_eq!(
            *bytes,
            key.len() as u64,
            "the record should say how much was held"
        );
        assert!(!matched.is_empty());

        let rendered = serde_json::to_string(entry).unwrap();
        assert!(
            !rendered.contains("BEGIN OPENSSH"),
            "the serialized record contains the key: {rendered}"
        );
    }

    /// Ordinary output is kept. Withholding everything would be safe and
    /// useless.
    #[test]
    fn ordinary_output_is_kept() {
        let ledger = ledger();
        let session = session();
        let recorded = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger
            .record_outcome(outcome_for(
                &recorded,
                "CONTAINER ID   IMAGE\nabc123  traefik",
            ))
            .unwrap();

        let Event::Completed { stdout, .. } = &ledger.entries()[1].event else {
            panic!("expected a completion");
        };
        assert!(matches!(stdout, Recorded::Kept { .. }), "got {stdout:?}");
    }

    #[test]
    fn evaluation_input_is_closed_and_bounded() {
        let with_extra = serde_json::json!({
            "evaluation_id": "eval-1",
            "decision_digest": "a".repeat(64),
            "model": "example-model",
            "prompt_version": "intent-review-v1",
            "verdict": "uncertain",
            "confidence": 50,
            "rationale": "The command has too little context.",
            "side_effects": [],
            "authorization": "permit"
        });
        assert!(serde_json::from_value::<EvaluationDraft>(with_extra).is_err());
        let too_confident = EvaluationDraft {
            evaluation_id: "eval-1".to_owned(),
            decision_digest: "a".repeat(64),
            model: "example-model".to_owned(),
            prompt_version: "intent-review-v1".to_owned(),
            verdict: EvaluationVerdict::Uncertain,
            confidence: 101,
            rationale: "The command has too little context.".to_owned(),
            side_effects: Vec::new(),
        };
        assert_eq!(
            EvaluationArtifact::from_draft(too_confident, "reviewer".to_owned()),
            Err(EvaluationError::InvalidConfidence)
        );
    }

    #[test]
    fn evaluations_are_immutable_idempotent_and_bound_to_a_decision_digest() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        let draft = |id: &str, digest: String, rationale: &str| EvaluationDraft {
            evaluation_id: id.to_owned(),
            decision_digest: digest,
            model: "example-model".to_owned(),
            prompt_version: "intent-review-v1".to_owned(),
            verdict: EvaluationVerdict::SupportsIntent,
            confidence: 91,
            rationale: rationale.to_owned(),
            side_effects: vec!["Reads Docker process metadata".to_owned()],
        };
        let artifact = EvaluationArtifact::from_draft(
            draft(
                "eval-1",
                receipt.digest().as_str().to_owned(),
                "The command lists containers.",
            ),
            "intent-reviewer".to_owned(),
        )
        .unwrap();
        let recorded = ledger.record_evaluation(artifact.clone()).unwrap();
        assert_eq!(recorded.session, session.id);
        let Event::Evaluated {
            decided,
            argv,
            agent_intent,
            purpose,
            access_class,
            ..
        } = &recorded.event
        else {
            panic!("expected an evaluated entry");
        };
        assert_eq!(*decided, receipt.sequence());
        assert_eq!(argv, &["docker", "ps"]);
        assert_eq!(agent_intent, "exercise the recorded command");
        assert_eq!(purpose, "find out why the deploy did not take effect");
        assert_eq!(*access_class, AccessClass::ReadOnly);
        assert_eq!(ledger.verify().unwrap().entries, 2);

        let retried = ledger.record_evaluation(artifact.clone()).unwrap();
        assert_eq!(retried.sequence, recorded.sequence);
        assert_eq!(
            ledger.entries().len(),
            2,
            "a retry duplicated immutable evidence"
        );

        let conflicting = EvaluationArtifact::from_draft(
            draft(
                "eval-1",
                receipt.digest().as_str().to_owned(),
                "A changed claim.",
            ),
            "intent-reviewer".to_owned(),
        )
        .unwrap();
        assert_eq!(
            ledger.record_evaluation(conflicting),
            Err(AuditError::EvaluationConflict {
                id: "eval-1".to_owned()
            })
        );

        let second_for_decision = EvaluationArtifact::from_draft(
            draft(
                "eval-2",
                receipt.digest().as_str().to_owned(),
                "A second assessment of the same decision.",
            ),
            "intent-reviewer".to_owned(),
        )
        .unwrap();
        assert_eq!(
            ledger.record_evaluation(second_for_decision),
            Err(AuditError::DecisionAlreadyEvaluated {
                digest: receipt.digest().as_str().to_owned()
            }),
            "one decision accepted append-amplified evaluation evidence"
        );

        let unknown = EvaluationArtifact::from_draft(
            draft("eval-3", "0".repeat(64), "This names no local decision."),
            "intent-reviewer".to_owned(),
        )
        .unwrap();
        assert_eq!(
            ledger.record_evaluation(unknown),
            Err(AuditError::EvaluationDecisionUnknown {
                digest: "0".repeat(64)
            })
        );

        ledger.seal_before(u64::MAX);
        let after_retention = EvaluationArtifact::from_draft(
            draft(
                "eval-4",
                receipt.digest().as_str().to_owned(),
                "Retention must not reopen the decision.",
            ),
            "intent-reviewer".to_owned(),
        )
        .unwrap();
        assert_eq!(
            ledger.record_evaluation(after_retention),
            Err(AuditError::DecisionAlreadyEvaluated {
                digest: receipt.digest().as_str().to_owned()
            }),
            "retention made an evaluated decision appendable again"
        );
        assert_eq!(
            ledger.record_evaluation(artifact),
            Err(AuditError::EvaluationConflict {
                id: "eval-1".to_owned()
            }),
            "retention made an issued evaluation id reusable"
        );
    }

    #[test]
    fn a_sealed_unevaluated_decision_is_not_available_to_the_evaluator() {
        let ledger = ledger();
        let session = session();
        let receipt = recorded_run(&ledger, &session, &["docker", "ps"]);
        ledger.seal_before(u64::MAX);
        let artifact = EvaluationArtifact::from_draft(
            EvaluationDraft {
                evaluation_id: "eval-after-retention".to_owned(),
                decision_digest: receipt.digest().as_str().to_owned(),
                model: "example-model".to_owned(),
                prompt_version: "intent-review-v1".to_owned(),
                verdict: EvaluationVerdict::SupportsIntent,
                confidence: 91,
                rationale: "The command lists containers.".to_owned(),
                side_effects: vec!["Reads Docker process metadata".to_owned()],
            },
            "intent-reviewer".to_owned(),
        )
        .unwrap();

        assert_eq!(
            ledger.record_evaluation(artifact),
            Err(AuditError::EvaluationDecisionUnknown {
                digest: receipt.digest().as_str().to_owned()
            }),
            "retention left a sealed decision available through the lookup index"
        );
    }

    #[test]
    fn recent_entries_are_newest_first_bounded_and_shared() {
        let ledger = ledger();
        let session = session();
        ledger.record_session_opened(&session).unwrap();
        ledger.record_session_closed(&session).unwrap();
        ledger.record_session_opened(&session).unwrap();

        let recent = ledger.recent_entries(2);
        assert_eq!(
            recent
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        let again = ledger.recent_entries(1);
        assert!(
            Arc::ptr_eq(&recent[0], &again[0]),
            "the read window copied an entry instead of sharing its storage"
        );
        assert_eq!(ledger.verify_recent(2).unwrap().entries, 2);

        ledger.seal_before(2);
        assert_eq!(ledger.recent_entries(10)[0].sequence, 2);
        assert_eq!(ledger.recent_entries(10).len(), 1);
    }

    #[test]
    fn an_empty_record_verifies() {
        assert_eq!(ledger().verify().unwrap().entries, 0);
    }
}
