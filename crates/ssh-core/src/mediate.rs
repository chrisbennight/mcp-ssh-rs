//! Audited SSH execution bound to a caller and configured account.
//! Effects require a recorded decision and, when configured, a valid human approval.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::approval::{
    AgreementId, Answer, ApprovalError, Approvals, Approver, Ask, Asked, RequestId, Standing,
    StandingApproval, StandingCoverage, Windows,
};
use crate::audit::{
    Accounted, AuditError, Authorization, Broken, Entry, EvaluationArtifact, Ledger, Receipt,
    Records, Verified,
};
use crate::clock::{Clock, Millis};
use crate::command::{Command, CommandError, CommandIntent};
use crate::connect::{ConnectError, Connection, Connector, CredentialSource};
use crate::policy::{Decision, Engine, PolicyError, Verdict};
use crate::registry::{Registry, ResolveError};
use crate::run::{Limits, Outcome, RunError, RunId, RunState, Runs, Settled};
use crate::session::{
    Lifetime, Purpose, Session, SessionError, SessionId, SessionSnapshot, SessionStore,
    TooManySessions,
};
use crate::{AccessClass, HostId, PrincipalId, RoleId};

/// What came of asking to run a command.
///
/// Every variant is an answer. Only [`Executed::Ran`] means the target did
/// anything; the rest say why it did not, and which of them it is decides what
/// a caller should do next.
///
/// Not `Clone`: it carries the decision that authorized the work and, where
/// something ran, the report of what the target did. Both are things exactly
/// one of should exist, and a copy of either is a second claim about one event.
#[derive(Debug)]
pub enum Executed {
    /// Permitted, and here is what happened.
    Ran {
        decision: Decision,
        outcome: Box<Outcome>,
        /// Who agreed, when a human's agreement is what allowed this.
        ///
        /// The approver rather than the grant: the grant was spent recording
        /// the agreement, and what is worth carrying afterwards is who said
        /// yes, not something that could be presented again.
        approved_by: Option<Approver>,
    },
    /// Permitted only with a human's agreement, which nobody has given yet.
    ///
    /// The command has **not** run. It is recorded as decided, so the wait is
    /// itself accounted for, and `asked` names the request a human will answer.
    /// What was decided about — the command and the facts behind it — travels
    /// inside the decision.
    ///
    /// Asking again after they answer is how the agent finds out: it is handed
    /// nothing to keep, and nothing it could present instead of asking.
    AwaitingApproval { decision: Decision, asked: Box<Ask> },
    /// A person agreed, and the agreement expired before anything collected it.
    ///
    /// The command has **not** run. `asked` names the fresh request now waiting
    /// in its place, so collecting an answer stays the act it always was: send
    /// the command again.
    ///
    /// Separate from `AwaitingApproval` so the difference can be said out loud.
    /// Asking again in silence leaves whoever agreed believing the work was
    /// done, and gives the agent nothing to tell them.
    ApprovalLapsed {
        decision: Decision,
        asked: Box<Ask>,
        /// Who agreed, before the agreement went uncollected.
        lapsed_from: Approver,
    },
    /// Not permitted. The command has not run and will not.
    ///
    /// `refused_by` names a person when the refusal is theirs rather than
    /// policy's. Both mean the same thing to a caller — do not send it again —
    /// but not to whoever reads the answer afterwards.
    Refused {
        decision: Decision,
        refused_by: Option<Approver>,
    },
}

/// What the service will not exceed.
///
/// Gathered rather than passed one by one, because they are one decision: how
/// much a deployment is willing to let a caller consume. Scattering them across
/// a constructor's arguments makes it easy to set one and forget the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// How long a session lives, and how long a lapsed one is remembered.
    pub lifetime: Lifetime,
    /// Most live sessions one principal may hold at once.
    pub sessions_per_principal: usize,
    /// What a single execution may consume.
    pub run: Limits,
    /// How long a held request waits for a human, and how long their agreement
    /// then lasts.
    pub approval: Windows,
    /// Most commands one session may have waiting on a human at once.
    pub waiting_per_session: usize,
}

impl Bounds {
    /// The longest a standing session agreement can answer for, whatever a
    /// grantor asks: the session's own maximum lifetime, because the session
    /// is what the agreement is about and nothing about it outlives it.
    const fn standing_cap(&self) -> Millis {
        self.lifetime.max
    }
}

/// Writes a command's completion the moment it finishes.
///
/// Holds only the record, never the run store, so nothing here can keep alive
/// the thing that is telling it. Releasing a finished run is a separate
/// question with a separate answer, and this deliberately does not touch it.
struct WritesCompletions<C: Clock> {
    ledger: Arc<Ledger<Arc<C>>>,
}

impl<C: Clock + 'static> Settled for WritesCompletions<C> {
    fn settled(&self, outcome: Outcome) {
        // An outcome already written is not a failure: this is the earliest
        // anyone could have written it, and every other path that reaches this
        // run tries again and is told it is already there.
        //
        // Anything else is. The run is what the record will not be able to
        // account for, so it is named — silence here is how a completion goes
        // missing without anybody being able to say which one.
        let run = outcome.run().as_str().to_owned();
        match self.ledger.record_outcome(outcome) {
            Ok(_) | Err(AuditError::AlreadyCompleted { .. }) => {}
            Err(why) => {
                tracing::error!(
                    %why,
                    run = %run,
                    "a command finished and its completion could not be recorded"
                );
            }
        }
    }
}

/// The connection a session is currently using, and the right to replace it.
///
/// Two locks rather than one, because they answer different questions. The map
/// says which session owns a connection at all; this says who may swap the one
/// inside. The inner lock is held only while dialling a replacement and never
/// while a command runs, so commands in one session stay concurrent while two
/// that both find the transport gone do not each dial their own.
///
/// The outer `Arc` is what lets the map lock be released before awaiting on the
/// inner one, which a caller must do: the map lock is a `std` lock and cannot
/// be held across an await.
type SessionConnection = Arc<tokio::sync::Mutex<Arc<Connection>>>;

/// The mediated service.
pub struct Bastion<C: Clock, S: CredentialSource> {
    clock: Arc<C>,
    sessions: SessionStore<Arc<C>>,
    approvals: Approvals<Arc<C>>,
    ledger: Arc<Ledger<Arc<C>>>,
    engine: Engine,
    registry: Registry,
    connector: Connector<S>,
    runs: Runs,
    /// One connection per session, held for its life — see
    /// [`SessionConnection`] for why the connection itself sits behind a
    /// second lock rather than in this map directly.
    ///
    /// A caller takes a handle and releases this lock before awaiting on it.
    /// Holding it across an await would serialise every session behind
    /// whichever command is currently running.
    connections: Mutex<HashMap<String, SessionConnection>>,
    /// The longest a standing session agreement can answer for.
    standing_cap: Millis,
    /// Set once the service is stopping, and never unset.
    ///
    /// A process on its way out waits for what is running to be recorded, and
    /// that wait means nothing if work can still start behind it. Stopping the
    /// listener is not enough: requests already accepted are still being
    /// handled, and one of them can reach here. So the refusal is here, where
    /// starting a command actually happens.
    stopping: AtomicBool,
    /// Held while a session and its connection are published together, and
    /// while they are reconciled against each other.
    ///
    /// The two are separate maps, so a reconciliation that reads one and then
    /// the other can see a session opened in between as a connection belonging
    /// to nobody, and close a connection that is in use. Nothing is awaited
    /// under this, so it serialises only the moment of publishing.
    publishing: Mutex<()>,
}

impl<C: Clock + 'static, S: CredentialSource> Bastion<C, S> {
    pub fn new(
        clock: Arc<C>,
        registry: Registry,
        engine: Engine,
        connector: S,
        bounds: Bounds,
    ) -> Self {
        Self::recording_to(clock, registry, engine, connector, bounds, None)
    }

    /// A service whose record also hands every entry to something that
    /// outlives the process.
    ///
    pub fn recording_to(
        clock: Arc<C>,
        registry: Registry,
        engine: Engine,
        connector: S,
        bounds: Bounds,
        records_to: Option<Arc<dyn Records>>,
    ) -> Self {
        // Built before the run store, which is told about it: a command that
        // finishes must get its entry then, rather than when something later
        // happens to look. An idle service is exactly when nothing looks.
        let ledger = Arc::new(match records_to {
            Some(records_to) => Ledger::recording_to(Arc::clone(&clock), records_to),
            None => Ledger::new(Arc::clone(&clock)),
        });
        Self {
            standing_cap: bounds.standing_cap(),
            sessions: SessionStore::new(
                Arc::clone(&clock),
                bounds.lifetime,
                bounds.sessions_per_principal,
            ),
            approvals: Approvals::new(
                Arc::clone(&clock),
                bounds.approval,
                bounds.waiting_per_session,
            ),
            ledger: Arc::clone(&ledger),
            engine,
            registry,
            connector: Connector::new(connector, crate::connect::Timeouts::default()),
            runs: Runs::watched(
                bounds.run,
                Some(Arc::new(WritesCompletions {
                    ledger: Arc::clone(&ledger),
                })),
            ),
            connections: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
            publishing: Mutex::new(()),
            clock,
        }
    }

    /// Opens a session and the connection it will use.
    ///
    /// The connection is established here rather than at the first command, so
    /// that a host that cannot be reached or cannot be verified fails while the
    /// caller is still asking for access, rather than in the middle of work it
    /// thought was authorized.
    pub async fn open_session(
        &self,
        principal: PrincipalId,
        host: HostId,
        role: RoleId,
        purpose: Purpose,
        access_class: AccessClass,
    ) -> Result<Session, MediationError> {
        self.check_account(&host, &role, access_class)?;
        let target = self.registry.resolve(&host, &role)?;
        // The target carries the host and role it was resolved for, so the
        // connection is labelled by the lookup that produced its address and
        // credential rather than by anything passed alongside.
        let connection = self.connector.connect(&target).await?;

        let session = {
            // The session and its connection become visible together, so a
            // reconciliation cannot catch the session existing without its
            // connection or the other way round.
            let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
            let session = self
                .sessions
                .open(principal, host, role, purpose, access_class)?;
            self.connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    session.id.as_str().to_owned(),
                    Arc::new(tokio::sync::Mutex::new(Arc::new(connection))),
                );
            session
        };
        self.ledger.record_session_opened(&session)?;

        // After the store has changed, not before: opening can itself evict a
        // lapsed session to make room, and reconciling first would leave what
        // this very call displaced. Opening is when the service grows, so it is
        // where it also lets go.
        self.reclaim().await;
        Ok(session)
    }

    /// Validates the caller's account label against administrator configuration.
    pub fn check_account(
        &self,
        host: &HostId,
        role: &RoleId,
        access_class: crate::AccessClass,
    ) -> Result<(), MediationError> {
        if self.registry.resolve(host, role)?.access_class() != access_class {
            return Err(MediationError::AccountMismatch);
        }
        Ok(())
    }

    /// Account selection is immutable for a session, including across reconnects.
    pub fn check_session_account(
        &self,
        principal: &PrincipalId,
        session: &SessionId,
        host: &HostId,
        role: &RoleId,
        access_class: crate::AccessClass,
    ) -> Result<(), MediationError> {
        self.sessions
            .check_binding(session, principal, host, role)?;
        self.check_account(host, role, access_class)
    }

    /// Test-only shorthand for execution-path tests whose subject is not
    /// caller-supplied intent. Production callers cannot omit it.
    #[cfg(test)]
    async fn exec(
        &self,
        principal: &PrincipalId,
        session: &SessionId,
        argv: Vec<String>,
    ) -> Result<Executed, MediationError> {
        let intent = match CommandIntent::parse("exercise the execution path") {
            Ok(intent) => intent,
            Err(_) => unreachable!("the fixed test intent is valid"),
        };
        self.exec_intended(principal, session, intent, argv).await
    }

    /// Runs a command in a session, if it is allowed to.
    pub async fn exec_intended(
        &self,
        principal: &PrincipalId,
        session: &SessionId,
        agent_intent: CommandIntent,
        argv: Vec<String>,
    ) -> Result<Executed, MediationError> {
        // Nothing new once the service is stopping. Refusing here rather than
        // at the door is what makes "no command starts after the wait begins"
        // true: a request accepted before the stop is still being handled, and
        // this is where it would otherwise start work nobody will be around to
        // record.
        if self.stopping.load(Ordering::SeqCst) {
            return Err(MediationError::Stopping);
        }
        // Ownership first. Everything after this point acts on behalf of the
        // principal, and doing any of it before the claim is checked would let
        // one caller drive work against another's session.
        let session = self.sessions.use_session(session, principal)?;

        let command = Command::new(argv)?;
        // The decision carries both of its inputs from here on, so nothing
        // downstream can pair this verdict with another command or session.
        let decision = self.engine.decide(&session, command.clone());

        // Recorded before the branch below, so a refusal and a command awaiting
        // approval are as accountable as one that ran. What was attempted is
        // usually the more interesting half of an incident.
        //
        // Recording consumes the decision and hands it back: one answer from
        // the decision point is one recorded intent and at most one receipt,
        // and this still has to answer with what was decided.
        let intended = self.ledger.record_intent(decision, agent_intent)?;

        match intended.decision().verdict() {
            Verdict::Deny => {
                let (decision, _) = intended.into_parts();
                Ok(Executed::Refused {
                    decision,
                    refused_by: None,
                })
            }
            Verdict::NeedsApproval => {
                // Asking and collecting an answer are the same act: an agent
                // retries the command, and the retry either goes through, still
                // waits, or is answered by a refusal. So it is one question to
                // the store, answered under one hold — asked separately, an
                // answer arriving in between belongs to neither and the retry
                // queues a second request for a command already decided.
                //
                // The agreement is found by the command rather than by an
                // identifier, so an agent that kept nothing can still collect
                // its answer, and one that kept something has nothing it can
                // present instead of asking. A command somebody has already
                // refused is answered with that refusal rather than put in
                // front of them again.
                //
                // The whole recorded deliberation goes to the store, rather
                // than the parts of it a request needs: a request that names
                // its own deliberation is the thing an agreement is later
                // checked against, and picking the parts out here is how they
                // could come to name something else.
                let standing = self.approvals.ask(&intended)?;
                // Taken before the match so that waiting and lapsing can share
                // one arm: what they have in common is a request in front of a
                // person, and only the words differ at the end of it.
                let lapsed_from = match &standing {
                    Standing::Lapsed { by, .. } => Some(by.clone()),
                    _ => None,
                };
                match standing {
                    Standing::Ready(grant) => {
                        // The agreement is written before anything runs, and it
                        // is what authorizes the run: the decision held the
                        // command and minted no receipt, so this entry is the
                        // one that allowed it. Same ordering as every other
                        // execution — recorded first, and running needs the
                        // receipt.
                        let (receipt, approver) = self.ledger.record_approval(&intended, *grant)?;
                        let outcome = self.run_it(&session, receipt).await?;
                        let (decision, _) = intended.into_parts();
                        Ok(Executed::Ran {
                            decision,
                            outcome: Box::new(self.account_for(outcome)?),
                            approved_by: Some(approver),
                        })
                    }
                    // Both leave a request in front of a person, so both are
                    // answerable by a standing agreement. They differ only in
                    // what the caller is told when no such agreement exists,
                    // and splitting the paths is how a lapsed agreement would
                    // come to bypass one.
                    Standing::Waiting(asked) | Standing::Lapsed { asked, .. } => {
                        // A standing agreement for the session answers in the
                        // operator's name, through the same acts a click
                        // performs: the answer is applied and recorded, and
                        // the agreement redeemed for this exact command,
                        // single-use like every other. What stands is who
                        // answers; nothing skips the record.
                        let request = asked.asked().id.clone();
                        let grant = self.approvals.use_standing(
                            &session.id,
                            |standing| -> Result<_, MediationError> {
                                // Keep selection, recording, and redemption
                                // serialized with withdrawal. Once this
                                // returns a grant, the standing agreement has
                                // already answered this exact command; a
                                // withdrawal can only govern later requests.
                                self.apply_answer(&request, standing, true)?;
                                Ok(self.approvals.redeem(
                                    &request,
                                    principal,
                                    &command,
                                    intended.agent_intent(),
                                )?)
                            },
                        );
                        if let Some(grant) = grant {
                            let grant = grant?;
                            let (receipt, approver) =
                                self.ledger.record_approval(&intended, grant)?;
                            let outcome = self.run_it(&session, receipt).await?;
                            let (decision, _) = intended.into_parts();
                            return Ok(Executed::Ran {
                                decision,
                                outcome: Box::new(self.account_for(outcome)?),
                                approved_by: Some(approver),
                            });
                        }
                        let (decision, _) = intended.into_parts();
                        // Nothing runs on a lapsed agreement: the window it was
                        // redeemable in is what it meant, and outliving that is
                        // the same as never having been given. All that is new
                        // is that the caller is told so.
                        match lapsed_from {
                            Some(by) => Ok(Executed::ApprovalLapsed {
                                decision,
                                asked,
                                lapsed_from: by,
                            }),
                            None => Ok(Executed::AwaitingApproval { decision, asked }),
                        }
                    }
                    Standing::Refused { by } => {
                        let (decision, _) = intended.into_parts();
                        Ok(Executed::Refused {
                            decision,
                            refused_by: Some(by),
                        })
                    }
                }
            }
            Verdict::Permit => {
                // A permit always carries a receipt, and the type says so:
                // there is no path from `Verdict::Permit` to a missing one.
                let (decision, receipt) = intended.into_parts();
                let receipt = receipt.ok_or(MediationError::NoReceipt)?;
                let outcome = self.run_it(&session, receipt).await?;
                Ok(Executed::Ran {
                    decision,
                    outcome: Box::new(self.account_for(outcome)?),
                    approved_by: None,
                })
            }
        }
    }

    /// Runs an authorized command on its session's connection.
    ///
    /// The handle is taken and the lock released before running. Holding it
    /// across the await would serialise every session behind whichever command
    /// happens to be running.
    ///
    /// Reached from both branches that run something, so a command a human
    /// agreed to goes down the same path as one policy permitted outright:
    /// approval decides *whether*, and changes nothing about how.
    async fn run_it(&self, session: &Session, receipt: Receipt) -> Result<Outcome, MediationError> {
        let connection = self.connection_for(session).await?;
        Ok(self.runs.run(&connection, receipt).await?)
    }

    /// The session's connection, dialled again if the transport has gone.
    ///
    /// A session is a grant with an expiry of its own; the connection under it
    /// is how the grant is spent. They do not last the same length of time — a
    /// target that restarts ends one without ending the other, and so does a
    /// network that drops it or a target that stops answering — so a closed
    /// handle is replaced rather than being reported as the end of the work.
    /// What ends a session is its expiry or its owner closing it.
    ///
    /// Dialled from the session's own host and role, resolved through the
    /// registry exactly as the first connection was, so the replacement carries
    /// the same pinned host key, the same account and the same credential. A
    /// caller supplies nothing here: it is the same target or it is a failure.
    ///
    /// Asked before anything runs and never after. Redialling around a command
    /// already in flight would run it a second time on a target that may have
    /// already seen the first, so a transport that dies mid-command stays a
    /// failure the caller is told about. Nothing here spends the receipt: a
    /// command that could not be dialled for did not run, which is what the
    /// record says.
    ///
    /// A dial that fails leaves the session alone. The target being unreachable
    /// now is not evidence about the session, and an agent that waits and asks
    /// again should find the work it opened still there.
    async fn connection_for(&self, session: &Session) -> Result<Arc<Connection>, MediationError> {
        let held = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session.id.as_str())
            .map(Arc::clone)
            .ok_or(MediationError::NoConnection)?;
        // Taken before the check, so of two commands that both find the
        // transport gone, the second waits and then sees the first's
        // replacement rather than dialling one of its own.
        let mut connection = held.lock().await;
        // Whether the grant is still good and this is still its connection,
        // asked again now that the wait for the lock is over.
        //
        // Ending a session removes its entry and only then waits for this lock,
        // so the holder above can be one that was taken out of the map while
        // this call was waiting — and its handle is closed *because* ending it
        // closed it. Dialling on that reading would put a live connection into
        // a holder nothing owns any more: the command would run for a session
        // that had expired or been closed, and the connection it ran on would
        // be one no cleanup can reach.
        self.still_the_live_session_connection(session, &held)?;
        if !connection.is_closed() {
            return Ok(Arc::clone(&connection));
        }
        let target = self.registry.resolve(&session.host, &session.role)?;
        // Nothing new once the service is stopping, asked here as well as at
        // the door. Dialling is the one thing on this path that starts
        // something new, and it is reached after waits long enough for a stop
        // to land in the meantime — so a request admitted before the stop
        // could otherwise open a connection to a target while the service is
        // draining, and spend the drain on a command that will not run.
        if self.stopping.load(Ordering::SeqCst) {
            return Err(MediationError::Stopping);
        }
        let fresh = Arc::new(self.connector.connect(&target).await?);
        // And asked again after the dial, which is the long wait of the two and
        // the one a deadline is most likely to pass during: a session can end
        // while its own replacement is still being established.
        if let Err(ended) = self.still_the_live_session_connection(session, &held) {
            // Closed rather than dropped. Nothing else knows this connection
            // exists, so letting it fall out of scope would leave the target
            // holding an authenticated session for a grant that is already
            // over.
            let _ = fresh.close().await;
            return Err(ended);
        }
        // Not closed first: the handle is already gone, which is what brought
        // us here, and there is nothing left to say goodbye to.
        *connection = Arc::clone(&fresh);
        tracing::info!(
            session = session.id.as_str(),
            host = session.host.as_str(),
            role = session.role.as_str(),
            "a session's connection had gone and was dialled again"
        );
        Ok(fresh)
    }

    /// Confirms the grant is still good and this is still its connection.
    ///
    /// Two questions, because the answer to one is not the answer to the other.
    ///
    /// The store owns whether the session may still be used, and it is asked
    /// rather than inferred: a session that has just expired is deliberately
    /// kept for a while so its owner can be told what happened to it, and its
    /// connection is let go of by a later reconciliation rather than the moment
    /// the deadline passes. Between those two, a map that still holds the entry
    /// says nothing about a grant that is already over — so presence in the map
    /// must not stand in for being live, and asking the store is what stops a
    /// deadline that passed mid-dial from being run through anyway.
    ///
    /// The map owns which holder is the session's, and identity rather than
    /// presence is the question: a holder that is no longer the entry is one
    /// that ending the session took out, whatever has since been put under the
    /// same key.
    ///
    /// This closes the window it is checked in, and no more. A session can
    /// still end between the last check and the command starting, and that
    /// remains what it was before any of this: the connection is the one the
    /// map holds, so ending the session closes it, and the command fails
    /// against a closed handle rather than running.
    fn still_the_live_session_connection(
        &self,
        session: &Session,
        held: &SessionConnection,
    ) -> Result<(), MediationError> {
        // The claim the caller already made, made again now. Its error carries
        // what the session was for, so a caller whose grant ended underneath it
        // is told that rather than being told it has no connection.
        self.sessions.use_session(&session.id, &session.principal)?;
        let connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        match connections.get(session.id.as_str()) {
            Some(current) if Arc::ptr_eq(current, held) => Ok(()),
            _ => Err(MediationError::NoConnection),
        }
    }

    /// Requests waiting on a human, for whatever shows them one.
    ///
    /// A request whose session can no longer redeem is not offered: the sweep
    /// drops such requests eventually, and until it runs this asks the same
    /// question per request, so nobody is offered a decision that could not
    /// take effect.
    #[must_use]
    pub fn waiting_for_approval(&self) -> Vec<Asked> {
        self.approvals
            .waiting(|session| self.sessions.holds(session))
    }
    /// A bounded newest-first session view for the authenticated workspace.
    #[must_use]
    pub fn recent_session_snapshots(&self, limit: usize) -> Vec<SessionSnapshot> {
        self.sessions.recent_snapshots(limit)
    }

    /// A bounded newest-first window over readable audit entries.
    ///
    /// Entries share immutable storage with the ledger, so reading an
    /// operations page does not duplicate retained command output.
    #[must_use]
    pub fn recent_audit_entries(&self, limit: usize) -> Vec<Arc<Entry>> {
        self.ledger.recent_entries(limit)
    }

    /// Verifies the complete process-local audit chain, including sealed links.
    pub fn verify_audit(&self) -> Result<Verified, Broken> {
        self.ledger.verify()
    }

    /// Verifies a bounded newest-entry audit window for a request path.
    pub fn verify_recent_audit(&self, limit: usize) -> Result<Verified, Broken> {
        self.ledger.verify_recent(limit)
    }

    /// Records separately authenticated evaluation evidence.
    pub fn record_evaluation(&self, artifact: EvaluationArtifact) -> Result<Entry, AuditError> {
        self.ledger.record_evaluation(artifact)
    }

    /// Records a human's decision on a held request.
    ///
    /// Nothing runs here. The agent's next attempt at the same command redeems
    /// the agreement, which keeps one path to execution rather than two — and
    /// means an approval cannot run something the agent has since stopped
    /// asking for.
    pub fn decide(
        &self,
        request: &RequestId,
        approver: Approver,
        agreed: bool,
    ) -> Result<(), MediationError> {
        self.apply_answer(request, approver, agreed).map(|_| ())
    }

    /// Applies an answer to a held request and records it.
    ///
    /// Taken first, then written down: an answer the store refuses is not an
    /// answer, and a record saying somebody decided something they did not
    /// is worse than one that is a moment behind. The agreement this may
    /// apply is born unrecorded, so nothing can collect it during the
    /// write; it becomes collectable only below, once the record has
    /// accepted the answer - and never does if the record refuses it.
    fn apply_answer(
        &self,
        request: &RequestId,
        approver: Approver,
        agreed: bool,
    ) -> Result<Answer, MediationError> {
        let answer = self
            .approvals
            .decide(request, approver, agreed, |session| {
                self.sessions.holds(session)
            })?;
        match self.ledger.record_answer(&answer) {
            Ok(_entry) => {
                if agreed && !self.approvals.mark_recorded(request) {
                    // The agreement lapsed between applying and recording;
                    // there is nothing to unlock, and nothing ran.
                    tracing::warn!(
                        request = request.as_str(),
                        "an agreement expired before its record unlocked it"
                    );
                }
                tracing::info!(
                    request = request.as_str(),
                    agreed,
                    "a decision was recorded"
                );
                Ok(answer)
            }
            Err(why) => {
                tracing::error!(
                    %why,
                    request = request.as_str(),
                    agreed,
                    "a decision could not be recorded; an agreement stays unredeemable, a refusal stands"
                );
                Err(why.into())
            }
        }
    }

    /// Approves a held request and records the operator's standing agreement
    /// for its session.
    ///
    /// The request in front of the operator is approved by them directly -
    /// they saw this command. The agreement then answers in their name: each
    /// later held command in the session is individually answered, recorded,
    /// and redeemed exactly as if they had clicked, until the agreement
    /// expires, is withdrawn, or the session ends. `for_millis` may shorten
    /// it; nothing can lengthen it past the session's own maximum lifetime,
    /// which is the default.
    pub fn approve_session(
        &self,
        request: &RequestId,
        who: String,
        for_millis: Option<Millis>,
    ) -> Result<AgreementId, MediationError> {
        let answer = self.apply_answer(request, Approver::Human { who: who.clone() }, true)?;
        let session = answer.asked().session.clone();
        let until = self.standing_until(&session, for_millis);
        let agreement =
            self.approvals
                .grant_standing(&session, who, until, StandingCoverage::Session);
        tracing::info!(
            session = session.as_str(),
            request = request.as_str(),
            agreement = agreement.as_str(),
            until,
            "a standing agreement was recorded for the session"
        );
        Ok(agreement)
    }

    fn standing_until(&self, session: &SessionId, for_millis: Option<Millis>) -> Millis {
        let mut until = self.clock.now().saturating_add(
            for_millis
                .unwrap_or(self.standing_cap)
                .min(self.standing_cap),
        );
        if let Some(ends) = self.sessions.ends_by(session) {
            until = until.min(ends);
        }
        until
    }

    /// The standing agreements still answering, each with how long it has
    /// left, for the surface that shows and withdraws them. An agreement
    /// whose session no longer holds is not offered: withdrawing it would
    /// change nothing.
    #[must_use]
    pub fn standing_approvals(&self) -> Vec<(StandingApproval, Millis)> {
        let now = self.clock.now();
        self.approvals
            .standing()
            .into_iter()
            .filter(|agreement| self.sessions.holds(&agreement.session))
            .map(|agreement| {
                let remaining = agreement.until.saturating_sub(now);
                (agreement, remaining)
            })
            .collect()
    }

    /// Withdraws one agreement. Not a refusal: the next matching held command
    /// waits for a person again unless another agreement covers it.
    pub fn revoke_standing(&self, agreement: &AgreementId) -> bool {
        let revoked = self.approvals.revoke_standing(agreement);
        if revoked {
            tracing::info!(
                agreement = agreement.as_str(),
                "a standing agreement was withdrawn"
            );
        }
        revoked
    }

    /// Asks again about a command that outlived its caller's wait.
    pub async fn poll(
        &self,
        principal: &PrincipalId,
        session: &SessionId,
        run: &RunId,
        wait: std::time::Duration,
    ) -> Result<Outcome, MediationError> {
        // Claimed again: a run belongs to the session that started it, and the
        // session belongs to a principal.
        let session = self.sessions.use_session(session, principal)?;
        // Whether this session may ask at all, decided before anything is
        // waited on. Owning some session is not owning every run: without this
        // an identifier would be a capability anyone holding one could redeem,
        // which is the opposite of an authorization bound to the session it was
        // granted to.
        //
        // Before the wait, not after, because the wait is observable. Answering
        // a foreign run only once it settles - or once the caller's whole wait
        // has elapsed - tells whoever asked that the run exists and is still
        // going, which is the enumeration this refuses to do. A run that is not
        // this session's is answered exactly as one that never existed: the
        // same error, from one lookup either way, with nothing about the run
        // read or copied on the way out.
        if !self.runs.belongs_to(run, &session.id) {
            return Err(MediationError::Run(RunError::Unknown {
                run: run.as_str().to_owned(),
            }));
        }

        let outcome = self.runs.wait(run, wait).await?;
        self.account_for(outcome)
    }

    /// Accounts for and lets go of what sessions that no longer exist left
    /// behind.
    ///
    /// A session can stop existing while one of its commands is still going,
    /// and after that nothing can reach that command through `poll` — a lapsed
    /// session is refused, which is correct, and would otherwise mean the run
    /// is never recorded and never released. So the service reclaims: a
    /// finished run gets the completion entry it is owed, and an unfinished one
    /// is left to be reclaimed the next time round.
    ///
    /// Requests waiting on a human are collected here for the same reason:
    /// nothing can be done about a request whose window has closed or whose
    /// session has gone, and what it holds is somebody's command line. That
    /// also takes such a request off the list a human is shown, so nobody is
    /// asked to decide something that could no longer happen.
    ///
    /// Public because reclamation is an operation a deployment schedules,
    /// exactly as `SessionStore::sweep` is; opening a session runs it too,
    /// because that is the moment the service is already growing.
    pub async fn reclaim(&self) {
        self.release_orphaned().await;

        // Requests nobody can act on any more: lapsed without an answer,
        // refused, already spent, or asked about a session that has since gone
        // away. Asking collects the first kinds too, but a service that has
        // gone quiet is exactly when nobody asks, and a request holds a command
        // line and who wanted to run it for as long as it is kept.
        //
        // Liveness is reconciled against the store rather than reacting to any
        // one route out, for the reason `release_orphaned` gives: sessions stop
        // existing several ways, and asking what is left covers all of them.
        self.approvals.sweep(|session| self.sessions.holds(session));

        // Driven from what the run store actually holds rather than from this
        // service's index of it. A command can be registered and sent and its
        // caller cancelled before anything here learned its identifier, and a
        // run nobody indexed is exactly the one that would otherwise never be
        // recorded or released. The store knows every run; the index only
        // knows the ones that were handed back.
        for run in self.runs.outstanding() {
            // Recording one completion can wait for the deployment boundary.
            // Yield between runs so a caller can enforce one deadline around
            // the whole pass rather than only around each individual write.
            tokio::task::yield_now().await;
            let Some(authorized) = self.runs.authorization(&run) else {
                continue;
            };
            // Whether it has finished, not waiting for it to. One still going
            // stays where it is and is asked again next time.
            let Some(outcome) = self.runs.finished(&run) else {
                continue;
            };
            // Recorded whatever became of its session. A finished command is
            // owed its entry, and waiting for its caller to come back - or for
            // the space to be wanted - would leave the record short of
            // something that has already happened. Recording twice is refused,
            // so a caller that polls first has simply got there first.
            let recorded = self.record_completion(outcome);
            // Released once the record says what it did and nobody can ask for
            // it any more, which is the case exactly when its session is gone.
            // Letting go of an unrecorded one would lose the only account of a
            // command that ran.
            //
            // The session is asked about here rather than read once for the
            // whole pass. A reading taken earlier goes stale while this works
            // through the runs: a session opened since would be missing from
            // it, and its finished run - one its caller was told was still
            // running and can still come back for - would look orphaned and be
            // thrown away. Asked at the moment of release there is nothing to
            // go stale: a session that is gone now cannot return, because an
            // identifier names one session and is never reissued.
            if recorded && !self.sessions.holds(authorized.session()) {
                self.release(&run);
            }
        }
    }

    /// Closes the connections of sessions that no longer exist.
    ///
    /// Asks the store what it *has* rather than what it just removed. Sessions
    /// stop existing by several routes — swept, dropped when their owner
    /// returns after the grace, evicted to make room — and a reconciliation
    /// against the live set covers all of them, including any added later,
    /// where reacting to removals means knowing every route and eventually
    /// missing one.
    ///
    /// A target that has already gone away is not a failure to close: the point
    /// is to stop holding the handle, and the far end is entitled to have hung
    /// up first.
    async fn release_orphaned(&self) {
        self.sessions.sweep();
        let released: Vec<SessionConnection> = {
            // Both sides read under the hold that publishing takes. Reading the
            // sessions and then the connections as two separate steps cannot
            // answer a question about both: an open landing in between looks
            // like a connection nobody owns, and closing it breaks a session
            // that has just been told it exists.
            let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
            let live: HashSet<String> = self
                .sessions
                .live()
                .into_iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());
            let orphaned: Vec<String> = connections
                .keys()
                .filter(|id| !live.contains(*id))
                .cloned()
                .collect();
            orphaned
                .iter()
                .filter_map(|id| connections.remove(id))
                .collect()
        };
        for connection in released {
            let _ = connection.lock().await.close().await;
        }
    }

    /// Records what a command did, once it has done it.
    ///
    /// A run that outlived the caller's wait has not finished and has nothing
    /// to record yet; it is handed back so the caller can ask again. One that
    /// has finished is recorded and then released — its output has reached the
    /// record, and holding it a second time would mean the service kept every
    /// command any caller ever ran.
    fn account_for(&self, outcome: Outcome) -> Result<Outcome, MediationError> {
        if outcome.still_running() {
            return Ok(outcome);
        }
        let run = outcome.run().clone();
        // Read before the record takes the outcome, because what the run did is
        // half of what a failure to record it has to say.
        let state = outcome.state();
        let outcome = match self.ledger.record_outcome(outcome) {
            Ok(Accounted { outcome, .. }) => outcome,
            // Housekeeping recorded this run before its caller came back for
            // it, which is the whole point of recording a finished command
            // promptly. The caller is owed its output all the same: the entry
            // it would have written is already there, and the store still holds
            // what the command did until this releases it. Handing back an
            // error here would turn doing the right thing early into a
            // continuation that fails.
            Err(AuditError::AlreadyCompleted { .. }) => match self.runs.finished(&run) {
                Some(outcome) => outcome,
                None => {
                    return Err(AuditError::AlreadyCompleted {
                        run: run.as_str().to_owned(),
                    }
                    .into());
                }
            },
            // The run settled and the record would not take what it did. What
            // it did is carried with the failure rather than flattened into the
            // audit error, because "it ran", "it did not" and "nobody knows"
            // are the three things a caller acts on and a record failure does
            // not erase which of them happened.
            Err(source) => {
                return Err(MediationError::Unaccounted {
                    run: run.as_str().to_owned(),
                    state,
                    source,
                });
            }
        };
        self.release(&run);
        Ok(outcome)
    }

    /// Lets go of a run.
    fn release(&self, run: &RunId) {
        self.runs.forget(run);
    }

    /// Writes a finished run's completion, if it is not already written.
    ///
    /// Recording and releasing are separate acts. What a run did belongs in the
    /// record as soon as it has finished, whether or not anybody has come back
    /// for it; whether the service may then let go of it is a different
    /// question, answered by whether its caller can still ask. Because these
    /// are separate, more than one path can reach a settled run - its caller
    /// polling, housekeeping passing by - and the second one finding the entry
    /// already there is the record doing its job rather than a failure.
    /// Reports whether the completion is now in the record, which is the only
    /// thing that makes letting go of the run safe.
    ///
    /// Finding it already written counts: some other path got there first, and
    /// the entry exists either way. Any other refusal does not — the command
    /// ran and the record does not say so — so the run is kept, and a later
    /// pass tries again. Discarding it would lose the only remaining account of
    /// something that happened on a target, which is the one thing this record
    /// exists to prevent.
    fn record_completion(&self, outcome: Outcome) -> bool {
        match self.ledger.record_outcome(outcome) {
            Ok(_) | Err(AuditError::AlreadyCompleted { .. }) => true,
            Err(_) => false,
        }
    }

    /// Ends a session, its connection, and its place in the record.
    pub async fn close_session(
        &self,
        principal: &PrincipalId,
        session: &SessionId,
    ) -> Result<(), MediationError> {
        let connection = {
            // Claiming the session, writing that it closed, and removing it are
            // one step. Split apart, two callers closing at once can both find
            // the session and both write that it closed, leaving a record that
            // verifies and says a session ended twice. The same hold covers
            // publishing, so a close and an open cannot interleave either.
            let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
            let held = self.sessions.use_session(session, principal)?;
            self.ledger.record_session_closed(&held)?;
            self.sessions.close(session, principal)?;
            self.connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(session.as_str())
        };
        if let Some(connection) = connection {
            // A target that has already gone away is not a failure to close.
            let _ = connection.lock().await.close().await;
        }
        // Whatever this session had going is now nobody's to ask about, so it
        // is accounted for here rather than waiting for an unrelated open.
        self.reclaim().await;
        Ok(())
    }

    /// Hosts and roles this service is configured for.
    ///
    /// Discovery reports configuration. Upstream authorization still governs
    /// whether a caller can select an account.
    pub fn inventory(&self) -> Vec<(&HostId, Vec<&RoleId>)> {
        self.registry
            .hosts()
            .map(|host| (host, self.registry.roles(host).collect()))
            .collect()
    }

    pub fn account_inventory(&self) -> Vec<(&HostId, Vec<(&RoleId, crate::AccessClass)>)> {
        self.registry
            .hosts()
            .map(|host| (host, self.registry.accounts(host).collect()))
            .collect()
    }

    #[must_use]
    pub fn ledger(&self) -> &Ledger<Arc<C>> {
        &self.ledger
    }

    /// Connections this service is still holding.
    ///
    /// One per live session, and none for a session that has stopped existing,
    /// which is how a test says the reconciliation happened.
    #[must_use]
    pub fn held_connections(&self) -> usize {
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Refuses anything that has not started yet.
    ///
    /// One way, deliberately: a service that could be told to carry on again
    /// would need to say what happens to whatever was refused in between, and
    /// stopping is not a state anything recovers from.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Where it actually holds. The check below is a courtesy — it answers
        // a caller plainly instead of letting it get most of the way through —
        // but the one that cannot be raced is the store's, taken while it is
        // registering the run.
        self.runs.stop();
    }

    /// Commands still running on their targets.
    ///
    /// What a caller waiting for work to finish needs, as against
    /// `outstanding_runs`, which counts records too: a finished run is kept
    /// until whoever asked collects it, and waiting for that is waiting for a
    /// client, not for a command.
    ///
    /// Named rather than counted, because whatever gives up waiting has to be
    /// able to say which commands it gave up on.
    #[must_use]
    pub fn runs_in_flight(&self) -> Vec<RunId> {
        self.runs.unfinished()
    }

    /// Commands still being read, with the audit entries that authorized them.
    ///
    /// For an operator-facing shutdown diagnostic: the authorization supplies
    /// the session and exact record entry needed to find the command without
    /// copying command text into a diagnostic log.
    #[must_use]
    pub fn runs_in_flight_with_authorization(&self) -> Vec<(RunId, Authorization)> {
        self.runs.unfinished_authorized()
    }
    /// Approval requests this service is still keeping.
    ///
    /// Counts everything the store holds, including requests that have been
    /// answered or have lapsed and are merely waiting to be collected — which
    /// is what makes it the measure of whether reclamation happened, where
    /// `waiting_for_approval` deliberately hides them.
    #[must_use]
    pub fn requests_held(&self) -> usize {
        self.approvals.len()
    }

    /// Runs this service is still holding.
    ///
    /// Every run it has finished with should have been released, so this is
    /// how a test says that in as many words.
    #[must_use]
    pub fn outstanding_runs(&self) -> Vec<RunId> {
        self.runs.outstanding()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum MediationError {
    #[error("the requested account access class does not match configuration")]
    AccountMismatch,
    #[error("the service is stopping and is not starting new work")]
    Stopping,
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error(transparent)]
    TooManySessions(#[from] TooManySessions),
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    /// The run settled, and the record would not take what it did.
    ///
    /// Distinct from an audit error, which means the *intent* could not be
    /// recorded — and running requires a receipt, so nothing ran. Here the
    /// command reached the target and the record failed afterwards, so the
    /// answer carries what the run did: a caller that reads only "failed" and
    /// sends it again repeats work that may already have happened.
    ///
    /// What was attempted is in the record; what it did is not, which is an
    /// operator's problem rather than something a caller can retry its way out
    /// of.
    #[error("{run} {}, and its completion could not be recorded: {source}", .state.what_happened())]
    Unaccounted {
        run: String,
        /// What the run did, which the message says in words rather than
        /// assuming: a refused command did not run, and a command nothing came
        /// back about may or may not have.
        state: RunState,
        #[source]
        source: AuditError,
    },
    #[error("the session has no connection")]
    NoConnection,
    #[error("a permitted command was recorded without a receipt")]
    NoReceipt,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use russh::keys::ssh_key;
    use russh::server::{self, Auth, Msg, Server as _};
    use russh::{Channel, ChannelId, keys};
    use tokio::net::TcpListener;

    use super::*;
    use crate::audit::Event;
    use crate::clock::{SystemClock, TestClock};
    use crate::connect::CredentialError;
    use crate::secret::Secret;

    /// A target that runs what it is asked to run, so the whole path is
    /// exercised against a real SSH server and a real shell.
    #[derive(Clone)]
    struct ShellServer;

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
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).into_owned();
            let handle = session.handle();
            let _ = session.channel_success(channel);
            tokio::spawn(async move {
                let output = tokio::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(&command)
                    .output()
                    .await;
                let (stdout, code) = match output {
                    Ok(output) => (output.stdout, output.status.code().unwrap_or(255)),
                    Err(_) => (Vec::new(), 255),
                };
                if !stdout.is_empty() {
                    let _ = handle
                        .data(
                            channel,
                            russh::keys::ssh_encoding::bytes::Bytes::from(stdout),
                        )
                        .await;
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

    /// Holds a dial where it is, so a test can act while one is in flight.
    ///
    /// The window it opens is inside `Connector::connect`, which fetches the
    /// credential before it dials anything. A real dial takes microseconds, so
    /// this is the only way to reach what happens *after* one — and what
    /// happens after one is where a deadline that passed meanwhile has to be
    /// caught.
    ///
    /// Unarmed by default, so every other test dials normally.
    #[derive(Clone, Default)]
    struct DialGate {
        armed: Arc<AtomicBool>,
        reached: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl DialGate {
        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }

        /// Resolves once a dial has stopped at the gate.
        async fn until_a_dial_waits(&self) {
            self.reached.notified().await;
        }

        fn let_it_through(&self) {
            self.release.notify_one();
        }
    }

    struct OneKey(String, DialGate);

    impl CredentialSource for OneKey {
        async fn fetch(
            &self,
            _: &crate::registry::CredentialRef,
        ) -> Result<Secret<String>, CredentialError> {
            if self.1.armed.load(Ordering::SeqCst) {
                self.1.reached.notify_one();
                self.1.release.notified().await;
            }
            Ok(Secret::new(self.0.clone()))
        }
    }

    const LIFETIME: Lifetime = Lifetime {
        idle: 600_000,
        max: 3_600_000,
        grace: 60_000,
    };

    async fn bastion() -> Bastion<SystemClock, OneKey> {
        bastion_running(Limits::default()).await
    }

    async fn bastion_running(run: Limits) -> Bastion<SystemClock, OneKey> {
        bastion_with(Arc::new(SystemClock::new().expect("a boot clock")), run).await
    }

    async fn bastion_with<C: Clock + 'static>(clock: Arc<C>, run: Limits) -> Bastion<C, OneKey> {
        bastion_recording(clock, run, None).await
    }

    /// A service whose dials can be held open, and the gate that holds them.
    async fn bastion_gated<C: Clock + 'static>(clock: Arc<C>) -> (Bastion<C, OneKey>, DialGate) {
        let gate = DialGate::default();
        let bastion = bastion_dialling(clock, Limits::default(), None, gate.clone()).await;
        (bastion, gate)
    }

    async fn bastion_recording<C: Clock + 'static>(
        clock: Arc<C>,
        run: Limits,
        records_to: Option<Arc<dyn Records>>,
    ) -> Bastion<C, OneKey> {
        bastion_dialling(clock, run, records_to, DialGate::default()).await
    }

    async fn bastion_dialling<C: Clock + 'static>(
        clock: Arc<C>,
        run: Limits,
        records_to: Option<Arc<dyn Records>>,
        gate: DialGate,
    ) -> Bastion<C, OneKey> {
        let host_key =
            keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519).unwrap();
        let pinned = host_key.public_key().to_openssh().unwrap().to_string();
        let config = Arc::new(server::Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            auth_rejection_time: Duration::from_millis(1),
            keys: vec![host_key],
            ..server::Config::default()
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let mut server = ShellServer;
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });

        let registry = Registry::from_json(&format!(
            r#"{{ "dns1": {{
                   "address": "{address}",
                   "host_key": "{}",
                   "roles": {{
                     "readonly": {{ "user": "mcp-ro", "access_class": "read_only", "credential": "mcp-ssh/dns1/readonly" }},
                     "operator": {{ "user": "mcp-op", "access_class": "privileged", "credential": "mcp-ssh/dns1/readonly" }}
                   }}
                 }} }}"#,
            pinned.trim()
        ))
        .unwrap();

        let client_key = keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        Bastion::recording_to(
            clock,
            registry,
            Engine::new(crate::policy::ReviewMode::Privileged),
            OneKey(client_key, gate),
            Bounds {
                lifetime: LIFETIME,
                sessions_per_principal: 8,
                run,
                approval: Windows {
                    decide_within: 300_000,
                    redeem_within: 60_000,
                },
                waiting_per_session: 4,
            },
            records_to,
        )
    }

    fn alice() -> PrincipalId {
        PrincipalId::parse("alice").unwrap()
    }

    #[tokio::test]
    async fn account_class_cannot_be_asserted_by_the_caller() {
        let bastion = bastion().await;
        let host = HostId::parse("dns1").unwrap();
        let role = RoleId::parse("readonly").unwrap();
        assert_eq!(
            bastion.check_account(&host, &role, crate::AccessClass::Privileged),
            Err(MediationError::AccountMismatch)
        );
        assert_eq!(bastion.held_connections(), 0);
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        assert_eq!(
            bastion.check_session_account(
                &alice(),
                &session.id,
                &host,
                &role,
                crate::AccessClass::Privileged
            ),
            Err(MediationError::AccountMismatch)
        );
        bastion
            .check_session_account(
                &alice(),
                &session.id,
                &host,
                &role,
                crate::AccessClass::ReadOnly,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn a_privileged_account_cannot_be_downgraded_before_connecting() {
        let (bastion, gate) = bastion_gated(Arc::new(TestClock::at(1_000))).await;
        gate.arm();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            bastion.open_session(
                alice(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse("inspect the target").unwrap(),
                AccessClass::ReadOnly,
            ),
        )
        .await
        .expect("account validation must precede credential retrieval");
        assert_eq!(result, Err(MediationError::AccountMismatch));
        assert_eq!(bastion.held_connections(), 0);
        assert!(bastion.ledger().entries().is_empty());
    }

    async fn session_for<C: Clock + 'static>(
        bastion: &Bastion<C, OneKey>,
        access_class: AccessClass,
    ) -> Session {
        bastion
            .open_session(
                alice(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse(match access_class {
                    AccessClass::ReadOnly => "readonly",
                    AccessClass::Privileged => "operator",
                })
                .unwrap(),
                Purpose::parse("find out why the deploy did not take effect").unwrap(),
                access_class,
            )
            .await
            .expect("opening a session")
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The same service with a wait too short for a slow command, so the
    /// outlived-the-wait path is reached without the test waiting for it.
    async fn impatient() -> Bastion<SystemClock, OneKey> {
        bastion_running(Limits {
            wait: Duration::from_millis(50),
            ..Limits::default()
        })
        .await
    }

    /// Waiting for running commands to be recorded is worth nothing if new
    /// ones can start behind the wait. A request accepted a moment before the
    /// stop is still being handled, so refusing at the door is not enough —
    /// the refusal has to be where a command would otherwise begin.
    #[tokio::test]
    async fn a_stopping_service_starts_nothing_new() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        bastion.stop();

        let refused = bastion
            .exec(&alice(), &session.id, argv(&["docker", "ps"]))
            .await
            .expect_err("a stopping service ran a command");
        assert!(
            matches!(refused, MediationError::Stopping),
            "unexpected error: {refused:?}"
        );
        assert!(
            bastion.runs_in_flight().is_empty(),
            "a stopping service started a command anyway"
        );
    }

    /// A command can outlive the wait it was given, and that is an answer
    /// rather than a failure: the work has started, so the caller has to be
    /// handed something it can ask about again. Recording it as finished would
    /// be false, and refusing to return it would strand a command that is
    /// running on the target.
    #[tokio::test]
    async fn a_command_that_outlives_its_wait_is_returned_and_can_be_continued() {
        let bastion = impatient().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["sleep", "5"]))
            .await
            .expect("a slow command is an answer, not an error");
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run, got {executed:?}");
        };
        assert!(outcome.still_running(), "the command should still be going");

        let correlated = bastion.runs_in_flight_with_authorization();
        let [(running, authorized)] = correlated.as_slice() else {
            panic!("expected one correlated run, got {correlated:?}");
        };
        assert_eq!(running, outcome.run());
        assert_eq!(authorized.session(), &session.id);
        assert!(
            bastion.ledger().entries().iter().any(|entry| {
                entry.sequence == authorized.sequence()
                    && &entry.digest == authorized.digest()
                    && entry.session == session.id
                    && matches!(entry.event, crate::audit::Event::Decided { .. })
            }),
            "the in-flight run could not be joined to its authorizing command"
        );

        // Nothing is recorded as completed while it is still going.
        assert!(
            !bastion
                .ledger()
                .entries()
                .iter()
                .any(|entry| matches!(entry.event, crate::audit::Event::Completed { .. })),
            "a running command was recorded as finished"
        );

        // And the same session can pick it up again.
        let again = bastion
            .poll(
                &alice(),
                &session.id,
                outcome.run(),
                Duration::from_millis(20),
            )
            .await
            .expect("the run should still be addressable");
        assert_eq!(again.run(), outcome.run());
    }

    /// A command can outlive the session that authorized it. After that nothing
    /// can reach it through `poll` — a lapsed session is refused, rightly — so
    /// without reclamation its completion would never be written and the run
    /// would be held for as long as the service runs.
    #[tokio::test]
    async fn work_outliving_its_session_is_still_accounted_for() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(
            Arc::clone(&clock),
            Limits {
                wait: Duration::from_millis(50),
                ..Limits::default()
            },
        )
        .await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["sleep", "1"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run");
        };
        assert!(outcome.still_running(), "the run must outlive the wait");
        let run = outcome.run().clone();

        // The session lapses and is forgotten while the command is still going,
        // and the command then finishes.
        clock.advance(LIFETIME.max + LIFETIME.grace + 1);
        tokio::time::sleep(Duration::from_millis(1_400)).await;

        bastion.reclaim().await;

        assert!(
            bastion.outstanding_runs().is_empty(),
            "the abandoned run is still held: {:?}",
            bastion.outstanding_runs()
        );
        let completed = bastion.ledger().entries().into_iter().any(|entry| {
            matches!(entry.event, crate::audit::Event::Completed { run: ref id, .. } if *id == run)
        });
        assert!(
            completed,
            "the run finished with no completion in the record"
        );
    }

    /// Opening a session publishes two things - the session and its connection
    /// - and reconciliation reads both. If either can happen halfway through
    /// the other, a session is told it is open and then has its connection
    /// closed underneath it by housekeeping that saw a connection nobody owned.
    ///
    /// A smoke rather than a pin: what makes this safe is that publishing and
    /// reconciling take the same lock and neither awaits under it, and no
    /// scheduling this can arrange proves the absence of an interleaving. Run
    /// on several threads so the parallelism is real rather than notional.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opening_sessions_concurrently_does_not_close_their_connections() {
        let bastion = Arc::new(bastion().await);

        // Every open also reconciles, so these interleave with each other's
        // reconciliations - which is the window.
        let mut opening = Vec::new();
        for _ in 0..6 {
            let bastion = Arc::clone(&bastion);
            opening.push(tokio::spawn(async move {
                session_for(&*bastion, AccessClass::ReadOnly).await
            }));
        }
        let mut sessions = Vec::new();
        for task in opening {
            sessions.push(task.await.expect("opening should not panic"));
        }

        for session in sessions {
            bastion
                .exec(&alice(), &session.id, argv(&["uptime"]))
                .await
                .expect("a session that opened successfully lost its connection");
        }
    }

    /// A finished command is owed its entry when it finishes, not when someone
    /// next looks. An idle service is exactly when nobody is looking, so a
    /// completion that waits to be discovered can wait for ever.
    #[tokio::test]
    async fn a_command_that_finishes_is_recorded_without_anyone_asking() {
        let bastion = bastion_running(Limits {
            wait: Duration::from_millis(50),
            ..Limits::default()
        })
        .await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["sleep", "0.3"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run");
        };
        assert!(outcome.still_running(), "the command must outlive the wait");

        // Nothing is polled, nothing is opened or closed, and reclamation is
        // never called. The service simply sits there while the command ends.
        tokio::time::sleep(Duration::from_millis(900)).await;

        let completions = bastion
            .ledger()
            .entries()
            .into_iter()
            .filter(|entry| matches!(entry.event, crate::audit::Event::Completed { .. }))
            .count();
        assert_eq!(
            completions, 1,
            "an idle service left a finished command out of the record"
        );
    }

    /// Drops the transport under a live session, the way an inactivity timeout
    /// or a restarted target does, and leaves the session itself untouched.
    async fn lose_the_transport<C: Clock + 'static>(
        bastion: &Bastion<C, OneKey>,
        session: &SessionId,
    ) {
        let held = bastion
            .connections
            .lock()
            .unwrap()
            .get(session.as_str())
            .map(Arc::clone)
            .expect("the session has a connection");
        let _ = held.lock().await.close().await;
        // Closing asks the session task to stop; the handle admits it once it
        // has, and everything this is setting up starts from that point.
        let started = Instant::now();
        while !held.lock().await.is_closed() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the transport did not go away"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A session outlives the connection underneath it.
    ///
    /// A target that restarts ends the transport without ending the session,
    /// and so does a network that drops it or a target that stops answering.
    /// None of those is the work being over, so a caller that comes back to a
    /// session it still holds finds it usable: what ends a session is its own
    /// expiry or its owner closing it, and a lost connection is dialled again
    /// underneath.
    #[tokio::test]
    async fn a_session_outlives_the_connection_underneath_it() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        bastion
            .exec(&alice(), &session.id, argv(&["uptime"]))
            .await
            .expect("a session that just opened could not run anything");

        lose_the_transport(&bastion, &session.id).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["uptime"]))
            .await
            .expect("a lost transport ended a session that had not expired");
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected the command to run, got {executed:?}");
        };
        assert_eq!(
            outcome.state(),
            RunState::Exited { code: 0 },
            "the command was answered for without reaching the target"
        );
    }

    /// Dialling again replaces the session's one connection rather than
    /// leaving a second alongside it. A session holds exactly one, and a
    /// replacement that accumulated would mean every silence cost the service
    /// another open connection to a target for as long as the session lived.
    #[tokio::test]
    async fn dialling_again_replaces_the_session_connection_rather_than_adding_one() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        assert_eq!(bastion.held_connections(), 1);

        lose_the_transport(&bastion, &session.id).await;
        let executed = bastion
            .exec(&alice(), &session.id, argv(&["uptime"]))
            .await
            .expect("a lost transport ended a session that had not expired");
        // Asserted rather than assumed: a command refused before anything was
        // dialled would also leave the count at one, and say nothing at all
        // about what replacement does.
        assert!(
            matches!(executed, Executed::Ran { .. }),
            "nothing was dialled, so this says nothing about replacing: {executed:?}"
        );

        assert_eq!(
            bastion.held_connections(),
            1,
            "the session ended up holding more than one connection"
        );
    }

    /// Replacing a connection must not outlive the session it is for.
    ///
    /// Ending a session takes its connection out of the map and only then waits
    /// for the lock a replacement holds, so a command already waiting for that
    /// lock wakes holding a connection that is nobody's — and finds it closed,
    /// because ending the session is what closed it. Dialling on that reading
    /// would run the command for a session that had already ended, on a
    /// connection no later cleanup could reach.
    #[tokio::test]
    async fn a_session_that_ends_while_its_connection_is_replaced_runs_nothing() {
        let (bastion, gate) =
            bastion_gated(Arc::new(SystemClock::new().expect("a boot clock"))).await;
        let bastion = Arc::new(bastion);
        let session = session_for(&*bastion, AccessClass::ReadOnly).await;

        // The transport goes, so the next command has to dial rather than reuse.
        lose_the_transport(&bastion, &session.id).await;
        gate.arm();

        let running = {
            let bastion = Arc::clone(&bastion);
            let who = alice();
            let id = session.id.clone();
            tokio::spawn(async move { bastion.exec(&who, &id, argv(&["uptime"])).await })
        };
        // The command is now inside its dial, holding the session's connection.
        gate.until_a_dial_waits().await;

        // The owner closes the session while that replacement is in flight.
        // Closing ends by waiting for the very connection the dial is holding,
        // so it is spawned: what this window is about is the part that runs
        // before that wait, which is the session leaving the store and the map.
        let closing = {
            let bastion = Arc::clone(&bastion);
            let who = alice();
            let id = session.id.clone();
            tokio::spawn(async move { bastion.close_session(&who, &id).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;

        gate.let_it_through();

        let outcome = running.await.expect("the command task panicked");
        let Err(why) = outcome else {
            panic!("a command ran for a session its owner had closed: {outcome:?}");
        };
        assert!(
            matches!(why, MediationError::Session(SessionError::Unknown)),
            "the caller was not told its session was gone: {why:?}"
        );

        closing
            .await
            .expect("the closing task panicked")
            .expect("closing a session its owner still held");
        // What this deliberately does not assert: that the replacement was
        // closed rather than dropped. Nothing here can see it. The connection
        // map is not the place to look — closing took this session's entry out
        // before the dial finished, so it is empty either way — and the only
        // thing that could tell the difference is the target, which would mean
        // teaching the loopback server to count live sessions for one cleanup
        // detail. That the replacement is closed is held by reading
        // `connection_for`, not by this test.
    }

    /// A stop that lands after a command was admitted still stops it dialling.
    ///
    /// The door is checked when a command arrives, and dialling happens after
    /// waits long enough for a stop to land in between. Opening a connection to
    /// a target then would spend a draining service's bounded wait on a command
    /// that is not going to run.
    #[tokio::test]
    async fn a_service_that_is_stopping_does_not_dial_a_replacement() {
        let bastion = Arc::new(bastion().await);
        let session = session_for(&*bastion, AccessClass::ReadOnly).await;
        // The transport goes, so the next command has to dial rather than reuse.
        lose_the_transport(&bastion, &session.id).await;

        let held = bastion
            .connections
            .lock()
            .unwrap()
            .get(session.id.as_str())
            .map(Arc::clone)
            .expect("the session has a connection");
        // Held so the command is past the door and waiting, which is where a
        // stop has to be able to reach it.
        let guard = held.lock().await;

        let running = {
            let bastion = Arc::clone(&bastion);
            let who = alice();
            let id = session.id.clone();
            tokio::spawn(async move { bastion.exec(&who, &id, argv(&["uptime"])).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;

        bastion.stop();
        drop(guard);

        let outcome = running.await.expect("the command task panicked");
        assert!(
            matches!(outcome, Err(MediationError::Stopping)),
            "a stopping service dialled a target anyway: {outcome:?}"
        );
    }

    /// A deadline that passes while the replacement is being dialled ends the
    /// session, and the command must not run on what the dial produced.
    ///
    /// The dial is the longest wait on this path, so it is where a session is
    /// most likely to age out mid-flight — and the connection map cannot tell
    /// anyone it did. A session that has just expired keeps its entry: it is
    /// held so its owner can be told what happened to it, and its connection is
    /// let go of by a later reconciliation. Between those two the map still
    /// names a holder for a grant that is already over, which is why being live
    /// is asked of the store rather than read off the map.
    #[tokio::test]
    async fn a_session_that_expires_mid_dial_does_not_get_its_command_run() {
        let clock = Arc::new(TestClock::at(1_000));
        let (bastion, gate) = bastion_gated(Arc::clone(&clock)).await;
        let bastion = Arc::new(bastion);
        let session = session_for(&*bastion, AccessClass::ReadOnly).await;

        // The transport goes, so the next command has to dial rather than reuse.
        lose_the_transport(&bastion, &session.id).await;
        gate.arm();

        let running = {
            let bastion = Arc::clone(&bastion);
            let who = alice();
            let id = session.id.clone();
            tokio::spawn(async move { bastion.exec(&who, &id, argv(&["uptime"])).await })
        };

        // The command is now inside its dial, holding the session's own
        // connection slot, so nothing can reconcile the map underneath it.
        gate.until_a_dial_waits().await;
        clock.advance(LIFETIME.idle);
        gate.let_it_through();

        let outcome = running.await.expect("the command task panicked");
        let Err(why) = outcome else {
            panic!("a command ran for a session that expired while it dialled: {outcome:?}");
        };
        assert!(
            matches!(why, MediationError::Session(SessionError::Expired { .. })),
            "the caller was not told its session had lapsed: {why:?}"
        );
    }

    /// A finished command is owed its entry whether or not anyone came back
    /// for it. Waiting until its session ends leaves the record short of
    /// something that has already happened, for as long as the session lives.
    ///
    /// Its *output* is another matter: that is held until the session ends,
    /// because until then nothing can tell a caller that walked away from one
    /// that is about to come back.
    #[tokio::test]
    async fn an_abandoned_command_is_recorded_when_it_finishes_not_when_it_is_needed() {
        let bastion = bastion_running(Limits {
            wait: Duration::from_secs(30),
            ..Limits::default()
        })
        .await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        let who = alice();

        let abandoned = bastion.exec(&who, &session.id, argv(&["sleep", "0.3"]));
        assert!(
            tokio::time::timeout(Duration::from_millis(80), abandoned)
                .await
                .is_err(),
            "the call was supposed to be cancelled"
        );
        tokio::time::sleep(Duration::from_millis(900)).await;

        // The session is alive and nobody has asked for this run.
        bastion.reclaim().await;

        let completions = bastion
            .ledger()
            .entries()
            .into_iter()
            .filter(|entry| matches!(entry.event, crate::audit::Event::Completed { .. }))
            .count();
        assert_eq!(
            completions, 1,
            "a finished command was left out of the record"
        );

        // The output stays until the session does. Bounded by the session's
        // own lifetime and by what one run may retain, and unlike the entry it
        // is not something a later reader needs.
        assert_eq!(bastion.outstanding_runs().len(), 1);

        bastion.close_session(&who, &session.id).await.unwrap();
        assert!(
            bastion.outstanding_runs().is_empty(),
            "the run outlived the session that authorized it: {:?}",
            bastion.outstanding_runs()
        );
    }

    /// Recording a finished command promptly must not cost its caller the
    /// output. Housekeeping can reach a settled run before its owner polls -
    /// that is the point of recording on settlement - and the owner is still
    /// owed what the command did.
    #[tokio::test]
    async fn a_slow_command_polls_successfully_after_housekeeping_recorded_it() {
        let bastion = bastion_running(Limits {
            wait: Duration::from_millis(50),
            ..Limits::default()
        })
        .await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["sleep", "0.4"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run");
        };
        assert!(outcome.still_running(), "the command must outlive the wait");
        let run = outcome.run().clone();

        // It finishes, and housekeeping gets to it before its owner does.
        tokio::time::sleep(Duration::from_millis(900)).await;
        bastion.reclaim().await;

        let collected = bastion
            .poll(&alice(), &session.id, &run, Duration::from_millis(50))
            .await
            .expect("the owner was refused output that had been recorded early");
        assert!(!collected.still_running());
        assert_eq!(collected.run(), &run);

        // And exactly one completion, whoever wrote it.
        let completions = bastion
            .ledger()
            .entries()
            .into_iter()
            .filter(|entry| matches!(entry.event, crate::audit::Event::Completed { .. }))
            .count();
        assert_eq!(
            completions, 1,
            "the record says it finished {completions} times"
        );
    }

    /// Closing is one step. Split into a lookup, an append and a removal, two
    /// callers closing at once both find the session and both write that it
    /// closed - a record that verifies and says a session ended twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_closes_once_however_many_callers_ask() {
        let bastion = Arc::new(bastion().await);
        let session = session_for(&*bastion, AccessClass::ReadOnly).await;

        let mut closing = Vec::new();
        for _ in 0..6 {
            let bastion = Arc::clone(&bastion);
            let id = session.id.clone();
            closing.push(tokio::spawn(async move {
                bastion.close_session(&alice(), &id).await
            }));
        }
        let mut closed = 0;
        for task in closing {
            if task.await.expect("closing should not panic").is_ok() {
                closed += 1;
            }
        }

        assert_eq!(closed, 1, "more than one caller closed the session");
        let closures = bastion
            .ledger()
            .entries()
            .into_iter()
            .filter(|entry| matches!(entry.event, crate::audit::Event::SessionClosed))
            .count();
        assert_eq!(
            closures, 1,
            "the record says the session closed {closures} times"
        );
    }

    /// A caller can be cancelled after its command has been registered and sent
    /// but before anything here learns the identifier. That run is real, and
    /// reclaiming has to find it - which it can only do by asking the store
    /// what it holds rather than asking this service what it indexed.
    #[tokio::test]
    async fn a_run_nobody_indexed_is_still_reclaimed() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(
            Arc::clone(&clock),
            Limits {
                wait: Duration::from_secs(30),
                ..Limits::default()
            },
        )
        .await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        // Cancelled while the command is running, so the identifier it would
        // have returned is never handed over and never indexed.
        let who = alice();
        let abandoned = bastion.exec(&who, &session.id, argv(&["sleep", "1"]));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), abandoned)
                .await
                .is_err(),
            "the call was supposed to be cancelled"
        );
        assert_eq!(bastion.outstanding_runs().len(), 1, "the run should exist");

        clock.advance(LIFETIME.max + LIFETIME.grace + 1);
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        bastion.reclaim().await;

        assert!(
            bastion.outstanding_runs().is_empty(),
            "an unindexed run was never reclaimed: {:?}",
            bastion.outstanding_runs()
        );
    }

    /// A foreign run must not be distinguishable from one that never existed,
    /// and *how long the answer takes* is part of the answer. Deciding after
    /// the wait would have a running foreign run take the caller's whole wait
    /// while a made-up identifier came back at once, which tells whoever asked
    /// that the run is real and still going.
    #[tokio::test]
    async fn a_foreign_run_and_a_made_up_one_answer_alike_and_as_quickly() {
        let bastion = impatient().await;
        let mine = session_for(&bastion, AccessClass::ReadOnly).await;
        let theirs = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &mine.id, argv(&["sleep", "5"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run");
        };
        assert!(outcome.still_running(), "the run must still be going");

        let wait = Duration::from_secs(2);
        let started = Instant::now();
        let foreign = bastion
            .poll(&alice(), &theirs.id, outcome.run(), wait)
            .await
            .expect_err("another session read this run");
        let took = started.elapsed();

        let started = Instant::now();
        let absent = bastion
            .poll(&alice(), &theirs.id, &RunId::from_raw("no-such-run"), wait)
            .await
            .expect_err("a run that does not exist");
        let absent_took = started.elapsed();

        // The same answer - each echoes back the identifier it was handed,
        // which is the caller's own input and says nothing about what exists.
        assert!(
            matches!(foreign, MediationError::Run(RunError::Unknown { .. })),
            "a foreign run answered differently: {foreign:?}"
        );
        assert!(
            matches!(absent, MediationError::Run(RunError::Unknown { .. })),
            "an absent run answered differently: {absent:?}"
        );
        assert!(
            took < wait / 4 && absent_took < wait / 4,
            "the answer waited on the run: foreign {took:?}, absent {absent_took:?}"
        );
    }

    /// A session can stop existing without anybody closing it, and each one
    /// holds a connection to a target. A caller that lets sessions lapse and
    /// opens new ones would otherwise leave a connection behind every time.
    #[tokio::test]
    async fn a_session_that_no_longer_exists_does_not_keep_its_connection() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;

        let lapsed = session_for(&bastion, AccessClass::ReadOnly).await;
        assert_eq!(bastion.held_connections(), 1);

        // Past its whole life and its grace, so the store gives up on it.
        clock.advance(LIFETIME.max + LIFETIME.grace + 1);
        let fresh = session_for(&bastion, AccessClass::ReadOnly).await;

        assert_ne!(fresh.id, lapsed.id);
        assert_eq!(
            bastion.held_connections(),
            1,
            "the lapsed session's connection is still held"
        );

        // And a session the store drops by another route - here, its owner
        // returning after the grace - is reconciled the same way, because what
        // is asked is which sessions exist rather than which just went away.
        clock.advance(LIFETIME.max + LIFETIME.grace + 1);
        assert!(
            bastion
                .exec(&alice(), &fresh.id, argv(&["uptime"]))
                .await
                .is_err()
        );
        let third = session_for(&bastion, AccessClass::ReadOnly).await;

        assert_ne!(third.id, fresh.id);
        assert_eq!(
            bastion.held_connections(),
            1,
            "a session dropped by another route kept its connection"
        );
    }

    /// A lapsed session is remembered past its expiry so its owner is told what
    /// happened, but it refuses every command from the instant it lapses. Its
    /// connection is therefore already good for nothing, and holding it until
    /// the store stops remembering keeps an authenticated connection to a
    /// target open for a session nothing can ever use.
    #[tokio::test]
    async fn a_lapsed_session_gives_up_its_connection_before_it_is_forgotten() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;

        let lapsed = session_for(&bastion, AccessClass::ReadOnly).await;
        assert_eq!(bastion.held_connections(), 1);

        // Idle past its bound but inside the grace, so the store still has it.
        clock.advance(LIFETIME.idle + 1);
        let fresh = session_for(&bastion, AccessClass::ReadOnly).await;

        assert_ne!(fresh.id, lapsed.id);
        assert_eq!(
            bastion.held_connections(),
            1,
            "a session that is remembered but unusable kept its connection"
        );

        // And it was still remembered when that happened: reaching it says it
        // lapsed and what it was for, which is the answer only a session the
        // store still holds can give.
        let err = bastion
            .exec(&alice(), &lapsed.id, argv(&["uptime"]))
            .await
            .expect_err("a lapsed session runs nothing");
        assert!(
            matches!(err, MediationError::Session(SessionError::Expired { .. })),
            "unexpected error: {err:?}"
        );
    }

    /// A run identifier is not a capability. Owning some session is not owning
    /// every run, and a caller holding an identifier from elsewhere learns
    /// nothing about it - not its output, and not that it exists.
    #[tokio::test]
    async fn a_run_belongs_to_the_session_that_started_it() {
        let bastion = impatient().await;
        let mine = session_for(&bastion, AccessClass::ReadOnly).await;
        let theirs = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &mine.id, argv(&["sleep", "5"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("expected a run, got {executed:?}");
        };

        let err = bastion
            .poll(
                &alice(),
                &theirs.id,
                outcome.run(),
                Duration::from_millis(20),
            )
            .await
            .expect_err("another session read this run");
        assert!(
            matches!(err, MediationError::Run(RunError::Unknown { .. })),
            "got {err:?}"
        );
    }

    /// Output reaches the record and is then let go. Holding it a second time
    /// would mean the service kept every command any caller ever ran, which a
    /// caller can turn into memory exhaustion by running permitted work.
    #[tokio::test]
    async fn a_finished_run_is_released_once_it_is_recorded() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        for _ in 0..3 {
            let executed = bastion
                .exec(&alice(), &session.id, argv(&["uptime"]))
                .await
                .unwrap();
            let Executed::Ran { outcome, .. } = executed else {
                panic!("expected a run");
            };
            assert!(!outcome.still_running());
        }

        assert!(
            bastion.outstanding_runs().is_empty(),
            "finished runs are still held: {:?}",
            bastion.outstanding_runs()
        );
    }

    /// The whole promise, end to end: an agent names a host, a role and a
    /// purpose, asks for a read, and gets output from a real target it never
    /// held a credential for.
    #[tokio::test]
    async fn a_permitted_command_runs_and_is_recorded() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["uptime"]))
            .await
            .unwrap();
        let Executed::Ran { outcome, .. } = executed else {
            panic!("a read should have run: {executed:?}");
        };
        assert!(!outcome.stdout().text.is_empty(), "no output came back");

        // Opened, decided, completed — and the chain holds.
        let entries = bastion.ledger().entries();
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0].event, Event::SessionOpened { .. }));
        assert!(matches!(entries[1].event, Event::Decided { .. }));
        assert!(matches!(entries[2].event, Event::Completed { .. }));
        assert!(bastion.ledger().verify().is_ok());
    }

    /// The human-in-the-loop path, end to end and against a real target: a
    /// command policy holds does not run, a human agrees, and the *service*
    /// then runs it. The agent holds nothing in between and presents nothing to
    /// collect the answer — it sends the same command again.
    /// A human refusing a command is a decision somebody made, and it is the
    /// one that leaves nothing else behind: no run, no completion, no
    /// agreement to spend. Recorded when it is given, or the only trace of an
    /// operator saying no would be a command that never appears again.
    #[tokio::test]
    async fn a_refusal_by_a_human_is_recorded_when_it_is_given() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };

        bastion
            .decide(
                &asked.asked().id,
                Approver::Override {
                    who: "chris".to_owned(),
                    because: "nobody on call answered".to_owned(),
                },
                false,
            )
            .unwrap();

        let entries = bastion.ledger().entries();
        let answer = entries
            .iter()
            .find_map(|entry| match &entry.event {
                Event::Answered {
                    decided,
                    approver,
                    override_of,
                    agreed,
                    ..
                } => Some((*decided, approver.clone(), override_of.clone(), *agreed)),
                _ => None,
            })
            .expect("a human's answer was not recorded at all");

        let (decided, approver, override_of, agreed) = answer;
        assert!(!agreed, "a refusal was recorded as an agreement");
        assert_eq!(approver, "chris");
        assert_eq!(
            override_of.as_deref(),
            Some("nobody on call answered"),
            "the reason a break-glass was taken was not kept"
        );
        assert!(
            matches!(
                entries[usize::try_from(decided).unwrap()].event,
                Event::Decided { .. }
            ),
            "the answer does not name the deliberation it answered"
        );
        assert!(bastion.ledger().verify().is_ok());
    }

    /// One click can answer for a whole session. The command in front of the
    /// operator is approved by them; their standing agreement then answers
    /// each later held command in that session - individually recorded and
    /// redeemed in their name - while another session still waits, and a
    /// withdrawal makes the next command wait for a person again.
    #[tokio::test]
    async fn a_standing_agreement_answers_for_its_session_alone() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };

        let agreement = bastion
            .approve_session(&asked.asked().id, "chris".to_owned(), None)
            .unwrap();

        // The triggering command redeems the operator's own approval: they
        // saw it, so it is theirs, not the agreement's.
        let retried = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::Ran { approved_by, .. } = retried else {
            panic!("the approved command did not run: {retried:?}");
        };
        assert_eq!(
            approved_by,
            Some(Approver::Human {
                who: "chris".to_owned()
            })
        );

        // A command nobody was asked about runs on the standing agreement,
        // in the operator's name, and the record says so as a fact of its
        // own.
        let unasked = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "echo two"]))
            .await
            .unwrap();
        let Executed::Ran { approved_by, .. } = unasked else {
            panic!("the standing agreement did not answer: {unasked:?}");
        };
        assert_eq!(
            approved_by,
            Some(Approver::SessionStanding {
                who: "chris".to_owned(),
                agreement: agreement.clone()
            })
        );
        assert!(
            bastion.ledger().entries().iter().any(|entry| matches!(
                &entry.event,
                Event::Answered {
                    standing: true,
                    mode: crate::audit::ApprovalMode::Session,
                    agreement: Some(recorded),
                    agreed: true,
                    ..
                } if recorded == agreement.as_str()
            )),
            "no recorded answer names the standing agreement"
        );

        // Another session is not covered: the agreement is about one
        // session's work, not the operator's account.
        let other = session_for(&bastion, AccessClass::Privileged).await;
        let elsewhere = bastion
            .exec(&alice(), &other.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        assert!(
            matches!(elsewhere, Executed::AwaitingApproval { .. }),
            "a standing agreement crossed sessions: {elsewhere:?}"
        );

        // Withdrawn, the next held command waits for a person again.
        assert!(bastion.revoke_standing(&agreement));
        let after = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "echo three"]))
            .await
            .unwrap();
        assert!(
            matches!(after, Executed::AwaitingApproval { .. }),
            "a withdrawn agreement still answered: {after:?}"
        );
        assert!(bastion.ledger().verify().is_ok());
    }

    /// A standing agreement is bounded twice: by the time its grantor chose,
    /// and - whatever they chose - by when the session's own age will end it,
    /// so an agreement given late in a session cannot claim or display more
    /// time than the session has.
    #[tokio::test]
    async fn a_standing_agreement_expires_when_its_time_is_up() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        // A third of the session's idle bound in, the default grant reaches
        // only to the session's end - not a full maximum lifetime from now.
        clock.advance(200_000);
        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        let agreement = bastion
            .approve_session(&asked.asked().id, "chris".to_owned(), None)
            .unwrap();
        let remaining = bastion
            .standing_approvals()
            .first()
            .map(|(_, remaining)| *remaining)
            .expect("the agreement is not offered");
        assert_eq!(
            remaining,
            LIFETIME.max - 200_000,
            "the agreement claims more time than the session has"
        );
        bastion.revoke_standing(&agreement);

        // A chosen time shorter than the session bounds it instead.
        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "echo again"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        bastion
            .approve_session(&asked.asked().id, "chris".to_owned(), Some(60_000))
            .unwrap();

        clock.advance(60_001);
        let after = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "echo late"]))
            .await
            .unwrap();
        assert!(
            matches!(after, Executed::AwaitingApproval { .. }),
            "an expired agreement still answered: {after:?}"
        );
        assert!(
            bastion.standing_approvals().is_empty(),
            "an expired agreement was still offered for withdrawal"
        );
    }

    /// An agreement nothing collected in time is said out loud.
    ///
    /// The window is what the agreement meant, so nothing runs on one that has
    /// outlived it. What the attempt finding it gone is owed is the reason:
    /// handed a fresh request it cannot tell from the first, an agent asks
    /// again in silence, and the person who agreed is never told that what
    /// they allowed did not happen.
    #[tokio::test]
    async fn an_agreement_nothing_collected_in_time_is_reported_as_lapsed() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        bastion
            .decide(
                &asked.asked().id,
                Approver::Human {
                    who: "chris".to_owned(),
                },
                true,
            )
            .unwrap();

        // Past the window that agreement was redeemable in, then through the
        // housekeeping that runs on its own schedule, and then long enough
        // afterwards that no window of its own could still be holding the
        // record. Being told does not depend on an agent retrying inside some
        // interval it cannot see: a length of silence during which the answer
        // reads as never given is exactly what this reports, so there is no
        // defensible length. The session is the bound.
        clock.advance(60_001);
        bastion.reclaim().await;
        clock.advance(400_000);
        bastion.reclaim().await;
        let late = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::ApprovalLapsed {
            asked: again,
            lapsed_from,
            ..
        } = late
        else {
            panic!("a lapsed agreement was not reported as one: {late:?}");
        };
        assert_eq!(
            lapsed_from,
            Approver::Human {
                who: "chris".to_owned()
            },
            "the lapse does not name who had agreed"
        );
        assert_ne!(
            again.asked().id,
            asked.asked().id,
            "a lapsed request was handed back instead of a fresh one to answer"
        );
        assert!(
            !bastion
                .ledger()
                .entries()
                .iter()
                .any(|entry| matches!(&entry.event, Event::Completed { .. })),
            "a lapsed agreement still ran the command"
        );

        // Said once. The attempt that was owed the answer has had it, and the
        // request now waiting is an ordinary one: repeating the lapse would
        // describe an agreement that is no longer anybody's business.
        let after = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        assert!(
            matches!(after, Executed::AwaitingApproval { .. }),
            "a lapse already reported was reported again: {after:?}"
        );
        assert!(bastion.ledger().verify().is_ok());
    }

    /// A standing agreement answers a retry whose own approval lapsed.
    ///
    /// Lapsing changes what a caller is told, never who may answer. An
    /// operator who agreed to the rest of the session has already answered
    /// this question, so putting it back in front of them because an earlier
    /// click went uncollected would be asking twice for one decision.
    #[tokio::test]
    async fn a_standing_agreement_answers_a_retry_whose_own_approval_lapsed() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        bastion
            .decide(
                &asked.asked().id,
                Approver::Human {
                    who: "chris".to_owned(),
                },
                true,
            )
            .unwrap();

        // That click goes uncollected, and the operator then agrees to the
        // rest of the session on a different command.
        clock.advance(60_001);
        let other = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "echo two"]))
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked: other, .. } = other else {
            panic!("expected the second command to be held, got {other:?}");
        };
        let agreement = bastion
            .approve_session(&other.asked().id, "chris".to_owned(), None)
            .unwrap();

        let retried = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        let Executed::Ran { approved_by, .. } = retried else {
            panic!("the standing agreement did not answer a lapsed retry: {retried:?}");
        };
        assert_eq!(
            approved_by,
            Some(Approver::SessionStanding {
                who: "chris".to_owned(),
                agreement
            }),
            "the run is not attributed to the standing agreement"
        );
        assert!(bastion.ledger().verify().is_ok());
    }

    /// A request outlives nothing. Once the session it was asked about has
    /// gone, no retry can redeem an agreement about it, so continuing to offer
    /// it to a human is asking somebody to decide something that could not
    /// happen either way.
    #[tokio::test]
    async fn requests_about_a_closed_session_are_not_still_offered() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        assert!(
            matches!(held, Executed::AwaitingApproval { .. }),
            "expected the command to be held, got {held:?}"
        );
        assert_eq!(bastion.waiting_for_approval().len(), 1);

        bastion.close_session(&alice(), &session.id).await.unwrap();

        assert!(
            bastion.waiting_for_approval().is_empty(),
            "a request about a session that no longer exists was still offered"
        );
        assert_eq!(
            bastion.requests_held(),
            0,
            "a request nothing could redeem was kept anyway"
        );
    }

    /// A recording boundary the test can fail on demand, standing in for the
    /// flushed stdout write production selects.
    struct FlakyBoundary(std::sync::atomic::AtomicBool);

    impl FlakyBoundary {
        fn healthy() -> Arc<Self> {
            Arc::new(Self(std::sync::atomic::AtomicBool::new(false)))
        }
        fn fail_now(&self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        fn recover(&self) {
            self.0.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Records for FlakyBoundary {
        fn wrote(&self, _entry: &crate::audit::Entry) -> Result<(), crate::audit::NotRecorded> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Err(crate::audit::NotRecorded)
            } else {
                Ok(())
            }
        }
    }

    /// A human's agreement is worth nothing until the record has accepted the
    /// answer. When the recording boundary refuses it, the decision reports
    /// the audit failure, the agent's retry keeps waiting rather than
    /// collecting the agreement, and nothing reaches the target on the
    /// strength of an approval the record has no entry for.
    #[tokio::test]
    async fn an_agreement_the_record_refused_never_runs_anything() {
        let boundary = FlakyBoundary::healthy();
        let bastion = bastion_recording(
            Arc::new(SystemClock::new().expect("a boot clock")),
            Limits::default(),
            Some(Arc::clone(&boundary) as Arc<dyn Records>),
        )
        .await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let mut bytes = [0_u8; 8];
        rand::fill(&mut bytes);
        let probe = std::env::temp_dir().join(format!(
            "mcp-ssh-unrecorded-{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let argv = argv(&["sh", "-c", &format!("touch {}", probe.display())]);

        let held = bastion
            .exec(&alice(), &session.id, argv.clone())
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };

        // The boundary goes down at exactly the moment the answer arrives.
        boundary.fail_now();
        let refused = bastion
            .decide(
                &asked.asked().id,
                Approver::Human {
                    who: "chris".to_owned(),
                },
                true,
            )
            .unwrap_err();
        assert!(
            matches!(refused, MediationError::Audit(_)),
            "the refused record was reported as something else: {refused:?}"
        );

        // The boundary recovers, but the unrecorded agreement stays worthless:
        // the retry is told to keep waiting, and nothing has run.
        boundary.recover();
        let retry = bastion.exec(&alice(), &session.id, argv).await.unwrap();
        assert!(
            matches!(retry, Executed::AwaitingApproval { .. }),
            "a retry collected an agreement the record refused: {retry:?}"
        );
        assert!(
            !probe.exists(),
            "a command ran on an approval the record has no entry for"
        );
        assert!(
            bastion
                .ledger()
                .entries()
                .iter()
                .all(|entry| !matches!(entry.event, Event::Answered { .. })),
            "the record holds an answer it refused"
        );
    }

    /// A request nobody answered stops occupying the service. Asking collects
    /// what has lapsed, but a service nobody is asking anything is exactly when
    /// that never runs — and until it does, a request keeps a command line and
    /// the identity of whoever wanted it run.
    #[tokio::test]
    async fn requests_nobody_answered_are_let_go_of() {
        let clock = Arc::new(TestClock::at(1_000));
        let bastion = bastion_with(Arc::clone(&clock), Limits::default()).await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        let held = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", "true"]))
            .await
            .unwrap();
        assert!(
            matches!(held, Executed::AwaitingApproval { .. }),
            "expected the command to be held, got {held:?}"
        );
        assert_eq!(bastion.requests_held(), 1);

        // Nobody answers, and the window to answer closes.
        clock.advance(300_001);
        assert!(
            bastion.waiting_for_approval().is_empty(),
            "a request past its window was still offered for an answer"
        );

        bastion.reclaim().await;
        assert_eq!(
            bastion.requests_held(),
            0,
            "a request nobody can answer was kept anyway"
        );
    }

    /// Whether an ask created the request survives mediation: whatever
    /// announces a held command must be able to tell a fresh hold from a
    /// retry joining one, or every retry would page a human again.
    #[tokio::test]
    async fn a_retry_joins_the_request_rather_than_creating_one() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;
        let argv = argv(&["sh", "-c", "true"]);

        let held = bastion
            .exec(&alice(), &session.id, argv.clone())
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        assert!(asked.is_new());

        let again = bastion.exec(&alice(), &session.id, argv).await.unwrap();
        let Executed::AwaitingApproval { asked: retry, .. } = again else {
            panic!("expected the retry to keep waiting, got {again:?}");
        };
        assert!(
            !retry.is_new(),
            "a retry claimed to have created the request"
        );
        assert_eq!(retry.asked().id, asked.asked().id);
    }

    #[tokio::test]
    async fn a_held_command_runs_once_a_human_agrees_and_not_twice() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        // Named freshly, so what this observes is this command's effect rather
        // than a leftover from an earlier run.
        let mut bytes = [0_u8; 8];
        rand::fill(&mut bytes);
        let probe = std::env::temp_dir().join(format!(
            "mcp-ssh-approved-{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let argv = argv(&["sh", "-c", &format!("touch {}", probe.display())]);

        let held = bastion
            .exec(&alice(), &session.id, argv.clone())
            .await
            .unwrap();
        let Executed::AwaitingApproval { asked, .. } = held else {
            panic!("expected the command to be held, got {held:?}");
        };
        assert!(
            !probe.exists(),
            "the command ran before anybody had agreed to it"
        );
        assert_eq!(bastion.waiting_for_approval().len(), 1);

        bastion
            .decide(
                &asked.asked().id,
                Approver::Human {
                    who: "chris".to_owned(),
                },
                true,
            )
            .unwrap();

        // The agent asks again, and this time the service runs it.
        let ran = bastion
            .exec(&alice(), &session.id, argv.clone())
            .await
            .unwrap();
        let Executed::Ran { approved_by, .. } = ran else {
            panic!("expected the approved command to run, got {ran:?}");
        };
        assert!(
            approved_by.is_some(),
            "an approved run should name who agreed"
        );
        let ran_at_all = probe.exists();
        let _ = std::fs::remove_file(&probe);
        assert!(ran_at_all, "the approved command did not run");

        // And the agreement is spent: asking again holds afresh rather than
        // running a second time under the same one.
        let again = bastion.exec(&alice(), &session.id, argv).await.unwrap();
        assert!(
            matches!(again, Executed::AwaitingApproval { .. }),
            "an approval was redeemed twice: {again:?}"
        );
    }

    /// Work that needs a human does not run, and the fact that it was asked for
    /// is recorded anyway. What was attempted is usually the more interesting
    /// half of an incident.
    #[tokio::test]
    async fn work_needing_approval_does_not_run_but_is_still_recorded() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::Privileged).await;

        // Named freshly each run, so what this observes is this command's
        // effect. A fixed name would let a leftover from an earlier run, or
        // another test running beside this one, decide the answer.
        let mut bytes = [0_u8; 8];
        rand::fill(&mut bytes);
        let untouched = std::env::temp_dir().join(format!(
            "mcp-ssh-should-not-exist-{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let touch = format!("touch {}", untouched.display());

        let executed = bastion
            .exec(&alice(), &session.id, argv(&["sh", "-c", &touch]))
            .await
            .unwrap();
        assert!(
            matches!(executed, Executed::AwaitingApproval { .. }),
            "got {executed:?}"
        );
        // Removed either way: if approval leaked and the command ran, the file
        // is this test's to clean up rather than the next run's to trip over.
        let ran = untouched.exists();
        let _ = std::fs::remove_file(&untouched);
        assert!(!ran, "the command ran while waiting for approval");

        let entries = bastion.ledger().entries();
        assert!(
            matches!(entries[1].event, Event::Decided { .. }),
            "the attempt was not recorded"
        );
        assert_eq!(entries.len(), 2, "nothing was recorded as having completed");
    }

    /// Invariant 3 at the surface a caller actually touches: holding another
    /// principal's session identifier is not enough to use it, and the answer
    /// is the same one given for a session that never existed.
    #[tokio::test]
    async fn another_principal_cannot_drive_the_session() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        let bob = PrincipalId::parse("bob").unwrap();

        let err = bastion
            .exec(&bob, &session.id, argv(&["uptime"]))
            .await
            .unwrap_err();
        assert_eq!(err, MediationError::Session(SessionError::Unknown));

        // And nothing was decided, recorded, or run on their behalf.
        assert_eq!(
            bastion.ledger().entries().len(),
            1,
            "only the session opening should be recorded"
        );
    }

    /// A host that cannot be verified fails while the caller is still asking
    /// for access, not in the middle of work it believed was authorized.
    #[tokio::test]
    async fn a_host_that_cannot_be_reached_fails_at_open() {
        let bastion = bastion().await;
        let err = bastion
            .open_session(
                alice(),
                HostId::parse("nowhere").unwrap(),
                RoleId::parse("readonly").unwrap(),
                Purpose::parse("check something").unwrap(),
                AccessClass::ReadOnly,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MediationError::Resolve(_)), "got {err:?}");
    }

    /// Closing releases the session and its connection, and the record says the
    /// session ended.
    #[tokio::test]
    async fn closing_ends_the_session_and_records_it() {
        let bastion = bastion().await;
        let session = session_for(&bastion, AccessClass::ReadOnly).await;
        bastion.close_session(&alice(), &session.id).await.unwrap();

        let entries = bastion.ledger().entries();
        assert!(matches!(
            entries[entries.len() - 1].event,
            Event::SessionClosed
        ));
        // `Executed` is not comparable - it carries a decision and an outcome,
        // neither of which is a value to compare - so the error is matched.
        let err = bastion
            .exec(&alice(), &session.id, argv(&["uptime"]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, MediationError::Session(SessionError::Unknown)),
            "got {err:?}"
        );
    }

    /// Discovery reports what is configured, which is what a caller needs in
    /// order to name a host at all.
    #[tokio::test]
    async fn discovery_reports_configured_hosts_and_roles() {
        let bastion = bastion().await;
        let inventory = bastion.inventory();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].0.as_str(), "dns1");
        let roles: std::collections::BTreeSet<_> =
            inventory[0].1.iter().map(|role| role.as_str()).collect();
        assert_eq!(
            roles,
            std::collections::BTreeSet::from(["operator", "readonly"])
        );
    }
}
