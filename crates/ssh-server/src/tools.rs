//! The tools an agent can call, and what calling them means.
//!
//! Five, and no more than five: name the hosts you could reach, open a session,
//! run something, ask again about something slow, and give the session back.
//! Typed per-operation tools were considered and deferred — until real traffic
//! says which operations matter, a larger surface is a guess with maintenance
//! attached.
//!
//! # Identity is not an argument
//!
//! No tool takes a principal. The caller does not get to say who it is: the
//! principal arrives from HTTP authentication and is handed to [`dispatch`]
//! separately from the arguments. A tool schema that accepted one would make
//! impersonation a matter of typing.
//!
//! # A refusal is a result, not an error
//!
//! Policy declining a command is an ordinary answer and comes back as one, with
//! the reason. An MCP error means the service could not reach a decision — a
//! host that will not answer, a record that could not be written. An agent
//! should retry the second and never the first, and collapsing them would make
//! that impossible to tell.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult, Tool, ToolAnnotations,
};
use rmcp::{ErrorData as McpError, model::JsonObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ssh_core::clock::Clock;
use ssh_core::command::CommandIntent;
use ssh_core::connect::{ConnectError, CredentialSource};
use ssh_core::mediate::{Bastion, Executed, MediationError};
use ssh_core::run::RunId;
use ssh_core::session::{Purpose, SessionId};
use ssh_core::{HostId, RoleId, Scope};

use crate::mcp::AuthenticatedPrincipal;

pub const HOSTS: &str = "ssh_hosts";
pub const OPEN_SESSION: &str = "ssh_open_session";
pub const EXEC: &str = "ssh_exec";
pub const POLL: &str = "ssh_poll";
pub const CLOSE_SESSION: &str = "ssh_close_session";

/// How long `poll` waits before answering "still running" again.
const POLL_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenSessionArgs {
    /// The host to work on, as named by `ssh_hosts`.
    pub host: String,
    /// Which role to act as on that host.
    pub role: String,
    /// What this session is for, in a sentence.
    ///
    /// A human may be asked to approve work in this session, and this is what
    /// they are shown. "Investigating" is not a purpose.
    pub purpose: String,
    /// The most privileged class of work this session may perform.
    ///
    /// A ceiling, not a grant: every command is still decided individually, and
    /// asking for more than the work needs makes approval harder, not easier.
    pub scope: ScopeArg,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScopeArg {
    Read,
    Mutate,
    Privileged,
}

impl From<ScopeArg> for Scope {
    fn from(arg: ScopeArg) -> Self {
        match arg {
            ScopeArg::Read => Self::Read,
            ScopeArg::Mutate => Self::Mutate,
            ScopeArg::Privileged => Self::Privileged,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecArgs {
    /// The session to run in, exactly as `ssh_open_session` returned it.
    pub session: String,
    /// What this command is intended to accomplish.
    ///
    /// Written by the calling agent, shown to reviewers, and recorded for
    /// audit and advisory evaluation. It is not trusted user intent.
    pub intent: String,
    /// The command, as a program followed by its arguments.
    ///
    /// Not a shell line. Each element is one argument and reaches the target as
    /// one argument, whatever it contains — so `["grep", "a b"]` searches for
    /// `a b` rather than for `a` in a file called `b`.
    pub command: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PollArgs {
    /// The session the command was run in, exactly as `ssh_open_session`
    /// returned it.
    pub session: String,
    /// The run identifier from an earlier `ssh_exec` that had not finished,
    /// exactly as it was returned. Identifiers are issued by this service and
    /// are not constructed by a caller.
    pub run: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseSessionArgs {
    /// The session to end, exactly as `ssh_open_session` returned it.
    pub session: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SessionOpened {
    pub session: String,
    pub host: String,
    pub role: String,
    pub scope: ScopeArg,
}

/// What an agent is told about one of a command's streams.
///
/// The same two answers the record gives, for the same reason: output that was
/// recognised as credential-shaped is described rather than handed over, and a
/// caller is told that is what happened. Returning an empty string instead
/// would say the target produced nothing, which is a different fact and a
/// wrong one.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "kept", rename_all = "snake_case")]
pub enum StreamOut {
    /// What the target produced, up to what is retained.
    Text {
        text: String,
        /// True when the target produced more than was kept.
        truncated: bool,
        /// How much the target produced, including anything not kept.
        bytes: u64,
    },
    /// Recognised as credential-shaped and deliberately not returned.
    ///
    /// Asking again will not produce it. Whatever the command was reaching for
    /// is not something this service hands to a caller.
    Withheld { bytes: u64, matched: String },
    /// Still arriving. How much so far, and nothing else yet.
    ///
    /// Whether a stream is credential-shaped is decided from all of it, and a
    /// command that is still running has not produced all of it: the marker
    /// that would withhold a private key can arrive in the next packet, after
    /// the lines before it have already been handed over. Bytes given to an
    /// agent cannot be taken back, so none are given until the stream is
    /// complete and what it is has been settled.
    Pending { bytes: u64 },
}

impl StreamOut {
    /// A stream from a command still going: how much, and nothing else.
    const fn pending(stream: &ssh_core::run::Stream) -> Self {
        Self::Pending {
            bytes: stream.bytes,
        }
    }

    /// A stream from a run that has settled, which is the only kind that can be
    /// released: whether it is credential-shaped is decided from all of it, and
    /// until the command is over there is no all of it.
    fn released(stream: &ssh_core::run::Stream) -> Self {
        match stream.matched {
            Some(matched) => Self::Withheld {
                // What the target produced, not what survived the retention
                // bound: a count describing only the kept prefix understates
                // what is missing whenever the stream was also truncated.
                bytes: stream.bytes,
                matched: matched.to_owned(),
            },
            None => Self::Text {
                text: stream.text.clone(),
                truncated: stream.truncated,
                bytes: stream.bytes,
            },
        }
    }
}

/// What an agent is told about a command it asked to run.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExecResult {
    /// It ran, and it is over.
    ///
    /// Only a command the target took and finished with is reported this way,
    /// so `ran` can be read as meaning what it says.
    Ran {
        run: String,
        /// Absent when the command ended without the target reporting one.
        exit: Option<u32>,
        stdout: StreamOut,
        stderr: StreamOut,
        why: String,
    },
    /// Still going. Ask again with `ssh_poll`.
    ///
    /// This does not say the command started: a target may be producing output,
    /// or may have taken the request and said nothing yet. Both are the same
    /// instruction — ask again, and do not send it a second time — so they are
    /// the same answer, and neither is `ran`.
    ///
    /// Output is not released while a command is going: what a stream is cannot
    /// be decided from part of it.
    StillRunning {
        run: String,
        stdout: StreamOut,
        stderr: StreamOut,
        why: String,
    },
    /// The target would not start it, and said so. Nothing ran.
    ///
    /// Distinct from `ran` because a caller told a command completed will not
    /// think to send it again, and distinct from `refused` because policy
    /// permitted this one — the target declined it.
    NotStarted { run: String, why: String },
    /// Nobody said whether it ran.
    ///
    /// The connection ended without the target answering, producing output, or
    /// reporting a status. The command may have run and may not have.
    ///
    /// **Do not simply send it again.** Look at what it would have changed, or
    /// ask a human, before repeating anything that is not safe to do twice.
    /// This is reported rather than guessed at because both guesses are wrong
    /// in ways a caller cannot see.
    Unknown { run: String, why: String },
    /// It has not run, and will not until a human agrees.
    ///
    /// There is nothing to poll: no run was started. Ask again with the same
    /// command once a human has decided — that is how the answer is found, and
    /// asking again does not queue a second request for them to wade through.
    AwaitingApproval {
        /// Names the request a human will answer, for anyone tracking it. It is
        /// not needed to collect the answer: sending the command again is.
        request: String,
        why: String,
        /// Where a person decides, when this deployment has named its approval
        /// page: the page's address with this request's identifier as the
        /// fragment. Tell the person you act for that their decision is waited
        /// on here. Holding this address moves nothing - deciding there takes
        /// their own sign-on, which is the point. Absent when no page is
        /// named; the request still waits, and a person with access still
        /// sees it.
        #[serde(skip_serializing_if = "Option::is_none")]
        decide_at: Option<String>,
    },
    /// A person agreed, their agreement expired before this collected it, and
    /// the command has **not** run.
    ///
    /// Nothing was lost but the answer: `request` names a fresh one now waiting,
    /// and sending the command again is still how the answer is found. Say this
    /// to the person you act for rather than quietly asking them again — they
    /// have no other way to learn that what they allowed never happened, and
    /// the second question looks identical to the first.
    ApprovalLapsed {
        request: String,
        why: String,
        /// Where a person decides, on the same terms as `awaiting_approval`:
        /// the page's address with the new request as the fragment.
        #[serde(skip_serializing_if = "Option::is_none")]
        decide_at: Option<String>,
    },
    /// It has not run and will not.
    ///
    /// Policy declined it - including a command the catalog could not read in
    /// a session whose scope does not reach the maximal assessment such a
    /// command carries; `why` says what would have to be different. It is a
    /// decision about the command that was sent, and sending it again in the
    /// same session gets the same answer.
    Refused { why: String },
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HostsResult {
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HostEntry {
    pub host: String,
    pub roles: Vec<String>,
}

/// The tools this service publishes.
///
/// Annotations describe consequences honestly. `ssh_exec` is not read-only and
/// is not idempotent, because it can be neither: what a command does is the
/// command's business, and a surface that claimed otherwise would be telling a
/// client it is safe to retry things that are not.
pub fn catalog() -> ListToolsResult {
    ListToolsResult {
        next_cursor: None,
        meta: None,
        tools: vec![
            tool::<Empty, HostsResult>(
                HOSTS,
                "Hosts this service can reach, and the roles available on each. \
                 A role's presence means it is configured, not that policy will \
                 permit any particular command with it.",
                ToolAnnotations::new()
                    .read_only(true)
                    .idempotent(true)
                    .open_world(false),
            ),
            tool::<OpenSessionArgs, SessionOpened>(
                OPEN_SESSION,
                "Open a session on a host as a role, for a stated purpose. \
                 Connects and verifies the host immediately, so a host that \
                 cannot be reached fails here rather than mid-command. \
                 Sessions expire; close one when the work is done.",
                ToolAnnotations::new()
                    .read_only(false)
                    // Additive: it creates a session and takes a connection,
                    // and destroys nothing. Left unsaid, the protocol's default
                    // is the cautious one, and a client would confirm a call
                    // that needs no confirming.
                    .destructive(false)
                    .idempotent(false)
                    .open_world(true),
            ),
            tool::<ExecArgs, ExecResult>(
                EXEC,
                "Run a command in a session. The command is an argument vector, \
                 not a shell line. Include what this command is intended to \
                 accomplish; that explanation is shown and recorded as \
                 agent-supplied evidence, not trusted user intent. Every command \
                 is authorized individually: it may run, may be refused, or may \
                 need a human to approve it - and a held answer names the page \
                 where a person decides, when this deployment has one, so you \
                 can tell the person you act for. Send the exact same command \
                 and intent again to collect their answer, and keep asking while \
                 it waits: an agreement nobody collects in time lapses, and the \
                 answer then says whose it was so you can tell them it did not \
                 happen. A command that outlives its wait returns a run \
                 identifier to poll.",
                ToolAnnotations::new()
                    .read_only(false)
                    .destructive(true)
                    .idempotent(false)
                    .open_world(true),
            ),
            tool::<PollArgs, ExecResult>(
                POLL,
                "Ask again about a command that had not finished. Waits briefly \
                 and returns the same shape as ssh_exec. A finished command is \
                 delivered once: its result is recorded and released, so asking \
                 again about a run you have already collected says it is \
                 unknown. Keep what you were given.",
                ToolAnnotations::new()
                    // Nothing on the target changes, but the service does: this
                    // is what hands a finished run's output over, and what then
                    // lets go of it. Claiming idempotence would tell a client
                    // the second call answers like the first, and it does not.
                    .read_only(false)
                    // Destructive of the one thing a caller came for. The
                    // target is untouched, but the result exists once and this
                    // is what spends it — a client that treats the call as free
                    // to repeat after a lost response loses the output.
                    .destructive(true)
                    .idempotent(false)
                    // What it reports is a command running on somebody else's
                    // machine. The bytes are held here by the time they are
                    // handed over, but they are not this service's news.
                    .open_world(true),
            ),
            tool::<CloseSessionArgs, Empty>(
                CLOSE_SESSION,
                "End a session and release its connection. Anything still \
                 running in it goes with the connection, so collect what you \
                 are waiting for first. A session that has already ended is not \
                 a session any more, so closing it again says there is no such \
                 session.",
                ToolAnnotations::new()
                    .read_only(false)
                    // The connection is closed on the wire, and a command still
                    // running on the target goes with it. That is a caller
                    // ending work in progress, which is the thing this hint
                    // exists to make a client stop and think about.
                    .destructive(true)
                    // Idempotent in effect: a second close changes nothing more,
                    // because the session and its connection are already gone.
                    // It is answered as an unknown session rather than as a
                    // repeated success, which the description says.
                    .idempotent(true)
                    // It reaches the target: the connection is closed on the
                    // wire, not merely forgotten here.
                    .open_world(true),
            ),
        ],
    }
}

/// An empty argument or result object.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

fn tool<Input, Output>(
    name: &'static str,
    description: &'static str,
    annotations: ToolAnnotations,
) -> Tool
where
    Input: JsonSchema,
    Output: JsonSchema,
{
    Tool::new(
        Cow::Borrowed(name),
        Cow::Borrowed(description),
        Arc::new(schema_for::<Input>()),
    )
    .with_raw_output_schema(Arc::new(schema_for::<Output>()))
    .with_annotations(annotations)
}

fn schema_for<T: JsonSchema>() -> JsonObject {
    let schema = schemars::schema_for!(T);
    serde_json::to_value(schema)
        .ok()
        .and_then(|value| match value {
            serde_json::Value::Object(object) => Some(object),
            _ => None,
        })
        .unwrap_or_default()
}

/// Routes one tool call at the bastion.
///
/// The principal comes from HTTP authentication, never from the request body.
pub async fn dispatch<C: Clock + 'static, S: CredentialSource>(
    bastion: &Bastion<C, S>,
    notifier: &dyn crate::notify::Notifier,
    dashboard: Option<&url::Url>,
    acting_for: &AuthenticatedPrincipal,
    params: CallToolRequestParams,
) -> Result<CallToolResult, McpError> {
    // Taken as an authenticated identity rather than a bare principal, so nothing
    // outside this crate can call this on behalf of somebody it merely named.
    let principal = acting_for.get();
    let arguments = params.arguments.unwrap_or_default();
    match params.name.as_ref() {
        HOSTS => {
            // Read even though it declares nothing, so that a caller sending
            // fields this tool does not have is told rather than ignored. Every
            // other tool refuses them; discovery skipping the check would make
            // it the one place a made-up argument passes unnoticed.
            let Empty {} = parse(arguments)?;
            let hosts = bastion
                .inventory()
                .into_iter()
                .map(|(host, roles)| HostEntry {
                    host: host.as_str().to_owned(),
                    roles: roles
                        .iter()
                        .map(|role| (*role).as_str().to_owned())
                        .collect(),
                })
                .collect();
            ok(&HostsResult { hosts })
        }
        OPEN_SESSION => {
            let args: OpenSessionArgs = parse(arguments)?;
            let host = HostId::parse(&args.host).map_err(bad_request)?;
            let role = RoleId::parse(&args.role).map_err(bad_request)?;
            let purpose = Purpose::parse(&args.purpose).map_err(bad_request)?;
            let session = match bastion
                .open_session(principal.clone(), host, role, purpose, args.scope.into())
                .await
            {
                Ok(session) => session,
                Err(error) => return Ok(mediation_failure(&error)),
            };
            ok(&SessionOpened {
                session: session.id.as_str().to_owned(),
                host: session.host.as_str().to_owned(),
                role: session.role.as_str().to_owned(),
                scope: args.scope,
            })
        }
        EXEC => {
            let args: ExecArgs = parse(arguments)?;
            let intent = CommandIntent::parse(&args.intent).map_err(bad_request)?;
            match bastion
                .exec_intended(
                    principal,
                    &session_named(&args.session)?,
                    intent,
                    args.command,
                )
                .await
            {
                Ok(executed) => {
                    announce(notifier, dashboard, &executed);
                    ok(&exec_result(executed, dashboard))
                }
                Err(error) => without_an_outcome(&error),
            }
        }
        POLL => {
            let args: PollArgs = parse(arguments)?;
            match bastion
                .poll(
                    principal,
                    &session_named(&args.session)?,
                    &RunId::parse(&args.run).map_err(bad_request)?,
                    POLL_WAIT,
                )
                .await
            {
                Ok(outcome) => ok(&ran(&outcome, "polled".to_owned())),
                Err(error) => without_an_outcome(&error),
            }
        }
        CLOSE_SESSION => {
            let args: CloseSessionArgs = parse(arguments)?;
            match bastion
                .close_session(principal, &session_named(&args.session)?)
                .await
            {
                Ok(()) => ok(&Empty {}),
                Err(error) => Ok(mediation_failure(&error)),
            }
        }
        other => Err(McpError::invalid_params(
            format!("no tool named {other}"),
            None,
        )),
    }
}

/// Tells a human, once, that a command is waiting on them.
///
/// Only for a request this call created. Asking is idempotent - an agent
/// retrying a held command joins the request it already made - so announcing
/// every ask would notify on every retry.
fn announce(
    notifier: &dyn crate::notify::Notifier,
    dashboard: Option<&url::Url>,
    executed: &Executed,
) {
    // A lapsed agreement leaves a genuinely new request behind it, so the
    // person who answered the last one is told about this one. Withholding the
    // note would leave it waiting where nobody was sent to look.
    if let Executed::AwaitingApproval { asked, .. } | Executed::ApprovalLapsed { asked, .. } =
        executed
    {
        announce_ask(notifier, dashboard, asked);
    }
}

/// The once-per-request rule, on the value that carries it.
fn announce_ask(
    notifier: &dyn crate::notify::Notifier,
    dashboard: Option<&url::Url>,
    asked: &ssh_core::approval::Ask,
) {
    if !asked.is_new() {
        return;
    }
    // No dashboard address, no note: a notification whose link goes nowhere is
    // worse than none, because it looks like the way to answer.
    let Some(dashboard) = dashboard else {
        return;
    };
    notifier.waiting(crate::notify::Note::about(asked.asked(), dashboard));
}

fn exec_result(executed: Executed, dashboard: Option<&url::Url>) -> ExecResult {
    match executed {
        Executed::Ran {
            decision,
            outcome,
            approved_by,
        } => {
            // Who agreed is said in the answer, so a run a human allowed is not
            // indistinguishable from one policy allowed outright.
            //
            // Not built from the decision's own words: they describe a command
            // waiting for somebody, which is what it was, not what it is. A
            // caller told that its finished run is still waiting is being
            // invited to ask again for something that already happened.
            let why = match &approved_by {
                Some(who) => held_and(&self::approved_by(who)),
                None => decision.explanation().to_owned(),
            };
            ran(&outcome, why)
        }
        Executed::AwaitingApproval { decision, asked } => ExecResult::AwaitingApproval {
            request: asked.asked().id.as_str().to_owned(),
            why: decision.explanation().to_owned(),
            decide_at: decide_at(dashboard, &asked),
        },
        Executed::ApprovalLapsed {
            asked, lapsed_from, ..
        } => ExecResult::ApprovalLapsed {
            request: asked.asked().id.as_str().to_owned(),
            // Not the decision's own words: they say a command is waiting for
            // somebody, which is true of the new request but says nothing of
            // the answer that was already given and went uncollected. That is
            // the part a caller cannot work out for itself.
            why: held_and(&agreement_lapsed(&lapsed_from)),
            decide_at: decide_at(dashboard, &asked),
        },
        Executed::Refused {
            decision,
            refused_by,
        } => ExecResult::Refused {
            // A person's no is final, and saying it while repeating that the
            // command is waiting for one would read as something still to come
            // back for. Policy's own refusal keeps its own words: it never said
            // anything was pending.
            why: match &refused_by {
                Some(who) => held_and(&said_no(who)),
                None => decision.explanation().to_owned(),
            },
        },
    }
}

/// What became of a command policy held for a person.
///
/// Says that it was held and what was then decided, in the past tense, because
/// by the time either is reported there is nothing left to wait for.
fn held_and(answer: &str) -> String {
    format!("this needed a person's decision, and it was {answer}")
}

/// Who agreed, and whether they were overriding rather than approving.
///
/// An override is not an approval by another name: nobody was reached, and
/// somebody proceeded anyway. Rendering the two alike would hide break-glass
/// use behind an ordinary-looking name on the one surface an agent reads.
fn approved_by(approver: &ssh_core::approval::Approver) -> String {
    match approver {
        ssh_core::approval::Approver::Human { who } => format!("approved by {who}"),
        ssh_core::approval::Approver::Override { who, because } => {
            format!("overridden by {who}: {because}")
        }
        ssh_core::approval::Approver::SessionStanding { who, .. } => {
            format!("approved by {who}'s standing agreement for this session")
        }
        ssh_core::approval::Approver::MatchingStanding { who, .. } => {
            format!("approved by {who}'s standing agreement for matching work")
        }
    }
}

/// Who agreed, and that their agreement went uncollected.
///
/// Names the person rather than the window: what a caller has to pass on is
/// that somebody's decision did not take effect, and whose it was.
fn agreement_lapsed(approver: &ssh_core::approval::Approver) -> String {
    format!(
        "{}, and that agreement expired before it was collected, so the command did not run and is waiting for a person again",
        approved_by(approver)
    )
}

/// Where a person decides, with a request as the fragment.
///
/// The address the note carries, so the person a caller flags lands on the card
/// waiting for them rather than on a list. The identifier is service-minted
/// hex, safe to sit in a URL.
fn decide_at(dashboard: Option<&url::Url>, asked: &ssh_core::approval::Ask) -> Option<String> {
    dashboard.map(|page| {
        let mut page = page.clone();
        page.set_fragment(Some(asked.asked().id.as_str()));
        page.to_string()
    })
}

/// The same, for a refusal.
fn said_no(approver: &ssh_core::approval::Approver) -> String {
    match approver {
        ssh_core::approval::Approver::Human { who } => format!("refused by {who}"),
        ssh_core::approval::Approver::Override { who, because } => {
            format!("refused by {who}: {because}")
        }
        ssh_core::approval::Approver::SessionStanding { who, .. } => {
            format!("refused by {who}'s standing agreement for this session")
        }
        ssh_core::approval::Approver::MatchingStanding { who, .. } => {
            format!("refused by {who}'s standing agreement for matching work")
        }
    }
}

fn ran(outcome: &ssh_core::run::Outcome, why: String) -> ExecResult {
    reported(
        outcome.run(),
        outcome.state(),
        outcome.stdout(),
        outcome.stderr(),
        why,
    )
}

/// What a caller is told about a run, from what the run says about itself.
///
/// Takes the parts rather than the outcome so that what it decides can be
/// asked directly, without a target to run a command against.
fn reported(
    run: &RunId,
    state: ssh_core::run::RunState,
    stdout: &ssh_core::run::Stream,
    stderr: &ssh_core::run::Stream,
    why: String,
) -> ExecResult {
    use ssh_core::run::RunState;
    // What the target said, said back. Only a run that reached the target and
    // produced something is reported as one that ran; the other two answers are
    // separate because what a caller should do next differs, and a `ran` with
    // no exit status and empty output is what a command that ran and printed
    // nothing looks like too.
    match state {
        // The target answered the request negatively: it did not happen, and
        // sending it elsewhere is safe.
        RunState::Refused => {
            return ExecResult::NotStarted {
                run: run.as_str().to_owned(),
                why,
            };
        }
        // Nobody said either way. Reported as its own answer rather than folded
        // into one of the others, because both of those are claims nobody can
        // make here, and one of them invites a caller to run a destructive
        // command a second time.
        RunState::Indeterminate => {
            return ExecResult::Unknown {
                run: run.as_str().to_owned(),
                why,
            };
        }
        // Not over, so not `ran`: a run still going may be producing output, or
        // may be one the target has not answered about at all, and neither is
        // something to tell a caller happened.
        RunState::Running => {
            return ExecResult::StillRunning {
                run: run.as_str().to_owned(),
                stdout: StreamOut::pending(stdout),
                stderr: StreamOut::pending(stderr),
                why,
            };
        }
        RunState::Ended | RunState::Exited { .. } => {}
    }
    ExecResult::Ran {
        run: run.as_str().to_owned(),
        exit: match state {
            RunState::Exited { code } => Some(code),
            RunState::Running | RunState::Ended | RunState::Refused | RunState::Indeterminate => {
                None
            }
        },
        stdout: StreamOut::released(stdout),
        stderr: StreamOut::released(stderr),
        why,
    }
}

fn parse<T: for<'de> Deserialize<'de>>(arguments: JsonObject) -> Result<T, McpError> {
    serde_json::from_value(serde_json::Value::Object(arguments))
        .map_err(|source| McpError::invalid_params(source.to_string(), None))
}

fn ok<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let json = serde_json::to_value(value)
        .map_err(|source| McpError::internal_error(source.to_string(), None))?;
    let text = serde_json::to_string(&json)
        .map_err(|source| McpError::internal_error(source.to_string(), None))?;
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(json);
    Ok(result)
}

fn bad_request<E: std::fmt::Display>(error: E) -> McpError {
    McpError::invalid_params(error.to_string(), None)
}

/// Reads a session identifier a caller supplied.
///
/// A string that could not name any session is refused as a malformed request
/// rather than looked up, which is what the core's own parser is for.
///
/// That says nothing about which sessions exist. The shape is not a secret —
/// it is deliberately not written into the published schema either, since a
/// second copy of a rule the parser owns is free to drift from it — and a
/// well-formed identifier for a session that is not this caller's is answered
/// exactly as one that never existed.
fn session_named(raw: &str) -> Result<SessionId, McpError> {
    SessionId::parse(raw).map_err(bad_request)
}

/// What a caller is told when asking to run something produced no outcome.
///
/// No outcome is not the same as nothing happening, and the name of this is
/// deliberately about the outcome rather than about the command.
///
/// A command the catalog cannot describe no longer surfaces here at all: it
/// classifies at the maximal assessment and flows through the ordinary
/// decision path, so the caller sees the same refusal or awaiting-approval
/// answers any other command gets. What remains here are failures, and the
/// failures are not alike: a command that ran and could not be recorded says
/// so in as many words, because a caller reading "failed" and sending it
/// again repeats work that already happened. The rest could not be carried
/// through to an answer at all.
fn without_an_outcome(error: &MediationError) -> Result<CallToolResult, McpError> {
    Ok(mediation_failure(error))
}

/// Reports a mediation failure to the caller.
///
/// A tool-level error rather than a protocol error, because the request was
/// well formed and routed correctly — the work behind it failed. MCP clients
/// render tool-level errors to the caller and protocol errors opaquely, and a
/// caller that cannot read "no such session" or "dns1 did not answer" cannot
/// act on it.
///
/// Only *failures* reach here. A refusal and work awaiting approval are
/// successful results carrying an answer: an agent must be able to tell "the
/// service could not decide" from "the service decided no", because retrying
/// is right for one and pointless for the other.
fn mediation_failure(error: &MediationError) -> CallToolResult {
    let told = match error {
        MediationError::Connect(source) => {
            // Logged whole, answered in part: an operator needs the address and
            // the credential reference to fix this, and the agent must not have
            // them.
            tracing::warn!(error = %source, "could not connect to the target");
            reaching_the_target(source)
        }
        other => other.to_string(),
    };
    CallToolResult::error(vec![ContentBlock::text(told)])
}

/// What a caller is told when the target could not be connected to.
///
/// A caller works in host and role names. The address behind a host, the
/// reference the credential is stored under, and the account a role logs in as
/// are all on the other side of that boundary, and an error message is not a
/// reason to hand them across it — an agent that never learns an address cannot
/// be talked into using one.
///
/// Which check failed is still said, because what to do next differs: a host
/// that cannot be reached may be worth retrying, a host key that does not match
/// never is.
fn reaching_the_target(error: &ConnectError) -> String {
    match error {
        ConnectError::UnusableHostKey => {
            "the target cannot be verified, so no connection was made".to_owned()
        }
        ConnectError::CredentialUnavailable { .. } | ConnectError::UnusableCredential { .. } => {
            "the credential for that role is unavailable".to_owned()
        }
        ConnectError::HostKeyMismatch { host } => {
            format!("{host} presented a host key that does not match the pinned one")
        }
        ConnectError::Unreachable { .. } => "the target could not be reached".to_owned(),
        ConnectError::AuthenticationFailed { host, .. }
        | ConnectError::AuthenticationRejected { host, .. } => {
            format!("authenticating to {host} as that role failed")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    /// Nothing an agent can type may say who it is. If a schema accepted a
    /// principal, impersonation would be a matter of filling in a field.
    ///
    /// Naming no such field is half of it. The other half is that a caller
    /// cannot add one: an open object would let a request carry `principal`
    /// and still be a valid request, which is a poor place to be relying on
    /// nothing downstream reading it. Every published input closes itself, and
    /// this asserts that rather than the absence of a word.
    #[test]
    fn no_tool_accepts_a_principal() {
        let catalog = catalog();
        assert!(!catalog.tools.is_empty(), "nothing was published");

        for tool in &catalog.tools {
            let schema = serde_json::to_value(&*tool.input_schema).unwrap();
            assert_eq!(
                schema.get("additionalProperties"),
                Some(&serde_json::Value::Bool(false)),
                "{}'s arguments are open, so a caller can add fields it never declared: {schema}",
                tool.name
            );
        }

        let rendered = serde_json::to_string(&catalog).unwrap();
        for forbidden in ["principal", "identity", "on_behalf_of"] {
            assert!(
                !rendered.contains(forbidden),
                "a tool schema exposes {forbidden}: identity must come from the gateway"
            );
        }
    }

    /// The closed schemas are only a promise if the code enforces them, and the
    /// code is what a caller actually meets.
    #[test]
    fn a_request_carrying_a_field_no_tool_declares_is_refused() {
        let with_principal = |json: serde_json::Value| match json {
            serde_json::Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        };

        let smuggled = with_principal(serde_json::json!({
            "session": "0123456789abcdef0123456789abcdef",
            "command": ["uptime"],
            "intent": "Check whether the host is up",
            "principal": "root",
        }));
        assert!(
            parse::<ExecArgs>(smuggled).is_err(),
            "a request naming a principal was accepted"
        );

        // Including the tool that declares no arguments at all.
        let junk = with_principal(serde_json::json!({ "principal": "root" }));
        assert!(
            parse::<Empty>(junk).is_err(),
            "a tool with no arguments accepted one"
        );

        let honest = with_principal(serde_json::json!({
            "session": "0123456789abcdef0123456789abcdef",
            "command": ["uptime"],
            "intent": "Check whether the host is up",
        }));
        assert!(
            parse::<ExecArgs>(honest).is_ok(),
            "a valid request was refused"
        );
    }

    /// The shape a store mints: which store, then which run, both in hex.
    const MINTED_RUN: &str = "0123456789abcdef-0123456789abcdef0123456789abcdef";

    fn produced(text: &str) -> ssh_core::run::Stream {
        ssh_core::run::Stream {
            bytes: text.len() as u64,
            text: text.to_owned(),
            truncated: false,
            matched: None,
        }
    }

    /// Something that could not be decided is a failure, not an answer: a
    /// caller must be able to tell "the service could not decide" from "the
    /// service decided no", because retrying is right for one and pointless
    /// for the other.
    #[test]
    fn what_could_not_be_decided_is_a_failure() {
        let broken = without_an_outcome(&MediationError::NoConnection).expect("an answer");
        assert_eq!(
            broken.is_error,
            Some(true),
            "a failure was reported as a decision"
        );
    }

    /// Not every failure means nothing happened. A command that ran and whose
    /// completion the record would not take is a failure an operator has to see
    /// — and a caller that reads "failed" and sends it again repeats work that
    /// already happened, which for this tool is the thing to avoid.
    #[test]
    fn a_failure_after_the_command_ran_says_what_the_command_did() {
        use ssh_core::run::RunState;
        let unrecorded = |state| {
            let error = MediationError::Unaccounted {
                run: MINTED_RUN.to_owned(),
                state,
                source: ssh_core::audit::AuditError::Full,
            };
            let told = without_an_outcome(&error).expect("an answer");
            assert_eq!(told.is_error, Some(true), "a record failure was hidden");
            serde_json::to_string(&told).unwrap()
        };

        // The state is what decides the words, so a refused command is not
        // described as one that ran just because the record then failed.
        let ran = unrecorded(RunState::Exited { code: 0 });
        assert!(
            ran.contains("ran") && !ran.contains("did not run"),
            "the caller cannot tell this from a command that never started: {ran}"
        );
        assert!(
            unrecorded(RunState::Refused).contains("did not run"),
            "a refused command was reported as one that ran"
        );
        assert!(
            unrecorded(RunState::Indeterminate).contains("may or may not"),
            "a command nobody knows about was reported as settled"
        );

        // A failure before anything ran does not say any of it.
        let before = serde_json::to_string(
            &without_an_outcome(&MediationError::NoReceipt).expect("an answer"),
        )
        .unwrap();
        assert_ne!(ran, before);
    }

    /// A caller works in host and role names. An error message is not a reason
    /// to hand it what those stand for: an agent that never learns an address,
    /// a credential reference, or the account a role logs in as cannot be
    /// talked into using one.
    #[test]
    fn a_failure_to_connect_does_not_name_what_is_behind_the_host() {
        // Asked of what the caller is actually handed, so that routing the
        // answer around the boundary would fail this as surely as widening it.
        let behind = [
            ConnectError::CredentialUnavailable {
                reference: "mcp-ssh/dns1/readonly".to_owned(),
            },
            ConnectError::UnusableCredential {
                reference: "mcp-ssh/dns1/readonly".to_owned(),
            },
            ConnectError::Unreachable {
                address: "10.10.10.4:22".to_owned(),
                detail: "connection refused".to_owned(),
            },
            ConnectError::AuthenticationFailed {
                host: "dns1".to_owned(),
                user: "mcp-ro".to_owned(),
            },
            ConnectError::AuthenticationRejected {
                host: "dns1".to_owned(),
                user: "mcp-ro".to_owned(),
            },
        ];

        for error in behind {
            let answer = mediation_failure(&MediationError::Connect(error));
            let told = serde_json::to_string(&answer).unwrap();
            for secret in ["mcp-ssh/dns1/readonly", "10.10.10.4", "mcp-ro"] {
                assert!(
                    !told.contains(secret),
                    "{told:?} names {secret}, which is behind the host/role boundary"
                );
            }
            assert!(!told.is_empty(), "the caller was told nothing at all");
        }

        // The host is the caller's own word for it, and which check failed is
        // what decides whether trying again is sensible.
        let mismatch = serde_json::to_string(&mediation_failure(&MediationError::Connect(
            ConnectError::HostKeyMismatch {
                host: "dns1".to_owned(),
            },
        )))
        .unwrap();
        assert!(mismatch.contains("dns1") && mismatch.contains("host key"));
    }

    /// Three different things a caller must do next, so three different
    /// answers. A command that ran and printed nothing looks exactly like a
    /// command that never started, if the surface is careless enough to report
    /// them the same way — and the caller acting on that runs the work twice or
    /// not at all.
    #[test]
    fn ran_did_not_start_and_nobody_knows_are_three_answers() {
        use ssh_core::run::RunState;
        let run = RunId::parse(MINTED_RUN).unwrap();
        let answer = |state| {
            reported(
                &run,
                state,
                &produced(""),
                &produced(""),
                "permitted".to_owned(),
            )
        };

        let refused = answer(RunState::Refused);
        assert!(
            matches!(refused, ExecResult::NotStarted { .. }),
            "got {refused:?}"
        );

        let silent = answer(RunState::Indeterminate);
        assert!(
            matches!(silent, ExecResult::Unknown { .. }),
            "silence was reported as something definite: {silent:?}"
        );

        let ended = answer(RunState::Ended);
        assert!(matches!(ended, ExecResult::Ran { .. }), "got {ended:?}");
    }

    /// The record withholds output it recognised as credential-shaped. Handing
    /// it to the caller instead would put the credential somewhere worse than
    /// the log store it was kept out of — an agent's context.
    #[test]
    fn credential_shaped_output_is_described_rather_than_returned() {
        let secret = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let stream = ssh_core::run::Stream {
            text: secret.to_owned(),
            truncated: false,
            bytes: 4096,
            matched: Some("private key"),
        };

        let reported = StreamOut::released(&stream);
        let rendered = serde_json::to_string(&reported).unwrap();
        assert!(
            !rendered.contains(secret),
            "the caller was handed output the record refused to keep: {rendered}"
        );
        match reported {
            StreamOut::Withheld { bytes, matched } => {
                assert_eq!(bytes, 4096, "what was produced, not what was kept");
                assert_eq!(matched, "private key");
            }
            other => panic!("credential-shaped output was not withheld: {other:?}"),
        }

        let ordinary = StreamOut::released(&produced("uptime: 4 days"));
        assert!(matches!(ordinary, StreamOut::Text { .. }));
    }

    /// What a stream is cannot be decided from part of it. A command still
    /// running may produce the first lines of a private key and the marker that
    /// recognises it in the next packet — and bytes already handed to an agent
    /// cannot be taken back by withholding the rest.
    #[test]
    fn nothing_is_released_from_a_command_that_is_still_running() {
        use ssh_core::run::RunState;
        let so_far = produced("-----BEGIN OPENSSH PRIVATE");

        let rendered = serde_json::to_string(&reported(
            &RunId::parse(MINTED_RUN).unwrap(),
            RunState::Running,
            &so_far,
            &produced(""),
            "permitted".to_owned(),
        ))
        .unwrap();

        assert!(
            !rendered.contains("BEGIN OPENSSH"),
            "output was handed over before the stream was complete: {rendered}"
        );
        assert!(
            rendered.contains("pending"),
            "the caller was not told the output is still arriving: {rendered}"
        );
        // And a command still going is not reported as one that ran: the target
        // may not have taken it at all, and `ran` has to keep meaning ran.
        assert!(
            rendered.contains("still_running") && !rendered.contains("\"outcome\":\"ran\""),
            "a command still going was reported as one that ran: {rendered}"
        );

        // The same stream, once its run has settled, is released as it stands.
        assert!(matches!(
            StreamOut::released(&so_far),
            StreamOut::Text { .. }
        ));
    }

    /// A session identifier arrives as a string a caller typed, and the shape
    /// of one is decided by the core rather than here. What this pins is that
    /// the surface asks: a string no session could have is refused, and a
    /// well-formed one is passed along to be looked up like any other.
    #[test]
    fn a_string_that_could_not_name_a_session_is_refused() {
        let minted = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            session_named(minted)
                .expect("a well-formed identifier")
                .as_str(),
            minted
        );

        for unusable in ["", "not-a-session", &minted[1..], &minted.to_uppercase()] {
            assert!(
                session_named(unusable).is_err(),
                "{unusable:?} was accepted as a session identifier"
            );
        }
    }

    /// Once a person has decided, there is nothing left to wait for, and the
    /// answer an agent reads must not still describe the command as pending.
    /// A caller told its finished run is waiting for approval will come back
    /// for something that already happened; one told a final refusal is
    /// pending will keep asking.
    #[test]
    fn an_answered_command_is_not_described_as_still_waiting() {
        use ssh_core::approval::Approver;

        let approved = held_and(&approved_by(&Approver::Human {
            who: "chris".to_owned(),
        }));
        let refused = held_and(&said_no(&Approver::Human {
            who: "chris".to_owned(),
        }));

        for answer in [&approved, &refused] {
            assert!(
                !answer.contains("waiting"),
                "a decided command still reads as pending: {answer}"
            );
            assert!(
                answer.contains("needed a person"),
                "the answer no longer says a person was needed: {answer}"
            );
        }
        assert!(approved.contains("approved by chris"), "{approved}");
        assert!(refused.contains("refused by chris"), "{refused}");

        // And it is what a caller is actually handed, rather than a phrase the
        // answer could be built without.
        let ExecResult::Refused { why } = exec_result(
            Executed::Refused {
                decision: held_for_a_person(),
                refused_by: Some(Approver::Human {
                    who: "chris".to_owned(),
                }),
            },
            None,
        ) else {
            panic!("a refusal was reported as something else");
        };
        assert!(
            !why.contains("waiting") && why.contains("refused by chris"),
            "a human's refusal reads as still pending: {why}"
        );
    }

    /// A decision policy held for a person, made the way the service makes one.
    fn held_for_a_person() -> ssh_core::policy::Decision {
        use ssh_core::clock::TestClock;
        use ssh_core::command::Command;
        use ssh_core::session::{Lifetime, SessionStore};
        use ssh_core::{PrincipalId, catalog::Catalog, policy::Engine};

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
            PrincipalId::parse("alice").unwrap(),
            HostId::parse("dns1").unwrap(),
            RoleId::parse("operator").unwrap(),
            Purpose::parse("restart the proxy after the config change").unwrap(),
            Scope::Privileged,
        )
        .unwrap();
        let command = Command::new(
            ["docker", "restart", "traefik"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        )
        .unwrap();
        Engine::builtin()
            .unwrap()
            .decide(&session, Catalog::builtin().unwrap().classify(&command))
            .unwrap()
    }

    /// Break-glass is not an approval by another name: nobody was reached, and
    /// somebody proceeded anyway. If the answer an agent reads renders the two
    /// alike, the one surface that would have shown an override in passing
    /// shows an ordinary name instead.
    #[test]
    fn an_override_does_not_read_as_an_ordinary_approval() {
        use ssh_core::approval::Approver;

        let ordinary = approved_by(&Approver::Human {
            who: "chris".to_owned(),
        });
        let override_of = approved_by(&Approver::Override {
            who: "chris".to_owned(),
            because: "nobody on call at 03:00".to_owned(),
        });

        assert_ne!(ordinary, override_of, "an override read as an approval");
        assert!(
            override_of.contains("overridden") && override_of.contains("nobody on call"),
            "the answer does not say an override happened or why: {override_of}"
        );
    }

    /// Polling hands over a finished command's result and then lets go of it,
    /// so the second call does not answer like the first. A client told this is
    /// idempotent would treat a lost response as safe to re-request, and get an
    /// unknown-run error where the output used to be.
    #[test]
    fn polling_is_annotated_as_delivering_once() {
        let catalog = catalog();
        let poll = catalog
            .tools
            .iter()
            .find(|tool| tool.name == POLL)
            .expect("ssh_poll is published");
        let annotations = poll.annotations.as_ref().expect("annotated");
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(annotations.read_only_hint, Some(false));
        assert!(
            poll.description
                .as_ref()
                .is_some_and(|said| said.contains("once")),
            "the description does not say the result is delivered once"
        );
    }

    /// Annotations are what a client uses to decide whether to confirm, batch,
    /// or retry. Claiming execution is read-only or idempotent would tell a
    /// client it is safe to repeat something that is not.
    #[test]
    fn execution_is_annotated_as_consequential() {
        let catalog = catalog();
        let exec = catalog
            .tools
            .iter()
            .find(|tool| tool.name == EXEC)
            .expect("ssh_exec is published");
        let annotations = exec.annotations.as_ref().expect("annotated");
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(true));
    }

    /// Discovery is read-only and closed-world: it reports configuration and
    /// reaches nothing.
    #[test]
    fn discovery_is_annotated_as_harmless() {
        let catalog = catalog();
        let hosts = catalog
            .tools
            .iter()
            .find(|tool| tool.name == HOSTS)
            .expect("ssh_hosts is published");
        let annotations = hosts.annotations.as_ref().expect("annotated");
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.open_world_hint, Some(false));
    }

    /// The surface stays small on purpose. Typed per-operation tools are
    /// deferred until real traffic says which operations earn one.
    #[test]
    fn the_surface_is_the_five_tools_it_claims() {
        let names: Vec<_> = catalog()
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(names, vec![HOSTS, OPEN_SESSION, EXEC, POLL, CLOSE_SESSION]);
    }

    /// Every tool publishes an output schema, so a caller knows the shape of a
    /// refusal as well as the shape of a result.
    #[test]
    fn every_tool_declares_what_it_returns() {
        for tool in &catalog().tools {
            assert!(
                tool.output_schema.is_some(),
                "{} does not say what it returns",
                tool.name
            );
        }
    }

    /// A command is a vector and every execution names its intent. The schema
    /// is the contract agents plan against, so both facts must be explicit.
    #[test]
    fn execution_schema_requires_intent_and_an_argument_vector() {
        let catalog = catalog();
        let exec = catalog
            .tools
            .iter()
            .find(|tool| tool.name == EXEC)
            .expect("ssh_exec is published");
        let schema = serde_json::to_value(&exec.input_schema).unwrap();
        let command = schema
            .pointer("/properties/command/type")
            .and_then(serde_json::Value::as_str)
            .expect("command has a declared type");
        assert_eq!(command, "array");
        let required = schema
            .pointer("/required")
            .and_then(serde_json::Value::as_array)
            .expect("execution has required fields");
        assert!(
            required.iter().any(|field| field == "intent"),
            "ssh_exec lets an agent omit intent: {schema}"
        );
        let intent_description = schema
            .pointer("/properties/intent/description")
            .and_then(serde_json::Value::as_str)
            .expect("intent provenance is documented");
        assert!(intent_description.contains("not trusted user intent"));
    }

    /// A held answer points the caller's human at the page - when the
    /// deployment names one - as the configured address with the request's
    /// own identifier as the fragment, and omits the field entirely when no
    /// page is named rather than sending an empty somewhere.
    #[test]
    fn a_held_answer_names_the_page_where_a_person_decides() {
        use ssh_core::approval::{Approvals, Standing, Windows};
        use ssh_core::audit::Ledger;
        use ssh_core::catalog::Catalog;
        use ssh_core::clock::TestClock;
        use ssh_core::command::Command;
        use ssh_core::mediate::Executed;
        use ssh_core::policy::Engine;
        use ssh_core::session::{Lifetime, Purpose, SessionStore};
        use ssh_core::{HostId, PrincipalId, RoleId, Scope};
        use std::sync::Arc;

        let clock = Arc::new(TestClock::at(1_000));
        let sessions = SessionStore::new(
            Arc::clone(&clock),
            Lifetime {
                idle: 60_000,
                max: 600_000,
                grace: 60_000,
            },
            4,
        );
        let session = sessions
            .open(
                PrincipalId::parse("agent-clawde").unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse("restart the resolver").unwrap(),
                Scope::Mutate,
            )
            .unwrap();
        let approvals = Approvals::new(
            Arc::clone(&clock),
            Windows {
                decide_within: 300_000,
                redeem_within: 60_000,
            },
            4,
        );
        let command = Command::new(vec![
            "systemctl".to_owned(),
            "restart".to_owned(),
            "unbound".to_owned(),
        ])
        .unwrap();
        let ledger = Ledger::new(Arc::clone(&clock));
        let held = || {
            let decision = Engine::builtin()
                .unwrap()
                .decide(&session, Catalog::builtin().unwrap().classify(&command))
                .unwrap();
            let asked = match approvals
                .ask(
                    &ledger
                        .record_intent(
                            Engine::builtin()
                                .unwrap()
                                .decide(&session, Catalog::builtin().unwrap().classify(&command))
                                .unwrap(),
                            CommandIntent::parse("exercise tool rendering").unwrap(),
                        )
                        .unwrap(),
                )
                .unwrap()
            {
                Standing::Waiting(ask) => ask,
                other => panic!("expected a waiting request, got {other:?}"),
            };
            Executed::AwaitingApproval { decision, asked }
        };

        let page = url::Url::parse("https://ssh.cacahuate.org/dashboard/approvals").unwrap();
        let told = serde_json::to_value(exec_result(held(), Some(&page))).unwrap();
        let request = told
            .get("request")
            .and_then(|value| value.as_str())
            .expect("a request identifier")
            .to_owned();
        assert_eq!(
            told.get("decide_at").and_then(|value| value.as_str()),
            Some(format!("https://ssh.cacahuate.org/dashboard/approvals#{request}").as_str()),
            "the page is not the configured address with the request as fragment"
        );

        let unnamed = serde_json::to_value(exec_result(held(), None)).unwrap();
        assert!(
            unnamed.get("decide_at").is_none(),
            "a deployment with no page still sent one: {unnamed}"
        );
    }

    /// A lapsed agreement reaches the caller as an outcome of its own, naming
    /// the person whose decision expired and the page where the fresh request
    /// now waits.
    ///
    /// Told only that something awaits approval, a caller cannot tell this
    /// from never having asked, and passes nothing back to the person who
    /// already answered.
    #[test]
    fn a_lapsed_agreement_says_whose_it_was_and_where_the_new_one_waits() {
        use ssh_core::approval::{Approvals, Approver, Standing, Windows};
        use ssh_core::audit::Ledger;
        use ssh_core::catalog::Catalog;
        use ssh_core::clock::TestClock;
        use ssh_core::command::Command;
        use ssh_core::mediate::Executed;
        use ssh_core::policy::Engine;
        use ssh_core::session::{Lifetime, Purpose, SessionStore};
        use ssh_core::{HostId, PrincipalId, RoleId, Scope};
        use std::sync::Arc;

        let clock = Arc::new(TestClock::at(1_000));
        let sessions = SessionStore::new(
            Arc::clone(&clock),
            Lifetime {
                idle: 60_000,
                max: 600_000,
                grace: 60_000,
            },
            4,
        );
        let session = sessions
            .open(
                PrincipalId::parse("agent-clawde").unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse("restart the resolver").unwrap(),
                Scope::Mutate,
            )
            .unwrap();
        let approvals = Approvals::new(
            Arc::clone(&clock),
            Windows {
                decide_within: 300_000,
                redeem_within: 60_000,
            },
            4,
        );
        let command = Command::new(vec![
            "systemctl".to_owned(),
            "restart".to_owned(),
            "unbound".to_owned(),
        ])
        .unwrap();
        let ledger = Ledger::new(Arc::clone(&clock));
        let decision = Engine::builtin()
            .unwrap()
            .decide(&session, Catalog::builtin().unwrap().classify(&command))
            .unwrap();
        let asked = match approvals
            .ask(
                &ledger
                    .record_intent(
                        Engine::builtin()
                            .unwrap()
                            .decide(&session, Catalog::builtin().unwrap().classify(&command))
                            .unwrap(),
                        CommandIntent::parse("exercise tool rendering").unwrap(),
                    )
                    .unwrap(),
            )
            .unwrap()
        {
            Standing::Waiting(ask) => ask,
            other => panic!("expected a waiting request, got {other:?}"),
        };

        let page = url::Url::parse("https://ssh.cacahuate.org/dashboard/approvals").unwrap();
        let told = serde_json::to_value(exec_result(
            Executed::ApprovalLapsed {
                decision,
                asked,
                lapsed_from: Approver::Human {
                    who: "chris".to_owned(),
                },
            },
            Some(&page),
        ))
        .unwrap();

        assert_eq!(
            told.get("outcome").and_then(serde_json::Value::as_str),
            Some("approval_lapsed"),
            "a lapsed agreement is not told apart from a fresh hold: {told}"
        );
        let request = told
            .get("request")
            .and_then(serde_json::Value::as_str)
            .expect("a request identifier")
            .to_owned();
        assert_eq!(
            told.get("decide_at").and_then(serde_json::Value::as_str),
            Some(format!("https://ssh.cacahuate.org/dashboard/approvals#{request}").as_str()),
            "the new request is not where the caller is sent"
        );
        let why = told
            .get("why")
            .and_then(serde_json::Value::as_str)
            .expect("a reason");
        assert!(
            why.contains("chris"),
            "the reason does not name who had agreed: {why}"
        );
        assert!(
            why.contains("expired"),
            "the reason does not say the agreement expired: {why}"
        );
    }

    /// The announce bridge is where "a fresh hold produces one note and a
    /// retry produces none" actually happens: the store distinguishes new
    /// from pending, and this is the only caller that acts on it.
    #[test]
    fn only_a_fresh_hold_is_announced_and_only_somewhere_to_go() {
        use ssh_core::approval::{Approvals, Asked, Standing, Windows};
        use ssh_core::audit::Ledger;
        use ssh_core::catalog::Catalog;
        use ssh_core::clock::TestClock;
        use ssh_core::command::Command;
        use ssh_core::policy::Engine;
        use ssh_core::session::{Lifetime, Purpose, SessionStore};
        use ssh_core::{HostId, PrincipalId, RoleId, Scope};
        use std::sync::{Arc, Mutex};

        struct Recording(Mutex<Vec<crate::notify::Note>>);
        impl crate::notify::Notifier for Recording {
            fn waiting(&self, note: crate::notify::Note) {
                self.0.lock().unwrap().push(note);
            }
        }

        fn asked() -> Asked {
            let clock = Arc::new(TestClock::at(1_000));
            let sessions = SessionStore::new(
                Arc::clone(&clock),
                Lifetime {
                    idle: 60_000,
                    max: 600_000,
                    grace: 60_000,
                },
                4,
            );
            let session = sessions
                .open(
                    PrincipalId::parse("agent-clawde").unwrap(),
                    HostId::parse("dns1").unwrap(),
                    RoleId::parse("operator").unwrap(),
                    Purpose::parse("restart the resolver").unwrap(),
                    Scope::Mutate,
                )
                .unwrap();
            let approvals = Approvals::new(
                Arc::clone(&clock),
                Windows {
                    decide_within: 300_000,
                    redeem_within: 60_000,
                },
                4,
            );
            let command = Command::new(vec![
                "systemctl".to_owned(),
                "restart".to_owned(),
                "unbound".to_owned(),
            ])
            .unwrap();
            let decision = Engine::builtin()
                .unwrap()
                .decide(&session, Catalog::builtin().unwrap().classify(&command))
                .unwrap();
            let held = Ledger::new(clock)
                .record_intent(
                    decision,
                    CommandIntent::parse("exercise tool rendering").unwrap(),
                )
                .unwrap();
            match approvals.ask(&held).unwrap() {
                Standing::Waiting(ask) => ask.into_asked(),
                other => panic!("expected a waiting request, got {other:?}"),
            }
        }

        let notes = Recording(Mutex::new(Vec::new()));
        let dashboard = url::Url::parse("https://ssh.cacahuate.org/").unwrap();

        announce_ask(
            &notes,
            Some(&dashboard),
            &ssh_core::approval::Ask::New(asked()),
        );
        assert_eq!(
            notes.0.lock().unwrap().len(),
            1,
            "a fresh hold says so once"
        );

        announce_ask(
            &notes,
            Some(&dashboard),
            &ssh_core::approval::Ask::Pending(asked()),
        );
        assert_eq!(
            notes.0.lock().unwrap().len(),
            1,
            "a retry joining a request was announced"
        );

        announce_ask(&notes, None, &ssh_core::approval::Ask::New(asked()));
        assert_eq!(
            notes.0.lock().unwrap().len(),
            1,
            "a note was sent with nowhere to go"
        );
    }
}
