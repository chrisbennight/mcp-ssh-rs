//! Where a human answers a request the policy held.
//!
//! This is the approval surface, not a view over one: a request is answered
//! here, the answer is what the service acts on, and who gave it is recorded.
//! That is what makes an approval a decision a second party can check later
//! rather than a message somebody replied to.
//!
//! # Who is allowed in
//!
//! Two facts, the same shape as the MCP surface's, and for a sharper reason.
//! The reverse proxy presents its own shared credential, and the operator's
//! name comes from the header the proxy's authenticator sets after a single
//! sign-on round trip.
//!
//! The credential is *not* the gateway's. The gateway is how the agent whose
//! command was held reaches this service, and container networks do not
//! separate the two: an agent that could reach this port with the gateway's
//! credential and a forged operator header would approve its own work. Two
//! different values mean reaching one surface confers nothing on the other.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse as _, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use serde::Deserialize;
use ssh_core::Scope;
use ssh_core::approval::{
    AgreementId, Approver, Asked, MatchingWork, StandingApproval, StandingCoverage,
};
use ssh_core::clock::Clock;
use ssh_core::connect::CredentialSource;
use ssh_core::mediate::{Bastion, MediationError};
use ssh_core::run::RunId;
use ssh_core::session::{Expiry, SessionId, SessionStatus};

use crate::audit_history::{self, ReadsAudit};
use crate::ingress::SharedBearer;

/// Where the dashboard is mounted.
pub const DASHBOARD_PATH: &str = "/dashboard";

/// Most cards one operations response may render.
const OPERATIONS_RESULT_LIMIT: usize = 100;

/// Most retained bytes from each completed-command stream shown or searched.
const OPERATIONS_OUTPUT_PREVIEW_BYTES: usize = 2 << 10;

/// Header the proxy's authenticator puts the signed-in operator's name in.
///
/// Authentik's outpost sets this and Traefik forwards it. It is believed only
/// because the request also carried the proxy's credential, which nothing on
/// the other side of the proxy holds.
const OPERATOR_HEADER: &str = "x-authentik-username";

/// Header a browser stamps on every request with how the initiating page
/// relates to the destination.
///
/// The proxy authenticates the *operator*, not the *page*: any site open in a
/// signed-in operator's browser can auto-submit a form here and arrive wearing
/// the proxy's credential and the operator's name - and the agent whose
/// command is held learns its request identifier from the tool result, which
/// is everything such a form needs. The browser's own `Sec-Fetch-Site` header
/// says whether the submission came from this origin, and no page content can
/// forge it. Absent or non-`same-origin` is refused: this surface exists for a
/// human in a current browser behind the proxy, so failing closed costs no
/// supported caller.
const FETCH_SITE_HEADER: &str = "sec-fetch-site";

/// The human who is answering, as the proxy authenticated them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator(String);

impl Operator {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// What the dashboard needs to admit a request.
#[derive(Clone)]
pub struct Proxy {
    bearers: Arc<SharedBearer>,
}

impl Proxy {
    #[must_use]
    pub const fn new(bearers: Arc<SharedBearer>) -> Self {
        Self { bearers }
    }
}

/// Admits a request only if it came through the proxy and names an operator.
pub async fn require_operator(
    State(proxy): State<Proxy>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(presented) = bearer(request.headers()) else {
        return refused();
    };
    if !proxy.bearers.accepts(presented.as_bytes()) {
        return refused();
    }
    let Some(who) = single_header(request.headers(), OPERATOR_HEADER) else {
        return refused();
    };
    if who.trim().is_empty() {
        return refused();
    }
    let who = who.to_owned();
    request.extensions_mut().insert(Operator(who));
    let mut response = next.run(request).await;
    // A framed approvals page defeats the same-origin submission guard from
    // inside: a hostile site frames the real page and induces a click on the
    // real Approve control, and the resulting submission is genuinely
    // same-origin. So no dashboard response may be framed at all; both
    // spellings, because older browsers read only the second.
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = single_header(headers, header::AUTHORIZATION.as_str())?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token)
}

/// A header's value, or nothing if it was sent more than once.
///
/// A repeated header is ambiguous, and the ambiguity here decides whose name
/// is recorded against an approval.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn refused() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Html("<p>This page is reached through the proxy.</p>"),
    )
        .into_response()
}

/// One waiting request, as the page shows it.
///
/// A view rather than the core type: the template then holds no opinion about
/// how a principal or a scope is spelled, and escaping applies to plain strings
/// whatever those types become.
pub struct Pending {
    pub id: String,
    pub session: String,
    pub principal: String,
    pub host: String,
    pub role: String,
    pub purpose: String,
    pub scope: String,
    pub assessment: String,
    /// The calling agent's explanation, visibly untrusted on the page.
    pub agent_intent: String,
    pub matching: Option<MatchingShown>,
    /// Why the command waits, in the decision's words. Passed through
    /// `visible` like every agent-adjacent string: the text embeds the
    /// program name the agent chose.
    pub why: String,
    pub command: Vec<String>,
}

impl From<Asked> for Pending {
    fn from(asked: Asked) -> Self {
        Self {
            id: asked.id.as_str().to_owned(),
            session: asked.session.as_str().to_owned(),
            principal: asked.principal.as_str().to_owned(),
            host: asked.host.as_str().to_owned(),
            role: asked.role.as_str().to_owned(),
            purpose: visible(asked.purpose.as_str()),
            scope: scope_name(asked.scope).to_owned(),
            assessment: scope_name(asked.assessment).to_owned(),
            agent_intent: visible(asked.agent_intent.as_str()),
            matching: asked.matching.map(MatchingShown::from),
            why: visible(&asked.why),
            command: asked.command.iter().map(|arg| visible(arg)).collect(),
        }
    }
}

/// The exact v1 matcher an operator is considering.
pub struct MatchingShown {
    pub family: String,
    pub max_assessment: String,
    pub matcher_version: String,
}

impl From<MatchingWork> for MatchingShown {
    fn from(work: MatchingWork) -> Self {
        Self {
            family: format!("{} {}", visible(work.program()), visible(work.subcommand())),
            max_assessment: scope_name(work.max_assessment()).to_owned(),
            matcher_version: work.matcher_version().to_owned(),
        }
    }
}

/// Renders agent-written text so nothing in it is invisible or reordered.
///
/// HTML escaping stops markup, not deception: bidirectional controls reorder
/// what the eye reads, and zero-width characters hide content entirely, so an
/// argument could *display* as something other than what would run — on the
/// page whose one job is showing exactly what would run. Only characters with
/// a single unambiguous appearance pass through; every other one is shown as
/// its written-out escape. Legitimate non-ASCII text pays for that by
/// rendering escaped, which is the right side of the tradeoff here: an
/// approver reading an escape can still decide, an approver reading reordered
/// text decides about the wrong command. Display-only; the argument vector
/// itself is untouched.
///
/// The backslash is escaped too, so the escape alphabet is its own: a literal
/// backslash never appears bare in output, and text that *spells* an escape
/// cannot render identically to the character it spells.
pub(crate) fn visible(text: &str) -> String {
    use std::fmt::Write as _;
    let mut shown = String::with_capacity(text.len());
    for ch in text.chars() {
        if (ch.is_ascii_graphic() && ch != '\\') || ch == ' ' {
            shown.push(ch);
        } else {
            // Infallible for String; written out to avoid unwrap in rendering.
            let _ = write!(shown, "\\u{{{:x}}}", u32::from(ch));
        }
    }
    shown
}

const fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::Read => "read",
        Scope::Mutate => "mutate",
        Scope::Privileged => "privileged",
    }
}

#[derive(Template)]
#[template(path = "approvals.html")]
struct ApprovalsPage {
    operator: String,
    /// Where the decision form posts, so the template does not build the mount
    /// path out of a constant it cannot see.
    action: String,
    waiting: Vec<Pending>,
    standing: Vec<StandingShown>,
}

/// One standing agreement, as the page shows it.
pub struct StandingShown {
    pub id: String,
    pub session: String,
    pub who: String,
    pub remaining: String,
    pub coverage: String,
    pub detail: String,
}

impl StandingShown {
    fn from(agreement: StandingApproval, remaining_ms: u64) -> Self {
        let minutes = remaining_ms / 60_000;
        let (coverage, detail) = match &agreement.coverage {
            StandingCoverage::Session => (
                "Session-wide".to_owned(),
                "Every held command in this session".to_owned(),
            ),
            StandingCoverage::Matching { work } => (
                "Matching work".to_owned(),
                format!(
                    "{} {} at or below {} · {}",
                    visible(work.program()),
                    visible(work.subcommand()),
                    scope_name(work.max_assessment()),
                    work.matcher_version()
                ),
            ),
        };
        Self {
            id: agreement.id.as_str().to_owned(),
            session: agreement.session.as_str().to_owned(),
            who: visible(&agreement.who),
            coverage,
            detail,
            remaining: if minutes >= 60 {
                format!("{} h {} min", minutes / 60, minutes % 60)
            } else {
                format!("{minutes} min")
            },
        }
    }
}

/// What a form submission says.
#[derive(Debug, Deserialize)]
pub struct Decision {
    decision: String,
    /// How long a standing agreement should answer for, in minutes;
    /// absent or `session` means as long as the session itself can last.
    /// Read only for matching-work or session-wide approval.
    duration: Option<String>,
}

pub struct SessionShown {
    pub id: String,
    pub principal: String,
    pub host: String,
    pub role: String,
    pub purpose: String,
    pub scope: String,
    pub status: String,
    pub opened_at: String,
    pub last_used: String,
    pub idle_by: String,
    pub ends_by: String,
    pub history_url: String,
}

pub struct InventoryShown {
    pub host: String,
    pub roles: Vec<String>,
    pub live_sessions: usize,
    pub history_url: String,
}

pub struct AuditShown {
    pub sequence: u64,
    pub at: String,
    pub principal: String,
    pub session: String,
    pub session_url: String,
    pub host: String,
    pub role: String,
    pub event: String,
    pub summary: String,
    pub command: Vec<String>,
    pub outputs: Vec<OutputShown>,
    pub previous: String,
    pub digest: String,
}

pub struct OutputShown {
    pub label: &'static str,
    pub preview: String,
    pub note: String,
    pub inspect_url: String,
}

pub struct EvaluationShown {
    pub id: String,
    pub recorded_at: String,
    pub verdict: String,
    pub confidence: u8,
    pub evaluator: String,
    pub model: String,
    pub prompt_version: String,
    pub rationale: String,
    pub side_effects: Vec<String>,
    pub decision_digest: String,
    pub assessment: String,
    pub principal: String,
    pub session: String,
    pub command: Vec<String>,
    pub agent_intent: String,
    pub purpose: String,
    pub session_url: String,
}

pub struct JourneyEvaluationShown {
    pub verdict: String,
    pub confidence: u8,
    pub evaluator: String,
    pub rationale: String,
    pub side_effects: Vec<String>,
}

pub struct JourneyShown {
    pub decision: u64,
    pub decision_digest: String,
    pub assessment: String,
    pub verdict: String,
    pub command: Vec<String>,
    pub agent_intent: String,
    pub purpose: String,
    pub human_answer: String,
    pub authorization: String,
    pub outcome: String,
    pub outputs: Vec<OutputShown>,
    pub evaluation: Option<JourneyEvaluationShown>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQuery {
    principal: Option<String>,
    session: Option<String>,
    host: Option<String>,
    event: Option<String>,
    assessment: Option<String>,
    verdict: Option<String>,
    window: Option<String>,
    q: Option<String>,
    before: Option<String>,
    start: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    before: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationQuery {
    assessment: Option<String>,
    verdict: Option<String>,
    window: Option<String>,
    before: Option<String>,
    start: Option<String>,
}

struct Filters {
    principal: String,
    session: String,
    host: String,
    event: String,
    assessment: String,
    verdict: String,
    window: String,
    q: String,
}

#[derive(Template)]
#[template(path = "operations.html")]
struct OperationsPage {
    operator: String,
    title: String,
    inventory_active: bool,
    sessions_active: bool,
    transcript_active: bool,
    output_active: bool,
    audit_active: bool,
    evaluations_active: bool,
    inventory: Vec<InventoryShown>,
    sessions: Vec<SessionShown>,
    journeys: Vec<JourneyShown>,
    transcript_session: String,
    output_run: String,
    output: Option<OutputShown>,
    output_back_url: String,
    audit: Vec<AuditShown>,
    evaluations: Vec<EvaluationShown>,
    filters: Filters,
    verification: String,
    verification_ok: bool,
    result_limit: usize,
    source_notice: String,
    source_available: bool,
    next_url: String,
    page_size: usize,
}

impl OperationsPage {
    fn new(operator: String, title: impl Into<String>) -> Self {
        Self {
            operator,
            title: title.into(),
            inventory_active: false,
            sessions_active: false,
            transcript_active: false,
            output_active: false,
            audit_active: false,
            evaluations_active: false,
            inventory: Vec::new(),
            sessions: Vec::new(),
            journeys: Vec::new(),
            transcript_session: String::new(),
            output_run: String::new(),
            output: None,
            output_back_url: String::new(),
            audit: Vec::new(),
            evaluations: Vec::new(),
            filters: blank_filters(),
            verification: String::new(),
            verification_ok: true,
            result_limit: OPERATIONS_RESULT_LIMIT,
            source_notice: String::new(),
            source_available: true,
            next_url: String::new(),
            page_size: audit_history::PAGE_SIZE,
        }
    }
}

fn milliseconds(at: u64) -> String {
    format!("{at} ms")
}

fn retained_prefix(text: &str) -> &str {
    if text.len() <= OPERATIONS_OUTPUT_PREVIEW_BYTES {
        return text;
    }
    if let Some(prefix) = text.get(..OPERATIONS_OUTPUT_PREVIEW_BYTES) {
        return prefix;
    }
    let end = text
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index < OPERATIONS_OUTPUT_PREVIEW_BYTES)
        .last()
        .unwrap_or_default();
    text.get(..end).unwrap_or_default()
}

fn wire_string<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn wire_u64(value: &serde_json::Value, field: &str) -> Option<u64> {
    value.get(field)?.as_u64()
}

fn wire_event_name(event: &serde_json::Value) -> &str {
    wire_string(event, "event").unwrap_or("unrecognized")
}

fn wire_summary(event: &serde_json::Value) -> String {
    match wire_event_name(event) {
        "session_opened" => format!(
            "Opened for {} at {} scope",
            visible(wire_string(event, "purpose").unwrap_or("unavailable")),
            wire_string(event, "scope").unwrap_or("unavailable")
        ),
        "decided" => format!(
            "{} · {} · intent: {}",
            wire_string(event, "verdict").unwrap_or("unavailable"),
            wire_string(event, "assessment").unwrap_or("unavailable"),
            visible(wire_string(event, "agent_intent").unwrap_or("unavailable"))
        ),
        "approved" => format!(
            "{} approved decision {} via {}",
            visible(wire_string(event, "approver").unwrap_or("unavailable")),
            event
                .get("decided")
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
            wire_string(event, "mode").unwrap_or("unavailable")
        ),
        "answered" => format!(
            "{} {} decision {} via {}",
            visible(wire_string(event, "approver").unwrap_or("unavailable")),
            if event.get("agreed").and_then(serde_json::Value::as_bool) == Some(true) {
                "accepted"
            } else {
                "refused"
            },
            event
                .get("decided")
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
            wire_string(event, "mode").unwrap_or("unavailable")
        ),
        "completed" => format!(
            "Run {} completed: {} · authorization entry #{}",
            wire_string(event, "run").unwrap_or("unavailable"),
            visible(wire_string(event, "state").unwrap_or("unavailable")),
            event
                .get("decided")
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
        ),
        "session_closed" => "Session closed".to_owned(),
        "evaluated" => {
            let artifact = event.get("artifact").unwrap_or(&serde_json::Value::Null);
            format!(
                "{} assessed decision {} as {} ({}%)",
                visible(wire_string(artifact, "evaluator").unwrap_or("unavailable")),
                wire_string(artifact, "decision_digest").unwrap_or("unavailable"),
                wire_string(artifact, "verdict")
                    .unwrap_or("unavailable")
                    .replace('_', " "),
                artifact
                    .get("confidence")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
            )
        }
        other => format!("Unrecognized audit event: {}", visible(other)),
    }
}

fn wire_output(label: &'static str, output: &serde_json::Value) -> Option<OutputShown> {
    match wire_string(output, "kind")? {
        "kept" => {
            let text = wire_string(output, "text")?;
            let retained = retained_prefix(text);
            let mut note = format!(
                "{} of {} retained bytes shown; target produced {} bytes",
                retained.len(),
                text.len(),
                output
                    .get("bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
            );
            if retained.len() < text.len() {
                note.push_str("; dashboard preview truncated");
            }
            if output.get("truncated").and_then(serde_json::Value::as_bool) == Some(true) {
                note.push_str("; execution capture truncated");
            }
            Some(OutputShown {
                label,
                preview: if retained.is_empty() {
                    "(empty)".to_owned()
                } else {
                    visible(retained)
                },
                note,
                inspect_url: String::new(),
            })
        }
        "withheld" => Some(OutputShown {
            label,
            preview: "[withheld]".to_owned(),
            note: format!(
                "{} bytes produced; content not retained because it matched {}",
                output
                    .get("bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                visible(wire_string(output, "matched").unwrap_or("a secret pattern"))
            ),
            inspect_url: String::new(),
        }),
        _ => None,
    }
}

fn wire_retained_output(label: &'static str, output: &serde_json::Value) -> Option<OutputShown> {
    if wire_string(output, "kind") != Some("kept") {
        return wire_output(label, output);
    }
    let text = wire_string(output, "text")?;
    let produced = output
        .get("bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let mut note = format!(
        "{} retained bytes shown; target produced {produced} bytes",
        text.len()
    );
    if output.get("truncated").and_then(serde_json::Value::as_bool) == Some(true) {
        note.push_str("; execution capture truncated");
    }
    Some(OutputShown {
        label,
        preview: if text.is_empty() {
            "(empty)".to_owned()
        } else {
            visible(text)
        },
        note,
        inspect_url: String::new(),
    })
}

fn wire_outputs(event: &serde_json::Value) -> Vec<OutputShown> {
    if wire_event_name(event) != "completed" {
        return Vec::new();
    }
    [("stdout", "stdout"), ("stderr", "stderr")]
        .into_iter()
        .filter_map(|(label, field)| event.get(field).and_then(|value| wire_output(label, value)))
        .collect()
}

fn wire_command(event: &serde_json::Value) -> Vec<String> {
    if wire_event_name(event) != "decided" {
        return Vec::new();
    }
    wire_argv(event)
}

fn wire_argv(event: &serde_json::Value) -> Vec<String> {
    event
        .get("argv")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(visible)
        .collect()
}

fn wire_journeys(
    entries: &[audit_history::Entry],
    session: &SessionId,
    before: u64,
    start: u64,
    end: u64,
) -> Vec<JourneyShown> {
    entries
        .iter()
        .filter(|entry| wire_event_name(&entry.event) == "decided")
        .map(|decision| {
            let answer = entries.iter().find(|entry| {
                wire_event_name(&entry.event) == "answered"
                    && wire_u64(&entry.event, "decided") == Some(decision.sequence)
            });
            let approval = entries.iter().find(|entry| {
                wire_event_name(&entry.event) == "approved"
                    && wire_u64(&entry.event, "decided") == Some(decision.sequence)
            });
            let verdict = wire_string(&decision.event, "verdict").unwrap_or("unavailable");
            let mut authorizations = Vec::with_capacity(2);
            if verdict == "permit" {
                authorizations.push(decision.sequence);
            }
            if let Some(approval) = approval {
                authorizations.push(approval.sequence);
            }
            let completion = entries.iter().find(|entry| {
                wire_event_name(&entry.event) == "completed"
                    && wire_u64(&entry.event, "decided")
                        .is_some_and(|sequence| authorizations.contains(&sequence))
            });
            let evaluation = entries.iter().find_map(|entry| {
                if wire_event_name(&entry.event) != "evaluated" {
                    return None;
                }
                let artifact = entry.event.get("artifact")?;
                (wire_string(artifact, "decision_digest") == Some(decision.digest.as_str()))
                    .then_some(artifact)
            });

            let human_answer = answer.map_or_else(
                || "No human answer is recorded for this command.".to_owned(),
                |entry| {
                    format!(
                        "{} {} via {}{}",
                        visible(wire_string(&entry.event, "approver").unwrap_or("unavailable")),
                        if entry
                            .event
                            .get("agreed")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                        {
                            "accepted"
                        } else {
                            "refused"
                        },
                        wire_string(&entry.event, "mode").unwrap_or("unavailable"),
                        if entry
                            .event
                            .get("standing")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                        {
                            " standing agreement"
                        } else {
                            ""
                        }
                    )
                },
            );
            let authorization = approval.map_or_else(
                || match verdict {
                    "permit" => format!("Policy decision entry #{}", decision.sequence),
                    "deny" => "Not authorized · policy denied".to_owned(),
                    _ => "No authorization is recorded for this command.".to_owned(),
                },
                |entry| {
                    format!(
                        "Approval entry #{} · {} via {}",
                        entry.sequence,
                        visible(wire_string(&entry.event, "approver").unwrap_or("unavailable")),
                        wire_string(&entry.event, "mode").unwrap_or("unavailable")
                    )
                },
            );
            let outcome = completion.map_or_else(
                || "No observed completion is recorded for this command.".to_owned(),
                |entry| {
                    format!(
                        "Run {} · {}",
                        visible(wire_string(&entry.event, "run").unwrap_or("unavailable")),
                        visible(wire_string(&entry.event, "state").unwrap_or("unavailable"))
                    )
                },
            );
            let outputs = completion.map_or_else(Vec::new, |entry| {
                let run = wire_string(&entry.event, "run").unwrap_or_default();
                wire_outputs(&entry.event)
                    .into_iter()
                    .map(|mut output| {
                        if entry
                            .event
                            .get(output.label)
                            .and_then(|stream| wire_string(stream, "kind"))
                            == Some("kept")
                        {
                            output.inspect_url = retained_output_url(
                                session.as_str(),
                                run,
                                output.label,
                                before,
                                start,
                                end,
                            );
                        }
                        output
                    })
                    .collect()
            });
            let evaluation = evaluation.map(|artifact| JourneyEvaluationShown {
                verdict: wire_string(artifact, "verdict")
                    .unwrap_or("unavailable")
                    .replace('_', " "),
                confidence: artifact
                    .get("confidence")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u8::try_from(value).ok())
                    .unwrap_or_default(),
                evaluator: visible(wire_string(artifact, "evaluator").unwrap_or("unavailable")),
                rationale: visible(wire_string(artifact, "rationale").unwrap_or("unavailable")),
                side_effects: artifact
                    .get("side_effects")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .map(visible)
                    .collect(),
            });

            JourneyShown {
                decision: decision.sequence,
                decision_digest: decision.digest.clone(),
                assessment: wire_string(&decision.event, "assessment")
                    .unwrap_or("unavailable")
                    .to_owned(),
                verdict: verdict.replace('_', " "),
                command: wire_command(&decision.event),
                agent_intent: visible(
                    wire_string(&decision.event, "agent_intent").unwrap_or("unavailable"),
                ),
                purpose: visible(wire_string(&decision.event, "purpose").unwrap_or("unavailable")),
                human_answer,
                authorization,
                outcome,
                outputs,
                evaluation,
            }
        })
        .collect()
}

fn source_time(nanos: u64) -> String {
    format!(
        "{}.{:03} Unix seconds",
        nanos / 1_000_000_000,
        (nanos % 1_000_000_000) / 1_000_000
    )
}

fn audit_shown(entry: audit_history::Entry) -> AuditShown {
    let event = wire_event_name(&entry.event).to_owned();
    AuditShown {
        sequence: entry.sequence,
        at: source_time(entry.source_nanos),
        principal: visible(&entry.principal),
        session_url: session_history_url(&entry.session),
        session: visible(&entry.session),
        host: visible(&entry.host),
        role: visible(&entry.role),
        summary: wire_summary(&entry.event),
        command: wire_command(&entry.event),
        outputs: wire_outputs(&entry.event),
        event,
        previous: entry.previous,
        digest: entry.digest,
    }
}

fn session_history_url(session: &str) -> String {
    format!("/dashboard/sessions/{}", visible(session))
}

fn retained_output_url(
    session: &str,
    run: &str,
    stream: &str,
    before: u64,
    start: u64,
    end: u64,
) -> String {
    format!(
        "/dashboard/sessions/{}/runs/{}/{}?before={before}&start={start}&end={end}",
        visible(session),
        visible(run),
        visible(stream)
    )
}

fn transcript_page_url(session: &str, before: u64, start: u64, end: u64) -> String {
    format!(
        "/dashboard/sessions/{}?before={before}&start={start}&end={end}",
        visible(session)
    )
}

fn host_audit_url(host: &str) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    encoded.append_pair("host", host);
    format!("/dashboard/audit?{}", encoded.finish())
}

fn next_audit_url(filters: &Filters, before: Option<u64>, start: u64) -> String {
    let Some(before) = before else {
        return String::new();
    };
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in [
        ("principal", filters.principal.as_str()),
        ("session", filters.session.as_str()),
        ("host", filters.host.as_str()),
        ("event", filters.event.as_str()),
        ("assessment", filters.assessment.as_str()),
        ("verdict", filters.verdict.as_str()),
        ("window", filters.window.as_str()),
        ("q", filters.q.as_str()),
    ] {
        if !value.is_empty() {
            encoded.append_pair(name, value);
        }
    }
    encoded.append_pair("before", &before.to_string());
    encoded.append_pair("start", &start.to_string());
    format!("/dashboard/audit?{}", encoded.finish())
}

fn next_session_url(session: &str, before: Option<u64>, start: u64, end: u64) -> String {
    before.map_or_else(String::new, |before| {
        format!("/dashboard/sessions/{session}?before={before}&start={start}&end={end}")
    })
}

fn next_evaluations_url(filters: &Filters, before: Option<u64>, start: u64) -> String {
    let Some(before) = before else {
        return String::new();
    };
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in [
        ("assessment", filters.assessment.as_str()),
        ("verdict", filters.verdict.as_str()),
        ("window", filters.window.as_str()),
    ] {
        if !value.is_empty() {
            encoded.append_pair(name, value);
        }
    }
    encoded.append_pair("before", &before.to_string());
    encoded.append_pair("start", &start.to_string());
    format!("/dashboard/evaluations?{}", encoded.finish())
}

fn query_value(value: Option<String>, max: usize) -> Result<String, ()> {
    let value = value.unwrap_or_default();
    (value.len() <= max).then_some(value).ok_or(())
}

fn cursor_value(value: Option<String>) -> Result<Option<u64>, ()> {
    match value {
        None => Ok(None),
        Some(raw) if raw.len() <= 20 => raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or(()),
        Some(_) => Err(()),
    }
}

fn page_bounds(
    before: Option<String>,
    start: Option<String>,
) -> Result<(Option<u64>, Option<u64>), ()> {
    let before = cursor_value(before)?;
    let start = cursor_value(start)?;
    match (before, start) {
        (None, None) => Ok((None, None)),
        (Some(before), Some(start)) if start <= before => Ok((Some(before), Some(start))),
        _ => Err(()),
    }
}

struct TranscriptBounds {
    before: Option<u64>,
    start: Option<u64>,
    end: Option<u64>,
}

fn transcript_bounds(
    before: Option<String>,
    start: Option<String>,
    end: Option<String>,
) -> Result<TranscriptBounds, ()> {
    let before = cursor_value(before)?;
    let start = cursor_value(start)?;
    let end = cursor_value(end)?;
    match (before, start, end) {
        (None, None, None) => Ok(TranscriptBounds {
            before: None,
            start: None,
            end: None,
        }),
        (Some(before), Some(start), Some(end)) if start <= before && before <= end => {
            Ok(TranscriptBounds {
                before: Some(before),
                start: Some(start),
                end: Some(end),
            })
        }
        _ => Err(()),
    }
}

fn choice_value(value: Option<String>, choices: &[&str]) -> Result<String, ()> {
    let value = value.unwrap_or_default();
    (value.is_empty() || choices.contains(&value.as_str()))
        .then_some(value)
        .ok_or(())
}

fn window_value(value: Option<String>) -> Result<(String, audit_history::Window), ()> {
    match value.as_deref().unwrap_or("30d") {
        "1h" => Ok(("1h".to_owned(), audit_history::Window::Hour)),
        "24h" => Ok(("24h".to_owned(), audit_history::Window::Day)),
        "7d" => Ok(("7d".to_owned(), audit_history::Window::Week)),
        "30d" => Ok(("30d".to_owned(), audit_history::Window::Month)),
        _ => Err(()),
    }
}

fn blank_filters() -> Filters {
    Filters {
        principal: String::new(),
        session: String::new(),
        host: String::new(),
        event: String::new(),
        assessment: String::new(),
        verdict: String::new(),
        window: "30d".to_owned(),
        q: String::new(),
    }
}

fn render_operations(page: OperationsPage) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(why) => {
            tracing::error!(%why, "an operations page could not be rendered");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<p>The operations page could not be rendered.</p>"),
            )
                .into_response()
        }
    }
}

/// Routes for the approval surface.
///
/// Generic over the bastion's clock and credential source for the same reason
/// the rest of the crate is: the tests drive time by hand, and the process does
/// not.
pub fn routes<C, S>(bastion: Arc<Bastion<C, S>>) -> Router
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    routes_with_audit(bastion, Arc::new(audit_history::Unavailable))
}

pub fn routes_with_audit<C, S>(
    bastion: Arc<Bastion<C, S>>,
    audit_reader: Arc<dyn ReadsAudit>,
) -> Router
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    Router::new()
        .route("/approvals", get(queue::<C, S>))
        .route("/inventory", get(inventory::<C, S>))
        .route("/sessions", get(sessions::<C, S>))
        .route(
            "/sessions/{id}/runs/{run}/{stream}",
            get(retained_output::<C, S>),
        )
        .route("/sessions/{id}", get(session_transcript::<C, S>))
        .route("/audit", get(audit::<C, S>))
        .route("/evaluations", get(evaluations::<C, S>))
        .route("/approvals/{id}", axum::routing::post(answer::<C, S>))
        .route(
            "/approvals/standing/{agreement}",
            axum::routing::post(revoke::<C, S>),
        )
        .with_state(bastion)
        .layer(axum::Extension(audit_reader))
}

pub(crate) async fn home() -> Redirect {
    Redirect::to(&format!("{DASHBOARD_PATH}/approvals"))
}

async fn inventory<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let mut live_by_host = HashMap::<String, usize>::new();
    for snapshot in bastion.recent_session_snapshots(OPERATIONS_RESULT_LIMIT) {
        if snapshot.status == SessionStatus::Live {
            let count = live_by_host
                .entry(snapshot.session.host.as_str().to_owned())
                .or_default();
            *count = count.saturating_add(1);
        }
    }
    let inventory = bastion
        .inventory()
        .into_iter()
        .map(|(host, roles)| InventoryShown {
            host: visible(host.as_str()),
            roles: roles
                .into_iter()
                .map(|role| visible(role.as_str()))
                .collect(),
            live_sessions: live_by_host.get(host.as_str()).copied().unwrap_or_default(),
            history_url: host_audit_url(host.as_str()),
        })
        .collect();
    let mut page = OperationsPage::new(operator.0, "Host and role inventory");
    page.inventory_active = true;
    page.inventory = inventory;
    page.source_notice = "Live configuration view. Hosts and roles come from this process's loaded registry; listing describes configured reachability, not permission for any principal or command.".to_owned();
    render_operations(page)
}

async fn sessions<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let sessions = bastion
        .recent_session_snapshots(OPERATIONS_RESULT_LIMIT)
        .into_iter()
        .map(|snapshot| SessionShown {
            id: snapshot.session.id.as_str().to_owned(),
            principal: snapshot.session.principal.as_str().to_owned(),
            host: snapshot.session.host.as_str().to_owned(),
            role: snapshot.session.role.as_str().to_owned(),
            purpose: visible(snapshot.session.purpose.as_str()),
            scope: scope_name(snapshot.session.scope).to_owned(),
            status: match snapshot.status {
                SessionStatus::Live => "live".to_owned(),
                SessionStatus::Lapsed(Expiry::Idle) => "lapsed · idle".to_owned(),
                SessionStatus::Lapsed(Expiry::MaxLifetime) => {
                    "lapsed · maximum lifetime".to_owned()
                }
            },
            opened_at: milliseconds(snapshot.opened_at),
            last_used: milliseconds(snapshot.last_used),
            idle_by: milliseconds(snapshot.idle_by),
            ends_by: milliseconds(snapshot.ends_by),
            history_url: session_history_url(snapshot.session.id.as_str()),
        })
        .collect();
    let mut page = OperationsPage::new(operator.0, "Sessions");
    page.sessions_active = true;
    page.sessions = sessions;
    page.source_notice = "Live process view. Data shown here is retained since this service restart; each session links to its separate durable fleet transcript.".to_owned();
    render_operations(page)
}

async fn session_transcript<C, S>(
    State(_bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(audit_reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Path(raw_session): Path<String>,
    Query(query): Query<PageQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let Ok(session) = SessionId::parse(&raw_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(bounds) = transcript_bounds(query.before, query.start, query.end) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let read = audit_reader
        .transcript(&audit_history::TranscriptQuery {
            before: bounds.before,
            start: bounds.start,
            end: bounds.end,
            session: session.clone(),
        })
        .await;
    let mut page =
        OperationsPage::new(operator.0, format!("Session {}", visible(session.as_str())));
    page.transcript_active = true;
    page.transcript_session = visible(session.as_str());
    match read {
        Ok(history) => {
            let page_before = bounds.before.unwrap_or(history.window_end);
            page.journeys = wire_journeys(
                &history.entries,
                &session,
                page_before,
                history.window_start,
                history.window_end,
            );
            page.audit = history.entries.into_iter().map(audit_shown).collect();
            page.next_url = next_session_url(
                session.as_str(),
                history.next_before,
                history.window_start,
                history.window_end,
            );
            page.source_notice = "Durable fleet transcript. Every recorded command decision on this page—policy-permitted, approval-held, or denied—is assembled with the answers, authorization, outcomes, and evaluations the exact session contains in the deployment log store.".to_owned();
            page.verification = "Loki available · exact session filter".to_owned();
        }
        Err(why) => {
            tracing::warn!(%why, session = %session.as_str(), "the durable session transcript is unavailable");
            page.source_available = false;
            page.verification_ok = false;
            page.verification = "Durable source unavailable".to_owned();
            page.source_notice = "Durable fleet transcript unavailable. The page does not substitute process-local data or stale success.".to_owned();
        }
    }
    render_operations(page)
}

async fn retained_output<C, S>(
    State(_bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(audit_reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Path((raw_session, raw_run, raw_stream)): Path<(String, String, String)>,
    Query(query): Query<PageQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let Ok(session) = SessionId::parse(&raw_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(run) = RunId::parse(&raw_run) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let stream = match raw_stream.as_str() {
        "stdout" => "stdout",
        "stderr" => "stderr",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let Ok(bounds) = transcript_bounds(query.before, query.start, query.end) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(before), Some(start), Some(end)) = (bounds.before, bounds.start, bounds.end) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let read = audit_reader
        .output(&audit_history::OutputQuery {
            start,
            end,
            session: session.clone(),
            run: run.clone(),
        })
        .await;
    let mut page = OperationsPage::new(
        operator.0,
        format!("Retained {stream} · run {}", visible(run.as_str())),
    );
    page.output_active = true;
    page.output_run = visible(run.as_str());
    page.output_back_url = transcript_page_url(session.as_str(), before, start, end);
    match read {
        Ok(Some(entry)) => {
            page.output = entry
                .event
                .get(stream)
                .and_then(|value| wire_retained_output(stream, value));
            if page.output.is_some() {
                page.source_notice = "Retained command output from the exact session and run in the deployment log store. This view expands the complete retained stream; it cannot recover bytes discarded by the execution capture bound.".to_owned();
                page.verification = "Loki available · exact session and run filter".to_owned();
            } else {
                page.source_available = false;
                page.verification_ok = false;
                page.verification = "Malformed durable output".to_owned();
                page.source_notice =
                    "The durable completion did not contain a readable output stream.".to_owned();
            }
        }
        Ok(None) => {
            page.verification_ok = false;
            page.verification = "No retained completion found".to_owned();
            page.source_notice = "No completion for this exact session and run is present in the selected durable transcript window.".to_owned();
        }
        Err(why) => {
            tracing::warn!(%why, session = %session.as_str(), run = %run.as_str(), stream, "retained command output is unavailable");
            page.source_available = false;
            page.verification_ok = false;
            page.verification = "Durable source unavailable".to_owned();
            page.source_notice = "Retained command output is unavailable. The page does not substitute process-local data or a truncated preview.".to_owned();
        }
    }
    render_operations(page)
}

async fn audit<C, S>(
    State(_bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(audit_reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Query(query): Query<AuditQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let Ok(principal) = query_value(query.principal, 256) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(session) = query_value(query.session, 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(host) = query_value(query.host, 253) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(event) = query_value(query.event, 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(assessment) = choice_value(query.assessment, &["read", "mutate", "privileged"]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(verdict) = choice_value(
        query.verdict,
        &[
            "permit",
            "needs_approval",
            "deny",
            "supports_intent",
            "does_not_support_intent",
            "uncertain",
        ],
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok((window_label, window)) = window_value(query.window) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(q) = query_value(query.q, 128) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok((before, start)) = page_bounds(query.before, query.start) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let filters = Filters {
        principal,
        session,
        host,
        event,
        assessment,
        verdict,
        window: window_label,
        q,
    };
    let read_query = audit_history::Query {
        before,
        start,
        window,
        principal: filters.principal.clone(),
        session: filters.session.clone(),
        host: filters.host.clone(),
        event: filters.event.clone(),
        assessment: filters.assessment.clone(),
        verdict: filters.verdict.clone(),
        text: filters.q.clone(),
    };
    let (entries, next_url, source_notice, source_available, verification, verification_ok) =
        match audit_reader.page(&read_query).await {
            Ok(page) => {
                let entries = page.entries.into_iter().map(audit_shown).collect();
                (
                    entries,
                    next_audit_url(&filters, page.next_before, page.window_start),
                    "Durable fleet view. Entries are read from the deployment log store; timestamps are the collector's wall clock.".to_owned(),
                    true,
                    "Loki available · entry digests shown".to_owned(),
                    true,
                )
            }
            Err(why) => {
                tracing::warn!(%why, "the durable audit page is unavailable");
                (
                    Vec::new(),
                    String::new(),
                    "Durable fleet view unavailable. No historical rows are shown; the page does not substitute process-local data or stale success.".to_owned(),
                    false,
                    "Durable source unavailable".to_owned(),
                    false,
                )
            }
        };
    let mut page = OperationsPage::new(operator.0, "Audit log");
    page.audit_active = true;
    page.audit = entries;
    page.filters = filters;
    page.verification = verification;
    page.verification_ok = verification_ok;
    page.source_notice = source_notice;
    page.source_available = source_available;
    page.next_url = next_url;
    render_operations(page)
}

async fn evaluations<C, S>(
    State(_bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(audit_reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Query(query): Query<EvaluationQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let Ok((before, start)) = page_bounds(query.before, query.start) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(assessment) = choice_value(query.assessment, &["read", "mutate", "privileged"]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(verdict) = choice_value(
        query.verdict,
        &["supports_intent", "does_not_support_intent", "uncertain"],
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok((window_label, window)) = window_value(query.window) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut filters = blank_filters();
    filters.assessment = assessment;
    filters.verdict = verdict;
    filters.window = window_label;
    let read = audit_reader
        .page(&audit_history::Query {
            before,
            start,
            window,
            event: "evaluated".to_owned(),
            assessment: filters.assessment.clone(),
            verdict: filters.verdict.clone(),
            ..audit_history::Query::default()
        })
        .await;
    let (evaluations, source_notice, source_available, next_url) = match read {
        Ok(page) => {
            let decisions: HashMap<_, _> = page
                .entries
                .iter()
                .filter(|entry| wire_event_name(&entry.event) == "decided")
                .map(|entry| {
                    (
                        entry.digest.clone(),
                        (
                            wire_command(&entry.event),
                            visible(
                                wire_string(&entry.event, "agent_intent").unwrap_or("unavailable"),
                            ),
                            visible(wire_string(&entry.event, "purpose").unwrap_or("unavailable")),
                        ),
                    )
                })
                .collect();
            let evaluations = page
                .entries
                .iter()
                .filter_map(|entry| {
                    if wire_event_name(&entry.event) != "evaluated" {
                        return None;
                    }
                    let artifact = entry.event.get("artifact")?;
                    let decision_digest = wire_string(artifact, "decision_digest")?.to_owned();
                    let context = decisions.get(&decision_digest);
                    let recorded_command = wire_argv(&entry.event);
                    Some(EvaluationShown {
                        id: visible(
                            wire_string(artifact, "evaluation_id").unwrap_or("unavailable"),
                        ),
                        recorded_at: source_time(entry.source_nanos),
                        verdict: wire_string(artifact, "verdict")
                            .unwrap_or("unavailable")
                            .replace('_', " "),
                        confidence: artifact
                            .get("confidence")
                            .and_then(serde_json::Value::as_u64)
                            .and_then(|value| u8::try_from(value).ok())
                            .unwrap_or_default(),
                        evaluator: visible(
                            wire_string(artifact, "evaluator").unwrap_or("unavailable"),
                        ),
                        model: visible(wire_string(artifact, "model").unwrap_or("unavailable")),
                        prompt_version: visible(
                            wire_string(artifact, "prompt_version").unwrap_or("unavailable"),
                        ),
                        rationale: visible(
                            wire_string(artifact, "rationale").unwrap_or("unavailable"),
                        ),
                        side_effects: artifact
                            .get("side_effects")
                            .and_then(serde_json::Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(serde_json::Value::as_str)
                            .map(visible)
                            .collect(),
                        decision_digest,
                        assessment: visible(
                            wire_string(&entry.event, "assessment").unwrap_or("unavailable"),
                        ),
                        principal: visible(&entry.principal),
                        session: visible(&entry.session),
                        command: if recorded_command.is_empty() {
                            context.map_or_else(Vec::new, |item| item.0.clone())
                        } else {
                            recorded_command
                        },
                        agent_intent: wire_string(&entry.event, "agent_intent")
                            .map(visible)
                            .or_else(|| context.map(|item| item.1.clone()))
                            .unwrap_or_else(|| "unavailable".to_owned()),
                        purpose: wire_string(&entry.event, "purpose")
                            .map(visible)
                            .or_else(|| context.map(|item| item.2.clone()))
                            .unwrap_or_else(|| "unavailable".to_owned()),
                        session_url: session_history_url(&entry.session),
                    })
                })
                .collect();
            let next_url = next_evaluations_url(&filters, page.next_before, page.window_start);
            (
                evaluations,
                "Durable fleet view. Evaluation artifacts are read from the deployment log store and remain advisory only.".to_owned(),
                true,
                next_url,
            )
        }
        Err(why) => {
            tracing::warn!(%why, "the durable evaluation page is unavailable");
            (
                Vec::new(),
                "Durable fleet view unavailable. No evaluation artifacts are shown; the page does not substitute process-local data or stale success.".to_owned(),
                false,
                String::new(),
            )
        }
    };
    let mut page = OperationsPage::new(operator.0, "Evaluations");
    page.evaluations_active = true;
    page.evaluations = evaluations;
    page.filters = filters;
    page.source_notice = source_notice;
    page.source_available = source_available;
    page.next_url = next_url;
    render_operations(page)
}

async fn queue<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    let page = ApprovalsPage {
        operator: operator.0,
        action: format!("{DASHBOARD_PATH}/approvals"),
        waiting: bastion
            .waiting_for_approval()
            .into_iter()
            .map(Pending::from)
            .collect(),
        standing: bastion
            .standing_approvals()
            .into_iter()
            .map(|(agreement, remaining)| StandingShown::from(agreement, remaining))
            .collect(),
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(why) => {
            tracing::error!(%why, "the approvals page could not be rendered");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<p>The approvals page could not be rendered.</p>"),
            )
                .into_response()
        }
    }
}

async fn answer<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Decision>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    // Only a submission from this page is a decision; see FETCH_SITE_HEADER
    // for why anything else may be another site borrowing the operator's
    // browser.
    if single_header(&headers, FETCH_SITE_HEADER) != Some("same-origin") {
        return (
            StatusCode::FORBIDDEN,
            Html("<p>Decisions are made from the approvals page, not from another site.</p>"),
        )
            .into_response();
    }
    let id = match ssh_core::approval::RequestId::parse(&id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::NOT_FOUND, Html("<p>No such request.</p>")).into_response(),
    };

    let agreed = match form.decision.as_str() {
        "approve" => true,
        "refuse" => false,
        "approve-matching" => {
            let Ok(for_millis) = standing_duration(form.duration.as_deref()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Html("<p>That is not a duration.</p>"),
                )
                    .into_response();
            };
            return match bastion.approve_matching_work(&id, operator.0.clone(), for_millis) {
                Ok(agreement) => {
                    tracing::info!(
                        operator = operator.0,
                        request = id.as_str(),
                        agreement = agreement.as_str(),
                        "a request was approved with a matching-work agreement"
                    );
                    Redirect::to(&format!("{DASHBOARD_PATH}/approvals")).into_response()
                }
                Err(why) => decision_failure(&id, &why),
            };
        }
        "approve-session" => {
            // The command in front of the operator is approved by them
            // directly; their standing agreement then answers for the rest of
            // the session, for as long as they chose - never longer than the
            // session itself can last.
            let Ok(for_millis) = standing_duration(form.duration.as_deref()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Html("<p>That is not a duration.</p>"),
                )
                    .into_response();
            };
            return match bastion.approve_session(&id, operator.0.clone(), for_millis) {
                Ok(agreement) => {
                    tracing::info!(
                        operator = operator.0,
                        request = id.as_str(),
                        agreement = agreement.as_str(),
                        "a request was approved with a standing agreement for its session"
                    );
                    Redirect::to(&format!("{DASHBOARD_PATH}/approvals")).into_response()
                }
                Err(why) => decision_failure(&id, &why),
            };
        }
        // No recognised button. Nothing is a safe default here: agreeing by
        // accident runs a command a policy flagged, and refusing by accident
        // discards a decision the operator did not make.
        _ => return (StatusCode::BAD_REQUEST, Html("<p>Approve or refuse.</p>")).into_response(),
    };

    // The operator's name goes into the record with the decision, which is the
    // point of requiring one.
    let by = Approver::Human {
        who: operator.0.clone(),
    };
    match bastion.decide(&id, by, agreed) {
        Ok(()) => {
            tracing::info!(
                operator = operator.0,
                request = id.as_str(),
                agreed,
                "a request was answered"
            );
            // Answered with a redirect rather than a rendered page, so a
            // reloaded browser re-reads the queue instead of re-submitting the
            // decision.
            Redirect::to(&format!("{DASHBOARD_PATH}/approvals")).into_response()
        }
        Err(why) => decision_failure(&id, &why),
    }
}

/// How long a standing agreement should answer for, from the form's words.
///
/// The page's vocabulary, exactly: the session default and three shorter
/// choices. A value the page never offers did not come from an operator
/// reading it, so it is refused rather than interpreted.
fn standing_duration(duration: Option<&str>) -> Result<Option<u64>, NotADuration> {
    match duration {
        None | Some("session") => Ok(None),
        Some("15") => Ok(Some(900_000)),
        Some("30") => Ok(Some(1_800_000)),
        Some("60") => Ok(Some(3_600_000)),
        Some(_) => Err(NotADuration),
    }
}

/// The form named a duration the page never offers.
struct NotADuration;

/// Withdraws one standing agreement.
///
/// Guarded like a decision - same origin, named operator - because it changes
/// what the service will do with held commands, even though it grants nothing:
/// after it, they wait for a person again.
async fn revoke<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    Path(agreement): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Decision>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource,
{
    if single_header(&headers, FETCH_SITE_HEADER) != Some("same-origin") {
        return (
            StatusCode::FORBIDDEN,
            Html("<p>Decisions are made from the approvals page, not from another site.</p>"),
        )
            .into_response();
    }
    if form.decision != "revoke" {
        return (StatusCode::BAD_REQUEST, Html("<p>Revoke or leave it.</p>")).into_response();
    }
    let Ok(agreement) = AgreementId::parse(&agreement) else {
        return (
            StatusCode::NOT_FOUND,
            Html("<p>No such standing agreement.</p>"),
        )
            .into_response();
    };
    if bastion.revoke_standing(&agreement) {
        tracing::info!(
            operator = operator.0,
            agreement = agreement.as_str(),
            "a standing agreement was withdrawn"
        );
        Redirect::to(&format!("{DASHBOARD_PATH}/approvals")).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Html("<p>No such standing agreement.</p>"),
        )
            .into_response()
    }
}

/// Reports a failed decision as what actually happened.
///
/// Most failures mean the request was never acted on - it lapsed, was already
/// answered, or named nothing - and the queue is simply behind, which a
/// conflict says. A refused *record* is the opposite: the approval store
/// already applied the answer and then the recording boundary rejected the
/// entry, so the decision governs the agent with no record naming who made
/// it. Reporting that as "no longer waiting" would hide the one failure an
/// operator must hear about under a fail-closed audit boundary.
fn decision_failure(id: &ssh_core::approval::RequestId, why: &MediationError) -> Response {
    if let MediationError::Audit(why) = why {
        tracing::error!(%why, request = id.as_str(), "a decision was applied but not recorded");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(
                "<p>The decision was applied, but recording it failed. \
                 Tell an operator; it is not in the record.</p>",
            ),
        )
            .into_response();
    }
    tracing::warn!(%why, request = id.as_str(), "a request could not be answered");
    (
        StatusCode::CONFLICT,
        Html("<p>That request is no longer waiting.</p>"),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use ssh_core::approval::{Approvals, Standing, Windows};
    use ssh_core::audit::Ledger;
    use ssh_core::catalog::Catalog;
    use ssh_core::clock::TestClock;
    use ssh_core::command::Command;
    use ssh_core::policy::Engine;
    use ssh_core::session::{Lifetime, Purpose, SessionStore};
    use ssh_core::{HostId, PrincipalId, RoleId};
    use tower::ServiceExt as _;

    const PROXY_BEARER: &str = "89abcdef0123456789abcdef01234567";

    /// Builds a request that is waiting, without standing up a whole bastion:
    /// what the page renders is an `Asked`, and that is what this produces.
    fn asked(argv: &[&str]) -> Asked {
        asked_for(argv, "find out why resolution is failing")
    }

    fn asked_for(argv: &[&str], purpose: &str) -> Asked {
        asked_at_scope(argv, purpose, Scope::Mutate)
    }

    fn asked_at_scope(argv: &[&str], purpose: &str, scope: Scope) -> Asked {
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
                RoleId::parse("readonly").unwrap(),
                Purpose::parse(purpose).unwrap(),
                scope,
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
        let command = Command::new(argv.iter().map(|a| (*a).to_owned()).collect()).unwrap();
        let decision = Engine::builtin()
            .unwrap()
            .decide(&session, Catalog::builtin().unwrap().classify(&command))
            .unwrap();
        let held = Ledger::new(Arc::clone(&clock))
            .record_intent(
                decision,
                ssh_core::command::CommandIntent::parse("exercise the dashboard").unwrap(),
            )
            .unwrap();
        match approvals.ask(&held).unwrap() {
            Standing::Waiting(asked) => asked.into_asked(),
            other => panic!("expected a waiting request, got {other:?}"),
        }
    }

    fn page(waiting: Vec<Asked>) -> String {
        ApprovalsPage {
            operator: "chris".to_owned(),
            action: format!("{DASHBOARD_PATH}/approvals"),
            waiting: waiting.into_iter().map(Pending::from).collect(),
            standing: Vec::new(),
        }
        .render()
        .unwrap()
    }

    /// An unidentified command's request must say what the catalog could not
    /// read: "privileged" alone tells the approver nothing about why this
    /// command, of all commands, needs their judgement.
    #[test]
    fn the_page_says_why_an_unidentified_command_waits() {
        let waiting = asked_at_scope(
            &["tar", "-cf", "/tmp/x", "/etc"],
            "archive a directory",
            Scope::Privileged,
        );
        let rendered = page(vec![waiting]);
        assert!(
            rendered.contains("does not know the program tar"),
            "the page does not say what could not be read: {rendered}"
        );
    }

    /// A decision made from a command alone is not a decision. Everything that
    /// changes what the same command means has to be on the page.
    #[test]
    fn the_page_shows_what_a_decision_needs() {
        let waiting = asked(&["systemctl", "restart", "unbound"]);
        // The assessment shown must be the one this request was actually held
        // with, whatever the catalog assesses this command as today.
        let assessment = scope_name(waiting.assessment).to_owned();
        // The card carries the request's identifier, so the fragment link in
        // notes and in the agent's held answer lands the reader on it.
        let anchor = format!(r#"<article id="{}""#, waiting.id.as_str());
        let session = waiting.session.as_str().to_owned();
        let rendered = page(vec![waiting]);
        assert!(
            rendered.contains(&anchor),
            "the card cannot be landed on by fragment: {anchor}"
        );
        for needed in [
            "agent-clawde",
            session.as_str(),
            "dns1",
            "readonly",
            "find out why resolution is failing",
            assessment.as_str(),
            "systemctl",
            "restart",
            "unbound",
            "Session purpose",
            "Agent-supplied:",
            "exercise the dashboard",
        ] {
            assert!(rendered.contains(needed), "the page omits {needed}");
        }
    }

    /// Identity is required decision context, including at the largest valid
    /// unbroken identifier size on a narrow screen.
    #[test]
    fn identity_context_can_wrap_inside_the_card_header() {
        let rendered = page(vec![asked(&["systemctl", "restart", "unbound"])]);
        assert!(rendered.contains(".request-head > div { min-width:0; }"));
        assert!(rendered.contains(
            ".request-head h3 { margin:0 0 .3rem; font-size:1rem; overflow-wrap:anywhere; }"
        ));
    }

    /// The command is written by the agent whose request this is, so it is the
    /// one thing on the page an attacker controls. Rendering it unescaped would
    /// let a held command run script in the approver's browser - on the page
    /// whose whole purpose is deciding whether to trust that agent.
    #[test]
    fn an_argument_cannot_become_markup() {
        // The hostile words ride a catalogued command as subcommand operands:
        // only a classified command can be held, and operands are the part an
        // agent writes freely.
        let rendered = page(vec![asked(&[
            "systemctl",
            "restart",
            "<script>alert('x')</script>",
            "\" onmouseover=\"alert(1)",
        ])]);
        assert!(
            !rendered.contains("<script>alert"),
            "an argument was rendered as markup"
        );
        assert!(
            rendered.contains("&#60;script&#62;") || rendered.contains("&lt;script&gt;"),
            "the argument was not rendered at all: {rendered}"
        );
    }

    #[test]
    fn an_empty_queue_says_so_rather_than_rendering_nothing() {
        let rendered = page(Vec::new());
        assert!(rendered.contains("Nothing is waiting."));
    }

    /// HTML escaping stops markup, not deception: a bidirectional control
    /// reorders what the eye reads and a zero-width character hides content,
    /// so either could make the page display something other than what would
    /// run. Nothing invisible or reordering may reach the rendered page from
    /// agent-written text - the command or the purpose - only its written-out
    /// escape may.
    #[test]
    fn an_invisible_character_cannot_survive_into_the_page() {
        let mut request = asked_for(
            &["systemctl", "restart", "evil\u{202e}txt.\u{200b}sh"],
            "looks\u{2066}fine",
        );
        request.agent_intent =
            ssh_core::command::CommandIntent::parse("do what looks\u{2067}safe").unwrap();
        let rendered = page(vec![request]);
        for raw in ['\u{202e}', '\u{200b}', '\u{2066}', '\u{2067}'] {
            assert!(
                !rendered.contains(raw),
                "U+{:04X} reached the page unescaped",
                u32::from(raw)
            );
        }
        assert!(rendered.contains("evil\\u{202e}txt.\\u{200b}sh"));
        assert!(rendered.contains("looks\\u{2066}fine"));
        assert!(rendered.contains("looks\\u{2067}safe"));
    }

    /// The escape alphabet must be its own: an argument that *spells* an
    /// escape may not render identically to the character it spells, or the
    /// agent could dress a hidden character as a harmless-looking escape and
    /// vice versa.
    #[test]
    fn text_that_spells_an_escape_is_not_the_character_it_spells() {
        let spelled = page(vec![asked(&["systemctl", "restart", "a\\u{202e}b"])]);
        let real = page(vec![asked(&["systemctl", "restart", "a\u{202e}b"])]);
        assert_ne!(spelled, real);
        // The literal backslash itself renders escaped, never bare.
        assert!(spelled.contains("a\\u{5c}u{202e}b"));
        assert!(real.contains("a\\u{202e}b"));
    }

    /// An argument may contain a newline, so argument boundaries must come
    /// from page structure rather than from line breaks: an operator shown
    /// `a\nb` as two lines would approve two arguments that are really one.
    /// One list item per argument is the contract; content can never add an
    /// item.
    #[test]
    fn an_embedded_newline_cannot_pose_as_an_argument_boundary() {
        let one_argument = page(vec![asked(&["systemctl", "restart", "a\nb"])]);
        let two_arguments = page(vec![asked(&["systemctl", "restart", "a", "b"])]);
        assert_ne!(one_argument, two_arguments);
        assert_eq!(one_argument.matches("<li>").count(), 3);
        assert_eq!(two_arguments.matches("<li>").count(), 4);
    }

    /// One decision can cover the session, so the control has to be on the
    /// page - beside the per-command buttons, with the duration choices, and
    /// never pre-selected to anything shorter than the session default.
    #[test]
    fn the_page_offers_a_session_wide_approval() {
        let rendered = page(vec![asked(&["systemctl", "restart", "unbound"])]);
        assert!(rendered.contains(r#"value="approve-session""#));
        assert!(rendered.contains(r#"value="approve-matching""#));
        assert!(rendered.contains("systemctl restart"));
        assert!(rendered.contains("catalog-family-v1"));
        assert!(rendered.contains("does not infer a resource selector"));
        assert!(rendered.contains(r#"value="session" selected"#));
        for minutes in ["15", "30", "60"] {
            assert!(
                rendered.contains(&format!(r#"value="{minutes}""#)),
                "the {minutes}-minute choice is missing"
            );
        }
    }

    #[test]
    fn unmatchable_commands_never_offer_a_matching_agreement() {
        let rendered = page(vec![asked(&["journalctl", "--rotate"])]);
        assert!(!rendered.contains(r#"value="approve-matching""#));
        assert!(!rendered.contains("Matching coverage:"));
        assert!(rendered.contains(r#"value="approve-session""#));
    }

    /// A standing agreement is visible and withdrawable where decisions are
    /// made, and the grantor's name passes the same visibility rules as any
    /// other text shown to an operator.
    #[test]
    fn standing_agreements_are_shown_and_withdrawable() {
        let rendered = ApprovalsPage {
            operator: "chris".to_owned(),
            action: format!("{DASHBOARD_PATH}/approvals"),
            waiting: Vec::new(),
            standing: vec![StandingShown {
                id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                session: "0123456789abcdef0123456789abcdef".to_owned(),
                who: visible("chris\u{202e}"),
                remaining: "3 h 59 min".to_owned(),
                coverage: "Session-wide".to_owned(),
                detail: "Every held command in this session".to_owned(),
            }],
        }
        .render()
        .unwrap();
        assert!(rendered.contains("Standing agreements"));
        assert!(rendered.contains("0123456789abcdef0123456789abcdef"));
        assert!(rendered.contains("3 h 59 min"));
        assert!(rendered.contains(r#"value="revoke""#));
        assert!(
            rendered.contains("/approvals/standing/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "the withdrawal form does not name the agreement"
        );
        assert!(!rendered.contains('\u{202e}'));
    }

    /// The duration control's vocabulary is closed: the session default, a
    /// shorter number of minutes, and nothing else.
    #[test]
    fn a_duration_the_page_never_offers_is_refused() {
        assert!(matches!(standing_duration(None), Ok(None)));
        assert!(matches!(standing_duration(Some("session")), Ok(None)));
        assert!(matches!(standing_duration(Some("30")), Ok(Some(1_800_000))));
        for bad in ["0", "17", "45", "240", "-5", "an hour", ""] {
            assert!(
                standing_duration(Some(bad)).is_err(),
                "{bad:?} was accepted as a duration"
            );
        }
    }

    fn proxy() -> Proxy {
        Proxy::new(Arc::new(
            SharedBearer::new(PROXY_BEARER.to_owned(), None).unwrap(),
        ))
    }

    /// Just enough of an app to exercise admission: the layer, and a route that
    /// reports who got through it.
    fn guarded() -> Router {
        Router::new()
            .route(
                "/approvals",
                get(
                    |axum::Extension(operator): axum::Extension<Operator>| async move {
                        operator.name().to_owned()
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                proxy(),
                require_operator,
            ))
    }

    /// A refused audit record is the one decision failure where the answer
    /// already took effect, so it must not be reported as the harmless "queue
    /// is behind" conflict every other failure amounts to.
    #[test]
    fn a_refused_record_is_not_reported_as_a_stale_request() {
        let id = ssh_core::approval::RequestId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let refused_record = MediationError::Audit(ssh_core::audit::AuditError::NotRecorded);
        let never_acted_on = MediationError::Approval(ssh_core::approval::ApprovalError::Unknown);
        assert_eq!(
            decision_failure(&id, &refused_record).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            decision_failure(&id, &never_acted_on).status(),
            StatusCode::CONFLICT
        );
    }

    /// The same-origin submission guard is judged from inside the page's own
    /// origin, so a framed copy of the real page would pass it; the page must
    /// therefore refuse framing outright, in both spellings browsers read.
    #[tokio::test]
    async fn the_page_cannot_be_framed() {
        let response = guarded()
            .oneshot(
                HttpRequest::builder()
                    .uri("/approvals")
                    .header("authorization", "Bearer 89abcdef0123456789abcdef01234567")
                    .header(OPERATOR_HEADER, "chris")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("frame-ancestors 'none'")
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_FRAME_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
    }

    async fn admit(headers: Vec<(&'static str, &'static str)>) -> (StatusCode, String) {
        let mut builder = HttpRequest::builder().uri("/approvals");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = guarded()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// A request identifier arrives from a form submission, so the surface has
    /// to be sure about what it does with one it cannot act on. None of these
    /// may be mistaken for agreement.
    #[tokio::test]
    async fn a_decision_that_cannot_be_acted_on_is_not_taken_as_agreement() {
        let bastion = Arc::new(Bastion::new(
            Arc::new(TestClock::at(1_000)),
            ssh_core::registry::Registry::from_json("{}").unwrap(),
            ssh_core::catalog::Catalog::builtin().unwrap(),
            ssh_core::policy::Engine::builtin().unwrap(),
            NoCredentials,
            crate::settings::bounds(),
        ));
        let known_shape = "0123456789abcdef0123456789abcdef";

        for (what, id, form, expected) in [
            (
                "an identifier of the wrong shape",
                "not-an-identifier",
                "decision=approve",
                StatusCode::NOT_FOUND,
            ),
            (
                "a request that is not waiting",
                known_shape,
                "decision=approve",
                StatusCode::CONFLICT,
            ),
            (
                "neither button",
                known_shape,
                "decision=maybe",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let app =
                routes(Arc::clone(&bastion)).layer(axum::Extension(Operator("chris".to_owned())));
            let response = app
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri(format!("/approvals/{id}"))
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header(FETCH_SITE_HEADER, "same-origin")
                        .body(Body::from(form))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{what}");
        }
    }

    /// The proxy authenticates the operator, not the page: any site open in a
    /// signed-in browser can auto-submit this form, and the agent knows its
    /// request identifier. Only the browser's own statement that the
    /// submission came from this origin is accepted; see FETCH_SITE_HEADER.
    #[tokio::test]
    async fn a_submission_not_made_from_this_page_is_refused() {
        let bastion = Arc::new(Bastion::new(
            Arc::new(TestClock::at(1_000)),
            ssh_core::registry::Registry::from_json("{}").unwrap(),
            ssh_core::catalog::Catalog::builtin().unwrap(),
            ssh_core::policy::Engine::builtin().unwrap(),
            NoCredentials,
            crate::settings::bounds(),
        ));

        for (what, sites) in [
            ("another site's form", vec!["cross-site"]),
            ("a browser too old to say", vec![]),
            (
                "an ambiguous repeated header",
                vec!["same-origin", "same-origin"],
            ),
        ] {
            let app =
                routes(Arc::clone(&bastion)).layer(axum::Extension(Operator("chris".to_owned())));
            let mut builder = HttpRequest::builder()
                .method("POST")
                .uri("/approvals/0123456789abcdef0123456789abcdef")
                .header("content-type", "application/x-www-form-urlencoded");
            for site in sites {
                builder = builder.header(FETCH_SITE_HEADER, site);
            }
            let response = app
                .oneshot(builder.body(Body::from("decision=approve")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "admitted {what}");
        }
    }

    fn operations_bastion() -> Arc<Bastion<TestClock, NoCredentials>> {
        operations_bastion_with_registry("{}")
    }

    fn operations_bastion_with_registry(registry: &str) -> Arc<Bastion<TestClock, NoCredentials>> {
        Arc::new(Bastion::new(
            Arc::new(TestClock::at(1_000)),
            ssh_core::registry::Registry::from_json(registry).unwrap(),
            ssh_core::catalog::Catalog::builtin().unwrap(),
            ssh_core::policy::Engine::builtin().unwrap(),
            NoCredentials,
            crate::settings::bounds(),
        ))
    }

    #[tokio::test]
    async fn inventory_lists_configured_boundaries_without_promising_permission() {
        let bastion = operations_bastion_with_registry(
            r#"{
              "dns1": {
                "address": "dns1.internal:22",
                "host_key": "SHA256:AAAA1111",
                "roles": {
                  "readonly": {"user": "mcp-ro", "credential": "mcp-ssh/dns1/readonly"},
                  "operator": {"user": "mcp-op", "credential": "mcp-ssh/dns1/operator"}
                }
              }
            }"#,
        );
        let response = routes(bastion)
            .layer(axum::Extension(Operator("chris".to_owned())))
            .oneshot(
                HttpRequest::builder()
                    .uri("/inventory")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("dns1"));
        assert!(body.contains("readonly"));
        assert!(body.contains("operator"));
        assert!(body.contains("not an authorization promise"));
        assert!(body.contains("/dashboard/audit?host=dns1"));
        assert!(!body.contains("mcp-ssh/dns1/readonly"));
    }

    struct DurablePage;

    fn no_transcript<'a>() -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<audit_history::TranscriptPage, audit_history::ReadError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(audit_history::ReadError::NotConfigured) })
    }

    impl ReadsAudit for DurablePage {
        fn page<'a>(
            &'a self,
            _query: &'a audit_history::Query,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::Page, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                Ok(audit_history::Page {
                    entries: vec![audit_history::Entry {
                        source_nanos: 1_800_000_000_123_000_000,
                        sequence: 7,
                        at: 500,
                        session: "session-1".to_owned(),
                        principal: "agent-clawde".to_owned(),
                        host: "dns1".to_owned(),
                        role: "readonly".to_owned(),
                        event: serde_json::json!({
                            "event": "decided",
                            "argv": ["systemctl", "status", "unbound"],
                            "agent_intent": "inspect dns health",
                            "assessment": "read",
                            "verdict": "permit"
                        }),
                        previous: "b".repeat(64),
                        digest: "a".repeat(64),
                    }],
                    next_before: Some(1_799_999_999_999_999_999),
                    window_start: 1_700_000_000_000_000_000,
                })
            })
        }

        fn transcript<'a>(
            &'a self,
            _query: &'a audit_history::TranscriptQuery,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::TranscriptPage, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            no_transcript()
        }
    }

    #[tokio::test]
    async fn durable_audit_rows_link_to_session_history_and_the_older_page() {
        let response = routes_with_audit(operations_bastion(), Arc::new(DurablePage))
            .layer(axum::Extension(Operator("chris".to_owned())))
            .oneshot(
                HttpRequest::builder()
                    .uri("/audit?window=7d&assessment=read&verdict=permit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Durable fleet view."));
        assert!(body.contains("systemctl"));
        assert!(body.contains(r#"value="7d" selected"#));
        assert!(body.contains(r#"value="read" selected"#));
        assert!(body.contains(r#"value="permit" selected"#));
        assert!(
            body.contains("/dashboard/sessions/session-1"),
            "session link missing: {body}"
        );
        assert!(
            body.contains("before=1799999999999999999"),
            "older-page link missing: {body}"
        );
        assert!(
            body.contains("start=1700000000000000000"),
            "fixed window boundary missing: {body}"
        );
    }

    struct EvaluationPage;

    impl ReadsAudit for EvaluationPage {
        fn page<'a>(
            &'a self,
            query: &'a audit_history::Query,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::Page, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                assert_eq!(query.window, audit_history::Window::Week);
                assert_eq!(query.event, "evaluated");
                assert_eq!(query.assessment, "read");
                assert_eq!(query.verdict, "supports_intent");
                Ok(audit_history::Page {
                    entries: vec![audit_history::Entry {
                        source_nanos: 1_800_000_000_123_000_000,
                        sequence: 8,
                        at: 500,
                        session: "0123456789abcdef0123456789abcdef".to_owned(),
                        principal: "agent-clawde".to_owned(),
                        host: "dns1".to_owned(),
                        role: "readonly".to_owned(),
                        event: serde_json::json!({
                            "event": "evaluated",
                            "artifact": {
                                "evaluation_id": "eval-8",
                                "decision_digest": "d".repeat(64),
                                "evaluator": "shadow-reviewer",
                                "model": "review-model",
                                "prompt_version": "intent-v1",
                                "verdict": "supports_intent",
                                "confidence": 91,
                                "rationale": "The read-only command supports the diagnosis.",
                                "side_effects": ["Reads service metadata"]
                            },
                            "decided": 7,
                            "argv": ["systemctl", "status", "unbound"],
                            "agent_intent": "inspect dns health",
                            "purpose": "diagnose dns",
                            "assessment": "read"
                        }),
                        previous: "b".repeat(64),
                        digest: "a".repeat(64),
                    }],
                    next_before: Some(1_799_999_999_999_999_999),
                    window_start: 1_700_000_000_000_000_000,
                })
            })
        }

        fn transcript<'a>(
            &'a self,
            _query: &'a audit_history::TranscriptQuery,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::TranscriptPage, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            no_transcript()
        }
    }

    #[tokio::test]
    async fn filtered_evaluations_keep_recorded_decision_context() {
        let response = routes_with_audit(operations_bastion(), Arc::new(EvaluationPage))
            .layer(axum::Extension(Operator("chris".to_owned())))
            .oneshot(
                HttpRequest::builder()
                    .uri("/evaluations?window=7d&assessment=read&verdict=supports_intent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        for expected in [
            r#"value="read" selected"#,
            r#"value="supports_intent" selected"#,
            "Decision assessment",
            "inspect dns health",
            "diagnose dns",
            "systemctl",
            "Reads service metadata",
            "assessment=read",
            "verdict=supports_intent",
        ] {
            assert!(
                body.contains(expected),
                "evaluation omitted {expected}: {body}"
            );
        }
    }

    struct SessionJourneyPage;

    impl ReadsAudit for SessionJourneyPage {
        fn page<'a>(
            &'a self,
            _query: &'a audit_history::Query,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::Page, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                let session = "0123456789abcdef0123456789abcdef";
                let decision_digest = "d".repeat(64);
                let entry = |sequence, event, digest: String| audit_history::Entry {
                    source_nanos: 1_800_000_000_000_000_000_u64.saturating_add(sequence),
                    sequence,
                    at: sequence,
                    session: session.to_owned(),
                    principal: "agent-clawde".to_owned(),
                    host: "dns1".to_owned(),
                    role: "readonly".to_owned(),
                    event,
                    previous: "a".repeat(64),
                    digest,
                };
                Ok(audit_history::Page {
                    entries: vec![
                        entry(
                            21,
                            serde_json::json!({
                                "event": "completed",
                                "run": "0123456789abcdef-0123456789abcdef0123456789abcdef",
                                "decided": 20,
                                "state": "exit 0",
                                "stdout": {"kind": "kept", "text": "automatic", "truncated": false, "bytes": 9},
                                "stderr": {"kind": "kept", "text": "", "truncated": false, "bytes": 0}
                            }),
                            "9".repeat(64),
                        ),
                        entry(
                            20,
                            serde_json::json!({
                                "event": "decided",
                                "argv": ["uname", "-a"],
                                "agent_intent": "inspect kernel",
                                "purpose": "diagnose dns",
                                "assessment": "read",
                                "verdict": "permit"
                            }),
                            "8".repeat(64),
                        ),
                        entry(
                            14,
                            serde_json::json!({
                                "event": "evaluated",
                                "artifact": {
                                    "evaluation_id": "eval-14",
                                    "decision_digest": decision_digest,
                                    "evaluator": "shadow-reviewer",
                                    "model": "review-model",
                                    "prompt_version": "intent-v1",
                                    "verdict": "supports_intent",
                                    "confidence": 91,
                                    "rationale": "The read-only command supports the stated diagnosis.",
                                    "side_effects": ["May reveal service metadata"]
                                }
                            }),
                            "e".repeat(64),
                        ),
                        entry(
                            13,
                            serde_json::json!({
                                "event": "completed",
                                "run": "abcdef0123456789-abcdef0123456789abcdef0123456789",
                                "decided": 12,
                                "state": "exit 0",
                                "stdout": {"kind": "kept", "text": "active", "truncated": false, "bytes": 6},
                                "stderr": {"kind": "kept", "text": "", "truncated": false, "bytes": 0}
                            }),
                            "c".repeat(64),
                        ),
                        entry(
                            12,
                            serde_json::json!({
                                "event": "approved",
                                "decided": 10,
                                "request": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "approver": "chris",
                                "override_of": null,
                                "standing": true,
                                "mode": "matching",
                                "agreement": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "matcher_version": "matching-v1"
                            }),
                            "b".repeat(64),
                        ),
                        entry(
                            11,
                            serde_json::json!({
                                "event": "answered",
                                "decided": 10,
                                "request": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "approver": "chris",
                                "override_of": null,
                                "standing": true,
                                "mode": "matching",
                                "agreement": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "matcher_version": "matching-v1",
                                "agreed": true
                            }),
                            "a".repeat(64),
                        ),
                        entry(
                            10,
                            serde_json::json!({
                                "event": "decided",
                                "argv": ["systemctl", "status", "unbound"],
                                "agent_intent": "inspect dns health",
                                "purpose": "diagnose dns",
                                "assessment": "read",
                                "verdict": "needs_approval"
                            }),
                            "d".repeat(64),
                        ),
                    ],
                    next_before: Some(1_700_000_000_000_000_000),
                    window_start: 1_600_000_000_000_000_000,
                })
            })
        }

        fn transcript<'a>(
            &'a self,
            query: &'a audit_history::TranscriptQuery,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<audit_history::TranscriptPage, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let page = self.page(&audit_history::Query::default()).await?;
                Ok(audit_history::TranscriptPage {
                    entries: page.entries,
                    next_before: page.next_before,
                    window_start: page.window_start,
                    window_end: query.end.unwrap_or(1_800_000_000_000_000_000),
                })
            })
        }

        fn output<'a>(
            &'a self,
            query: &'a audit_history::OutputQuery,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Option<audit_history::Entry>, audit_history::ReadError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                assert_eq!(query.session.as_str(), "0123456789abcdef0123456789abcdef");
                assert_eq!(
                    query.run.as_str(),
                    "0123456789abcdef-0123456789abcdef0123456789abcdef"
                );
                assert_eq!(query.start, 1_600_000_000_000_000_000);
                assert_eq!(query.end, 1_800_000_000_000_000_000);
                Ok(Some(audit_history::Entry {
                    source_nanos: query.end,
                    sequence: 21,
                    at: 21,
                    session: query.session.as_str().to_owned(),
                    principal: "agent-clawde".to_owned(),
                    host: "dns1".to_owned(),
                    role: "readonly".to_owned(),
                    event: serde_json::json!({
                        "event": "completed",
                        "run": query.run.as_str(),
                        "decided": 20,
                        "state": "exit 0",
                        "stdout": {
                            "kind": "kept",
                            "text": format!("{}TAIL", "x".repeat(OPERATIONS_OUTPUT_PREVIEW_BYTES + 1)),
                            "truncated": true,
                            "bytes": 9_000
                        },
                        "stderr": {"kind": "kept", "text": "", "truncated": false, "bytes": 0}
                    }),
                    previous: "a".repeat(64),
                    digest: "9".repeat(64),
                }))
            })
        }
    }

    #[tokio::test]
    async fn a_session_transcript_joins_decision_authorization_outcome_and_evaluation() {
        let session = "0123456789abcdef0123456789abcdef";
        let response = routes_with_audit(operations_bastion(), Arc::new(SessionJourneyPage))
            .layer(axum::Extension(Operator("chris".to_owned())))
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/sessions/{session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        for expected in [
            "Decision #10",
            "Decision #20",
            "Policy decision entry #20",
            "automatic",
            "chris accepted via matching standing agreement",
            "Approval entry #12",
            "Run abcdef0123456789-abcdef0123456789abcdef0123456789 · exit 0",
            "The read-only command supports the stated diagnosis.",
            "May reveal service metadata",
            "active",
            "Older commands",
            "Inspect complete retained stdout",
        ] {
            assert!(
                body.contains(expected),
                "transcript omitted {expected}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn retained_output_expands_every_kept_byte_for_a_policy_permitted_command() {
        let session = "0123456789abcdef0123456789abcdef";
        let run = "0123456789abcdef-0123456789abcdef0123456789abcdef";
        let response = routes_with_audit(operations_bastion(), Arc::new(SessionJourneyPage))
            .layer(axum::Extension(Operator("chris".to_owned())))
            .oneshot(
                HttpRequest::builder()
                    .uri(format!(
                        "/sessions/{session}/runs/{run}/stdout?before=1800000000000000000&start=1600000000000000000&end=1800000000000000000"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Complete retained command output"));
        assert!(
            body.contains("TAIL"),
            "the retained tail was omitted: {body}"
        );
        assert!(body.contains("target produced 9000 bytes"));
        assert!(body.contains("execution capture truncated"));
        assert!(body.contains("exact session and run filter"));
    }

    #[test]
    fn completed_output_previews_are_bounded_explicit_and_safe_to_read() {
        let text = format!("{}éTAIL", "x".repeat(OPERATIONS_OUTPUT_PREVIEW_BYTES - 1));
        let shown = wire_output(
            "stdout",
            &serde_json::json!({
                "kind": "kept",
                "text": text,
                "truncated": true,
                "bytes": 9_000
            }),
        )
        .unwrap();
        assert_eq!(shown.label, "stdout");
        assert_eq!(shown.preview.len(), OPERATIONS_OUTPUT_PREVIEW_BYTES - 1);
        assert!(shown.preview.chars().all(|ch| ch == 'x'));
        assert!(shown.note.contains("dashboard preview truncated"));
        assert!(shown.note.contains("execution capture truncated"));
        assert!(shown.note.contains("target produced 9000 bytes"));

        let controls = wire_output(
            "stderr",
            &serde_json::json!({
                "kind": "kept",
                "text": "line one\n\u{202e}line two",
                "truncated": false,
                "bytes": 20
            }),
        )
        .unwrap();
        assert!(controls.preview.contains("\\u{a}"));
        assert!(controls.preview.contains("\\u{202e}"));

        let withheld = wire_output(
            "stdout",
            &serde_json::json!({
                "kind": "withheld",
                "bytes": 42,
                "matched": "private key"
            }),
        )
        .unwrap();
        assert_eq!(withheld.preview, "[withheld]");
        assert!(withheld.note.contains("42 bytes produced"));
        assert!(withheld.note.contains("content not retained"));
    }

    #[tokio::test]
    async fn operations_views_state_live_and_durable_source_boundaries_honestly() {
        let bastion = operations_bastion();
        for (path, expected) in [
            ("/sessions", "No sessions are held by this process."),
            (
                "/sessions/0123456789abcdef0123456789abcdef",
                "The durable session transcript is currently unavailable.",
            ),
            ("/audit", "Historical audit data is currently unavailable."),
            (
                "/evaluations",
                "Historical evaluation data is currently unavailable.",
            ),
        ] {
            let response = routes(Arc::clone(&bastion))
                .layer(axum::Extension(Operator("chris".to_owned())))
                .oneshot(
                    HttpRequest::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(body.contains(expected), "{path} omitted {expected}: {body}");
            if path == "/sessions" {
                assert!(body.contains("retained since this service restart"));
                assert!(body.contains("100"), "sessions omitted its result bound");
            } else {
                assert!(body.contains("does not substitute process-local data or stale success"));
                assert!(body.contains("20"), "{path} omitted its durable page bound");
            }
            if path == "/evaluations" {
                assert!(body.contains("Advisory · cannot authorize"));
            }
        }
    }

    #[tokio::test]
    async fn audit_search_inputs_are_bounded() {
        assert!(query_value(Some("p".repeat(256)), 256).is_ok());
        assert!(query_value(Some("h".repeat(253)), 253).is_ok());
        assert_eq!(
            window_value(Some("7d".to_owned())),
            Ok(("7d".to_owned(), audit_history::Window::Week))
        );
        let too_long = "x".repeat(129);
        for path in [
            format!("/audit?q={too_long}"),
            "/audit?window=90d".to_owned(),
            "/audit?assessment=unknown".to_owned(),
            "/audit?verdict=allow".to_owned(),
            "/evaluations?verdict=permit".to_owned(),
            "/evaluations?assessment=unknown".to_owned(),
            "/audit?before=20".to_owned(),
            "/audit?start=10".to_owned(),
            "/audit?before=20&start=21".to_owned(),
        ] {
            let response = routes(operations_bastion())
                .layer(axum::Extension(Operator("chris".to_owned())))
                .oneshot(
                    HttpRequest::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    /// Stands in for the secret store; nothing here reaches a target.
    struct NoCredentials;

    impl CredentialSource for NoCredentials {
        async fn fetch(
            &self,
            _reference: &ssh_core::registry::CredentialRef,
        ) -> Result<ssh_core::secret::Secret<String>, ssh_core::connect::CredentialError> {
            Err(ssh_core::connect::CredentialError::NotFound)
        }
    }

    /// The operator's name is what gets recorded against an approval, so a
    /// request that does not carry one cannot be allowed to answer anything.
    #[tokio::test]
    async fn only_a_named_operator_arriving_through_the_proxy_is_admitted() {
        let good = admit(vec![
            ("authorization", "Bearer 89abcdef0123456789abcdef01234567"),
            (OPERATOR_HEADER, "chris"),
        ])
        .await;
        assert_eq!(good.0, StatusCode::OK);
        assert_eq!(good.1, "chris");

        for (what, headers) in [
            ("nothing", vec![]),
            (
                "an operator but no proxy credential",
                vec![(OPERATOR_HEADER, "chris")],
            ),
            (
                "the wrong proxy credential",
                vec![
                    ("authorization", "Bearer ffffffffffffffffffffffffffffffff"),
                    (OPERATOR_HEADER, "chris"),
                ],
            ),
            (
                "the proxy credential but no operator",
                vec![("authorization", "Bearer 89abcdef0123456789abcdef01234567")],
            ),
            (
                "an operator whose name is blank",
                vec![
                    ("authorization", "Bearer 89abcdef0123456789abcdef01234567"),
                    (OPERATOR_HEADER, "   "),
                ],
            ),
        ] {
            let (status, _) = admit(headers).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "admitted {what}");
        }
    }
}
