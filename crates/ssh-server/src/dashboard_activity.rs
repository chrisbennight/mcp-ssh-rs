//! Shared operator-facing operation browsing. All reads are observational.
use super::*;
use serde::Serialize;
use ssh_core::audit::Event;
use ssh_core::run::{Cancellation, RunState};

#[path = "dashboard_current.rs"]
mod current;

#[path = "dashboard_exports.rs"]
mod exports;
pub(super) use exports::{export_activity, export_view};

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ActivityQuery {
    pub session: String,
    pub host: String,
    pub principal: String,
    pub q: String,
    pub source: String,
    pub before: Option<u64>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub window: String,
    pub kind: String,
    pub view: String,
    pub selected: String,
    pub role: String,
    pub request: String,
    pub agreement: String,
    pub run: String,
    pub approval: String,
    pub assessment: String,
    pub time_basis: String,
    pub service_start: Option<u64>,
    pub service_end: Option<u64>,
    pub instance: String,
    pub page_ids: String,
}

impl ActivityQuery {
    fn valid(&self) -> bool {
        self.session.len() <= 32
            && (self.session.is_empty() || SessionId::parse(&self.session).is_ok())
            && self.host.len() <= 253
            && self.principal.len() <= 256
            && self.q.len() <= 128
            && self.selected.len() <= 64
            && matches!(self.source.as_str(), "" | "current" | "history")
            && matches!(self.window.as_str(), "" | "1h" | "24h" | "7d" | "30d")
            && matches!(
                self.kind.as_str(),
                "" | "execute" | "files" | "upload" | "download" | "stat" | "list" | "checksum"
            )
            && state::Preset::parse(&self.view).is_some()
            && self.role.len() <= 128
            && (self.role.is_empty() || ssh_core::RoleId::parse(&self.role).is_ok())
            && (self.request.is_empty()
                || ssh_core::approval::RequestId::parse(&self.request).is_ok())
            && (self.agreement.is_empty()
                || ssh_core::approval::AgreementId::parse(&self.agreement).is_ok())
            && (self.run.is_empty() || RunId::parse(&self.run).is_ok())
            && matches!(
                self.approval.as_str(),
                "" | "waiting" | "approved" | "refused" | "not_required" | "expired"
            )
            && matches!(
                self.assessment.as_str(),
                "" | "supports_intent" | "does_not_support_intent" | "uncertain"
            )
            && matches!(self.time_basis.as_str(), "" | "requested" | "completed")
            && self
                .service_start
                .zip(self.service_end)
                .is_none_or(|(start, end)| start <= end)
            && (self.instance.is_empty() || is_digest(&self.instance))
            && self.page_ids.len() <= 4096
            && (self.page_ids.is_empty()
                || self.page_ids.split(',').count() <= 40
                    && self.page_ids.split(',').all(is_digest))
    }

    fn matches(&self, entry: &ssh_core::audit::Entry) -> bool {
        if (!self.session.is_empty() && entry.session.as_str() != self.session)
            || (!self.host.is_empty() && entry.host.as_str() != self.host)
            || (!self.principal.is_empty() && entry.principal.as_str() != self.principal)
            || (!self.role.is_empty() && entry.role.as_str() != self.role)
        {
            return false;
        }
        let Event::Decided {
            operation,
            argv,
            agent_intent,
            purpose,
            ..
        } = &entry.event
        else {
            return false;
        };
        let kind = operation.as_str();
        if !self.kind.is_empty()
            && !(self.kind == kind || (self.kind == "files" && kind != "execute"))
        {
            return false;
        }
        self.q.is_empty()
            || argv.iter().any(|argument| argument.contains(&self.q))
            || agent_intent.contains(&self.q)
            || purpose.contains(&self.q)
            || entry.digest.as_str() == self.q
    }

    fn url(&self, source: &str, before: Option<u64>) -> String {
        let mut pairs = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in [
            ("session", self.session.as_str()),
            ("host", &self.host),
            ("principal", &self.principal),
            ("q", &self.q),
            ("source", source),
            ("window", &self.window),
            ("kind", &self.kind),
            ("view", &self.view),
            ("selected", &self.selected),
            ("role", &self.role),
            ("request", &self.request),
            ("agreement", &self.agreement),
            ("run", &self.run),
            ("approval", &self.approval),
            ("assessment", &self.assessment),
            ("time_basis", &self.time_basis),
            (
                "instance",
                if source == "current" {
                    &self.instance
                } else {
                    ""
                },
            ),
        ] {
            if !value.is_empty() {
                pairs.append_pair(key, value);
            }
        }
        for (key, value) in [
            ("before", before),
            (
                "start",
                if source == "history" {
                    self.start
                } else {
                    None
                },
            ),
            ("end", if source == "history" { self.end } else { None }),
            (
                "service_start",
                if source == "current" {
                    self.service_start
                } else {
                    None
                },
            ),
            (
                "service_end",
                if source == "current" {
                    self.service_end
                } else {
                    None
                },
            ),
        ] {
            if let Some(value) = value {
                pairs.append_pair(key, &value.to_string());
            }
        }
        format!("/dashboard/activity?{}", pairs.finish())
    }
}

fn checksum_digest(info: Option<&ssh_core::files::FileInfo>) -> Option<&str> {
    match info {
        Some(ssh_core::files::FileInfo::Checksum { sha256, .. }) => Some(sha256),
        _ => None,
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_investigation(value: &str) -> Option<ActivityQuery> {
    if value.len() > 4096 {
        return None;
    }
    let uri: axum::http::Uri = value.parse().ok()?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() != "/dashboard/activity" {
        return None;
    }
    let Query(query) = Query::<ActivityQuery>::try_from_uri(&uri).ok()?;
    query.valid().then_some(query)
}

pub(super) fn investigation_return(value: &str) -> Option<String> {
    parse_investigation(value).map(|query| query.url(&query.source, query.before))
}

#[derive(Default, Serialize)]
struct OperationShown {
    id: String,
    session: String,
    host: String,
    role: String,
    principal: String,
    kind: String,
    preview: String,
    status: String,
    approval: String,
    when: String,
    intent: String,
    purpose: String,
    arguments: Vec<String>,
    result: Vec<(String, String)>,
    progress: String,
    cancellation: String,
    evidence: String,
    human_answer: String,
    authorization: String,
    outcome: String,
    outputs: Vec<OutputExport>,
    assessment: Option<AssessmentExport>,
    open: bool,
    attention: bool,
    file: Option<files::FileShown>,
    execution: state::Execution,
    approval_state: state::Approval,
    reasons: Vec<String>,
    request: String,
    run: String,
    agreement: String,
    requested_at: Option<u64>,
    sequence: u64,
    raw_arguments: Vec<String>,
    assessment_verdict: Option<ssh_core::audit::EvaluationVerdict>,
    missing_request: bool,
    completed_at: Option<u64>,
    raw_intent: String,
    raw_purpose: String,
    evidence_records: Vec<EvidenceShown>,
    investigation: String,
    session_url: String,
    agreement_url: String,
    file_info: Option<ssh_core::files::FileInfo>,
    file_identity: Option<ArtifactMetadata>,
}

#[derive(Serialize)]
struct ArtifactMetadata {
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct EvidenceShown {
    sequence: u64,
    digest: String,
    previous: String,
    recorded_at: u64,
    event: String,
    summary: String,
}

impl OperationShown {
    fn needs_review(&self) -> bool {
        self.approval_state == state::Approval::AwaitingDecision
    }
    fn classify(&mut self) {
        self.status = self.execution.label();
        self.reasons.clear();
        if self.approval_state == state::Approval::AwaitingDecision {
            self.reasons.push("Awaiting decision".to_owned());
        }
        if self.execution.failed()
            || self.execution.unknown()
            || self.execution.missing()
            || matches!(self.execution, state::Execution::Observed(RunState::Ended))
        {
            self.reasons.push(self.status.clone());
        }
        if self.missing_request {
            self.reasons
                .push("Original request evidence unavailable".to_owned());
        }
        if matches!(
            self.assessment_verdict,
            Some(
                ssh_core::audit::EvaluationVerdict::DoesNotSupportIntent
                    | ssh_core::audit::EvaluationVerdict::Uncertain
            )
        ) {
            self.reasons.push(format!(
                "Advisory assessment: {}",
                self.assessment
                    .as_ref()
                    .map(|assessment| assessment.verdict.as_str())
                    .unwrap_or("unavailable")
            ));
        }
        if !self.cancellation.is_empty() {
            self.reasons.push(self.cancellation.clone());
        }
        self.attention = !self.reasons.is_empty();
    }

    fn matches_view(&self, query: &ActivityQuery) -> bool {
        let view = state::Preset::parse(&query.view).is_some_and(|preset| {
            preset.includes(
                self.execution,
                self.approval_state,
                self.assessment.is_some(),
                self.attention,
            ) || (preset == state::Preset::Evidence && self.missing_request)
        });
        if !view {
            return false;
        }
        if !query.role.is_empty() && self.role != query.role
            || !query.request.is_empty() && self.request != query.request
            || !query.run.is_empty() && self.run != query.run
            || !query.agreement.is_empty() && self.agreement != query.agreement
        {
            return false;
        }
        if !query.kind.is_empty()
            && query.kind != self.kind
            && !(query.kind == "files" && self.kind != "execute" && self.kind != "unknown")
        {
            return false;
        }
        if !query.page_ids.is_empty() && !query.page_ids.split(',').any(|id| id == self.id) {
            return false;
        }
        if !query.approval.is_empty()
            && !match query.approval.as_str() {
                "waiting" => self.approval_state == state::Approval::AwaitingDecision,
                "approved" => matches!(
                    self.approval_state,
                    state::Approval::ApprovedOnce | state::Approval::Session
                ),
                "refused" => self.approval_state == state::Approval::Refused,
                "expired" => self.approval_state == state::Approval::Expired,
                "not_required" => self.approval_state == state::Approval::NotRequired,
                _ => false,
            }
        {
            return false;
        }
        if !query.assessment.is_empty()
            && self
                .assessment_verdict
                .and_then(|value| serde_json::to_value(value).ok())
                .and_then(|value| value.as_str().map(str::to_owned))
                .as_deref()
                != Some(query.assessment.as_str())
        {
            return false;
        }
        if !query.q.is_empty()
            && !self
                .raw_arguments
                .iter()
                .any(|argument| argument.contains(&query.q))
            && !self.raw_intent.contains(&query.q)
            && !self.raw_purpose.contains(&query.q)
            && checksum_digest(self.file_info.as_ref()) != Some(query.q.as_str())
            && !self
                .file_identity
                .as_ref()
                .is_some_and(|file| file.sha256 == query.q)
            && ![
                self.id.as_str(),
                self.session.as_str(),
                self.request.as_str(),
                self.run.as_str(),
                self.agreement.as_str(),
            ]
            .contains(&query.q.as_str())
            && !self.evidence_records.iter().any(|record| {
                record.digest == query.q
                    || record.sequence.to_string() == query.q
                    || format!("#{}", record.sequence) == query.q
            })
        {
            return false;
        }
        if self.evidence == "history"
            && query.time_basis == "completed"
            && self.completed_at.is_none_or(|at| {
                query.start.is_some_and(|start| at < start) || query.end.is_some_and(|end| at > end)
            })
        {
            return false;
        }
        true
    }
}

#[derive(Serialize)]
struct OutputExport {
    label: String,
    preview: String,
    note: String,
    url: String,
}

#[derive(Serialize)]
struct AssessmentExport {
    verdict: String,
    rationale: String,
    evaluator: String,
    confidence: u8,
    side_effects: Vec<String>,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityPage {
    operator: String,
    query: ActivityQuery,
    operations: Vec<OperationShown>,
    notice: String,
    current: Option<SessionShown>,
    standing: Vec<StandingShown>,
    next_url: String,
    current_url: String,
    history_url: String,
    source: String,
    live: bool,
    page_size: usize,
    matching: Option<usize>,
    available: bool,
    limited: bool,
    scanned: usize,
    investigation: String,
    page_ids: String,
    chips: Vec<(String, String)>,
    clear_view_url: String,
    refresh_url: String,
}

pub(super) fn preview(arguments: &[String], kind: &str) -> String {
    let first = arguments.first().map(String::as_str).unwrap_or("Operation");
    let title = match kind {
        "upload" => "Upload",
        "download" => "Download",
        "stat" => "Inspect file",
        "list" => "List directory",
        "checksum" => "Calculate checksum",
        _ => first,
    };
    let text = if kind == "execute" {
        arguments.join(" ")
    } else {
        format!(
            "{} {}",
            title,
            arguments.get(1).map(String::as_str).unwrap_or("")
        )
    };
    let mut chars = text.chars();
    let prefix: String = chars.by_ref().take(110).collect();
    if chars.next().is_some() {
        format!("{prefix} …")
    } else {
        prefix
    }
}

fn file_result(
    event: Option<&serde_json::Value>,
    command: &[String],
    kind: &str,
) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    if kind != "execute"
        && let Some(path) = command.get(1)
    {
        fields.push((
            if kind == "upload" {
                "Destination"
            } else {
                "Remote path"
            }
            .to_owned(),
            path.clone(),
        ));
    }
    if kind == "upload" {
        for (index, label) in [
            (2, "Source bytes"),
            (3, "SHA-256"),
            (4, "Write mode"),
            (6, "Staging path"),
        ] {
            if let Some(value) = command.get(index) {
                fields.push((label.to_owned(), value.clone()));
            }
        }
    }
    if let Some(event) = event {
        if let Some(file) = event.get("file").filter(|value| !value.is_null()) {
            for (name, label) in [("bytes", "Result bytes"), ("sha256", "Result SHA-256")] {
                if let Some(value) = file.get(name) {
                    fields.push((
                        label.to_owned(),
                        visible(
                            value
                                .as_str()
                                .map_or_else(|| value.to_string(), str::to_owned)
                                .as_str(),
                        ),
                    ));
                }
            }
        }
        if let Some(info) = event.get("info").filter(|value| !value.is_null()) {
            fields.push((
                "File metadata result".to_owned(),
                visible_output(&serde_json::to_string_pretty(info).unwrap_or_default()),
            ));
        }
    }
    fields
}

fn cancellation_status(value: Cancellation) -> &'static str {
    match value {
        Cancellation::NotRequested => "",
        Cancellation::Requested => "Cancellation requested",
        Cancellation::SignalSent => "TERM signal sent · termination not confirmed",
        Cancellation::SignalFailed => "Cancellation signal failed",
        Cancellation::TransferStopped => {
            "Transfer worker stopped · remote requests may have completed"
        }
    }
}

fn shown(
    entries: &[audit_history::Entry],
    query: &ActivityQuery,
    source: &str,
    before: u64,
    start: u64,
    end: u64,
) -> Vec<OperationShown> {
    let mut operations = Vec::new();
    for journey in wire_journeys(entries, before, start, end) {
        let Some(decision) = entries
            .iter()
            .find(|entry| entry.digest == journey.decision_digest)
        else {
            continue;
        };
        let Ok(session) = SessionId::parse(&decision.session) else {
            continue;
        };
        let authorizations = entries
            .iter()
            .filter(|entry| {
                entry.session == decision.session
                    && wire_event_name(&entry.event) == "approved"
                    && wire_u64(&entry.event, "decided") == Some(decision.sequence)
            })
            .map(|entry| entry.sequence)
            .collect::<std::collections::HashSet<_>>();
        let related =
            entries
                .iter()
                .filter(|entry| {
                    entry.session == decision.session
                        && (entry.sequence == decision.sequence
                            || match wire_event_name(&entry.event) {
                                "approved" | "answered" => {
                                    wire_u64(&entry.event, "decided") == Some(decision.sequence)
                                }
                                "completed" | "cancellation_requested" => {
                                    wire_u64(&entry.event, "decided").is_some_and(|sequence| {
                                        sequence == decision.sequence
                                            || authorizations.contains(&sequence)
                                    })
                                }
                                "evaluated" => {
                                    entry.event.get("artifact").and_then(|artifact| {
                                        wire_string(artifact, "decision_digest")
                                    }) == Some(decision.digest.as_str())
                                }
                                _ => false,
                            })
                })
                .collect::<Vec<_>>();
        let completion = related.iter().find(|entry| {
            entry.session == decision.session
                && wire_event_name(&entry.event) == "completed"
                && (wire_u64(&entry.event, "decided") == Some(decision.sequence)
                    || related.iter().any(|approval| {
                        approval.session == decision.session
                            && wire_event_name(&approval.event) == "approved"
                            && wire_u64(&approval.event, "decided") == Some(decision.sequence)
                            && wire_u64(&entry.event, "decided") == Some(approval.sequence)
                    }))
        });
        let kind = wire_string(&decision.event, "operation")
            .unwrap_or("execute")
            .to_owned();
        let mut status = journey.status.clone();
        if status == "Succeeded" {
            status = "Completed · exit 0".to_owned();
        }
        if status == "Approval requested" {
            status = "Historical approval request · current disposition unavailable".to_owned();
        }
        if status == "Approval recorded" {
            status = "Approved · collection not recorded".to_owned();
        }
        let outputs = journey
            .outputs
            .into_iter()
            .map(|output| {
                let url = if source == "current" && !output.inspect_url.is_empty() {
                    format!(
                        "{}?source=current",
                        output.inspect_url.split('?').next().unwrap_or_default()
                    )
                } else {
                    output.inspect_url
                };
                OutputExport {
                    label: output.label.to_owned(),
                    preview: output.preview,
                    note: output.note,
                    url: if url.is_empty() {
                        url
                    } else {
                        let mut scope = query.clone();
                        scope.selected = decision.digest.clone();
                        let back = scope.url(source, query.before);
                        let encoded = url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("return_to", &back)
                            .finish();
                        format!("{url}&{encoded}")
                    },
                }
            })
            .collect();
        let assessment = journey.evaluation.map(|evaluation| AssessmentExport {
            verdict: evaluation.verdict,
            rationale: evaluation.rationale,
            evaluator: evaluation.evaluator,
            confidence: evaluation.confidence,
            side_effects: evaluation.side_effects,
        });
        let cancellation = if related.iter().any(|entry| {
            entry.session == decision.session
                && wire_event_name(&entry.event) == "cancellation_requested"
                && (wire_u64(&entry.event, "decided") == Some(decision.sequence)
                    || related.iter().any(|approval| {
                        approval.session == decision.session
                            && wire_event_name(&approval.event) == "approved"
                            && wire_u64(&approval.event, "decided") == Some(decision.sequence)
                            && wire_u64(&entry.event, "decided") == Some(approval.sequence)
                    }))
        }) {
            "Cancellation requested · see observed result; request does not confirm termination"
                .to_owned()
        } else {
            String::new()
        };
        let attention = completion.is_some_and(|entry| {
            let state = wire_string(&entry.event, "state").unwrap_or("");
            state != "exit 0" && state != "Exited { code: 0 }"
        });
        let approval_entry = entries.iter().find(|entry| {
            entry.session == decision.session
                && wire_event_name(&entry.event) == "approved"
                && wire_u64(&entry.event, "decided") == Some(decision.sequence)
        });
        let answer = entries.iter().find(|entry| {
            entry.session == decision.session
                && wire_event_name(&entry.event) == "answered"
                && wire_u64(&entry.event, "decided") == Some(decision.sequence)
        });
        let refused = wire_string(&decision.event, "verdict") == Some("deny")
            || answer.is_some_and(|entry| {
                entry
                    .event
                    .get("agreed")
                    .and_then(serde_json::Value::as_bool)
                    == Some(false)
            });
        let approval_state = if refused {
            state::Approval::Refused
        } else if approval_entry.is_some_and(|entry| {
            entry
                .event
                .get("standing")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }) {
            state::Approval::Session
        } else if approval_entry.is_some() || answer.is_some() {
            state::Approval::ApprovedOnce
        } else if wire_string(&decision.event, "verdict") == Some("permit") {
            state::Approval::NotRequired
        } else {
            state::Approval::HistoricalUnconfirmed
        };
        let execution = completion
            .map(|entry| state::Execution::from_completion(&entry.event))
            .unwrap_or(
                if approval_entry.is_some() || approval_state == state::Approval::NotRequired {
                    state::Execution::EvidenceMissing
                } else {
                    state::Execution::NotStarted
                },
            );
        let raw_arguments = decision
            .event
            .get("argv")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let assessment_verdict = entries
            .iter()
            .find(|entry| {
                entry.session == decision.session
                    && wire_event_name(&entry.event) == "evaluated"
                    && entry
                        .event
                        .get("artifact")
                        .and_then(|artifact| wire_string(artifact, "decision_digest"))
                        == Some(decision.digest.as_str())
            })
            .and_then(|entry| entry.event.get("artifact"))
            .and_then(|artifact| artifact.get("verdict"))
            .and_then(|verdict| serde_json::from_value(verdict.clone()).ok());
        operations.push(OperationShown {
            execution,
            approval_state,
            reasons: Vec::new(),
            missing_request: false,
            completed_at: completion.map(|entry| {
                if source == "current" {
                    entry.at
                } else {
                    entry.source_nanos
                }
            }),
            raw_intent: wire_string(&decision.event, "agent_intent")
                .unwrap_or_default()
                .to_owned(),
            raw_purpose: wire_string(&decision.event, "purpose")
                .unwrap_or_default()
                .to_owned(),
            evidence_records: related
                .iter()
                .map(|entry| EvidenceShown {
                    sequence: entry.sequence,
                    digest: entry.digest.clone(),
                    previous: entry.previous.clone(),
                    recorded_at: if source == "current" {
                        entry.at
                    } else {
                        entry.source_nanos
                    },
                    event: wire_event_name(&entry.event).to_owned(),
                    summary: wire_summary(&entry.event),
                })
                .collect(),
            request: approval_entry
                .or(answer)
                .and_then(|entry| wire_string(&entry.event, "request"))
                .unwrap_or_default()
                .to_owned(),
            agreement: approval_entry
                .and_then(|entry| wire_string(&entry.event, "agreement"))
                .unwrap_or_default()
                .to_owned(),
            run: completion
                .and_then(|entry| wire_string(&entry.event, "run"))
                .unwrap_or_default()
                .to_owned(),
            requested_at: Some(if source == "current" {
                decision.at
            } else {
                decision.source_nanos
            }),
            sequence: decision.sequence,
            raw_arguments: raw_arguments.clone(),
            assessment_verdict,
            investigation: String::new(),
            session_url: String::new(),
            agreement_url: String::new(),
            file_info: completion
                .and_then(|entry| entry.event.get("info"))
                .and_then(|value| serde_json::from_value(value.clone()).ok()),
            file_identity: completion
                .and_then(|entry| entry.event.get("file"))
                .and_then(|file| {
                    Some(ArtifactMetadata {
                        bytes: file.get("bytes")?.as_u64()?,
                        sha256: file.get("sha256")?.as_str()?.to_owned(),
                    })
                }),
            file: files::describe(&kind, &raw_arguments, completion.map(|entry| &entry.event)),
            id: decision.digest.clone(),
            session: session.as_str().to_owned(),
            host: visible(&decision.host),
            role: visible(&decision.role),
            principal: visible(&decision.principal),
            preview: preview(&journey.command, &kind),
            status,
            approval: journey.approval,
            when: journey.when,
            intent: journey.agent_intent,
            purpose: journey.purpose,
            result: file_result(
                completion.map(|entry| &entry.event),
                &journey.command,
                &kind,
            ),
            arguments: journey.command,
            kind,
            progress: String::new(),
            cancellation,
            evidence: source.to_owned(),
            human_answer: journey.human_answer,
            authorization: journey.authorization,
            outcome: journey.outcome,
            outputs,
            assessment,
            open: query.selected == decision.digest,
            attention,
        });
    }
    for entry in entries
        .iter()
        .filter(|entry| wire_event_name(&entry.event) == "completed")
    {
        let authority = wire_u64(&entry.event, "decided").and_then(|sequence| {
            entries.iter().find(|candidate| {
                candidate.session == entry.session && candidate.sequence == sequence
            })
        });
        let original = authority.and_then(|authority| match wire_event_name(&authority.event) {
            "decided" => Some(authority),
            "approved" => wire_u64(&authority.event, "decided").and_then(|sequence| {
                entries.iter().find(|candidate| {
                    candidate.session == entry.session
                        && candidate.sequence == sequence
                        && wire_event_name(&candidate.event) == "decided"
                })
            }),
            _ => None,
        });
        if original.is_some() || operations.iter().any(|row| row.id == entry.digest) {
            continue;
        }
        let kind = entry
            .event
            .get("info")
            .and_then(|info| wire_string(info, "operation"))
            .unwrap_or("unknown")
            .to_owned();
        let approval_state =
            if authority.is_some_and(|authority| wire_event_name(&authority.event) == "approved") {
                if authority.is_some_and(|authority| {
                    authority
                        .event
                        .get("standing")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                }) {
                    state::Approval::Session
                } else {
                    state::Approval::ApprovedOnce
                }
            } else {
                state::Approval::HistoricalUnconfirmed
            };
        let run = wire_string(&entry.event, "run")
            .unwrap_or_default()
            .to_owned();
        let outputs = wire_outputs(&entry.event)
            .into_iter()
            .map(|output| OutputExport {
                label: output.label.to_owned(),
                preview: output.preview,
                note: output.note,
                url: if source == "current" {
                    format!(
                        "/dashboard/sessions/{}/runs/{}/{}?source=current",
                        entry.session, run, output.label
                    )
                } else {
                    retained_output_url(&entry.session, &run, output.label, before, start, end)
                },
            })
            .collect();
        operations.push(OperationShown {
            id: entry.digest.clone(),
            session: entry.session.clone(),
            host: visible(&entry.host),
            role: visible(&entry.role),
            principal: visible(&entry.principal),
            preview: "Recorded result · original request unavailable".to_owned(),
            execution: state::Execution::from_completion(&entry.event),
            approval_state,
            approval: "Original request evidence unavailable".to_owned(),
            missing_request: true,
            run,
            request: authority
                .and_then(|authority| wire_string(&authority.event, "request"))
                .unwrap_or_default()
                .to_owned(),
            agreement: authority
                .and_then(|authority| wire_string(&authority.event, "agreement"))
                .unwrap_or_default()
                .to_owned(),
            kind: kind.clone(),
            file: files::describe(&kind, &[], Some(&entry.event)),
            file_info: entry
                .event
                .get("info")
                .and_then(|value| serde_json::from_value(value.clone()).ok()),
            file_identity: entry.event.get("file").and_then(|file| {
                Some(ArtifactMetadata {
                    bytes: file.get("bytes")?.as_u64()?,
                    sha256: file.get("sha256")?.as_str()?.to_owned(),
                })
            }),
            evidence: source.to_owned(),
            outcome: wire_summary(&entry.event),
            outputs,
            when: format!(
                "Recorded {} · request time unavailable",
                source_time(entry.source_nanos)
            ),
            completed_at: Some(if source == "current" {
                entry.at
            } else {
                entry.source_nanos
            }),
            requested_at: None,
            sequence: entry.sequence,
            evidence_records: vec![EvidenceShown {
                sequence: entry.sequence,
                digest: entry.digest.clone(),
                previous: entry.previous.clone(),
                recorded_at: if source == "current" {
                    entry.at
                } else {
                    entry.source_nanos
                },
                event: "completed".to_owned(),
                summary: wire_summary(&entry.event),
            }],
            ..Default::default()
        });
    }
    for row in &mut operations {
        row.classify();
    }
    operations
}

pub(super) async fn activity<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Query(query): Query<ActivityQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    match load_activity(bastion, operator, reader, query).await {
        Ok(page) => match page.render() {
            Ok(html) => ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
            Err(error) => {
                tracing::error!(%error, "activity could not be rendered");
                state_unavailable()
            }
        },
        Err(error) => error.into_response(),
    }
}

enum ActivityError {
    InvalidFilters,
    StateUnavailable,
}

impl axum::response::IntoResponse for ActivityError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidFilters => (
                StatusCode::BAD_REQUEST,
                message_html("Choose supported activity filters."),
            )
                .into_response(),
            Self::StateUnavailable => state_unavailable(),
        }
    }
}

async fn load_activity<C: Clock + 'static, S: CredentialSource + 'static>(
    bastion: Arc<Bastion<C, S>>,
    operator: Operator,
    reader: Arc<dyn ReadsAudit>,
    mut query: ActivityQuery,
) -> Result<ActivityPage, ActivityError> {
    if !query.valid() {
        return Err(ActivityError::InvalidFilters);
    }
    if query.window.is_empty() {
        query.window = "24h".to_owned();
    }
    let snapshot_query = query.clone();
    let snapshot = bastion
        .blocking(move |state| {
            let current = SessionId::parse(&snapshot_query.session)
                .ok()
                .and_then(|id| state.session_snapshot(&id))
                .map(|snapshot| session_shown(&state, snapshot));
            let standing = state
                .standing_approvals()
                .into_iter()
                .filter(|(agreement, _)| agreement.session.as_str() == snapshot_query.session)
                .map(|(agreement, remaining)| StandingShown::from(agreement, remaining))
                .collect();
            let observations = current::Current::read(&state, &snapshot_query);
            let (entries, next) = state.ledger().operation_activity(
                snapshot_query.before,
                if snapshot_query.page_ids.is_empty() {
                    audit_history::PAGE_SIZE
                } else {
                    40
                },
                |entry| observations.includes(&snapshot_query, entry),
            );
            let entries = entries
                .iter()
                .map(|entry| current_entry(entry))
                .collect::<Result<Vec<_>, _>>();
            (current, standing, entries, next, observations)
        })
        .await;
    let Ok((current, standing, current_entries, current_next, observations)) = snapshot else {
        return Err(ActivityError::StateUnavailable);
    };
    let source = if query.source == "history"
        || (query.source.is_empty() && !query.session.is_empty() && current.is_none())
    {
        "history"
    } else {
        "current"
    };
    let mut available = true;
    let mut limited = false;
    let mut scanned = 0usize;
    let filtered_history = !query.view.is_empty()
        || !query.approval.is_empty()
        || !query.assessment.is_empty()
        || query.time_basis == "completed";
    let (mut operations, next, mut notice) = if source == "history" {
        let window = match window_value(Some(query.window.clone())) {
            Ok((_, window)) => window,
            Err(()) => return Err(ActivityError::InvalidFilters),
        };
        let request = audit_history::OperationQuery {
            filters: audit_history::Query {
                before: query.before,
                start: query.start,
                window,
                principal: query.principal.clone(),
                session: query.session.clone(),
                host: query.host.clone(),
                text: query.q.clone(),
                ..Default::default()
            },
            end: query.end,
            kind: query.kind.clone(),
            role: query.role.clone(),
            request: query.request.clone(),
            agreement: query.agreement.clone(),
            run: query.run.clone(),
            time_basis: query.time_basis.clone(),
            page_ids: query
                .page_ids
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        let mut request = request;
        let mut rows = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut next = None;
        let mut notice = "Saved history · request records in the selected window; related evidence is read through the fixed upper bound.".to_owned();
        if audit_history::is_operation_identifier(&query.q) {
            notice.push_str(" Identifier lookup selects matching evidence records; their original requests may predate this interval.");
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(8))
            .ok_or(ActivityError::StateUnavailable)?;
        let passes = if filtered_history { 5 } else { 1 };
        for _ in 0..passes {
            let result = tokio::time::timeout_at(deadline, reader.operations(&request)).await;
            let page = match result {
                Ok(Ok(page)) => page,
                _ => {
                    available = false;
                    limited = true;
                    notice = if rows.is_empty() { "Saved history unavailable or query budget exhausted. Narrow the range, retry, or inspect Current service; session controls remain available." } else { "Incomplete saved results: a source read failed or exceeded the query budget. Previously read evidence is shown." }.to_owned();
                    break;
                }
            };
            query.start = Some(page.window_start);
            query.end = Some(page.window_end);
            request.filters.start = query.start;
            request.end = query.end;
            let output_start = page
                .entries
                .iter()
                .map(|entry| entry.source_nanos)
                .min()
                .unwrap_or(page.window_start)
                .min(page.window_start);
            let page_rows = shown(
                &page.entries,
                &query,
                source,
                page.window_end,
                output_start,
                page.window_end,
            );
            scanned = scanned.saturating_add(page_rows.len());
            rows.extend(
                page_rows
                    .into_iter()
                    .filter(|row| row.matches_view(&query) && seen.insert(row.id.clone())),
            );
            limited |= page.evidence_limited;
            next = page.next_before;
            if rows.len() >= audit_history::PAGE_SIZE || next.is_none() {
                break;
            }
            request.filters.before = next;
        }
        if limited && available {
            notice.push_str(" Related cancellation evidence reached its retrieval limit; some requests may be absent.");
        }
        if filtered_history && next.is_some() {
            notice.push_str(" Matching examines at most 100 request records per page. Continue to older operations for remaining evidence.");
        }
        (rows, next, notice)
    } else {
        let Ok(entries) = current_entries else {
            return Err(ActivityError::StateUnavailable);
        };
        let mut operations = shown(&entries, &query, source, 0, 0, 0);
        for row in &mut operations {
            if let Some(decision) = entries.iter().find(|entry| entry.digest == row.id) {
                row.when = format!(
                    "{}{} ago{}",
                    if row.missing_request { "Recorded " } else { "" },
                    elapsed_time(observations.now.saturating_sub(decision.at)),
                    if row.missing_request {
                        " · request time unavailable"
                    } else {
                        ""
                    }
                );
                observations.apply(row, decision.sequence);
            }
        }
        let notice = if !query.instance.is_empty() && query.instance != observations.instance {
            available = false;
            limited = true;
            "This fixed observation belongs to an earlier service instance. Open Current service for a fresh observation or choose Saved history."
        } else {
            "Current service · retained operation evidence only; older activity may have expired or been lost on restart."
        };
        (operations, current_next, notice.to_owned())
    };
    if source == "history"
        && (matches!(query.view.as_str(), "waiting" | "waiting_agent" | "running")
            || matches!(query.approval.as_str(), "waiting" | "expired"))
    {
        notice.push_str(" Current waiting, running and expired states cannot be established from saved records. Choose Current service for live state.");
    }
    operations.retain(|row| row.matches_view(&query));
    let mut snapshot = query.clone();
    snapshot.source = source.to_owned();
    if source == "current" {
        let duration = match query.window.as_str() {
            "1h" => 3_600_000,
            "7d" => 604_800_000,
            "30d" => 2_592_000_000,
            _ => 86_400_000,
        };
        snapshot.service_start = Some(
            query
                .service_start
                .unwrap_or(observations.now.saturating_sub(duration)),
        );
        snapshot.service_end = Some(query.service_end.unwrap_or(observations.now));
        snapshot.instance.clone_from(&observations.instance);
    }
    let investigation = snapshot.url(source, query.before);
    let page_ids = operations
        .iter()
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    for row in &mut operations {
        let mut selected = snapshot.clone();
        selected.selected.clone_from(&row.id);
        row.investigation = selected.url(source, query.before);
        selected.session.clone_from(&row.session);
        row.session_url = selected.url(source, None);
        if !row.agreement.is_empty() {
            selected.agreement.clone_from(&row.agreement);
            row.agreement_url = selected.url(source, None);
        }
    }
    let mut live_query = query.clone();
    live_query.instance.clear();
    live_query.service_start = None;
    live_query.service_end = None;
    live_query.start = None;
    live_query.end = None;
    let mut clear_view = snapshot.clone();
    clear_view.view.clear();
    clear_view.selected.clear();
    let mut chips = Vec::new();
    for (key, label, value) in [
        ("session", "Session", &snapshot.session),
        ("host", "Host", &snapshot.host),
        ("principal", "Principal", &snapshot.principal),
        ("role", "Account", &snapshot.role),
        ("agreement", "Session approval", &snapshot.agreement),
        ("request", "Request", &snapshot.request),
        ("run", "Run", &snapshot.run),
        ("q", "Search", &snapshot.q),
        ("kind", "Operation", &snapshot.kind),
        ("approval", "Approval", &snapshot.approval),
        ("assessment", "Assessment", &snapshot.assessment),
    ] {
        if value.is_empty() {
            continue;
        }
        let mut removed = snapshot.clone();
        match key {
            "session" => removed.session.clear(),
            "host" => removed.host.clear(),
            "principal" => removed.principal.clear(),
            "role" => removed.role.clear(),
            "agreement" => removed.agreement.clear(),
            "request" => removed.request.clear(),
            "run" => removed.run.clear(),
            "q" => removed.q.clear(),
            "kind" => removed.kind.clear(),
            "approval" => removed.approval.clear(),
            "assessment" => removed.assessment.clear(),
            _ => {}
        }
        removed.selected.clear();
        chips.push((
            format!("Remove {label}: {value}"),
            removed.url(source, None),
        ));
    }
    let page = ActivityPage {
        operator: operator.0,
        chips,
        clear_view_url: clear_view.url(source, None),
        refresh_url: live_query.url(source, None),
        current,
        standing,
        operations,
        notice,
        next_url: next.map_or_else(String::new, |before| snapshot.url(source, Some(before))),
        current_url: live_query.url("current", None),
        history_url: query.url("history", None),
        source: source.to_owned(),
        live: query.before.is_none() && query.end.is_none() && query.service_end.is_none(),
        page_size: if source == "history" && filtered_history {
            40
        } else {
            audit_history::PAGE_SIZE
        },
        matching: (source == "current").then_some(observations.matches),
        available,
        limited,
        scanned,
        investigation,
        page_ids,
        query,
    };
    Ok(page)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(
        session: &str,
        sequence: u64,
        digest: char,
        event: serde_json::Value,
    ) -> audit_history::Entry {
        audit_history::Entry {
            source_nanos: 1,
            sequence,
            at: 1,
            session: session.to_owned(),
            principal: "agent".to_owned(),
            host: "server".to_owned(),
            role: "ops".to_owned(),
            event,
            previous: "0".repeat(64),
            digest: digest.to_string().repeat(64),
        }
    }

    #[test]
    fn cross_session_sequences_cannot_supply_an_operations_result() {
        let session = "0123456789abcdef0123456789abcdef";
        let other = "abcdef0123456789abcdef0123456789";
        let entries = vec![
            entry(
                session,
                1,
                'a',
                json!({"event":"decided","operation":"execute","argv":["true"],"verdict":"permit"}),
            ),
            entry(
                other,
                1,
                'b',
                json!({"event":"decided","operation":"execute","argv":["false"],"verdict":"permit"}),
            ),
            entry(
                other,
                2,
                'c',
                json!({"event":"completed","decided":1,"state":"Exited { code: 7 }"}),
            ),
            entry(
                session,
                2,
                'd',
                json!({"event":"completed","decided":1,"state":"Exited { code: 0 }"}),
            ),
        ];
        let rows = shown(&entries, &ActivityQuery::default(), "history", 1, 0, 1);
        let first = rows.iter().find(|row| row.session == session).unwrap();
        assert_eq!(first.status, "Completed · exit 0");
        let mut cancelled = entries.clone();
        cancelled.push(entry(
            session,
            3,
            'e',
            json!({"event":"cancellation_requested","decided":1}),
        ));
        let rows = shown(&cancelled, &ActivityQuery::default(), "history", 1, 0, 1);
        assert!(
            rows.iter()
                .find(|row| row.session == session)
                .unwrap()
                .cancellation
                .contains("Cancellation requested")
        );
        let second = rows.iter().find(|row| row.session == other).unwrap();
        assert!(second.status.contains("7"));
    }

    #[test]
    fn checksum_result_digest_matches_both_evidence_sources() {
        let session = "0123456789abcdef0123456789abcdef";
        let digest = "e".repeat(64);
        let entries = vec![
            entry(
                session,
                1,
                'a',
                json!({"event":"decided","operation":"checksum","argv":["file.checksum","/srv/report"],"verdict":"permit"}),
            ),
            entry(
                session,
                2,
                'b',
                json!({"event":"completed","decided":1,"run":"abcdef0123456789-abcdef0123456789abcdef0123456789","state":"exit 0","info":{"operation":"checksum","bytes":12,"sha256":digest}}),
            ),
        ];
        for source in ["current", "history"] {
            let query = ActivityQuery {
                q: digest.clone(),
                ..Default::default()
            };
            let rows = shown(&entries, &query, source, 10, 0, 10);
            assert_eq!(rows.len(), 1);
            assert!(rows.first().unwrap().matches_view(&query));
        }
    }

    #[test]
    fn a_file_operation_has_a_short_preview_and_complete_review_fields() {
        let path = format!("/srv/{}", "long-directory/".repeat(40));
        let args = vec![
            "file.upload".to_owned(),
            path.clone(),
            "1024".to_owned(),
            "a".repeat(64),
            "replace".to_owned(),
            "staged".to_owned(),
            "/srv/staging".to_owned(),
        ];
        let summary = preview(&args, "upload");
        assert!(summary.chars().count() < 120);
        assert!(summary.ends_with('…'));
        let result = file_result(None, &args, "upload");
        assert!(result.contains(&("Destination".to_owned(), path)));
        assert!(result.contains(&("Write mode".to_owned(), "replace".to_owned())));
        assert!(result.contains(&("Staging path".to_owned(), "/srv/staging".to_owned())));
    }

    #[test]
    fn returning_from_saved_history_drops_historical_bounds_for_current_reads() {
        let query = ActivityQuery {
            start: Some(100),
            end: Some(200),
            ..Default::default()
        };
        let url = query.url("current", None);
        assert!(!url.contains("start="));
        assert!(!url.contains("end="));
        assert!(query.url("history", Some(150)).contains("end=200"));
    }

    #[test]
    fn output_returns_only_to_a_valid_local_investigation() {
        let url = "/dashboard/activity?host=server&q=quoted%20%22text%22&kind=execute&source=current&before=10&selected=abcdef";
        let back = investigation_return(url).unwrap();
        assert!(back.contains("q=quoted+%22text%22"));
        assert!(back.contains("before=10"));
        assert!(back.contains("selected=abcdef"));
        for invalid in [
            "https://elsewhere.test/dashboard/activity",
            "//elsewhere.test/dashboard/activity",
            "/dashboard/approvals",
            "/dashboard/activity?source=unsupported",
            "/dashboard/activity?unknown=filter",
        ] {
            assert!(investigation_return(invalid).is_none());
        }
    }
}
