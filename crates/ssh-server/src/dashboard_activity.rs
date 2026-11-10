//! Shared operator-facing operation browsing. All reads are observational.
use super::*;
use serde::Serialize;
use ssh_core::audit::Event;
use ssh_core::run::{Cancellation, RunState};

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
            && matches!(
                self.view.as_str(),
                "" | "waiting" | "running" | "attention" | "assessments"
            )
    }

    fn matches(&self, entry: &ssh_core::audit::Entry) -> bool {
        if (!self.session.is_empty() && entry.session.as_str() != self.session)
            || (!self.host.is_empty() && entry.host.as_str() != self.host)
            || (!self.principal.is_empty() && entry.principal.as_str() != self.principal)
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
        ] {
            if let Some(value) = value {
                pairs.append_pair(key, &value.to_string());
            }
        }
        format!("/dashboard/activity?{}", pairs.finish())
    }
}

#[derive(Serialize)]
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
}

fn preview(arguments: &[String], kind: &str) -> String {
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

fn execution_status(state: &RunState) -> String {
    match state {
        RunState::Running => "Running".to_owned(),
        RunState::Exited { code } => format!("Completed · exit {code}"),
        RunState::Ended => "Ended · exit status unavailable".to_owned(),
        RunState::Refused => "Refused to start".to_owned(),
        RunState::Indeterminate => "Outcome unknown".to_owned(),
        RunState::TransferFailed {
            remote_write_may_be_partial,
            ..
        } => if *remote_write_may_be_partial {
            "Transfer failed · remote file may be partial"
        } else {
            "Transfer failed"
        }
        .to_owned(),
    }
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
        let related = entries;
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
                    url,
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
        let attention = completion.is_some_and(|entry| {
            let state = wire_string(&entry.event, "state").unwrap_or("");
            state != "exit 0" && state != "Exited { code: 0 }"
        });
        operations.push(OperationShown {
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
            cancellation: String::new(),
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
    operations
}

pub(super) async fn activity<C, S>(
    State(bastion): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Query(mut query): Query<ActivityQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    if !query.valid() {
        return (
            StatusCode::BAD_REQUEST,
            message_html("Choose supported activity filters."),
        )
            .into_response();
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
            let duration: u64 = match snapshot_query.window.as_str() {
                "1h" => 3_600_000,
                "7d" => 604_800_000,
                "30d" => 2_592_000_000,
                _ => 86_400_000,
            };
            let since = state.now().saturating_sub(duration);
            let (entries, next) = state.ledger().operation_activity(
                snapshot_query.before,
                audit_history::PAGE_SIZE,
                |entry| entry.at >= since && snapshot_query.matches(entry),
            );
            let entries = entries
                .iter()
                .map(|entry| current_entry(entry))
                .collect::<Result<Vec<_>, _>>();
            let progress = state
                .runs_in_flight_with_authorization()
                .into_iter()
                .filter_map(|(run, authorization)| {
                    state
                        .observe_progress(&run)
                        .map(|progress| (authorization, progress))
                })
                .collect::<Vec<_>>();
            (
                current,
                standing,
                entries,
                next,
                progress,
                state.waiting_for_approval(),
                state.uncollected_approvals(),
                state.now(),
            )
        })
        .await;
    let Ok((current, standing, current_entries, current_next, progress, waiting, uncollected, now)) =
        snapshot
    else {
        return state_unavailable();
    };
    let source = if query.source == "history"
        || (query.source.is_empty() && !query.session.is_empty() && current.is_none())
    {
        "history"
    } else {
        "current"
    };
    let (mut operations, next, notice) = if source == "history" {
        let window = match window_value(Some(query.window.clone())) {
            Ok((_, window)) => window,
            Err(()) => return StatusCode::BAD_REQUEST.into_response(),
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
        };
        match reader.operations(&request).await {
            Ok(page) => {
                query.start = Some(page.window_start);
                query.end = Some(page.window_end);
                (shown(&page.entries, &query, source, query.before.unwrap_or(page.window_end), page.window_start, page.window_end), page.next_before,
                    "Saved history · requested in the selected window. Related evidence may have later timestamps.".to_owned())
            }
            Err(_) => (Vec::new(), None, "Saved history unavailable. Current service activity and session controls remain available.".to_owned()),
        }
    } else {
        let Ok(entries) = current_entries else {
            return state_unavailable();
        };
        let mut operations = shown(&entries, &query, source, 0, 0, 0);
        for row in &mut operations {
            if let Some(decision) = entries.iter().find(|entry| entry.digest == row.id) {
                row.when = format!("{} ago", elapsed_time(now.saturating_sub(decision.at)));
                if let Some((_, progress)) = progress.iter().find(|(authorization, _)| {
                    authorization.session().as_str() == row.session
                        && (authorization.sequence() == decision.sequence
                            || entries.iter().any(|entry| {
                                entry.session == row.session
                                    && entry.sequence == authorization.sequence()
                                    && wire_u64(&entry.event, "decided") == Some(decision.sequence)
                            }))
                }) {
                    row.status = execution_status(&progress.state);
                    row.progress = format!(
                        "{} elapsed · stdout {} bytes · stderr {} bytes · transfer {} source bytes read",
                        elapsed_time(progress.elapsed_ms),
                        progress.stdout_bytes,
                        progress.stderr_bytes,
                        progress.transfer_bytes_read
                    );
                    row.cancellation = cancellation_status(progress.cancellation).to_owned();
                } else if waiting.iter().any(|request| {
                    request.session.as_str() == row.session && request.decided == decision.sequence
                }) {
                    row.status = "Awaiting decision".to_owned();
                } else if let Some((_, active)) = uncollected.iter().find(|(request, _)| {
                    request.session.as_str() == row.session && request.decided == decision.sequence
                }) {
                    row.status = if *active {
                        "Approved · waiting for agent"
                    } else {
                        "Approval expired · not collected"
                    }
                    .to_owned();
                }
            }
        }
        (operations, current_next, "Current service · retained operation evidence only; older activity may have expired or been lost on restart.".to_owned())
    };
    operations.retain(|row| match query.view.as_str() {
        "waiting" => row.status == "Awaiting decision",
        "running" => row.status == "Running",
        "attention" => {
            row.attention || row.status == "Awaiting decision" || !row.cancellation.is_empty()
        }
        "assessments" => row.assessment.is_some(),
        _ => true,
    });
    let page = ActivityPage {
        operator: operator.0,
        current,
        standing,
        operations,
        notice,
        next_url: next.map_or_else(String::new, |before| query.url(source, Some(before))),
        current_url: query.url("current", None),
        history_url: query.url("history", None),
        source: source.to_owned(),
        live: query.before.is_none() && query.end.is_none(),
        page_size: audit_history::PAGE_SIZE,
        query,
    };
    match page.render() {
        Ok(html) => ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
        Err(error) => {
            tracing::error!(%error, "activity could not be rendered");
            state_unavailable()
        }
    }
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
        let second = rows.iter().find(|row| row.session == other).unwrap();
        assert!(second.status.contains("7"));
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
}
