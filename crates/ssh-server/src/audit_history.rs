//! Read-only access to the deployment-owned audit record.
//!
//! The service writes audit entries to stdout before an authorized effect. The
//! fleet's log pipeline owns them after that boundary; this module queries that
//! existing copy and deliberately owns no durable storage of its own.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;
use ssh_core::audit::{EvaluationArtifact, EvaluationDraft, EvaluationVerdict};
use ssh_core::command::{Command, CommandIntent};
use ssh_core::run::RunId;
use ssh_core::session::{Purpose, SessionId};
use ssh_core::{HostId, PrincipalId, RoleId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

/// Entries rendered per durable page. One entry can contain up to two MiB of
/// retained command output, so a page is intentionally much smaller than the
/// process-local card limit.
pub const PAGE_SIZE: usize = 20;
const FETCH_LIMIT: usize = PAGE_SIZE + 1;
const RESPONSE_BYTES: usize = 48 << 20;
const QUERY_WITHIN: Duration = Duration::from_secs(5);

/// A bounded look-back selected by an operator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Window {
    Hour,
    Day,
    Week,
    #[default]
    Month,
}

impl Window {
    const fn duration(self) -> Duration {
        match self {
            Self::Hour => Duration::from_secs(60 * 60),
            Self::Day => Duration::from_secs(24 * 60 * 60),
            Self::Week => Duration::from_secs(7 * 24 * 60 * 60),
            Self::Month => Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub before: Option<u64>,
    /// Fixed lower boundary carried from the first page. The reader still
    /// clamps it to the selected window relative to this page's upper bound.
    pub start: Option<u64>,
    pub window: Window,
    pub principal: String,
    pub session: String,
    pub host: String,
    pub event: String,
    pub access_class: String,
    pub verdict: String,
    pub text: String,
}

#[derive(Debug)]
pub struct Page {
    pub entries: Vec<Entry>,
    pub next_before: Option<u64>,
    pub window_start: u64,
}

/// One command-oriented page of a durable session transcript.
///
/// `entries` contains the decisions selected for this page and the bounded
/// related evidence needed to render each as one transaction. Pagination is
/// driven only by decision timestamps, so an answer or completion cannot push
/// its command onto another page.
#[derive(Debug)]
pub struct TranscriptPage {
    pub entries: Vec<Entry>,
    pub next_before: Option<u64>,
    pub window_start: u64,
    /// The fixed upper edge of the first page's window. Related evidence may
    /// follow an older decision, so later pages continue to query through this
    /// edge rather than stopping at the decision cursor.
    pub window_end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptQuery {
    pub before: Option<u64>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub session: SessionId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputQuery {
    pub start: u64,
    pub end: u64,
    pub session: SessionId,
    pub run: RunId,
}

/// One audit line plus the fleet source's wall-clock timestamp.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(skip)]
    pub source_nanos: u64,
    pub sequence: u64,
    pub at: u64,
    pub session: String,
    pub principal: String,
    pub host: String,
    pub role: String,
    pub event: Value,
    pub previous: String,
    pub digest: String,
}

pub trait ReadsAudit: Send + Sync {
    fn page<'a>(
        &'a self,
        query: &'a Query,
    ) -> Pin<Box<dyn Future<Output = Result<Page, ReadError>> + Send + 'a>>;

    fn transcript<'a>(
        &'a self,
        query: &'a TranscriptQuery,
    ) -> Pin<Box<dyn Future<Output = Result<TranscriptPage, ReadError>> + Send + 'a>>;

    fn output<'a>(
        &'a self,
        _query: &'a OutputQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Entry>, ReadError>> + Send + 'a>> {
        Box::pin(async { Err(ReadError::NotConfigured) })
    }
}

/// Used when a deployment has not selected a durable reader.
pub struct Unavailable;

impl ReadsAudit for Unavailable {
    fn page<'a>(
        &'a self,
        _query: &'a Query,
    ) -> Pin<Box<dyn Future<Output = Result<Page, ReadError>> + Send + 'a>> {
        Box::pin(async { Err(ReadError::NotConfigured) })
    }

    fn transcript<'a>(
        &'a self,
        _query: &'a TranscriptQuery,
    ) -> Pin<Box<dyn Future<Output = Result<TranscriptPage, ReadError>> + Send + 'a>> {
        Box::pin(async { Err(ReadError::NotConfigured) })
    }

    fn output<'a>(
        &'a self,
        _query: &'a OutputQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Entry>, ReadError>> + Send + 'a>> {
        Box::pin(async { Err(ReadError::NotConfigured) })
    }
}

/// Exact label matches selecting the deployment's audit stream.
#[derive(Clone, Debug)]
pub struct Labels(String);

impl Labels {
    pub fn parse(raw: &str) -> Result<Self, ReadError> {
        if raw.len() > 16384 {
            return Err(ReadError::InvalidLabels);
        }
        let labels: std::collections::BTreeMap<String, String> =
            serde_json::from_str(raw).map_err(|_| ReadError::InvalidLabels)?;
        if labels.is_empty() || labels.len() > 16 || labels.values().all(String::is_empty) {
            return Err(ReadError::InvalidLabels);
        }
        let mut matches = Vec::new();
        for (name, value) in labels {
            let mut chars = name.bytes();
            if !chars
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                || !chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || value.len() > 1024
            {
                return Err(ReadError::InvalidLabels);
            }
            matches.push(format!("{name}={}", logql_string(&value)));
        }
        Ok(Self(format!("{{{}}}", matches.join(","))))
    }
}

/// A bounded reader for Loki's internal query API.
pub struct Loki {
    labels: Labels,
    endpoint: Url,
    client: reqwest::Client,
    // A worst-case page can contain tens of MiB of retained output. Serialize
    // reads so concurrent dashboard refreshes cannot multiply that bound.
    one_query: Arc<Semaphore>,
}

impl Loki {
    pub fn new(base: Url, labels: Labels) -> Result<Self, ReadError> {
        let endpoint = base
            .join("loki/api/v1/query_range")
            .map_err(|_| ReadError::InvalidEndpoint)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(QUERY_WITHIN)
            .build()
            .map_err(|_| ReadError::InvalidEndpoint)?;
        Ok(Self {
            labels,
            endpoint,
            client,
            one_query: Arc::new(Semaphore::new(1)),
        })
    }

    async fn read(&self, query: &Query) -> Result<Page, ReadError> {
        let _permit: OwnedSemaphorePermit =
            tokio::time::timeout(QUERY_WITHIN, Arc::clone(&self.one_query).acquire_owned())
                .await
                .map_err(|_| ReadError::Unavailable)?
                .map_err(|_| ReadError::Unavailable)?;
        let logql = logql(query);
        let (start, end) = read_window(query.before, query.start, None, query.window)?;
        let mut lines = self.fetch(logql, start, end, FETCH_LIMIT).await?;
        let next_before = collision_safe_page(&mut lines)?;
        Ok(Page {
            entries: lines,
            next_before,
            window_start: start,
        })
    }

    async fn read_transcript(&self, query: &TranscriptQuery) -> Result<TranscriptPage, ReadError> {
        let _permit: OwnedSemaphorePermit =
            tokio::time::timeout(QUERY_WITHIN, Arc::clone(&self.one_query).acquire_owned())
                .await
                .map_err(|_| ReadError::Unavailable)?
                .map_err(|_| ReadError::Unavailable)?;
        let (start, window_end) = read_window(None, query.start, query.end, Window::Month)?;
        let decision_end = query.before.unwrap_or(window_end);
        if decision_end > window_end || decision_end < start {
            return Err(ReadError::InvalidWindow);
        }

        let mut decisions = self
            .fetch(
                transcript_decisions_logql(&query.session),
                start,
                decision_end,
                FETCH_LIMIT,
            )
            .await?;
        let next_before = collision_safe_page(&mut decisions)?;
        if decisions.is_empty() {
            return Ok(TranscriptPage {
                entries: Vec::new(),
                next_before,
                window_start: start,
                window_end,
            });
        }

        // An exact decision can have one answer, one approval, one completion,
        // and one evaluation. Fetch one extra row so a broken producer cannot
        // silently turn an overfull relationship set into a complete page.
        let related_max = decisions.len().saturating_mul(4);
        let mut related = self
            .fetch(
                transcript_relations_logql(&query.session, &decisions),
                start,
                window_end,
                related_max.saturating_add(1),
            )
            .await?;
        if related.len() > related_max {
            return Err(ReadError::MalformedResponse);
        }

        // A policy permit is named directly by its completion. A human-held
        // command is completed against the later approval entry, so resolve
        // those authorization sequences in one further bounded source query.
        let decision_sequences: HashSet<u64> =
            decisions.iter().map(|entry| entry.sequence).collect();
        let approval_sequences: Vec<u64> = related
            .iter()
            .filter(|entry| {
                event_name(entry) == Some("approved")
                    && event_decided(entry)
                        .is_some_and(|decided| decision_sequences.contains(&decided))
            })
            .map(|entry| entry.sequence)
            .collect();
        if !approval_sequences.is_empty() {
            let completion_max = approval_sequences.len();
            let mut completions = self
                .fetch(
                    transcript_completions_logql(&query.session, &approval_sequences),
                    start,
                    window_end,
                    completion_max.saturating_add(1),
                )
                .await?;
            if completions.len() > completion_max {
                return Err(ReadError::MalformedResponse);
            }
            related.append(&mut completions);
        }

        decisions.append(&mut related);
        let mut seen = HashSet::new();
        decisions.retain(|entry| seen.insert((entry.source_nanos, entry.digest.clone())));
        decisions
            .sort_unstable_by_key(|entry| std::cmp::Reverse((entry.source_nanos, entry.sequence)));
        Ok(TranscriptPage {
            entries: decisions,
            next_before,
            window_start: start,
            window_end,
        })
    }

    async fn read_output(&self, query: &OutputQuery) -> Result<Option<Entry>, ReadError> {
        let _permit: OwnedSemaphorePermit =
            tokio::time::timeout(QUERY_WITHIN, Arc::clone(&self.one_query).acquire_owned())
                .await
                .map_err(|_| ReadError::Unavailable)?
                .map_err(|_| ReadError::Unavailable)?;
        let (start, end) = read_window(None, Some(query.start), Some(query.end), Window::Month)?;
        let mut entries = self
            .fetch(output_logql(&query.session, &query.run), start, end, 2)
            .await?;
        if entries.len() > 1 {
            return Err(ReadError::MalformedResponse);
        }
        let Some(entry) = entries.pop() else {
            return Ok(None);
        };
        let exact = entry.session == query.session.as_str()
            && event_name(&entry) == Some("completed")
            && entry.event.get("run").and_then(Value::as_str) == Some(query.run.as_str());
        if !exact {
            return Err(ReadError::MalformedResponse);
        }
        Ok(Some(entry))
    }

    async fn fetch(
        &self,
        logql: String,
        start: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<Entry>, ReadError> {
        let mut endpoint = self.endpoint.clone();
        {
            let mut pairs = endpoint.query_pairs_mut();
            pairs
                .append_pair("query", &format!("{}{}", self.labels.0, logql))
                .append_pair("direction", "backward")
                .append_pair("limit", &limit.to_string())
                // Explicit bounds keep the operator's original look-back
                // stable when `end` advances backward through older pages.
                .append_pair("start", &start.to_string())
                .append_pair("end", &end.to_string());
        }
        let response = self
            .client
            .get(endpoint)
            .send()
            .await
            .map_err(|_| ReadError::Unavailable)?;
        if !response.status().is_success() {
            return Err(ReadError::Unavailable);
        }
        let bytes = bounded_body(response).await?;
        let response: LokiResponse =
            serde_json::from_slice(&bytes).map_err(|_| ReadError::MalformedResponse)?;
        if response.status != "success" || response.data.result_type != "streams" {
            return Err(ReadError::MalformedResponse);
        }

        let mut lines = Vec::new();
        for stream in response.data.result {
            for (timestamp, line) in stream.values {
                let source_nanos = timestamp
                    .parse::<u64>()
                    .map_err(|_| ReadError::MalformedResponse)?;
                let mut entry: Entry =
                    serde_json::from_str(&line).map_err(|_| ReadError::MalformedEntry)?;
                if validate_entry(&entry).is_err() {
                    return Err(ReadError::MalformedEntry);
                }
                entry.source_nanos = source_nanos;
                lines.push(entry);
                if lines.len() > limit {
                    return Err(ReadError::MalformedResponse);
                }
            }
        }
        lines.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.source_nanos));
        Ok(lines)
    }
}

fn read_window(
    before: Option<u64>,
    start: Option<u64>,
    fixed_end: Option<u64>,
    window: Window,
) -> Result<(u64, u64), ReadError> {
    let end = fixed_end.or(before).map_or_else(now_nanos, Ok)?;
    let window_nanos =
        u64::try_from(window.duration().as_nanos()).map_err(|_| ReadError::Unavailable)?;
    let earliest = end.saturating_sub(window_nanos);
    let start = start.unwrap_or(earliest).max(earliest);
    (start <= end)
        .then_some((start, end))
        .ok_or(ReadError::InvalidWindow)
}

fn now_nanos() -> Result<u64, ReadError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReadError::Unavailable)?
            .as_nanos(),
    )
    .map_err(|_| ReadError::Unavailable)
}

fn event_name(entry: &Entry) -> Option<&str> {
    entry.event.get("event")?.as_str()
}

fn event_decided(entry: &Entry) -> Option<u64> {
    entry.event.get("decided")?.as_u64()
}

fn collision_safe_page(lines: &mut Vec<Entry>) -> Result<Option<u64>, ReadError> {
    if lines.len() <= PAGE_SIZE {
        return Ok(None);
    }
    let Some(boundary) = lines.get(PAGE_SIZE).map(|entry| entry.source_nanos) else {
        return Err(ReadError::MalformedResponse);
    };
    let first_at_boundary = lines
        .iter()
        .position(|entry| entry.source_nanos == boundary)
        .ok_or(ReadError::MalformedResponse)?;
    // Loki's cursor is a timestamp. Keep the entire boundary timestamp for the
    // next inclusive query rather than splitting a tie and skipping its tail.
    // More than a whole page at one nanosecond cannot be represented by that
    // API cursor, so report the source page unavailable instead of looping or
    // silently dropping entries.
    if first_at_boundary == 0 {
        return Err(ReadError::UnpageableTimestamp);
    }
    lines.truncate(first_at_boundary);
    Ok(Some(boundary))
}

fn validate_entry(entry: &Entry) -> Result<(), ()> {
    SessionId::parse(&entry.session).map_err(|_| ())?;
    PrincipalId::parse(&entry.principal).map_err(|_| ())?;
    HostId::parse(&entry.host).map_err(|_| ())?;
    RoleId::parse(&entry.role).map_err(|_| ())?;
    if !lower_hex_digest(&entry.previous) || !lower_hex_digest(&entry.digest) {
        return Err(());
    }
    validate_event(&entry.event)
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_event(event: &Value) -> Result<(), ()> {
    let object = event.as_object().ok_or(())?;
    match required_string(object, "event")? {
        "session_opened" => {
            exact_keys(object, &["event", "purpose", "access_class"])?;
            Purpose::parse(required_string(object, "purpose")?).map_err(|_| ())?;
            access_class(required_string(object, "access_class")?)
        }
        "decided" => {
            operation_keys(
                object,
                &[
                    "event",
                    "agent_intent",
                    "argv",
                    "program",
                    "operation",
                    "access_class",
                    "purpose",
                    "verdict",
                    "policies",
                ],
            )?;
            CommandIntent::parse(required_string(object, "agent_intent")?).map_err(|_| ())?;
            let command = Command::new(string_array(object, "argv")?).map_err(|_| ())?;
            if required_string(object, "program")? != command.program() {
                return Err(());
            }

            access_class(required_string(object, "access_class")?)?;
            Purpose::parse(required_string(object, "purpose")?).map_err(|_| ())?;
            one_of(
                required_string(object, "verdict")?,
                &["permit", "needs_approval", "deny"],
            )?;
            for policy in string_array(object, "policies")? {
                non_blank_string(&policy)?;
            }
            Ok(())
        }
        "approved" => {
            exact_keys(
                object,
                &[
                    "event",
                    "decided",
                    "request",
                    "approver",
                    "override_of",
                    "standing",
                    "mode",
                    "agreement",
                ],
            )?;
            validate_answer_fields(object)
        }
        "answered" => {
            exact_keys(
                object,
                &[
                    "event",
                    "decided",
                    "request",
                    "approver",
                    "override_of",
                    "standing",
                    "mode",
                    "agreement",
                    "agreed",
                ],
            )?;
            validate_answer_fields(object)?;
            required_bool(object, "agreed")?;
            Ok(())
        }
        "completed" => {
            exact_keys(
                object,
                if object.contains_key("file") {
                    &[
                        "event", "run", "decided", "state", "stdout", "stderr", "file",
                    ]
                } else {
                    &["event", "run", "decided", "state", "stdout", "stderr"]
                },
            )?;
            if let Some(file) = object.get("file") {
                let file = file.as_object().ok_or(())?;
                exact_keys(file, &["uri", "bytes", "sha256"])?;
                non_blank_string(required_string(file, "uri")?)?;
                required_u64(file, "bytes")?;
                if !lower_hex_digest(required_string(file, "sha256")?) {
                    return Err(());
                }
            }
            RunId::parse(required_string(object, "run")?).map_err(|_| ())?;
            required_u64(object, "decided")?;
            non_blank_string(required_string(object, "state")?)?;
            validate_recorded(object.get("stdout").ok_or(())?)?;
            validate_recorded(object.get("stderr").ok_or(())?)
        }
        "session_closed" => exact_keys(object, &["event"]),
        "evaluated" => {
            if object.contains_key("decided") {
                operation_keys(
                    object,
                    &[
                        "event",
                        "artifact",
                        "operation",
                        "decided",
                        "argv",
                        "agent_intent",
                        "purpose",
                        "access_class",
                    ],
                )?;

                required_u64(object, "decided")?;
                Command::new(string_array(object, "argv")?).map_err(|_| ())?;
                CommandIntent::parse(required_string(object, "agent_intent")?).map_err(|_| ())?;
                Purpose::parse(required_string(object, "purpose")?).map_err(|_| ())?;
                access_class(required_string(object, "access_class")?)?;
            } else {
                // Missing context renders as unavailable; the reader never invents audit facts.
                exact_keys(object, &["event", "artifact"])?;
            }
            let artifact: Artifact =
                serde_json::from_value(object.get("artifact").ok_or(())?.clone())
                    .map_err(|_| ())?;
            let draft = EvaluationDraft {
                evaluation_id: artifact.evaluation_id,
                decision_digest: artifact.decision_digest,
                model: artifact.model,
                prompt_version: artifact.prompt_version,
                verdict: artifact.verdict,
                confidence: artifact.confidence,
                rationale: artifact.rationale,
                side_effects: artifact.side_effects,
            };
            EvaluationArtifact::from_draft(draft, artifact.evaluator).map_err(|_| ())?;
            Ok(())
        }
        _ => Err(()),
    }
}

fn validate_answer_fields(object: &serde_json::Map<String, Value>) -> Result<(), ()> {
    required_u64(object, "decided")?;
    lower_hex_id(required_string(object, "request")?)?;
    non_blank_string(required_string(object, "approver")?)?;
    optional_non_blank_string(object, "override_of")?;
    required_bool(object, "standing")?;
    one_of(
        required_string(object, "mode")?,
        &["direct", "override", "session"],
    )?;
    if let Some(agreement) = optional_string(object, "agreement")? {
        lower_hex_id(agreement)?;
    }
    Ok(())
}

fn validate_recorded(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    match required_string(object, "kind")? {
        "kept" => {
            exact_keys(object, &["kind", "text", "truncated", "bytes"])?;
            // The producer bounds raw bytes and then converts them with
            // `from_utf8_lossy`, which may expand invalid UTF-8. The bounded
            // Loki response is the reader's aggregate memory ceiling.
            required_string(object, "text")?;
            required_bool(object, "truncated")?;
            required_u64(object, "bytes")?;
            Ok(())
        }
        "withheld" => {
            exact_keys(object, &["kind", "bytes", "matched"])?;
            required_u64(object, "bytes")?;
            non_blank_string(required_string(object, "matched")?)
        }
        _ => Err(()),
    }
}

/// Optional operation metadata is validated without rewriting recorded evidence.
fn operation_keys(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Result<(), ()> {
    if let Some(operation) = object.get("operation") {
        one_of(
            operation.as_str().ok_or(())?,
            &["execute", "download", "upload"],
        )?;
        exact_keys(object, keys)
    } else {
        let required: Vec<_> = keys
            .iter()
            .copied()
            .filter(|key| *key != "operation")
            .collect();
        exact_keys(object, &required)
    }
}

fn exact_keys(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Result<(), ()> {
    if object.len() == keys.len() && object.keys().all(|key| keys.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(())
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ()> {
    object.get(field).and_then(Value::as_str).ok_or(())
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, ()> {
    match object.get(field) {
        Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or(()),
        None => Err(()),
    }
}

fn required_u64(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64, ()> {
    object.get(field).and_then(Value::as_u64).ok_or(())
}

fn required_bool(object: &serde_json::Map<String, Value>, field: &str) -> Result<bool, ()> {
    object.get(field).and_then(Value::as_bool).ok_or(())
}

fn string_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<String>, ()> {
    let values = value_array(object, field)?;
    values
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(()))
        .collect()
}

fn value_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a Vec<Value>, ()> {
    object.get(field).and_then(Value::as_array).ok_or(())
}

fn non_blank_string(value: &str) -> Result<(), ()> {
    (!value.trim().is_empty()).then_some(()).ok_or(())
}

fn optional_non_blank_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), ()> {
    match optional_string(object, field)? {
        Some(value) => non_blank_string(value),
        None => Ok(()),
    }
}

fn access_class(value: &str) -> Result<(), ()> {
    one_of(value, &["read_only", "privileged"])
}

fn one_of(value: &str, choices: &[&str]) -> Result<(), ()> {
    choices.contains(&value).then_some(()).ok_or(())
}

fn lower_hex_id(value: &str) -> Result<(), ()> {
    (value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(())
    .ok_or(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
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

impl ReadsAudit for Loki {
    fn page<'a>(
        &'a self,
        query: &'a Query,
    ) -> Pin<Box<dyn Future<Output = Result<Page, ReadError>> + Send + 'a>> {
        Box::pin(self.read(query))
    }

    fn transcript<'a>(
        &'a self,
        query: &'a TranscriptQuery,
    ) -> Pin<Box<dyn Future<Output = Result<TranscriptPage, ReadError>> + Send + 'a>> {
        Box::pin(self.read_transcript(query))
    }

    fn output<'a>(
        &'a self,
        query: &'a OutputQuery,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Entry>, ReadError>> + Send + 'a>> {
        Box::pin(self.read_output(query))
    }
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ReadError::Unavailable)? {
        if body.len().saturating_add(chunk.len()) > RESPONSE_BYTES {
            return Err(ReadError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn logql(query: &Query) -> String {
    let mut expression = audit_logql();
    for (field, value) in [
        ("principal", query.principal.as_str()),
        ("session", query.session.as_str()),
        ("host", query.host.as_str()),
    ] {
        if !value.is_empty() {
            expression.push_str(" |= ");
            expression.push_str(&logql_string(&json_fragment(field, value)));
        }
    }
    if !query.event.is_empty() {
        expression.push_str(" |= ");
        expression.push_str(&logql_string(&json_fragment("event", &query.event)));
    }
    for (field, value) in [
        ("access_class", query.access_class.as_str()),
        ("verdict", query.verdict.as_str()),
    ] {
        if !value.is_empty() {
            expression.push_str(" |= ");
            expression.push_str(&logql_string(&json_fragment(field, value)));
        }
    }
    if !query.text.is_empty() {
        expression.push_str(" |= ");
        expression.push_str(&logql_string(&query.text));
    }
    expression
}

fn audit_logql() -> String {
    " |= \"\\\"event\\\":{\"".to_owned()
}

fn transcript_decisions_logql(session: &SessionId) -> String {
    let mut expression = audit_logql();
    expression.push_str(" |= ");
    expression.push_str(&logql_string(&json_fragment("session", session.as_str())));
    expression.push_str(" |= ");
    expression.push_str(&logql_string(&json_fragment("event", "decided")));
    expression
}

fn output_logql(session: &SessionId, run: &RunId) -> String {
    let mut expression = audit_logql();
    for (field, value) in [
        ("session", session.as_str()),
        ("event", "completed"),
        ("run", run.as_str()),
    ] {
        expression.push_str(" |= ");
        expression.push_str(&logql_string(&json_fragment(field, value)));
    }
    expression
}

fn transcript_relations_logql(session: &SessionId, decisions: &[Entry]) -> String {
    let sequences: Vec<u64> = decisions.iter().map(|entry| entry.sequence).collect();
    let digests: Vec<&str> = decisions
        .iter()
        .map(|entry| entry.digest.as_str())
        .collect();
    let pattern = format!(
        "({}|\\\"decision_digest\\\":\\\"({})\\\")",
        json_number_relation("decided", &sequences),
        digests.join("|")
    );
    transcript_relation_logql(session, &pattern)
}

fn transcript_completions_logql(session: &SessionId, approvals: &[u64]) -> String {
    let pattern = json_number_relation("decided", approvals);
    let mut expression = transcript_relation_logql(session, &pattern);
    expression.push_str(" |= ");
    expression.push_str(&logql_string(&json_fragment("event", "completed")));
    expression
}

fn json_number_relation(field: &str, values: &[u64]) -> String {
    // Audit entries are compact JSON. Requiring the delimiter after a number
    // keeps sequence 1 from matching 10, 11, and other unrelated records.
    format!("\\\"{field}\\\":({})(,|}})", joined_numbers(values))
}

fn transcript_relation_logql(session: &SessionId, pattern: &str) -> String {
    let mut expression = audit_logql();
    expression.push_str(" |= ");
    expression.push_str(&logql_string(&json_fragment("session", session.as_str())));
    expression.push_str(" |~ ");
    expression.push_str(&logql_string(pattern));
    expression
}

fn joined_numbers(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("|")
}

fn json_fragment(field: &str, value: &str) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned());
    format!("\"{field}\":{encoded}")
}

fn logql_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

#[derive(Deserialize)]
struct LokiResponse {
    status: String,
    data: LokiData,
}

#[derive(Deserialize)]
struct LokiData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<LokiStream>,
}

#[derive(Deserialize)]
struct LokiStream {
    values: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReadError {
    #[error("no durable audit reader is configured")]
    NotConfigured,
    #[error("the durable audit endpoint is invalid")]
    InvalidEndpoint,
    #[error("audit labels must be a bounded JSON object of valid label names and string values")]
    InvalidLabels,
    #[error("the durable audit source is unavailable")]
    Unavailable,
    #[error("the durable audit source returned an unexpected response")]
    MalformedResponse,
    #[error("the durable audit source returned an invalid audit entry")]
    MalformedEntry,
    #[error("the durable audit response exceeded its bound")]
    ResponseTooLarge,
    #[error("the durable audit source cannot paginate entries sharing one timestamp")]
    UnpageableTimestamp,
    #[error("the durable audit query window is invalid")]
    InvalidWindow,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Query as AxumQuery;
    use axum::http::StatusCode;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn deployment_labels_are_exact_matches_with_quoted_values() {
        let raw = serde_json::json!({"app": "ssh\"} | json", "stream": "audit"}).to_string();
        let labels = Labels::parse(&raw).unwrap();
        assert_eq!(labels.0, "{app=\"ssh\\\"} | json\",stream=\"audit\"}");
        for invalid in [
            "{}",
            r#"{"bad-name":"ssh"}"#,
            r#"{"app":4}"#,
            r#"{"app":""}"#,
        ] {
            assert!(Labels::parse(invalid).is_err());
        }
    }

    fn line(sequence: u64) -> String {
        format!(
            "{{\"sequence\":{sequence},\"at\":10,\"session\":\"0123456789abcdef0123456789abcdef\",\"principal\":\"alice\",\"host\":\"dns1\",\"role\":\"ops\",\"event\":{{\"event\":\"session_closed\"}},\"previous\":\"{}\",\"digest\":\"{}\"}}",
            "a".repeat(64),
            "b".repeat(64)
        )
    }

    fn event_line(sequence: u64, event: Value, digest: char) -> String {
        serde_json::json!({
            "sequence": sequence,
            "at": 10,
            "session": "0123456789abcdef0123456789abcdef",
            "principal": "alice",
            "host": "dns1",
            "role": "ops",
            "event": event,
            "previous": "a".repeat(64),
            "digest": digest.to_string().repeat(64),
        })
        .to_string()
    }

    #[test]
    fn numeric_relationships_require_a_json_delimiter() {
        assert_eq!(
            json_number_relation("decided", &[1, 11]),
            "\\\"decided\\\":(1|11)(,|})"
        );
    }

    async fn server(app: Router) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{address}/")).unwrap()
    }

    #[tokio::test]
    async fn a_loki_page_is_globally_ordered_bounded_and_cursor_paginated() {
        let app = Router::new().route(
            "/loki/api/v1/query_range",
            get(
                |AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                    assert_eq!(
                        params.get("direction").map(String::as_str),
                        Some("backward")
                    );
                    assert_eq!(params.get("limit").map(String::as_str), Some("21"));
                    assert!(!params.contains_key("since"));
                    let start = params.get("start").unwrap().parse::<u64>().unwrap();
                    let end = params.get("end").unwrap().parse::<u64>().unwrap();
                    assert_eq!(end - start, 7 * 24 * 60 * 60 * 1_000_000_000);
                    assert!(params.get("query").is_some_and(|query| {
                        query.contains("\\\"session\\\":\\\"0123456789abcdef0123456789abcdef\\\"")
                            && query.contains("\\\"access_class\\\":\\\"read_only\\\"")
                            && query.contains("\\\"verdict\\\":\\\"permit\\\"")
                    }));
                    let mut values = Vec::new();
                    for sequence in 1..=21_u64 {
                        values.push((sequence.to_string(), line(sequence)));
                    }
                    axum::Json(serde_json::json!({
                        "status": "success",
                        "data": {"resultType": "streams", "result": [
                            {"stream": {"host": "server"}, "values": values}
                        ]}
                    }))
                },
            ),
        );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        let page = reader
            .read(&Query {
                session: "0123456789abcdef0123456789abcdef".to_owned(),
                access_class: "read_only".to_owned(),
                verdict: "permit".to_owned(),
                window: Window::Week,
                ..Query::default()
            })
            .await
            .unwrap();
        assert_eq!(page.entries.len(), PAGE_SIZE);
        assert_eq!(page.entries.first().unwrap().sequence, 21);
        assert_eq!(page.entries.last().unwrap().sequence, 2);
        assert_eq!(page.next_before, Some(1));
        assert!(page.window_start > 0);
    }

    #[tokio::test]
    async fn a_transcript_pages_commands_and_finds_their_later_evidence() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/loki/api/v1/query_range",
            get({
                let calls = Arc::clone(&calls);
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        let query = params.get("query").unwrap();
                        let (timestamp, line, expected_limit) = if query
                            .contains("\\\"event\\\":\\\"completed\\\"")
                        {
                            assert_eq!(params.get("end").map(String::as_str), Some("200"));
                            (
                                "160",
                                event_line(
                                    12,
                                    serde_json::json!({
                                        "event": "completed",
                                        "run": "abcdef0123456789-abcdef0123456789abcdef0123456789",
                                        "decided": 11,
                                        "state": "Exited { code: 0 }",
                                        "stdout": {"kind": "kept", "text": "active", "truncated": false, "bytes": 6},
                                        "stderr": {"kind": "kept", "text": "", "truncated": false, "bytes": 0}
                                    }),
                                    'c',
                                ),
                                "2",
                            )
                        } else if query.contains("\\\"event\\\":\\\"decided\\\"") {
                            assert_eq!(params.get("end").map(String::as_str), Some("100"));
                            (
                                "90",
                                event_line(
                                    10,
                                    serde_json::json!({
                                        "event": "decided",
                                        "agent_intent": "inspect dns health",
                                        "argv": ["systemctl", "status", "unbound"],
                                        "program": "systemctl",
                                        "access_class": "read_only",
                                        "purpose": "diagnose dns",
                                        "verdict": "needs_approval",
                                        "policies": ["default"]
                                    }),
                                    'd',
                                ),
                                "21",
                            )
                        } else {
                            assert!(query.contains("decision_digest"));
                            assert_eq!(params.get("end").map(String::as_str), Some("200"));
                            (
                                "150",
                                event_line(
                                    11,
                                    serde_json::json!({
                                        "event": "approved",
                                        "decided": 10,
                                        "request": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                        "approver": "chris",
                                        "override_of": null,
                                        "standing": false,
                                        "mode": "direct",
                                        "agreement": null
                                    }),
                                    'b',
                                ),
                                "5",
                            )
                        };
                        assert_eq!(
                            params.get("limit").map(String::as_str),
                            Some(expected_limit)
                        );
                        let parsed: Entry = serde_json::from_str(&line).unwrap();
                        assert!(
                            validate_entry(&parsed).is_ok(),
                            "test produced an invalid entry: {line}"
                        );
                        axum::Json(serde_json::json!({
                            "status": "success",
                            "data": {"resultType": "streams", "result": [
                                {"stream": {"host": "server"}, "values": [[timestamp, line]]}
                            ]}
                        }))
                    }
                }
            }),
        );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        let page = reader
            .read_transcript(&TranscriptQuery {
                before: Some(100),
                start: Some(1),
                end: Some(200),
                session: SessionId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            })
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(page.window_start, 1);
        assert_eq!(page.window_end, 200);
        assert_eq!(
            page.entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![12, 11, 10]
        );
    }

    #[tokio::test]
    async fn retained_output_is_read_by_exact_session_run_and_window() {
        let run = "0123456789abcdef-0123456789abcdef0123456789abcdef";
        let app = Router::new().route(
            "/loki/api/v1/query_range",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                    assert_eq!(params.get("start").map(String::as_str), Some("1"));
                    assert_eq!(params.get("end").map(String::as_str), Some("200"));
                    assert_eq!(params.get("limit").map(String::as_str), Some("2"));
                    let query = params.get("query").unwrap();
                    for exact in [
                        "\\\"session\\\":\\\"0123456789abcdef0123456789abcdef\\\"",
                        "\\\"event\\\":\\\"completed\\\"",
                        "\\\"run\\\":\\\"0123456789abcdef-0123456789abcdef0123456789abcdef\\\"",
                    ] {
                        assert!(query.contains(exact), "missing {exact}: {query}");
                    }
                    let line = event_line(
                        12,
                        serde_json::json!({
                            "event": "completed",
                            "run": run,
                            "decided": 10,
                            "state": "Exited { code: 0 }",
                            "stdout": {"kind": "kept", "text": "complete response", "truncated": false, "bytes": 17},
                            "stderr": {"kind": "kept", "text": "", "truncated": false, "bytes": 0}
                        }),
                        'c',
                    );
                    axum::Json(serde_json::json!({
                        "status": "success",
                        "data": {"resultType": "streams", "result": [
                            {"stream": {"host": "server"}, "values": [["160", line]]}
                        ]}
                    }))
                },
            ),
        );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        let entry = reader
            .read_output(&OutputQuery {
                start: 1,
                end: 200,
                session: SessionId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                run: RunId::parse(run).unwrap(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            entry
                .event
                .get("stdout")
                .and_then(|output| output.get("text"))
                .and_then(Value::as_str),
            Some("complete response")
        );
    }

    #[tokio::test]
    async fn an_older_page_keeps_the_initial_window_start() {
        let fixed_start = 1_700_000_000_000_000_000_u64;
        let older_end = fixed_start + 60_000_000_000;
        let app = Router::new().route(
            "/loki/api/v1/query_range",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                    assert_eq!(
                        params.get("start").and_then(|value| value.parse().ok()),
                        Some(fixed_start)
                    );
                    assert_eq!(
                        params.get("end").and_then(|value| value.parse().ok()),
                        Some(older_end)
                    );
                    axum::Json(serde_json::json!({
                        "status": "success",
                        "data": {"resultType": "streams", "result": []}
                    }))
                },
            ),
        );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        let page = reader
            .read(&Query {
                before: Some(older_end),
                start: Some(fixed_start),
                window: Window::Hour,
                ..Query::default()
            })
            .await
            .unwrap();
        assert_eq!(page.window_start, fixed_start);
    }

    #[tokio::test]
    async fn an_unavailable_loki_is_reported_instead_of_becoming_an_empty_page() {
        let app = Router::new().route(
            "/loki/api/v1/query_range",
            get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reader.read(&Query::default()).await.unwrap_err(),
            ReadError::Unavailable
        );
    }

    #[tokio::test]
    async fn a_loki_redirect_is_not_followed() {
        let app = Router::new()
            .route(
                "/loki/api/v1/query_range",
                get(|| async { axum::response::Redirect::temporary("/unexpected") }),
            )
            .route(
                "/unexpected",
                get(|| async {
                    axum::Json(serde_json::json!({
                        "status": "success",
                        "data": {"resultType": "streams", "result": []}
                    }))
                }),
            );
        let reader = Loki::new(
            server(app).await,
            Labels::parse(r#"{"service":"ssh"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reader.read(&Query::default()).await.unwrap_err(),
            ReadError::Unavailable
        );
    }

    fn valid_entry(source_nanos: u64, sequence: u64) -> Entry {
        let mut entry: Entry = serde_json::from_str(&line(sequence)).unwrap();
        entry.source_nanos = source_nanos;
        entry
    }

    #[test]
    fn malformed_event_evidence_is_not_a_successful_durable_row() {
        let mut entry = valid_entry(10, 1);
        entry.event = serde_json::json!({
            "event": "evaluated",
            "artifact": {"evaluation_id": "incomplete"}
        });
        assert!(validate_entry(&entry).is_err());

        entry.event = serde_json::json!({"event": "session_closed"});
        entry.digest = "z".repeat(64);
        assert!(validate_entry(&entry).is_err());
    }

    #[test]
    fn evaluation_context_is_optional_and_validated_when_present() {
        let artifact = serde_json::json!({
            "evaluation_id": "eval-1",
            "decision_digest": "d".repeat(64),
            "evaluator": "shadow-reviewer",
            "model": "review-model",
            "prompt_version": "intent-v1",
            "verdict": "supports_intent",
            "confidence": 91,
            "rationale": "The command supports the stated diagnosis.",
            "side_effects": ["Reads service metadata"]
        });
        let mut entry = valid_entry(10, 1);
        entry.event = serde_json::json!({
            "event": "evaluated",
            "operation": "execute",
            "artifact": artifact.clone(),
            "decided": 7,
            "argv": ["systemctl", "status", "unbound"],
            "agent_intent": "inspect dns health",
            "purpose": "diagnose dns",
            "access_class": "read_only"
        });
        assert!(validate_entry(&entry).is_ok());

        entry.event.as_object_mut().unwrap().remove("operation");
        assert!(validate_entry(&entry).is_ok());

        entry.event = serde_json::json!({"event": "evaluated", "artifact": artifact});
        assert!(validate_entry(&entry).is_ok());
    }

    #[test]
    fn a_command_within_the_producer_contract_is_a_valid_durable_row() {
        let argv = std::iter::once("tool")
            .chain(std::iter::repeat_n("argument", 256))
            .collect::<Vec<_>>();
        let event = serde_json::json!({
            "event": "decided", "operation": "execute",
            "agent_intent": "inspect the target",
            "argv": argv,
            "program": "tool",
            "access_class": "privileged",
            "purpose": "inspect the target",
            "verdict": "needs_approval",
            "policies": ["unknown-command"]
        });

        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn lossy_output_expansion_within_the_bounded_response_is_valid() {
        let recorded = serde_json::json!({
            "kind": "kept",
            "text": "\u{fffd}".repeat((1 << 20) + 1),
            "truncated": false,
            "bytes": 1 << 20
        });

        assert!(validate_recorded(&recorded).is_ok());
    }

    #[test]
    fn a_page_boundary_never_splits_entries_with_the_same_timestamp() {
        let mut entries = (0..19_u64)
            .map(|offset| valid_entry(100 - offset, offset))
            .collect::<Vec<_>>();
        entries.push(valid_entry(50, 19));
        entries.push(valid_entry(50, 20));

        assert_eq!(collision_safe_page(&mut entries).unwrap(), Some(50));
        assert_eq!(entries.len(), 19);
        assert!(entries.iter().all(|entry| entry.source_nanos > 50));
    }
}
