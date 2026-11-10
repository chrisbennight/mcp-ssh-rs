//! Bounded, authenticated evidence preparation. No remote byte channel is used.
use super::*;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashSet};

const MAX_OPERATIONS: usize = 500;
const MAX_BYTES: usize = 2 << 20;
const MAX_PAGES: usize = 25;
static EXPORTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ExportRequest {
    investigation: String,
    page_ids: String,
    scope: String,
    format: String,
    output: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ViewRequest {
    investigation: String,
    mode: String,
}

#[derive(Serialize)]
struct ViewDefinition {
    version: u8,
    mode: String,
    filters: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Manifest {
    version: u8,
    status: String,
    generated_at_unix_ms: u64,
    scope: String,
    source: String,
    definition: ViewDefinition,
    exported_operations: usize,
    selected_operations: Option<usize>,
    missing_selected_ids: Vec<String>,
    coverage: Vec<String>,
    output_policy: String,
    operation_limit: usize,
    byte_limit: usize,
    page_scan_limit: usize,
    deadline_seconds: u64,
    continuation: String,
    integrity: &'static str,
}

fn definition(query: &ActivityQuery, mode: &str) -> ViewDefinition {
    let encoded = query.url(&query.source, query.before);
    let pairs = encoded
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let fixed = mode == "fixed";
    let filters = url::form_urlencoded::parse(pairs.as_bytes())
        .filter(|(key, _)| {
            fixed
                || !matches!(
                    key.as_ref(),
                    "before"
                        | "start"
                        | "end"
                        | "service_start"
                        | "service_end"
                        | "instance"
                        | "selected"
                )
        })
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    ViewDefinition {
        version: 1,
        mode: if fixed { "fixed" } else { "recurring" }.to_owned(),
        filters,
    }
}

fn generated_at() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| {
            u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
        })
}

fn attachment(
    bytes: Vec<u8>,
    mime: &'static str,
    extension: &str,
    status: &str,
    count: usize,
    stem: &str,
) -> Response {
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes));
    let filename = format!("{stem}-{status}-{}.{}", generated_at(), extension);
    let headers = [
        (header::CONTENT_TYPE.as_str(), mime.to_owned()),
        (
            header::CACHE_CONTROL.as_str(),
            "private, no-store".to_owned(),
        ),
        (
            header::CONTENT_DISPOSITION.as_str(),
            format!("attachment; filename=\"{filename}\""),
        ),
        ("x-content-type-options", "nosniff".to_owned()),
        ("content-digest", format!("sha-256=:{digest}:")),
        ("x-export-status", status.to_owned()),
        ("x-export-operations", count.to_string()),
    ];
    (headers, bytes).into_response()
}

pub(crate) async fn export_view(Query(request): Query<ViewRequest>) -> Response {
    let Some(query) = parse_investigation(&request.investigation) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !matches!(request.mode.as_str(), "" | "fixed" | "recurring") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match serde_json::to_vec_pretty(&definition(&query, &request.mode)) {
        Ok(bytes) => attachment(
            bytes,
            "application/json",
            "json",
            "ready",
            0,
            "activity-view",
        ),
        Err(error) => {
            tracing::error!(%error,"view definition could not be rendered");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn export_activity<C, S>(
    State(state): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    axum::Extension(reader): axum::Extension<Arc<dyn ReadsAudit>>,
    Query(mut request): Query<ExportRequest>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    let Some(mut query) = parse_investigation(&request.investigation) else {
        return (
            StatusCode::BAD_REQUEST,
            "Choose a valid local investigation.",
        )
            .into_response();
    };
    if request.scope.is_empty() {
        request.scope = "page".to_owned();
    }
    if request.format.is_empty() {
        request.format = "json".to_owned();
    }
    if !matches!(request.scope.as_str(), "page" | "selected" | "range")
        || !matches!(request.format.as_str(), "json" | "csv" | "text")
        || request.page_ids.len() > 4096
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let selected = match request.scope.as_str() {
        "selected" => {
            if !is_digest(&query.selected) {
                return (
                    StatusCode::BAD_REQUEST,
                    "Select an operation before preparing its evidence.",
                )
                    .into_response();
            }
            vec![query.selected.clone()]
        }
        "page" => {
            let ids = request
                .page_ids
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if ids.len() > 40 || !ids.iter().all(|id| is_digest(id)) {
                return StatusCode::BAD_REQUEST.into_response();
            }
            ids
        }
        _ => Vec::new(),
    };
    if request.scope != "range" && selected.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "There are no displayed operations to export.",
        )
            .into_response();
    }
    let Ok(_permit) = EXPORTS.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Evidence preparation is busy. Try again shortly.",
        )
            .into_response();
    };
    let original = query.clone();
    if request.scope == "range" {
        query.before = None;
    } else {
        query.page_ids = selected.join(",");
        query.view.clear();
        query.approval.clear();
        query.assessment.clear();
        query.q.clear();
        query.kind.clear();
        query.request.clear();
        query.agreement.clear();
        query.run.clear();
    }
    let Some(deadline) =
        tokio::time::Instant::now().checked_add(std::time::Duration::from_secs(15))
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut operations = Vec::new();
    let mut seen = HashSet::new();
    let mut coverage = Vec::new();
    let mut charge = 65_536usize;
    let mut limited = false;
    let mut incomplete = false;
    let mut continuation = String::new();
    let mut snapshot = original.clone();
    let mut source = String::new();
    for page_number in 0..MAX_PAGES {
        let result = tokio::time::timeout_at(
            deadline,
            load_activity(
                Arc::clone(&state),
                operator.clone(),
                Arc::clone(&reader),
                query.clone(),
            ),
        )
        .await;
        let page = match result {
            Ok(Ok(page)) => page,
            _ => {
                incomplete = true;
                coverage.push(
                    "Preparation stopped because a source read failed or the deadline was reached."
                        .to_owned(),
                );
                break;
            }
        };
        if page.unsupported {
            return (StatusCode::UNPROCESSABLE_ENTITY,"This live-state filter cannot be established from saved history. Choose Current service or a recorded-outcome filter.").into_response();
        }
        if page_number == 0 {
            source.clone_from(&page.source);
            if let Some(normalized) = parse_investigation(&page.investigation) {
                snapshot.source.clone_from(&normalized.source);
                snapshot.before = normalized.before;
                snapshot.start = normalized.start;
                snapshot.end = normalized.end;
                snapshot.service_start = normalized.service_start;
                snapshot.service_end = normalized.service_end;
                snapshot.instance = normalized.instance;
            }
        }
        incomplete |= !page.available || page.limited;
        coverage.push(page.notice.clone());
        continuation = page.next_url;
        for mut row in page.operations {
            if !seen.insert(row.id.clone()) {
                continue;
            }
            if !request.output {
                for output in &mut row.outputs {
                    output.preview.clear();
                    output.note.push_str("; preview omitted by export choice");
                }
            }
            incomplete |= row.missing_request || row.execution.missing();
            let bytes = match serde_json::to_vec(&row) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::error!(%error,"operation evidence could not be rendered");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            if operations.len() >= MAX_OPERATIONS || charge.saturating_add(bytes.len()) > MAX_BYTES
            {
                limited = true;
                continuation.clear();
                break;
            }
            charge = charge.saturating_add(bytes.len());
            operations.push(row);
        }
        if limited || !page.available || request.scope != "range" || continuation.is_empty() {
            break;
        }
        if page_number.saturating_add(1) == MAX_PAGES {
            limited = true;
            break;
        }
        let Some(next) = parse_investigation(&continuation) else {
            incomplete = true;
            coverage.push("The continuation could not be validated.".to_owned());
            break;
        };
        query = next;
    }
    if source.is_empty() || operations.is_empty() && incomplete {
        return (StatusCode::SERVICE_UNAVAILABLE,"Export failed because the evidence source could not complete the query. Narrow the range or retry.").into_response();
    }
    let exported = operations
        .iter()
        .map(|row| row.id.as_str())
        .collect::<HashSet<_>>();
    let missing_selected_ids = selected
        .iter()
        .filter(|id| !exported.contains(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    incomplete |= !missing_selected_ids.is_empty();
    if !missing_selected_ids.is_empty() {
        coverage.push(
            "Some selected identities are no longer available in this source or window.".to_owned(),
        );
    }
    if limited {
        coverage.push("A preparation limit was reached. This file is a bounded prefix; narrow the range to inspect further evidence.".to_owned());
    }
    coverage.push("Selection freezes operation identities or the query window. Live observations are read during preparation; later ingestion may change future saved searches.".to_owned());
    if source == "current" {
        coverage.push("Current service evidence is bounded by retention and service lifetime. Service timestamps use monotonic milliseconds.".to_owned());
    } else {
        coverage.push("Saved record timestamps and bounds use Unix nanoseconds. Related evidence may be outside the request interval but not beyond the observation cutoff.".to_owned());
    }
    coverage.sort();
    coverage.dedup();
    let status = if limited {
        "limit_reached"
    } else if incomplete {
        "incomplete"
    } else {
        "ready"
    };
    let manifest=Manifest {version:1,status:status.to_owned(),generated_at_unix_ms:generated_at(),scope:request.scope,source,definition:definition(&snapshot,"fixed"),exported_operations:operations.len(),selected_operations:(!selected.is_empty()).then_some(selected.len()),missing_selected_ids,coverage,output_policy:if request.output {"Retained display previews included; per-stream notes describe capture, preview and withholding limits. Remote file contents and byte credentials are excluded."} else {"Retained output previews excluded. Stream retention metadata remains included. Remote file contents and byte credentials are excluded."}.to_owned(),operation_limit:MAX_OPERATIONS,byte_limit:MAX_BYTES,page_scan_limit:MAX_PAGES,deadline_seconds:15,continuation,integrity:"Record digests identify original evidence. This operator projection is not a complete audit archive or full-chain verification. The response content digest checks only the downloaded file."};
    let rendered = match request.format.as_str() {
        "csv" => csv(&manifest, &operations).map(|bytes| (bytes, "text/csv; charset=utf-8", "csv")),
        "text" => Ok((
            report(&manifest, &operations).into_bytes(),
            "text/plain; charset=utf-8",
            "txt",
        )),
        _ => serde_json::to_vec(&serde_json::json!({"manifest":manifest,"operations":operations}))
            .map(|bytes| (bytes, "application/json", "json")),
    };
    match rendered {
        Ok((bytes, mime, extension)) if bytes.len() <= MAX_BYTES => attachment(
            bytes,
            mime,
            extension,
            status,
            manifest.exported_operations,
            "activity-evidence",
        ),
        Ok(_) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Export limit reached. Narrow the range or exclude output previews.",
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error,"evidence export could not be rendered");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn cell(value: &str) -> String {
    let dangerous = value.starts_with(['\t', '\r', '\n'])
        || value
            .trim_start_matches(|character: char| {
                character.is_whitespace() || character.is_control()
            })
            .starts_with(['=', '+', '-', '@']);
    format!(
        "\"{}{}\"",
        if dangerous { "'" } else { "" },
        value.replace('"', "\"\"")
    )
}

fn csv(manifest: &Manifest, rows: &[OperationShown]) -> Result<Vec<u8>, serde_json::Error> {
    let mut text="record_type,manifest,operation_id,requested_at,host,account,principal,operation,approval,execution,attention,summary,retained_output,evidence_ids\r\n".to_owned();
    text.push_str(&format!(
        "manifest,{}{}\r\n",
        cell(&serde_json::to_string(manifest)?),
        ",".repeat(12)
    ));
    for row in rows {
        let fields = [
            "operation".to_owned(),
            String::new(),
            row.id.clone(),
            row.requested_at
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Unavailable".to_owned()),
            row.host.clone(),
            row.role.clone(),
            row.principal.clone(),
            row.kind.clone(),
            row.approval.clone(),
            row.status.clone(),
            row.reasons.join("; "),
            row.preview.clone(),
            serde_json::to_string(&row.outputs)?,
            row.evidence_records
                .iter()
                .map(|record| record.digest.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        ];
        text.push_str(
            &fields
                .iter()
                .map(|field| cell(field))
                .collect::<Vec<_>>()
                .join(","),
        );
        text.push_str("\r\n");
    }
    Ok(text.into_bytes())
}

fn report(manifest: &Manifest, rows: &[OperationShown]) -> String {
    let mut text = format!(
        "Activity evidence\nStatus: {}\nOperations: {}\nSource: {}\nGenerated (Unix milliseconds): {}\nScope: {}\n{}\n\nCoverage\n",
        manifest.status,
        rows.len(),
        manifest.source,
        manifest.generated_at_unix_ms,
        manifest.scope,
        manifest.output_policy
    );
    text.push_str(&format!(
        "Filters (escaped): {}\n",
        visible_output(&serde_json::to_string(&manifest.definition).unwrap_or_default())
    ));
    for note in &manifest.coverage {
        text.push_str(&format!("- {note}\n"));
    }
    for row in rows {
        text.push_str(&format!(
            "\n{}\n{} / {} · {}\n{} · {}\nIntent: {}\nArguments (escaped display): {}\n",
            row.id,
            row.host,
            row.role,
            row.principal,
            row.status,
            row.approval,
            row.intent,
            serde_json::to_string(&row.arguments).unwrap_or_default()
        ));
        text.push_str(&format!("Requested: {:?} · Completed: {:?} (source clock)\nRequest: {} · Run: {} · Session approval: {}\n", row.requested_at, row.completed_at, row.request, row.run, row.agreement));
        for reason in &row.reasons {
            text.push_str(&format!("Reason: {reason}\n"));
        }
        if let Some(file) = &row.file {
            for (label, value) in &file.fields {
                text.push_str(&format!("{label}: {value}\n"));
            }
            text.push_str(&format!("{}\n{}\n", file.notice, file.artifact));
            if !file.entries.is_empty() {
                text.push_str(&format!(
                    "Directory entries (escaped display): {}\n",
                    serde_json::to_string(&file.entries).unwrap_or_default()
                ));
            }
        }
        for output in &row.outputs {
            text.push_str(&format!(
                "{}: {}\n{}\n",
                output.label, output.note, output.preview
            ));
        }
        for evidence in &row.evidence_records {
            text.push_str(&format!(
                "Evidence #{} {} {} · {}\n",
                evidence.sequence, evidence.event, evidence.digest, evidence.summary
            ));
        }
    }
    text.push_str(&format!("\n{}\n", manifest.integrity));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spreadsheet_cells_preserve_boundaries_and_neutralize_formulas() {
        for value in ["=SUM(1,2)", " +1", "-1", "@data", "\t=1", "\r@data"] {
            assert!(cell(value).starts_with("\"'"));
        }
        assert_eq!(cell("plain,\"quoted\""), "\"plain,\"\"quoted\"\"\"");
    }

    #[test]
    fn recurring_view_definitions_do_not_capture_runtime_snapshots() {
        let query = ActivityQuery {
            host: "server".to_owned(),
            source: "current".to_owned(),
            instance: "a".repeat(64),
            service_start: Some(1),
            service_end: Some(2),
            before: Some(3),
            ..Default::default()
        };
        let recurring = definition(&query, "recurring");
        assert_eq!(
            recurring.filters.get("host").map(String::as_str),
            Some("server")
        );
        assert!(!recurring.filters.contains_key("instance"));
        assert!(!recurring.filters.contains_key("before"));
        assert_eq!(
            definition(&query, "fixed").filters.get("instance"),
            Some(&"a".repeat(64))
        );
    }
}
