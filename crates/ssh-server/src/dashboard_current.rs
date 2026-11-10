//! Classify retained metadata before limiting or materializing operation details.
use super::*;
use ssh_core::audit::{Entry, EvaluationVerdict, Event};
use std::collections::HashMap;

#[cfg_attr(test, derive(Default))]
struct Observation {
    execution: state::Execution,
    approval: state::Approval,
    assessment: Option<EvaluationVerdict>,
    cancellation: bool,
    request: String,
    run: String,
    agreement: String,
    progress: Option<ssh_core::run::Progress>,
    completed_at: Option<u64>,
    missing_request: bool,
    identifiers: Vec<String>,
}

pub(super) struct Current {
    observations: HashMap<u64, Observation>,
    pub now: u64,
    pub matches: usize,
    pub instance: String,
}

impl Current {
    pub fn read<C: Clock + 'static, S: CredentialSource>(
        state: &Bastion<C, S>,
        query: &ActivityQuery,
    ) -> Self {
        let entries = state.ledger().recent_entries(usize::MAX);
        let mut result = Self {
            observations: HashMap::new(),
            now: state.now(),
            matches: 0,
            instance: state.ledger().instance_id().to_owned(),
        };
        let mut authorities = HashMap::new();
        for entry in &entries {
            if let Event::Decided { verdict, .. } = &entry.event {
                let (execution, approval) = match verdict {
                    ssh_core::policy::Verdict::Permit => (
                        state::Execution::EvidenceMissing,
                        state::Approval::NotRequired,
                    ),
                    ssh_core::policy::Verdict::Deny => {
                        (state::Execution::NotStarted, state::Approval::Refused)
                    }
                    ssh_core::policy::Verdict::NeedsApproval => (
                        state::Execution::NotStarted,
                        state::Approval::HistoricalUnconfirmed,
                    ),
                };
                result.observations.insert(
                    entry.sequence,
                    Observation {
                        execution,
                        approval,
                        assessment: None,
                        cancellation: false,
                        request: String::new(),
                        run: String::new(),
                        agreement: String::new(),
                        progress: None,
                        completed_at: None,
                        missing_request: false,
                        identifiers: Vec::new(),
                    },
                );
            }
            if let Event::Approved { decided, .. } = &entry.event {
                authorities.insert(entry.sequence, *decided);
            }
        }
        for entry in &entries {
            match &entry.event {
                Event::Approved {
                    decided,
                    request,
                    standing,
                    agreement,
                    ..
                } => {
                    if let Some(row) = result.observations.get_mut(decided) {
                        row.approval = if *standing {
                            state::Approval::Session
                        } else {
                            state::Approval::ApprovedOnce
                        };
                        row.execution = state::Execution::EvidenceMissing;
                        row.request.clone_from(request);
                        row.agreement = agreement.clone().unwrap_or_default();
                    }
                }
                Event::Answered {
                    decided,
                    request,
                    standing,
                    agreed,
                    ..
                } => {
                    if let Some(row) = result.observations.get_mut(decided) {
                        row.request.clone_from(request);
                        if !agreed {
                            row.approval = state::Approval::Refused;
                            row.execution = state::Execution::NotStarted;
                        } else if row.approval == state::Approval::HistoricalUnconfirmed {
                            row.approval = if *standing {
                                state::Approval::Session
                            } else {
                                state::Approval::ApprovedOnce
                            };
                        }
                    }
                }
                Event::Evaluated {
                    decided, artifact, ..
                } => {
                    if let Some(row) = result.observations.get_mut(decided) {
                        row.assessment = Some(artifact.verdict());
                    }
                }
                _ => {}
            }
        }
        for entry in &entries {
            match &entry.event {
                Event::Completed {
                    decided,
                    outcome,
                    run,
                    ..
                } => {
                    let root = authorities.get(decided).copied().unwrap_or(*decided);
                    let key = if result.observations.contains_key(&root) {
                        root
                    } else {
                        entry.sequence
                    };
                    result
                        .observations
                        .entry(key)
                        .or_insert_with(|| Observation {
                            execution: state::Execution::Observed(*outcome),
                            approval: state::Approval::HistoricalUnconfirmed,
                            assessment: None,
                            cancellation: false,
                            request: String::new(),
                            run: run.as_str().to_owned(),
                            agreement: String::new(),
                            progress: None,
                            completed_at: Some(entry.at),
                            missing_request: true,
                            identifiers: Vec::new(),
                        });
                    if let Some(row) = result.observations.get_mut(&key) {
                        row.execution = state::Execution::Observed(*outcome);
                        row.completed_at = Some(entry.at);
                        row.run = run.as_str().to_owned();
                    }
                }
                Event::CancellationRequested { decided, .. } => {
                    if let Some(row) = result
                        .observations
                        .get_mut(authorities.get(decided).unwrap_or(decided))
                    {
                        row.cancellation = true;
                    }
                }
                _ => {}
            }
        }
        for request in state.waiting_for_approval() {
            if let Some(row) = result.observations.get_mut(&request.decided) {
                row.approval = state::Approval::AwaitingDecision;
                row.execution = state::Execution::NotStarted;
                row.request = request.id.as_str().to_owned();
            }
        }
        for (request, active) in state.uncollected_approvals() {
            if let Some(row) = result.observations.get_mut(&request.decided) {
                row.execution = if active {
                    state::Execution::WaitingForAgent
                } else {
                    state::Execution::NotStarted
                };
                if !active {
                    row.approval = state::Approval::Expired;
                }
                row.request = request.id.as_str().to_owned();
            }
        }
        for (run, authorization) in state.runs_in_flight_with_authorization() {
            let root = authorities
                .get(&authorization.sequence())
                .copied()
                .unwrap_or(authorization.sequence());
            if let Some(row) = result.observations.get_mut(&root)
                && let Some(progress) = state.observe_progress(&run)
            {
                row.execution = state::Execution::Observed(progress.state);
                row.run = run.as_str().to_owned();
                row.progress = Some(progress);
            }
        }
        for entry in &entries {
            let key = match &entry.event {
                Event::Decided { .. } => entry.sequence,
                Event::Approved { decided, .. }
                | Event::Answered { decided, .. }
                | Event::Evaluated { decided, .. } => *decided,
                Event::Completed { decided, .. } | Event::CancellationRequested { decided, .. } => {
                    let root = authorities.get(decided).copied().unwrap_or(*decided);
                    if result.observations.contains_key(&root) {
                        root
                    } else {
                        entry.sequence
                    }
                }
                _ => continue,
            };
            if let Some(row) = result.observations.get_mut(&key) {
                row.identifiers.push(entry.digest.as_str().to_owned());
                row.identifiers.push(entry.sequence.to_string());
                row.identifiers.push(format!("#{}", entry.sequence));
                if let Event::Completed { file, decided, .. } = &entry.event {
                    if let Some(file) = file {
                        row.identifiers.push(file.sha256.clone());
                    }
                    if let Event::Completed { info, .. } = &entry.event
                        && let Some(digest) = checksum_digest(info.as_ref())
                    {
                        row.identifiers.push(digest.to_owned());
                    }
                    if row.missing_request
                        && let Some(authority) = entries
                            .iter()
                            .find(|candidate| candidate.sequence == *decided)
                        && let Event::Approved {
                            request,
                            agreement,
                            standing,
                            ..
                        } = &authority.event
                    {
                        row.request.clone_from(request);
                        row.agreement = agreement.clone().unwrap_or_default();
                        row.approval = if *standing {
                            state::Approval::Session
                        } else {
                            state::Approval::ApprovedOnce
                        };
                    }
                }
            }
        }
        result.matches = entries
            .iter()
            .filter(|entry| result.includes(query, entry))
            .count();
        result
    }

    pub fn includes(&self, query: &ActivityQuery, entry: &Entry) -> bool {
        let Some(row) = self.observations.get(&entry.sequence) else {
            return false;
        };
        let duration = match query.window.as_str() {
            "1h" => 3_600_000,
            "7d" => 604_800_000,
            "30d" => 2_592_000_000,
            _ => 86_400_000,
        };
        let at = if query.time_basis == "completed" {
            let Some(at) = row.completed_at else {
                return false;
            };
            at
        } else {
            entry.at
        };
        if at
            < query
                .service_start
                .unwrap_or(self.now.saturating_sub(duration))
            || at > query.service_end.unwrap_or(self.now)
        {
            return false;
        }
        if !query.instance.is_empty() && query.instance != self.instance {
            return false;
        }
        if !query.page_ids.is_empty()
            && !query
                .page_ids
                .split(',')
                .any(|id| id == entry.digest.as_str())
        {
            return false;
        }
        if !query.request.is_empty() && query.request != row.request
            || !query.run.is_empty() && query.run != row.run
            || !query.agreement.is_empty() && query.agreement != row.agreement
        {
            return false;
        }
        if !query.approval.is_empty()
            && !match query.approval.as_str() {
                "waiting" => row.approval == state::Approval::AwaitingDecision,
                "approved" => matches!(
                    row.approval,
                    state::Approval::ApprovedOnce | state::Approval::Session
                ),
                "refused" => row.approval == state::Approval::Refused,
                "not_required" => row.approval == state::Approval::NotRequired,
                "expired" => row.approval == state::Approval::Expired,
                _ => false,
            }
        {
            return false;
        }
        if !query.assessment.is_empty()
            && row
                .assessment
                .and_then(|value| serde_json::to_value(value).ok())
                .and_then(|value| value.as_str().map(str::to_owned))
                .as_deref()
                != Some(query.assessment.as_str())
        {
            return false;
        }
        let mut scope = query.clone();
        scope.q.clear();
        let scope_matches = if row.missing_request {
            (scope.session.is_empty() || scope.session == entry.session.as_str())
                && (scope.host.is_empty() || scope.host == entry.host.as_str())
                && (scope.principal.is_empty() || scope.principal == entry.principal.as_str())
                && (scope.role.is_empty() || scope.role == entry.role.as_str())
                && match &entry.event {
                    Event::Completed { info, file, .. } => {
                        let kind = files::retained_operation(info.as_ref(), file.is_some());
                        scope.kind.is_empty()
                            || scope.kind == kind
                            || (scope.kind == "files" && kind != "unknown")
                    }
                    _ => scope.kind.is_empty(),
                }
        } else {
            scope.matches(entry)
        };
        if !scope_matches {
            return false;
        }
        if !query.q.is_empty()
            && !query.matches(entry)
            && ![
                row.request.as_str(),
                row.run.as_str(),
                row.agreement.as_str(),
                entry.session.as_str(),
            ]
            .contains(&query.q.as_str())
            && !row.identifiers.contains(&query.q)
            && query.q != entry.digest.as_str()
            && query.q != entry.sequence.to_string()
            && query.q != format!("#{}", entry.sequence)
        {
            return false;
        }
        let adverse = matches!(
            row.assessment,
            Some(EvaluationVerdict::DoesNotSupportIntent | EvaluationVerdict::Uncertain)
        );
        let attention = row.missing_request
            || row.approval == state::Approval::AwaitingDecision
            || row.execution.failed()
            || row.execution.unknown()
            || row.execution.missing()
            || matches!(row.execution, state::Execution::Observed(RunState::Ended))
            || adverse
            || row.cancellation;
        state::Preset::parse(&query.view).is_some_and(|preset| {
            (preset == state::Preset::Evidence && row.missing_request)
                || preset.includes(
                    row.execution,
                    row.approval,
                    row.assessment.is_some(),
                    attention,
                )
        })
    }

    pub fn apply(&self, row: &mut OperationShown, sequence: u64) {
        let Some(observed) = self.observations.get(&sequence) else {
            return;
        };
        row.execution = observed.execution;
        row.missing_request = observed.missing_request;
        row.approval_state = observed.approval;
        row.request.clone_from(&observed.request);
        row.run.clone_from(&observed.run);
        row.agreement.clone_from(&observed.agreement);
        row.approval = match observed.approval {
            state::Approval::AwaitingDecision => "Awaiting decision".to_owned(),
            state::Approval::Expired => "Approval expired · not collected".to_owned(),
            state::Approval::HistoricalUnconfirmed => {
                "Historical request · current disposition unavailable".to_owned()
            }
            state::Approval::Refused => "Approval refused".to_owned(),
            state::Approval::ApprovedOnce
                if observed.execution == state::Execution::WaitingForAgent =>
            {
                "Approved once".to_owned()
            }
            _ => row.approval.clone(),
        };
        if let Some(progress) = &observed.progress {
            row.progress = if row.kind == "execute" {
                format!(
                    "{} elapsed · stdout {} bytes · stderr {} bytes",
                    elapsed_time(progress.elapsed_ms),
                    progress.stdout_bytes,
                    progress.stderr_bytes
                )
            } else {
                format!(
                    "{} elapsed · {} source bytes read",
                    elapsed_time(progress.elapsed_ms),
                    progress.transfer_bytes_read
                )
            };
            let cancellation = cancellation_status(progress.cancellation);
            if !cancellation.is_empty() {
                row.cancellation = cancellation.to_owned();
            }
        }
        row.classify();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ssh_core::audit::{Ledger, Recorded};
    use ssh_core::clock::TestClock;
    use ssh_core::session::{Lifetime, Purpose, SessionStore};

    #[test]
    fn typed_retained_results_survive_operation_filters_without_request_evidence() {
        let session = SessionStore::new(
            TestClock::at(1000),
            Lifetime {
                idle: 1000,
                max: 1000,
                grace: 0,
            },
            8,
        )
        .open(
            ssh_core::PrincipalId::parse("agent").unwrap(),
            ssh_core::HostId::parse("server").unwrap(),
            ssh_core::RoleId::parse("ops").unwrap(),
            Purpose::parse("inspect metadata").unwrap(),
            AccessClass::ReadOnly,
        )
        .unwrap();
        let ledger = Ledger::new(TestClock::at(1000));
        let original = ledger.record_session_opened(&session).unwrap();
        let kept = Recorded::Kept {
            text: String::new(),
            truncated: false,
            bytes: 0,
        };
        for (kind, info) in [
            (
                "stat",
                serde_json::json!({"operation":"stat","metadata":{"kind":"file","bytes":12,"permissions":384,"modified":0}}),
            ),
            (
                "list",
                serde_json::json!({"operation":"list","entries":[],"truncated":false}),
            ),
            (
                "checksum",
                serde_json::json!({"operation":"checksum","bytes":12,"sha256":"a".repeat(64)}),
            ),
        ] {
            let mut entry = original.clone();
            entry.event = Event::Completed {
                run: RunId::parse("abcdef0123456789-abcdef0123456789abcdef0123456789").unwrap(),
                decided: 999,
                state: "Exited { code: 0 }".into(),
                outcome: RunState::Exited { code: 0 },
                stdout: kept.clone(),
                stderr: kept.clone(),
                file: None,
                info: Some(serde_json::from_value(info).unwrap()),
            };
            let current = Current {
                observations: HashMap::from([(
                    entry.sequence,
                    Observation {
                        missing_request: true,
                        execution: state::Execution::Observed(RunState::Exited { code: 0 }),
                        completed_at: Some(1000),
                        ..Default::default()
                    },
                )]),
                now: 1000,
                matches: 0,
                instance: ledger.instance_id().to_owned(),
            };
            for filter in [kind, "files"] {
                assert!(current.includes(
                    &ActivityQuery {
                        kind: filter.to_owned(),
                        view: "evidence".into(),
                        ..Default::default()
                    },
                    &entry
                ));
            }
            assert!(!current.includes(
                &ActivityQuery {
                    kind: "execute".into(),
                    ..Default::default()
                },
                &entry
            ));
        }
    }
}
