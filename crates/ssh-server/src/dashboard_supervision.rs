//! Observations for supervision; none of these reads renew or collect work.
use super::*;
use ssh_core::audit::{Entry, Event};

#[derive(Clone, Default)]
pub struct WorkShown {
    pub running: usize,
    pub waiting: usize,
    pub waiting_agent: usize,
    pub activity: String,
    pub latest: String,
    pub latest_when: String,
    pub latest_url: String,
    pub latest_outcome: String,
}

pub struct AccountShown {
    pub role: String,
    pub sessions: usize,
    pub work: WorkShown,
    pub activity_url: String,
    pub sessions_url: String,
    pub access_class: String,
}

pub(super) struct Observation {
    now: u64,
    entries: Vec<Arc<Entry>>,
    by_session: HashMap<String, WorkShown>,
    by_account: HashMap<(String, String), WorkShown>,
    pub counts: HashMap<(HostId, ssh_core::RoleId), usize>,
}

impl Observation {
    pub fn read<C: Clock + 'static, S: CredentialSource>(state: &Bastion<C, S>) -> Self {
        let mut view = Self {
            now: state.now(),
            entries: state.ledger().recent_entries(usize::MAX),
            by_session: HashMap::new(),
            by_account: HashMap::new(),
            counts: state.account_session_counts(),
        };
        for (_, auth) in state.runs_in_flight_with_authorization() {
            view.add(
                auth.session().as_str(),
                auth.host().as_str(),
                auth.role().as_str(),
                1,
                0,
                0,
            );
        }
        for asked in state.waiting_for_approval() {
            view.add(
                asked.session.as_str(),
                asked.host.as_str(),
                asked.role.as_str(),
                0,
                1,
                0,
            );
        }
        for (asked, usable) in state.uncollected_approvals() {
            if usable {
                view.add(
                    asked.session.as_str(),
                    asked.host.as_str(),
                    asked.role.as_str(),
                    0,
                    0,
                    1,
                );
            }
        }
        view
    }

    fn add(
        &mut self,
        session: &str,
        host: &str,
        role: &str,
        running: usize,
        waiting: usize,
        agent: usize,
    ) {
        for work in [
            self.by_session.entry(session.to_owned()).or_default(),
            self.by_account
                .entry((host.to_owned(), role.to_owned()))
                .or_default(),
        ] {
            work.running = work.running.saturating_add(running);
            work.waiting = work.waiting.saturating_add(waiting);
            work.waiting_agent = work.waiting_agent.saturating_add(agent);
        }
    }

    fn work(&self, mut work: WorkShown, matches: impl Fn(&Entry) -> bool) -> WorkShown {
        work.activity = if work
            .running
            .saturating_add(work.waiting)
            .saturating_add(work.waiting_agent)
            == 0
        {
            "No active work"
        } else {
            "Active work"
        }
        .to_owned();
        if let Some(latest) = self.entries.iter().find(|entry| {
            matches(entry) && matches!(entry.event, Event::Decided { .. } | Event::Completed { .. })
        }) {
            let (origin, completed) = match &latest.event {
                Event::Completed { decided, state, .. } => {
                    let authority = self.entries.iter().find(|entry| {
                        entry.session == latest.session && entry.sequence == *decided
                    });
                    let origin = authority.and_then(|authority| match &authority.event {
                        Event::Approved { decided, .. } => self.entries.iter().find(|entry| {
                            entry.session == latest.session && entry.sequence == *decided
                        }),
                        Event::Decided { .. } => Some(authority),
                        _ => None,
                    });
                    (origin, Some(state))
                }
                _ => (Some(latest), None),
            };
            if let Some(origin) = origin
                && let Event::Decided {
                    argv, operation, ..
                } = &origin.event
            {
                work.latest = activity::preview(
                    &argv.iter().map(|arg| visible(arg)).collect::<Vec<_>>(),
                    operation.as_str(),
                );
                work.latest_url = format!(
                    "{}&selected={}",
                    session_history_url(origin.session.as_str()),
                    origin.digest.as_str()
                );
            } else {
                work.latest = "Result retained; original request context unavailable".to_owned();
            }
            work.latest_when = format!(
                "{} {} ago · retained service evidence",
                if completed.is_some() {
                    "Completed"
                } else {
                    "Requested"
                },
                elapsed_time(self.now.saturating_sub(latest.at))
            );
            work.latest_outcome = completed
                .map(|state| format!("Observed result: {}", visible(state)))
                .unwrap_or_else(|| "Completion not retained for this request".to_owned());
        } else {
            work.latest = "No operation in retained evidence".to_owned();
        }
        work
    }

    pub fn session(&self, session: &str) -> WorkShown {
        self.work(
            self.by_session.get(session).cloned().unwrap_or_default(),
            |entry| entry.session.as_str() == session,
        )
    }

    pub fn matches(&self, session: &str, view: &str) -> bool {
        let work = self.by_session.get(session).cloned().unwrap_or_default();
        match view {
            "running" => work.running > 0,
            "waiting" => work.waiting > 0,
            "waiting_agent" => work.waiting_agent > 0,
            "quiet" => {
                work.running
                    .saturating_add(work.waiting)
                    .saturating_add(work.waiting_agent)
                    == 0
            }
            _ => true,
        }
    }

    pub fn account(&self, host: &str, role: &str) -> WorkShown {
        self.work(
            self.by_account
                .get(&(host.to_owned(), role.to_owned()))
                .cloned()
                .unwrap_or_default(),
            |entry| entry.host.as_str() == host && entry.role.as_str() == role,
        )
    }

    pub fn standing<C: Clock + 'static, S: CredentialSource>(
        &self,
        state: &Bastion<C, S>,
        agreement: StandingApproval,
        remaining: u64,
    ) -> StandingShown {
        let mut row = StandingShown::from(agreement.clone(), remaining);
        row.work = self.session(&row.session);
        if let Some(snapshot) = state.session_snapshot(&agreement.session) {
            row.context = format!(
                "{} / {} · {} · {}",
                visible(snapshot.session.host.as_str()),
                visible(snapshot.session.role.as_str()),
                visible(snapshot.session.principal.as_str()),
                visible(snapshot.session.purpose.as_str())
            );
            row.remaining = elapsed_time(
                remaining.min(
                    snapshot
                        .ends_by
                        .min(snapshot.idle_by)
                        .saturating_sub(self.now),
                ),
            );
            row.expiring = remaining.min(
                snapshot
                    .ends_by
                    .min(snapshot.idle_by)
                    .saturating_sub(self.now),
            ) <= 600_000;
        }
        let uses = self.entries.iter().filter(|entry| matches!(&entry.event, Event::Approved { agreement: Some(id), .. } if id == agreement.id.as_str())).collect::<Vec<_>>();
        row.uses = uses.len();
        if let Some(latest) = uses.first() {
            row.last_use = format!(
                "Last use {} ago",
                elapsed_time(self.now.saturating_sub(latest.at))
            );
        }
        row
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ReviewQuery {
    tab: String,
    sort: String,
    request: String,
}

pub(super) async fn queue<C, S>(
    State(state): State<Arc<Bastion<C, S>>>,
    axum::Extension(operator): axum::Extension<Operator>,
    Query(query): Query<ReviewQuery>,
) -> Response
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    if !matches!(
        query.tab.as_str(),
        "" | "needs" | "standing" | "history" | "quiet" | "expiring"
    ) || !matches!(query.sort.as_str(), "" | "oldest" | "expiry")
        || (!query.request.is_empty()
            && ssh_core::approval::RequestId::parse(&query.request).is_err())
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let page = state
        .blocking(move |state| review_page(&state, operator, query))
        .await;
    match page {
        Ok(page) => match page.render() {
            Ok(html) => ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
            Err(error) => {
                tracing::error!(%error, "review could not be rendered");
                state_unavailable()
            }
        },
        Err(_) => state_unavailable(),
    }
}

fn review_page<C: Clock + 'static, S: CredentialSource + 'static>(
    state: &Bastion<C, S>,
    operator: Operator,
    query: ReviewQuery,
) -> ApprovalsPage {
    let observation = Observation::read(state);
    let now = state.now();
    let mut asked = state.waiting_for_approval();
    asked.sort_by_key(|item| {
        (
            if query.sort == "expiry" {
                item.decide_by
            } else {
                item.asked_at
            },
            item.id.as_str().to_owned(),
        )
    });
    let selected = if query.request.is_empty() {
        asked
            .first()
            .map(|item| item.id.as_str().to_owned())
            .unwrap_or_default()
    } else {
        query.request.clone()
    };
    let waiting = asked
        .into_iter()
        .map(|asked| {
            let mut row = Pending::from(asked.clone());
            row.age = elapsed_time(now.saturating_sub(asked.asked_at));
            row.deadline = elapsed_time(asked.decide_by.saturating_sub(now));
            row.session_remaining = state
                .session_snapshot(&asked.session)
                .map(|snapshot| {
                    elapsed_time(snapshot.ends_by.min(snapshot.idle_by).saturating_sub(now))
                })
                .unwrap_or_else(|| "unavailable".to_owned());
            row.selected = row.id == selected;
            row
        })
        .collect();
    let all_standing = state.standing_approvals();
    let active_ids = all_standing
        .iter()
        .map(|(agreement, _)| agreement.id.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>();
    let mut standing = all_standing
        .into_iter()
        .map(|(agreement, remaining)| observation.standing(state, agreement, remaining))
        .collect::<Vec<_>>();
    standing.sort_by(|a, b| a.session.cmp(&b.session));
    if query.tab == "quiet" {
        standing.retain(|row| {
            row.work
                .running
                .saturating_add(row.work.waiting)
                .saturating_add(row.work.waiting_agent)
                == 0
        });
    }
    if query.tab == "expiring" {
        standing.retain(|row| row.expiring);
    }
    let outcome_entry = observation.entries.iter().find(
        |entry| matches!(&entry.event, Event::Answered { request, .. } if request == &selected),
    );
    let mut outcome = outcome_entry
        .map(|entry| {
            format!(
                "{} · {} ago. A positive answer still requires agent collection before execution.",
                wire_summary(&serde_json::to_value(&entry.event).unwrap_or_default()),
                elapsed_time(now.saturating_sub(entry.at))
            )
        })
        .unwrap_or_default();
    if outcome.is_empty()
        && !query.request.is_empty()
        && !state
            .waiting_for_approval()
            .iter()
            .any(|asked| asked.id.as_str() == selected)
    {
        outcome =
            "This request is no longer actionable. Its answer or expiry evidence is not retained."
                .to_owned();
    }
    let reviewed_url = outcome_entry
        .map(|entry| session_history_url(entry.session.as_str()))
        .unwrap_or_default();
    let history = observation.entries.iter().filter(|entry| matches!(entry.event, Event::Answered { .. } | Event::SessionApprovalGranted { .. } | Event::SessionApprovalRevoked { .. })).take(OPERATIONS_RESULT_LIMIT).filter_map(|entry| {
            let mut row = audit_shown(current_entry(entry).ok()?);
            row.at = format!("{} ago", elapsed_time(now.saturating_sub(entry.at)));
            if let Event::SessionApprovalGranted { agreement, until, .. } = &entry.event {
                let status = if observation.entries.iter().any(|later| matches!(&later.event, Event::SessionApprovalRevoked { agreement: id, .. } if id == agreement)) { "Withdrawn; recorded operator shown in the withdrawal record" }
                else if observation.entries.iter().any(|later| matches!(&later.event, Event::SessionApprovalGranted { supersedes: Some(id), .. } if id == agreement)) { "Superseded by a newer recorded approval" }
                else if now >= *until { "Expired; inferred from the recorded deadline" }
                else if active_ids.contains(agreement) { "Active session approval" }
                else { "No longer active; current session or transition evidence unavailable" };
                row.summary.push_str(&format!(" · {status}"));
            }
            Some(row)
        }).collect();
    ApprovalsPage {
        operator: operator.0,
        action: format!("{DASHBOARD_PATH}/approvals"),
        waiting,
        standing,
        tab: query.tab,
        sort: query.sort,
        history,
        outcome,
        reviewed_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_requires_absence_of_every_kind_of_active_work() {
        for (running, waiting, waiting_agent, quiet) in [
            (0, 0, 0, true),
            (1, 0, 0, false),
            (0, 1, 0, false),
            (0, 0, 1, false),
            (1, 1, 1, false),
        ] {
            let mut observation = Observation {
                now: 0,
                entries: Vec::new(),
                by_session: HashMap::new(),
                by_account: HashMap::new(),
                counts: HashMap::new(),
            };
            observation.add("session", "host", "role", running, waiting, waiting_agent);
            assert_eq!(observation.matches("session", "quiet"), quiet);
            assert_eq!(observation.matches("session", "running"), running > 0);
            assert_eq!(observation.matches("session", "waiting"), waiting > 0);
            assert_eq!(
                observation.matches("session", "waiting_agent"),
                waiting_agent > 0
            );
        }
    }
}
