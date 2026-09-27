//! Disposable browser review server and session-history regression fixture.
//! All SSH traffic stays on loopback; the target returns fixed text without a shell.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use russh::keys::{self, ssh_key};
use russh::server::{self, Auth, Msg, Server as _};
use russh::{Channel, ChannelId};
use ssh_core::clock::SystemClock;
use ssh_core::command::CommandIntent;
use ssh_core::connect::{CredentialError, CredentialSource};
use ssh_core::mediate::Executed;
use ssh_core::secret::Secret;
use ssh_core::session::Purpose;
use ssh_core::{HostId, PrincipalId, RoleId};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

#[derive(Clone)]
struct DemoTarget;

impl server::Server for DemoTarget {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for DemoTarget {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"Demo target: check completed\n".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

struct DemoKey(String);
impl CredentialSource for DemoKey {
    async fn fetch(
        &self,
        _: &ssh_core::registry::CredentialRef,
    ) -> Result<Secret<String>, CredentialError> {
        Ok(Secret::new(self.0.clone()))
    }
}

type DemoBastion = Bastion<SystemClock, DemoKey>;

struct DemoHistory(Arc<DemoBastion>);

impl DemoHistory {
    fn entries(&self) -> Vec<audit_history::Entry> {
        self.0
            .ledger()
            .entries()
            .into_iter()
            .rev()
            .map(|entry| {
                let mut wire: audit_history::Entry =
                    serde_json::from_value(serde_json::to_value(entry).unwrap()).unwrap();
                wire.source_nanos = 1_800_000_000_000_000_000_u64.saturating_add(wire.sequence);
                wire
            })
            .collect()
    }
}

impl ReadsAudit for DemoHistory {
    fn page<'a>(
        &'a self,
        query: &'a audit_history::Query,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<audit_history::Page, audit_history::ReadError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let entries = self
                .entries()
                .into_iter()
                .filter(|entry| {
                    (query.host.is_empty() || entry.host == query.host)
                        && (query.session.is_empty() || entry.session == query.session)
                })
                .collect();
            Ok(audit_history::Page {
                entries,
                next_before: None,
                window_start: 1_700_000_000_000_000_000,
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
            Ok(audit_history::TranscriptPage {
                entries: self
                    .entries()
                    .into_iter()
                    .filter(|entry| entry.session == query.session.as_str())
                    .collect(),
                next_before: None,
                window_start: 1_700_000_000_000_000_000,
                window_end: 1_900_000_000_000_000_000,
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
            Ok(self.entries().into_iter().find(|entry| {
                entry.session == query.session.as_str()
                    && wire_string(&entry.event, "run") == Some(query.run.as_str())
            }))
        })
    }
}

async fn populated() -> (Arc<DemoBastion>, SessionId) {
    let host_key = keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519).unwrap();
    let pinned = host_key.public_key().to_openssh().unwrap().to_string();
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        DemoTarget.run_on_socket(config, &listener).await.unwrap();
    });
    let host = serde_json::json!({ "address": address, "host_key": pinned, "roles": {
        "operator": {"user": "demo", "access_class": "privileged", "credential": "demo"}
    }});
    let registry = ssh_core::registry::Registry::from_json(
        &serde_json::json!({"demo-dns": host, "demo-web": host}).to_string(),
    )
    .unwrap();
    let client_key = keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519)
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let bastion = Arc::new(Bastion::new(
        Arc::new(SystemClock::new().unwrap()),
        registry,
        ssh_core::policy::Engine::new(ssh_core::policy::ReviewMode::Privileged),
        DemoKey(client_key),
        crate::settings::bounds(),
    ));
    let principal = PrincipalId::parse("demo-agent").unwrap();
    let session = bastion
        .open_session(
            principal.clone(),
            HostId::parse("demo-dns").unwrap(),
            RoleId::parse("operator").unwrap(),
            Purpose::parse("Investigate intermittent DNS failures").unwrap(),
            AccessClass::Privileged,
        )
        .await
        .unwrap();
    let command = vec!["systemctl".into(), "status".into(), "unbound".into()];
    let intent = CommandIntent::parse("Check whether the DNS service is running").unwrap();
    let held = bastion
        .exec_intended(&principal, &session.id, intent.clone(), command.clone())
        .await
        .unwrap();
    let Executed::AwaitingApproval { asked, .. } = held else {
        panic!("expected approval");
    };
    bastion
        .approve_session(&asked.asked().id, "demo-operator".into(), None)
        .unwrap();
    bastion
        .exec_intended(&principal, &session.id, intent, command)
        .await
        .unwrap();
    for index in 1..=25 {
        let result = bastion
            .exec_intended(
                &principal,
                &session.id,
                CommandIntent::parse("Compare DNS responses after session approval").unwrap(),
                vec!["dig".into(), format!("check-{index}.example.test")],
            )
            .await
            .unwrap();
        assert!(matches!(result, Executed::Ran { .. }));
    }
    for index in 1..=7 {
        bastion
            .open_session(
                principal.clone(),
                HostId::parse("demo-web").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse(&format!("Earlier investigation {index}")).unwrap(),
                AccessClass::Privileged,
            )
            .await
            .unwrap();
    }
    (bastion, session.id)
}

#[tokio::test]
async fn commands_after_session_approval_are_present_in_history() {
    let (bastion, session) = populated().await;
    let history = DemoHistory(Arc::clone(&bastion));
    let entries = history.entries();
    let commands = wire_journeys(&entries, &session, u64::MAX, 0, u64::MAX);
    for index in 1..=25 {
        assert!(
            commands.iter().any(|command| command
                .command
                .contains(&format!("check-{index}.example.test"))),
            "missing command {index}"
        );
    }
    assert_eq!(
        entries
            .iter()
            .filter(|entry| wire_event_name(&entry.event) == "completed")
            .count(),
        26
    );
    let mut cursor = None;
    let mut seen = std::collections::HashSet::new();
    let mut completed = 0;
    loop {
        let (page, next) = bastion.ledger().session_activity(&session, cursor, 7);
        let decisions: Vec<_> = page
            .iter()
            .filter(|entry| matches!(entry.event, ssh_core::audit::Event::Decided { .. }))
            .collect();
        assert!(decisions.len() <= 7);
        for decision in decisions {
            assert!(seen.insert(decision.sequence));
        }
        completed += page
            .iter()
            .filter(|entry| matches!(entry.event, ssh_core::audit::Event::Completed { .. }))
            .count();
        for entry in page {
            assert_eq!(entry.session, session);
        }
        if next.is_none() {
            break;
        }
        assert_ne!(next, cursor);
        cursor = next;
    }
    assert_eq!(
        seen.len(),
        27,
        "initial approval request plus 26 executions"
    );
    assert_eq!(
        completed, 26,
        "pagination must keep each command's completion"
    );
    let app = routes(Arc::clone(&bastion)).layer(axum::Extension(Operator("demo-operator".into())));
    let body = get_html(app.clone(), &format!("/sessions/{}", session.as_str())).await;
    assert!(body.contains("check-25.example.test"));
    assert!(body.contains("Succeeded"));
    assert!(body.contains("Confirm end session"));
    assert!(body.contains("8 / 8"));
    assert!(body.contains("Recent activity held by this service"));
    let (_, next) = bastion
        .ledger()
        .session_activity(&session, None, audit_history::PAGE_SIZE);
    let next = next.unwrap();
    assert!(body.contains(&format!("before={next}")));
    let older = get_html(
        app.clone(),
        &format!(
            "/sessions/{}?source=current&before={next}",
            session.as_str()
        ),
    )
    .await;
    assert!(older.contains("check-1.example.test"));
    assert!(!older.contains("check-25.example.test"));
    let history = get_html(
        app,
        &format!("/sessions/{}?source=history", session.as_str()),
    )
    .await;
    assert!(history.contains("Command history could not be loaded"));
    assert!(
        history.contains("Confirm end session"),
        "unavailable history hid recovery"
    );
}

async fn get_html(app: Router, uri: &str) -> String {
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn operator_can_recover_a_slot_without_log_service_or_agent_credentials() {
    let (bastion, session) = populated().await;
    let app = routes(Arc::clone(&bastion)).layer(axum::Extension(Operator("demo-operator".into())));
    for (site, decision, status) in [
        ("cross-site", "terminate", StatusCode::FORBIDDEN),
        ("same-origin", "approve", StatusCode::BAD_REQUEST),
        ("same-origin", "terminate", StatusCode::SEE_OTHER),
    ] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/sessions/{}/terminate", session.as_str()))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(FETCH_SITE_HEADER, site)
                    .body(axum::body::Body::from(format!("decision={decision}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            bastion.session_snapshot(&session).is_some(),
            status != StatusCode::SEE_OTHER
        );
    }
    let principal = PrincipalId::parse("demo-agent").unwrap();
    assert_eq!(bastion.session_usage(&principal), (7, 8));
    assert!(bastion.standing_approvals().is_empty());
    let replacement = bastion
        .open_session(
            principal.clone(),
            HostId::parse("demo-dns").unwrap(),
            RoleId::parse("operator").unwrap(),
            Purpose::parse("Continue investigation").unwrap(),
            AccessClass::Privileged,
        )
        .await
        .unwrap();
    assert_ne!(replacement.id, session);
    assert_eq!(bastion.session_usage(&principal), (8, 8));
    let entries = bastion.ledger().entries();
    assert!(entries.iter().any(|entry| entry.session == session && entry.principal == principal && matches!(&entry.event, ssh_core::audit::Event::SessionTerminated { operator } if operator.as_str() == "demo-operator")));
    let filtered = get_html(app, "/sessions?host=demo-dns").await;
    assert!(filtered.contains("Continue investigation"));
    assert!(!filtered.contains("Earlier investigation"));
}

#[tokio::test]
#[ignore = "starts a loopback-only UI for manual browser review"]
async fn serve_browser_review() {
    let (bastion, session) = populated().await;
    let reader: Arc<dyn ReadsAudit> = Arc::new(DemoHistory(Arc::clone(&bastion)));
    let app = axum::Router::new()
        .nest("/dashboard", routes_with_audit(bastion, reader))
        .layer(axum::Extension(Operator("demo-operator".into())));
    let listener = TcpListener::bind(("127.0.0.1", 18765)).await.unwrap();
    println!(
        "DEMO_URL=http://127.0.0.1:18765/dashboard/sessions/{session}",
        session = session.as_str()
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::time::sleep(Duration::from_secs(7200)).await;
        })
        .await
        .unwrap();
}
