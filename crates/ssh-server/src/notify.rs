//! Telling a human that something is waiting.
//!
//! A notifier is a **pointer to the dashboard, not a channel for deciding**.
//! The dashboard holds the approval; a notification says one exists and where
//! to answer it. Keeping that separation is what stops approval degrading into
//! "somebody replied to a message", and it means a notifier that is down delays
//! an approval rather than losing or forging one.
//!
//! So everything here is best effort by construction: sending cannot fail in a
//! way the caller has to handle, cannot block the request that triggered it,
//! and is never retried. A held command stays held whatever happens here.
//!
//! # What a notification does not carry
//!
//! Not the command. A notification travels to whatever channel a deployment
//! configured, which may be a phone's lock screen or a chat room with a wider
//! audience than the dashboard behind single sign-on. Host, role, purpose and
//! how the command was assessed are enough to decide whether to go and look;
//! the argument vector belongs behind the link.

use std::time::Duration;

use serde::Serialize;
use ssh_core::approval::Asked;
use url::Url;

/// What a human is told, and where to go.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Note {
    pub request: String,
    pub principal: String,
    pub host: String,
    pub role: String,
    pub purpose: String,
    /// How the command was classified, which is why it is waiting.
    pub assessment: String,
    /// Where to answer it.
    pub url: String,
    /// A one-line rendering, for channels that show text and nothing else.
    pub text: String,
}

impl Note {
    /// Builds a note about a request, pointing at where it is answered.
    ///
    /// The dashboard address is taken as configured - no path arithmetic,
    /// which would quietly point notes somewhere else the moment a deployment
    /// mounts the page behind a prefix this code did not guess. The one thing
    /// added is the request's identifier as the fragment, which no server or
    /// proxy ever sees: it lands the reader on the card this note is about.
    #[must_use]
    pub fn about(asked: &Asked, dashboard: &Url) -> Self {
        let assessment = scope_name(asked.assessment);
        // The page with this request as the fragment, so the reader lands on
        // the card the note is about rather than at the top of a queue. The
        // identifier is service-minted hex, so it needs no escaping to sit in
        // a URL.
        let url = {
            let mut page = dashboard.clone();
            page.set_fragment(Some(asked.id.as_str()));
            page.to_string()
        };
        // The purpose is the one agent-written sentence in a note, and the
        // note travels to channels that render text however they like: a
        // newline forges a second line, a bidirectional control reorders what
        // the eye reads around the URL. The same rule as the dashboard: only
        // characters with one unambiguous appearance pass through.
        let purpose = crate::dashboard::visible(asked.purpose.as_str());
        // The principal is gateway-verified, but its charset excludes only
        // control characters: a bidirectional or zero-width character in a
        // signed subject would display as a different identity on exactly the
        // line that says who is waiting. Host and role are ASCII by
        // construction and need no such treatment.
        let principal = crate::dashboard::visible(asked.principal.as_str());
        Self {
            request: asked.id.as_str().to_owned(),
            principal: principal.clone(),
            host: asked.host.as_str().to_owned(),
            role: asked.role.as_str().to_owned(),
            purpose: purpose.clone(),
            assessment: assessment.to_owned(),
            text: format!(
                "{} is waiting to run a {} command on {} as {} — {} — {}",
                principal,
                assessment,
                asked.host.as_str(),
                asked.role.as_str(),
                purpose,
                url,
            ),
            url,
        }
    }
}

const fn scope_name(scope: ssh_core::Scope) -> &'static str {
    match scope {
        ssh_core::Scope::Read => "read",
        ssh_core::Scope::Mutate => "mutate",
        ssh_core::Scope::Privileged => "privileged",
    }
}

/// Somewhere to send a note.
///
/// Deliberately returns nothing. A caller cannot handle a failure here in any
/// way that helps: the request is already held, the dashboard already has it,
/// and the answer is to look at the dashboard. Implementations record their own
/// failures.
pub trait Notifier: Send + Sync {
    fn waiting(&self, note: Note);
}

/// What a deployment that configured no notifier gets.
///
/// Not an `Option` at every call site: "nobody is told, the dashboard still
/// knows" is the documented degraded mode, and a type that says so keeps the
/// callers from each deciding what absence means.
pub struct Silence;

impl Notifier for Silence {
    fn waiting(&self, _note: Note) {}
}

/// Posts a note as JSON to a configured endpoint.
///
/// One implementation rather than one per channel. Signal, ntfy and chat
/// services each want a different body, and a shim that maps this JSON to a
/// particular service is a few lines of configuration wherever that service is
/// already reachable — whereas a channel-specific client here is a credential,
/// a retry policy, and an upstream API to track, per channel.
pub struct Webhook {
    endpoint: Url,
    client: reqwest::Client,
}

impl Webhook {
    pub fn new(endpoint: Url) -> Result<Self, NotifierError> {
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(NotifierError::NotHttp);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            // A note is sent once, to the configured endpoint, and nowhere
            // else: following a redirect would both re-send the body and let
            // the receiving side re-aim it at a host nobody configured.
            .redirect(reqwest::redirect::Policy::none())
            // Short, and not retried. A notifier holding a task open is a
            // notifier accumulating tasks.
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| NotifierError::Client)?;
        Ok(Self { endpoint, client })
    }
}

impl Notifier for Webhook {
    fn waiting(&self, note: Note) {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        // Detached, because the agent asking is waiting on the response that
        // told it the command is held. A notifier that made that response slow
        // would be making the thing it exists to help worse.
        tokio::spawn(async move {
            match client.post(endpoint).json(&note).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    tracing::warn!(
                        status = %response.status(),
                        request = note.request,
                        "a notifier refused a note; the request is still on the dashboard"
                    );
                }
                Err(_) => {
                    // The error is not logged: a client error can carry the URL,
                    // and an endpoint may embed a token in its path.
                    tracing::warn!(
                        request = note.request,
                        "a note could not be delivered; the request is still on the dashboard"
                    );
                }
            }
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NotifierError {
    #[error("the notifier endpoint must use http or https")]
    NotHttp,
    #[error("the notifier's http client could not be built")]
    Client,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ssh_core::approval::{Approvals, Standing, Windows};
    use ssh_core::audit::Ledger;
    use ssh_core::catalog::Catalog;
    use ssh_core::clock::TestClock;
    use ssh_core::command::Command;
    use ssh_core::policy::Engine;
    use ssh_core::session::{Lifetime, Purpose, SessionStore};
    use ssh_core::{HostId, PrincipalId, RoleId, Scope};
    use std::sync::Arc;

    /// A waiting request, built the way production builds one: through policy
    /// and the record, so a note can only ever be about a request that could
    /// exist.
    fn asked() -> Asked {
        asked_for(
            "agent-clawde",
            "restart the resolver after the config change",
        )
    }

    fn asked_for(principal: &str, purpose: &str) -> Asked {
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
                PrincipalId::parse(principal).unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("operator").unwrap(),
                Purpose::parse(purpose).unwrap(),
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
                ssh_core::command::CommandIntent::parse("exercise notification").unwrap(),
            )
            .unwrap();
        match approvals.ask(&held).unwrap() {
            Standing::Waiting(ask) => ask.into_asked(),
            other => panic!("expected a waiting request, got {other:?}"),
        }
    }

    /// The note travels somewhere the dashboard's sign-on does not protect, so
    /// it carries what is needed to decide whether to go and look and nothing
    /// that would be a disclosure on its own.
    #[test]
    fn a_note_points_at_the_dashboard_without_carrying_the_command() {
        let note = Note::about(
            &asked(),
            &Url::parse("https://ssh.example/dashboard/approvals").unwrap(),
        );
        // The configured address is the link, carrying only the request's own
        // identifier as the fragment - the card this note is about.
        assert_eq!(
            note.url,
            format!("https://ssh.example/dashboard/approvals#{}", note.request)
        );
        for expected in ["agent-clawde", "dns1", "operator", "mutate"] {
            assert!(note.text.contains(expected), "the note omits {expected}");
        }
        let rendered = serde_json::to_string(&note).unwrap();
        for withheld in ["systemctl", "unbound"] {
            assert!(
                !rendered.contains(withheld),
                "the note carried the command: {rendered}"
            );
        }
    }

    /// The purpose is agent-written and the note travels to channels that
    /// render text however they like, so nothing invisible, reordering, or
    /// line-breaking may survive into either the structured field or the
    /// one-line text - a forged line or a reordered URL would make the note
    /// itself the deception it exists to point past.
    #[test]
    fn an_agent_written_purpose_cannot_forge_or_reorder_a_note() {
        // Built past the upstream filters on purpose: the policy engine
        // happens to refuse these characters in a principal today, and this
        // module must stay safe whether or not that remains true - a note
        // renders whatever it is handed.
        let mut hostile = asked();
        hostile.principal = PrincipalId::parse("agent\u{200b}clawde").unwrap();
        hostile.purpose = Purpose::parse("urgent\napprove \u{202e}won ").unwrap();
        let note = Note::about(
            &hostile,
            &Url::parse("https://ssh.example/dashboard/approvals").unwrap(),
        );
        for field in [&note.purpose, &note.principal, &note.text] {
            assert!(
                !field.contains('\n') && !field.contains('\u{202e}') && !field.contains('\u{200b}'),
                "agent-written text reached a note unescaped: {field}"
            );
        }
        assert!(note.text.contains("urgent\\u{a}approve \\u{202e}won"));
        assert!(note.principal.contains("agent\\u{200b}clawde"));
    }

    /// The whole contract of a notifier: it delivers, and if it cannot, nothing
    /// else is affected. Both halves are exercised against a real endpoint -
    /// one that answers, and one that is not listening at all.
    #[tokio::test]
    async fn a_note_is_delivered_and_a_failure_to_deliver_is_survivable() {
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/notify",
            // Takes the body as it arrives rather than deserializing into
            // `Note`: what a notifier sends is JSON on a wire, and asserting
            // against the bytes is what checks that.
            axum::routing::post(move |body: axum::body::Bytes| {
                let sent = sent.clone();
                async move {
                    let _ = sent.send(serde_json::from_slice(&body).unwrap());
                    "ok"
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let webhook =
            Webhook::new(Url::parse(&format!("http://{address}/notify")).unwrap()).unwrap();
        let note = Note::about(
            &asked(),
            &Url::parse("https://ssh.example/dashboard/approvals").unwrap(),
        );
        webhook.waiting(note.clone());

        let delivered = tokio::time::timeout(Duration::from_secs(10), received.recv())
            .await
            .expect("the note was not delivered in time")
            .expect("the notifier sent nothing");
        assert_eq!(delivered, serde_json::to_value(&note).unwrap());

        // Nothing is listening here. Sending must still return, and the process
        // must still be usable afterwards - a held request does not depend on
        // any of this working.
        let dead = Webhook::new(Url::parse("http://127.0.0.1:1/notify").unwrap()).unwrap();
        dead.waiting(note.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // And silence is a configuration, not a failure.
        Silence.waiting(note);
    }

    /// An endpoint this image cannot reach would fail on every send, and
    /// nothing waits for a send, so it would fail invisibly.
    #[test]
    fn an_endpoint_that_could_never_be_reached_is_refused_at_startup() {
        assert!(matches!(
            Webhook::new(Url::parse("ftp://notify.invalid/hook").unwrap()),
            Err(NotifierError::NotHttp)
        ));
        assert!(Webhook::new(Url::parse("http://ntfy/mcp-ssh").unwrap()).is_ok());
    }
}
