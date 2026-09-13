//! Dialling a target: proving who they are, and proving who we are.
//!
//! This is where the service's central promise is kept. The agent names a host
//! and a role; the service resolves that to a login account and a credential
//! reference, fetches the material itself, verifies the target against the key
//! an operator pinned, and authenticates. The credential exists only inside
//! this module's call stack — it is never returned, rendered, or attached to an
//! error.
//!
//! Verification is fail-closed in both directions. A pinned key that cannot be
//! read is a refusal rather than a connection made without checking, and a
//! target presenting a different key aborts instead of prompting: there is no
//! human at this end of the connection to answer a prompt, so the only
//! available answers are "matches" and "stop".

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, ssh_key};

use crate::registry::{CredentialRef, PinnedHostKey, Target};
use crate::secret::Secret;
use crate::{HostId, RoleId};

mod rsa;

/// Where the service gets the material it authenticates with.
///
/// A seam rather than a concrete store: the values live in the fleet's secret
/// manager, and this module's job is to use one, not to know where it came
/// from. Implementations hand back a [`Secret`], so a credential cannot be
/// logged on the way through.
pub trait CredentialSource: Send + Sync {
    fn fetch(
        &self,
        reference: &CredentialRef,
    ) -> impl Future<Output = Result<Secret<String>, CredentialError>> + Send;
}

/// How long the service waits at each stage of opening a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Establishing the transport and completing key exchange.
    pub connect: Duration,
    /// Silence on an established connection before it is dropped.
    ///
    /// A backstop rather than the ordinary end of a connection, because the
    /// keepalive below breaks the silence on any target still answering. What
    /// reaches this is a target that has stopped answering entirely.
    pub inactivity: Duration,
    /// How often an otherwise silent connection asks its target whether it is
    /// still there.
    ///
    /// A session may sit far longer between commands than a transport will sit
    /// idle — every wait for a human to approve something is such a pause — and
    /// without this each one costs a handshake, which is the expensive part of
    /// an SSH exchange and the reason a connection is reused at all.
    ///
    /// It is also the better liveness signal of the two. Silence cannot tell a
    /// quiet target from a gone one; an unanswered question can, and a target
    /// that stops answering is dropped on that rather than on waiting out the
    /// inactivity timeout above.
    pub keepalive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            inactivity: Duration::from_secs(300),
            // Comfortably inside the inactivity timeout, so a target that is
            // answering resets it several times over before it could fire.
            keepalive: Duration::from_secs(60),
        }
    }
}

/// Opens connections to targets.
pub struct Connector<S> {
    credentials: S,
    timeouts: Timeouts,
}

/// An authenticated connection to one host as one role.
///
/// Reused across a session's commands rather than re-established for each one:
/// the handshake is the expensive part of an SSH exchange, and paying it on
/// every command would make interactive use noticeably slow.
///
/// Reused for as long as it lasts, which is not as long as the session that
/// holds it — see [`Connection::is_closed`] for why, and for what replaces it.
pub struct Connection {
    handle: client::Handle<PinnedVerifier>,
    host: HostId,
    role: RoleId,
}

impl<S: CredentialSource> Connector<S> {
    pub fn new(credentials: S, timeouts: Timeouts) -> Self {
        Self {
            credentials,
            timeouts,
        }
    }

    /// Opens an authenticated connection to a target.
    ///
    /// The host and role are the target's own, from the lookup that produced
    /// its address and credential. Taking them as separate arguments would let
    /// a caller label a connection with one identity while it holds another's
    /// capability, and the record would report the label.
    pub async fn connect(&self, target: &Target<'_>) -> Result<Connection, ConnectError> {
        // Before anything is dialled: an unreadable pin means there is nothing
        // to verify against, and connecting anyway would be an unauthenticated
        // target with a configuration file that claims otherwise.
        let expected = parse_pinned(target.host_key())?;

        let material = self
            .credentials
            .fetch(target.credential())
            .await
            .map_err(|_| ConnectError::CredentialUnavailable {
                reference: target.credential().as_str().to_owned(),
            })?;
        // The parse error is deliberately dropped. It describes the shape of a
        // private key, and this error is going to be logged.
        let key = PrivateKey::from_openssh(material.expose()).map_err(|_| {
            ConnectError::UnusableCredential {
                reference: target.credential().as_str().to_owned(),
            }
        })?;
        let mut rsa_signer = key
            .key_data()
            .rsa()
            .map(|rsa| rsa::RsaSigner::new(rsa, key.public_key().clone()))
            .transpose()
            .map_err(|_| ConnectError::UnusableCredential {
                reference: target.credential().as_str().to_owned(),
            })?;

        // `keepalive_max` is left at russh's default. It is how many questions
        // may go unanswered before the connection is given up on, and the
        // default of a few is the right shape: one lost packet is not a dead
        // target, and a target that has answered none of them is not coming
        // back.
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(self.timeouts.inactivity),
            keepalive_interval: Some(self.timeouts.keepalive),
            ..client::Config::default()
        });
        let mismatch = Arc::new(AtomicBool::new(false));
        let verifier = PinnedVerifier {
            expected,
            mismatch: Arc::clone(&mismatch),
        };

        let dialled = tokio::time::timeout(
            self.timeouts.connect,
            client::connect(config, target.address(), verifier),
        )
        .await
        .map_err(|_| ConnectError::Unreachable {
            address: target.address().to_owned(),
            detail: "timed out".to_owned(),
        })?;

        let mut handle = match dialled {
            Ok(handle) => handle,
            // A mismatch surfaces from russh as an ordinary rejected
            // connection, so the verifier records it and it is reported as what
            // it is: the target is not the machine the operator pinned.
            Err(_) if mismatch.load(Ordering::SeqCst) => {
                return Err(ConnectError::HostKeyMismatch {
                    host: target.host().to_string(),
                });
            }
            Err(source) => {
                return Err(ConnectError::Unreachable {
                    address: target.address().to_owned(),
                    detail: source.to_string(),
                });
            }
        };

        let rsa_hash = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        let authenticated = if let Some(signer) = rsa_signer.as_mut() {
            handle
                .authenticate_publickey_with(
                    target.user(),
                    key.public_key().clone(),
                    rsa_hash,
                    signer,
                )
                .await
                .map_err(|_| ())
        } else {
            handle
                .authenticate_publickey(
                    target.user(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash),
                )
                .await
                .map_err(|_| ())
        }
        .map_err(|_| ConnectError::AuthenticationFailed {
            host: target.host().to_string(),
            user: target.user().to_owned(),
        })?;
        if !authenticated.success() {
            return Err(ConnectError::AuthenticationRejected {
                host: target.host().to_string(),
                user: target.user().to_owned(),
            });
        }

        Ok(Connection {
            handle,
            host: target.host().clone(),
            role: target.role().clone(),
        })
    }
}

impl Connection {
    #[must_use]
    pub fn host(&self) -> &HostId {
        &self.host
    }

    #[must_use]
    pub fn role(&self) -> &RoleId {
        &self.role
    }

    /// The live SSH connection, for the execution path to run commands on.
    ///
    /// Crate-private on purpose. Handing this out publicly would put a raw
    /// `exec` next to the one that requires a receipt, and a caller reaching
    /// for it would run a command with no decision and no record - which is
    /// the single thing this service exists to prevent. Outside this crate the
    /// only way to run anything is `Runs::run`, which needs proof the record
    /// was written.
    #[must_use]
    pub(crate) fn handle(&self) -> &client::Handle<PinnedVerifier> {
        &self.handle
    }

    /// Whether the transport underneath this connection has gone.
    ///
    /// A local question about this end's session task rather than a probe of
    /// the target: nothing is sent, so asking is free and cannot itself fail.
    ///
    /// It needs asking because a connection can end without the session
    /// holding it ending. A target that restarts takes its connection with it,
    /// a network can drop one, and a target that stops answering is given up
    /// on. None of those is the session ending, so the service asks this
    /// before running anything and dials again rather than treating a lost
    /// transport as a lost grant.
    ///
    /// Keepalive requests preserve idle connections across session pauses.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Ends the connection.
    pub async fn close(&self) -> Result<(), ConnectError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(|source| ConnectError::Unreachable {
                address: self.host.to_string(),
                detail: source.to_string(),
            })
    }
}

/// Nothing about a connection may render the credential, so `Debug` is written
/// rather than derived — a derived one on a future field would print it.
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("host", &self.host)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Compares the target's key against the operator's pin.
pub struct PinnedVerifier {
    expected: PublicKey,
    /// Set when the target presented something else, so the caller can report a
    /// mismatch rather than a generic refused connection.
    mismatch: Arc<AtomicBool>,
}

impl client::Handler for PinnedVerifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        presented: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Comparison is on parsed key material, not on the configured text:
        // the same key can be written with a different comment or spacing, and
        // a string comparison would reject a correct target for a cosmetic
        // difference while teaching operators to work around the check.
        let matches = presented.key_data() == self.expected.key_data();
        if !matches {
            self.mismatch.store(true, Ordering::SeqCst);
        }
        Ok(matches)
    }
}

/// Whether credential material is a private key this service could use.
///
/// Exposed so a deployment can be told at startup that a credential will never
/// authenticate anything, rather than when somebody first reaches that host.
/// The answer is yes or no and nothing else: why a key does not parse is a
/// description of the key, and this is asked in order to be logged about.
#[must_use]
pub fn usable_credential(material: &Secret<String>) -> bool {
    // Encrypted keys parse. They are still unusable here: this service has no
    // passphrase to give and no way to ask for one, so such a key would pass a
    // check that only asked whether it parsed and then fail on the first
    // connection — which is the discovery this check exists to move earlier.
    PrivateKey::from_openssh(material.expose()).is_ok_and(|key| {
        !key.is_encrypted()
            && key
                .key_data()
                .rsa()
                .is_none_or(|rsa| rsa::RsaSigner::new(rsa, key.public_key().clone()).is_ok())
    })
}

fn parse_pinned(pinned: &PinnedHostKey) -> Result<PublicKey, ConnectError> {
    PublicKey::from_openssh(pinned.as_str()).map_err(|_| ConnectError::UnusableHostKey)
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("the credential store is unavailable")]
    Unavailable,
    #[error("no credential is stored under that reference")]
    NotFound,
}

/// Failures opening a connection.
///
/// Every variant names references, hosts, and accounts, and none of them
/// carries credential material or the reason a key failed to parse. Those
/// details describe the secret, and these errors are logged.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConnectError {
    #[error("the pinned host key cannot be read, so the target cannot be verified")]
    UnusableHostKey,
    #[error("the credential {reference} could not be fetched")]
    CredentialUnavailable { reference: String },
    #[error("the credential {reference} is not a usable private key")]
    UnusableCredential { reference: String },
    #[error("{host} presented a host key that does not match the pinned one")]
    HostKeyMismatch { host: String },
    #[error("could not reach {address}: {detail}")]
    Unreachable { address: String, detail: String },
    #[error("authenticating to {host} as {user} failed")]
    AuthenticationFailed { host: String, user: String },
    #[error("{host} refused the credential offered for {user}")]
    AuthenticationRejected { host: String, user: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;

    use russh::server::{self, Auth, Msg, Server as _};
    use russh::{Channel, keys};
    use tokio::net::TcpListener;

    use super::*;
    use crate::registry::Registry;
    use std::sync::Mutex;

    /// A key with a passphrase on it parses perfectly well and authenticates
    /// nothing here: this service has no passphrase to give and nowhere to ask
    /// for one. Checking only that a key parses would pass it at startup and
    /// leave the failure for whoever first tried to reach that host, which is
    /// the discovery the check exists to move earlier.
    #[test]
    fn a_key_with_a_passphrase_is_not_usable_here() {
        let key = keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519).unwrap();
        let plain = Secret::new(
            key.to_openssh(keys::ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        );
        assert!(usable_credential(&plain), "a usable key was refused");

        let locked = key
            .encrypt(&mut rand::rng(), "a passphrase this service does not have")
            .unwrap();
        let locked = Secret::new(
            locked
                .to_openssh(keys::ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        );
        assert!(
            !usable_credential(&locked),
            "a key this service cannot decrypt was accepted"
        );
    }

    /// Every way opening a connection can fail, in sorted order.
    ///
    /// `failure_name` is an exhaustive match, so a new variant stops this module
    /// compiling until it is named, and the leak regression then fails until it
    /// is either driven or listed below as undrivable. That is the ratchet: a
    /// failure path cannot be added without something accounting for it.
    const EVERY_FAILURE: [&str; 7] = [
        "authentication failed",
        "authentication rejected",
        "credential unavailable",
        "host key mismatch",
        "unreachable",
        "unusable credential",
        "unusable host key",
    ];

    /// The failures a test cannot provoke against a real server, and why.
    ///
    /// "authentication failed" is the transport dying *during* authentication,
    /// as opposed to a credential being refused, which is "authentication
    /// rejected". A server handler that errors is still an answer and produces
    /// the rejection; provoking the other needs the socket to die inside the
    /// exchange, which is a race rather than a test. Its rendered form is
    /// checked below from a constructed value instead.
    const UNDRIVABLE: [&str; 1] = ["authentication failed"];

    fn failure_name(err: &ConnectError) -> &'static str {
        match err {
            ConnectError::AuthenticationFailed { .. } => "authentication failed",
            ConnectError::AuthenticationRejected { .. } => "authentication rejected",
            ConnectError::CredentialUnavailable { .. } => "credential unavailable",
            ConnectError::HostKeyMismatch { .. } => "host key mismatch",
            ConnectError::Unreachable { .. } => "unreachable",
            ConnectError::UnusableCredential { .. } => "unusable credential",
            ConnectError::UnusableHostKey => "unusable host key",
        }
    }

    /// Marker inside the test key material. Any output containing it has
    /// rendered a private key.
    const KEY_MARKER: &str = "PRIVATE KEY";

    /// A credential store that hands back whatever it was seeded with.
    struct FakeStore {
        entries: HashMap<String, String>,
        available: bool,
    }

    impl FakeStore {
        fn with(reference: &str, material: &str) -> Self {
            let mut entries = HashMap::new();
            entries.insert(reference.to_owned(), material.to_owned());
            Self {
                entries,
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                entries: HashMap::new(),
                available: false,
            }
        }
    }

    impl CredentialSource for FakeStore {
        async fn fetch(
            &self,
            reference: &CredentialRef,
        ) -> Result<Secret<String>, CredentialError> {
            if !self.available {
                return Err(CredentialError::Unavailable);
            }
            self.entries
                .get(reference.as_str())
                .map(|material| Secret::new(material.clone()))
                .ok_or(CredentialError::NotFound)
        }
    }

    /// Records who authenticated, so a test can assert the account and the key
    /// rather than only that *something* was accepted. A server that answers
    /// from a boolean would pass while the connector authenticated as the wrong
    /// account with a different key, which is most of what this module does.
    /// How the test server answers an authentication attempt.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answer {
        Accept,
        /// A well-formed refusal, which is a protocol answer.
        Reject,
        /// A handler failure, which breaks the transport rather than answering.
        /// This is the difference between a credential being refused and
        /// authentication not completing at all, and they are separate errors.
        Fail,
    }

    #[derive(Clone)]
    struct TestServer {
        answer: Answer,
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl server::Server for TestServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((user.to_owned(), key.to_openssh().unwrap_or_default()));
            }
            match self.answer {
                Answer::Accept => Ok(Auth::Accept),
                Answer::Reject => Ok(Auth::reject()),
                Answer::Fail => Err(russh::Error::Disconnect),
            }
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
    }

    struct Running {
        address: String,
        host_key: PinnedHostKey,
        /// Every (account, public key) the server was asked to authenticate.
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    /// Starts an SSH server on loopback with a freshly generated host key.
    ///
    /// A real server rather than a mock: host-key verification and public-key
    /// authentication are protocol behaviour, and a fake that agreed with our
    /// own idea of the protocol would pass while a real target refused.
    async fn start_server(answer: Answer) -> Running {
        start_server_with_rsa_sha1_only(answer, false).await
    }

    async fn start_server_with_rsa_sha1_only(answer: Answer, legacy_rsa: bool) -> Running {
        let host_key =
            keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519).unwrap();
        let pinned =
            PinnedHostKey::parse(&host_key.public_key().to_openssh().unwrap().to_string()).unwrap();

        let mut config = server::Config {
            inactivity_timeout: Some(Duration::from_secs(30)),
            auth_rejection_time: Duration::from_millis(1),
            keys: vec![host_key],
            ..server::Config::default()
        };
        if legacy_rsa {
            config.preferred.key = vec![
                keys::Algorithm::Ed25519,
                keys::Algorithm::Rsa { hash: None },
            ]
            .into();
        }
        let config = Arc::new(config);

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut server = TestServer {
            answer,
            seen: Arc::clone(&seen),
        };
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });

        Running {
            address,
            host_key: pinned,
            seen,
        }
    }

    fn client_key() -> String {
        keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn authenticates_with_an_rsa_credential() {
        let pair = ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048).unwrap();
        let private = PrivateKey::from(pair);
        let key = private
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(usable_credential(&Secret::new(key.clone())));
        let server = start_server(Answer::Accept).await;
        let connector = connector(FakeStore::with(REFERENCE, &key));
        let registry = registry_for(&server.address, &server.host_key);
        let target = registry.resolve(&host(), &role()).unwrap();
        let connection = connector.connect(&target).await.unwrap();
        assert_eq!(
            *server.seen.lock().unwrap(),
            vec![(
                "mcp-ro".to_owned(),
                private.public_key().to_openssh().unwrap()
            )]
        );
        connection.close().await.unwrap();
    }

    #[tokio::test]
    async fn an_rsa_credential_cannot_fall_back_to_sha1_signing() {
        let pair = ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048).unwrap();
        let key = PrivateKey::from(pair)
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let server = start_server_with_rsa_sha1_only(Answer::Accept, true).await;
        let connector = connector(FakeStore::with(REFERENCE, &key));
        let registry = registry_for(&server.address, &server.host_key);
        let target = registry.resolve(&host(), &role()).unwrap();
        assert!(matches!(
            connector.connect(&target).await,
            Err(ConnectError::AuthenticationFailed { .. })
        ));
        assert!(server.seen.lock().unwrap().is_empty());
    }

    const REFERENCE: &str = "mcp-ssh/test/readonly";

    fn host() -> HostId {
        HostId::parse("testhost").unwrap()
    }

    fn role() -> RoleId {
        RoleId::parse("readonly").unwrap()
    }

    /// A registry holding one host and one role, as a deployment's file would.
    ///
    /// The tests resolve through it rather than assembling a `Target` by hand,
    /// because a `Target` can only come from a lookup - that is what stops a
    /// connection reporting one identity while holding another's capability -
    /// and a test that could build one would be exercising a path production
    /// does not have.
    fn registry_for(address: &str, host_key: &PinnedHostKey) -> Registry {
        Registry::from_json(&format!(
            r#"{{"testhost": {{"address": "{address}", "host_key": "{key}",
                 "roles": {{"readonly": {{"user": "mcp-ro", "access_class": "read_only", "credential": "{REFERENCE}"}}}}}}}}"#,
            address = address,
            key = host_key.as_str().replace('\\', "\\\\").replace('"', "\\\""),
        ))
        .expect("the test registry is well formed")
    }

    fn connector(store: FakeStore) -> Connector<FakeStore> {
        Connector::new(
            store,
            Timeouts {
                connect: Duration::from_secs(10),
                inactivity: Duration::from_secs(30),
                keepalive: Duration::from_secs(10),
            },
        )
    }

    /// The whole promise, end to end: the service authenticates to a real
    /// target as a named account, using material the agent never saw.
    #[tokio::test]
    async fn authenticates_to_a_target_as_the_role_s_account() {
        let server = start_server(Answer::Accept).await;
        let key = client_key();
        let connector = connector(FakeStore::with(REFERENCE, &key));
        let registry = registry_for(&server.address, &server.host_key);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");

        let connection = connector
            .connect(&target)
            .await
            .expect("connecting to the test server");
        assert_eq!(connection.host(), &host());
        assert_eq!(connection.role(), &role());

        // The account the role configured, and the key the store held for it -
        // as the target saw them. Asserting only that a connection opened would
        // pass while authenticating as someone else with something else.
        let expected = PrivateKey::from_openssh(&key)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let seen = server.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![("mcp-ro".to_owned(), expected)]);

        connection.close().await.unwrap();
    }

    /// A session pauses for longer than a transport tolerates silence — waiting
    /// for a human to approve something is exactly such a pause — and the
    /// connection under it has to still be there afterwards.
    ///
    /// Opening a channel is the assertion rather than `is_closed`, because that
    /// is the operation a returning caller actually performs, and the one that
    /// reports a transport that went away while nothing was being sent on it.
    #[tokio::test]
    async fn a_connection_left_idle_is_still_usable() {
        let server = start_server(Answer::Accept).await;
        let key = client_key();
        // Silence would end this connection well inside the pause below. What
        // decides whether it does is whether anything speaks up in the
        // meantime, which is the whole of what this test is about.
        let connector = Connector::new(
            FakeStore::with(REFERENCE, &key),
            Timeouts {
                connect: Duration::from_secs(10),
                inactivity: Duration::from_secs(2),
                keepalive: Duration::from_millis(300),
            },
        );
        let registry = registry_for(&server.address, &server.host_key);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");

        let connection = connector
            .connect(&target)
            .await
            .expect("connecting to the test server");

        tokio::time::sleep(Duration::from_secs(5)).await;

        assert!(
            connection.handle().channel_open_session().await.is_ok(),
            "a connection nobody spoke on was gone when it was next needed"
        );
        connection.close().await.unwrap();
    }

    /// A target presenting a key other than the pinned one must abort. There is
    /// no human at this end to answer a prompt, so the only alternative to
    /// stopping is proceeding unverified.
    #[tokio::test]
    async fn a_target_whose_key_does_not_match_the_pin_is_refused() {
        let server = start_server(Answer::Accept).await;
        let other = start_server(Answer::Accept).await;
        let key = client_key();
        let connector = connector(FakeStore::with(REFERENCE, &key));
        // The pin belongs to a different machine than the one being dialled.
        let registry = registry_for(&server.address, &other.host_key);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");

        let err = connector.connect(&target).await.unwrap_err();
        assert_eq!(
            err,
            ConnectError::HostKeyMismatch {
                host: "testhost".to_owned()
            }
        );
    }

    /// A pin that cannot be read leaves nothing to verify against, so it
    /// refuses rather than connecting to an unverified target.
    #[tokio::test]
    async fn an_unreadable_pin_refuses_before_dialling() {
        let server = start_server(Answer::Accept).await;
        let key = client_key();
        let connector = connector(FakeStore::with(REFERENCE, &key));
        let unreadable = PinnedHostKey::parse("SHA256:not-an-openssh-public-key").unwrap();
        let registry = registry_for(&server.address, &unreadable);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");

        assert_eq!(
            connector.connect(&target).await.unwrap_err(),
            ConnectError::UnusableHostKey
        );
    }

    #[tokio::test]
    async fn a_target_that_refuses_the_credential_reports_that() {
        let server = start_server(Answer::Reject).await;
        let key = client_key();
        let connector = connector(FakeStore::with(REFERENCE, &key));
        let registry = registry_for(&server.address, &server.host_key);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");

        assert_eq!(
            connector.connect(&target).await.unwrap_err(),
            ConnectError::AuthenticationRejected {
                host: "testhost".to_owned(),
                user: "mcp-ro".to_owned()
            }
        );
    }

    /// This is the criterion issue #3 asks for, and it is the test rather than
    /// the prose because "credentials never leak" cannot be confirmed by
    /// reading. Every failure path and every rendered value is checked for the
    /// key material that went in.
    #[tokio::test]
    async fn no_failure_path_renders_credential_material() {
        let server = start_server(Answer::Reject).await;
        let key = client_key();
        assert!(key.contains(KEY_MARKER), "the test key lost its marker");

        let mut rendered = Vec::new();

        // Refused credential, unreadable pin, mismatched pin, unreachable
        // address, and a store that cannot answer: every way opening a
        // connection fails while a credential is in hand.
        let other = start_server(Answer::Accept).await;
        let breaks = start_server(Answer::Fail).await;
        let unreadable = PinnedHostKey::parse("not-a-key").unwrap();
        // The unusable-key path is handed its own credential, so the search
        // below has to look for that one too: searching only for the valid key
        // would leave this path free to render what it was given.
        const MALFORMED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key-but-secret-shaped\n-----END OPENSSH PRIVATE KEY-----";
        let cases: Vec<(&PinnedHostKey, &str, FakeStore)> = vec![
            (
                &server.host_key,
                server.address.as_str(),
                FakeStore::with(REFERENCE, &key),
            ),
            (
                &unreadable,
                server.address.as_str(),
                FakeStore::with(REFERENCE, &key),
            ),
            (
                &other.host_key,
                server.address.as_str(),
                FakeStore::with(REFERENCE, &key),
            ),
            (
                &server.host_key,
                "127.0.0.1:1",
                FakeStore::with(REFERENCE, &key),
            ),
            (
                &server.host_key,
                server.address.as_str(),
                FakeStore::unavailable(),
            ),
            (
                &server.host_key,
                server.address.as_str(),
                FakeStore::with(REFERENCE, MALFORMED),
            ),
            (
                &breaks.host_key,
                breaks.address.as_str(),
                FakeStore::with(REFERENCE, &key),
            ),
        ];

        let mut driven: Vec<&'static str> = Vec::new();
        for (host_key, address, store) in cases {
            let registry = registry_for(address, host_key);
            let target = registry
                .resolve(&host(), &role())
                .expect("the test registry resolves");
            let err = connector(store)
                .connect(&target)
                .await
                .expect_err("every case here fails");
            driven.push(failure_name(&err));
            rendered.push(format!("{err}"));
            rendered.push(format!("{err:?}"));
        }

        // Every way opening a connection can fail, not merely several of them:
        // one nobody drove could render a credential and this would stay green.
        // Every way opening a connection can fail is accounted for: driven
        // against a real server, or named above as undrivable and rendered from
        // a constructed value. One nobody accounted for could render a
        // credential and this would stay green.
        driven.sort_unstable();
        driven.dedup();

        let constructed = ConnectError::AuthenticationFailed {
            host: "testhost".to_owned(),
            user: "mcp-ro".to_owned(),
        };
        assert_eq!([failure_name(&constructed)], UNDRIVABLE);
        rendered.push(format!("{constructed}"));
        rendered.push(format!("{constructed:?}"));

        let mut accounted: Vec<&str> = driven.clone();
        accounted.extend(UNDRIVABLE);
        accounted.sort_unstable();
        accounted.dedup();
        assert_eq!(
            accounted, EVERY_FAILURE,
            "a way of failing to open a connection is neither driven nor named undrivable"
        );
        for name in &driven {
            assert!(
                !UNDRIVABLE.contains(name),
                "{name} is driven after all, so it should not be listed as undrivable"
            );
        }

        // And the success path's own rendered forms.
        let ok = start_server(Answer::Accept).await;
        let registry = registry_for(&ok.address, &ok.host_key);
        let target = registry
            .resolve(&host(), &role())
            .expect("the test registry resolves");
        let connection = connector(FakeStore::with(REFERENCE, &key))
            .connect(&target)
            .await
            .unwrap();
        rendered.push(format!("{connection:?}"));
        rendered.push(format!("{:?}", Secret::new(key.clone())));

        for output in &rendered {
            assert!(
                !output.contains(KEY_MARKER),
                "credential material appeared in: {output}"
            );
            // Every credential this test put in, not just the valid one: each
            // failure path is handed the material it was given, and a path that
            // rendered a different credential verbatim would otherwise pass.
            for material in [key.as_str(), MALFORMED] {
                for line in material.lines().filter(|line| line.len() > 20) {
                    assert!(
                        !output.contains(line),
                        "a line of a private key appeared in: {output}"
                    );
                }
            }
        }
        assert!(
            rendered.iter().any(|output| output.contains(REFERENCE)),
            "the credential's name is not secret and should still be reportable"
        );
    }
}
