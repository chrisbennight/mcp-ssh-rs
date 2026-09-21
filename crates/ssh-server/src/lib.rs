//! HTTP surface and process wiring.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;

pub mod audit_history;
pub mod credentials;
pub mod dashboard;
pub mod evaluation;
pub mod ingress;
pub mod mcp;
pub mod notify;
pub mod settings;
pub mod shipped;
pub mod tools;
pub mod transfer;
use axum::routing::get;
use rmcp::transport::StreamableHttpService;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use ssh_core::catalog::Catalog;
use ssh_core::clock::SystemClock;
use ssh_core::config::Config;
use ssh_core::mediate::Bastion;
use ssh_core::policy::Engine;
use ssh_core::registry::Registry;

use crate::credentials::EnvCredentials;
use crate::dashboard::{DASHBOARD_PATH, Proxy};
use crate::ingress::{IdentityVerifier, Ingress};
use crate::mcp::SshMcp;
use crate::settings::{Authentication, EvaluatorSettings, Settings};

pub struct OptionalSurfaces {
    pub evaluator: Option<EvaluatorSettings>,
    pub audit_reader: Arc<dyn crate::audit_history::ReadsAudit>,
}

/// Path clients or the gateway send MCP requests to.
pub const MCP_PATH: &str = "/mcp";

/// Path the container healthcheck and any external probe use.
pub const HEALTH_PATH: &str = "/healthz";

/// The address a self-probe should connect to for a given listen address.
///
/// A wildcard bind is not a destination, so probing it directly is unreliable;
/// the loopback of the same family is. Any other bind is probed as configured,
/// because assuming IPv4 loopback would leave a service bound to `[::1]` alive
/// but reported unhealthy by its own container healthcheck.
#[must_use]
pub fn probe_address(listen: SocketAddr) -> SocketAddr {
    if listen.ip().is_unspecified() {
        let loopback = match listen.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        SocketAddr::new(loopback, listen.port())
    } else {
        listen
    }
}

/// The Host authorities the transport will admit: the loopback set the rmcp
/// default ships, plus whatever the deployment named. Kept together so the
/// default is never dropped when a name is added — a deployment that adds a
/// gateway authority does not thereby stop answering a loopback probe.
fn allowed_hosts(trusted_hosts: &[String]) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];
    hosts.extend(trusted_hosts.iter().cloned());
    hosts
}

/// Builds the application router.
///
/// Separate from serving so tests exercise the same routes the binary does.
///
/// The healthcheck sits outside the ingress layer and the MCP surface sits
/// behind it. That split is deliberate: the probe is a second copy of this
/// binary running in the same container with no gateway credential to present,
/// and putting liveness behind authentication would report every credential
/// mistake as a dead container. It answers `ok` and nothing else, so what it
/// exposes without a credential is that a process is listening.
pub fn router<C, S>(
    bastion: Arc<Bastion<C, S>>,
    ingress: Ingress,
    proxy: Proxy,
    notifier: Arc<dyn crate::notify::Notifier>,
    dashboard: Option<url::Url>,
    optional: OptionalSurfaces,
    trusted_hosts: &[String],
) -> Router
where
    C: ssh_core::clock::Clock + 'static,
    S: ssh_core::connect::CredentialSource + 'static,
{
    let handler = SshMcp::new(Arc::clone(&bastion), notifier, dashboard);
    let mcp = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            // Sessions here are the service's own, held in the bastion and
            // bound to a principal, a host and a purpose. A second notion of
            // session in the transport would be a second lifetime to reason
            // about, expiring on its own schedule, attached to nothing that
            // appears in the record.
            .with_stateful_mode(false)
            .with_json_response(true)
            // The transport still refuses a Host it was not told to expect —
            // the rebinding guard stays on. The default allows only loopback,
            // and the gateway reaches this surface by a network name, so the
            // authorities the deployment names are added to loopback rather
            // than replacing it. Naming them in the environment keeps the guard
            // in step with how the gateway is told to address the service,
            // rather than compiling that name into the image.
            .with_allowed_hosts(allowed_hosts(trusted_hosts)),
    );

    let evaluator_routes = optional.evaluator.map_or_else(Router::new, |settings| {
        crate::evaluation::routes(Arc::clone(&bastion), settings)
    });

    Router::new()
        .route(HEALTH_PATH, get(health))
        .merge(Router::new().nest_service(MCP_PATH, mcp).layer(
            axum::middleware::from_fn_with_state(ingress, crate::ingress::require_mcp),
        ))
        // Separate operator authentication keeps MCP access from conferring
        // permission to approve a held command.
        .merge(
            Router::new()
                // Somebody who typed the deployment's name and nothing else —
                // which is what an identity provider hands back after a sign-in
                // — is asking for the review queue. Sending them there from
                // inside this layer rather than beside the probe keeps the site
                // root from telling an unadmitted caller which surfaces exist.
                .route("/", get(crate::dashboard::home))
                .route(DASHBOARD_PATH, get(crate::dashboard::home))
                .route("/dashboard/", get(crate::dashboard::home))
                .nest(
                    DASHBOARD_PATH,
                    crate::dashboard::routes_with_audit(bastion, optional.audit_reader),
                )
                .layer(axum::middleware::from_fn_with_state(
                    proxy,
                    crate::dashboard::require_operator,
                )),
        )
        // Evaluators append evidence through their own credential boundary.
        // This surface is outside both the agent and human-review layers, and
        // is absent unless a deployment explicitly configures it.
        .merge(evaluator_routes)
}

/// Liveness only.
///
/// It reports nothing about targets, credentials, or policy: a health endpoint
/// is reachable by anything that can open a socket, so naming hosts or
/// reporting credential state would hand out an inventory of the fleet.
async fn health() -> &'static str {
    "ok"
}

/// Serves until the process is asked to stop.
///
/// Local configuration and SSH credentials are validated before binding.
/// In gateway mode, unavailable signing keys cause requests to be refused;
/// the service can start while the gateway is restarting.
pub async fn serve(config: &Config) -> anyhow::Result<()> {
    let settings = Settings::from_env().context("reading settings")?;
    let registry = std::fs::read_to_string(&settings.registry)
        .with_context(|| format!("reading the registry at {}", settings.registry.display()))?;
    let registry = Registry::from_json(&registry).context("parsing the registry")?;
    let hosts = registry.hosts().count();

    // Every credential the registry names, resolved before anything is served.
    // A reference with nothing behind it, or two that read one credential, is a
    // deployment mistake that would otherwise wait for somebody to reach that
    // host — and the second means authenticating with a key issued for a
    // different one, which is not something to find out that way.
    let credentials = EnvCredentials::from_env();
    let unusable = credentials.unusable(&registry);
    if !unusable.is_empty() {
        anyhow::bail!(
            "this deployment's credentials cannot be used: {}",
            unusable.join("; ")
        );
    }

    // A deployment's policy replaces the shipped text, never the ceiling
    // rules: the engine prepends those to whatever is loaded here.
    let engine = match &settings.policy {
        Some(path) => {
            let source = std::fs::read_to_string(path)
                .with_context(|| format!("reading the policy at {}", path.display()))?;
            Engine::from_source(&source).context("loading the deployment's policy")?
        }
        None => Engine::builtin().context("loading the policy")?,
    };

    let bastion = Arc::new(Bastion::recording_to(
        Arc::new(SystemClock::new().context("reading the boot clock")?),
        registry,
        Catalog::builtin().context("loading the command catalog")?,
        engine,
        credentials,
        settings::bounds(),
        // A complete entry must cross the selected boundary — flushed stdout —
        // before it joins the ledger and before an authorized command can run.
        // The ledger remains process-local; the fleet log pipeline owns
        // collection, storage, and retention beyond this point.
        Some(Arc::new(
            crate::shipped::ToAuditOutput::to_output()
                .context("starting the audit output writer")?,
        )),
    ));
    let (ingress, proxy) = match settings.identity {
        Authentication::Gateway(identity) => {
            let verifier =
                Arc::new(IdentityVerifier::new(identity).context("configuring identity")?);
            verifier.warm().await;
            (
                Ingress::new(Arc::new(settings.bearers), verifier),
                Proxy::new(Arc::new(settings.proxy_bearers)),
            )
        }
        Authentication::Standalone {
            principal,
            operator,
        } => (
            Ingress::standalone(Arc::new(settings.bearers), principal),
            Proxy::standalone(Arc::new(settings.proxy_bearers), operator),
        ),
    };
    // Silence is a configuration, not a failure: the dashboard still holds
    // every waiting request, and a deployment that has not chosen a channel is
    // told to look there.
    let notifier: Arc<dyn crate::notify::Notifier> = match settings.notify {
        Some(endpoint) => {
            Arc::new(crate::notify::Webhook::new(endpoint).context("configuring the notifier")?)
        }
        None => Arc::new(crate::notify::Silence),
    };
    let dashboard = settings.dashboard;
    let evaluator = settings.evaluator;
    let audit_reader: Arc<dyn crate::audit_history::ReadsAudit> = match settings.audit_query {
        Some(endpoint) => Arc::new(
            crate::audit_history::Loki::new(endpoint)
                .context("configuring the durable audit reader")?,
        ),
        None => Arc::new(crate::audit_history::Unavailable),
    };
    let trusted_hosts = settings.trusted_hosts;

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    // Hosts are counted, not named: this line goes to the fleet's log store,
    // and an inventory of what the service can reach does not need to be there.
    tracing::info!(listen = %config.listen, hosts, "serving");
    // The server is asked to drain by a message rather than by holding the
    // signal itself, so the clock on draining starts when the signal arrives.
    // Bounding the whole of serving instead would stop a healthy service after
    // the bound; bounding nothing hands the length of the stop to whoever holds
    // a stream open, and what runs out meanwhile is the container's patience.
    // Being killed there is the outcome worth avoiding: it takes the readers
    // with it, and they are what write down what commands did.
    let (drain, asked_to_drain) = tokio::sync::oneshot::channel::<()>();
    let mut serving = tokio::spawn({
        let bastion = Arc::clone(&bastion);
        async move {
            axum::serve(
                listener,
                router(
                    bastion,
                    ingress,
                    proxy,
                    notifier,
                    dashboard,
                    OptionalSurfaces {
                        evaluator,
                        audit_reader,
                    },
                    &trusted_hosts,
                ),
            )
            .with_graceful_shutdown(async move {
                let _ = asked_to_drain.await;
            })
            .await
        }
    });

    // Reclaiming is what lets go of a lapsed session's connection, and the
    // service is its own scheduler for that: a deployment that had to arrange
    // it separately would hold connections open for as long as it forgot to.
    // Idle is exactly when nothing else triggers it and exactly when the
    // sessions holding connections are lapsing.
    let housekeeping = tokio::spawn({
        let bastion = Arc::clone(&bastion);
        async move {
            loop {
                tokio::time::sleep(RECLAIM_EVERY).await;
                bastion.reclaim().await;
            }
        }
    });

    // Either the service is asked to stop, or the server stops on its own —
    // and the second must not go unnoticed. A process still alive with no
    // listener answers nothing and tells its supervisor nothing, which is the
    // one failure a healthcheck cannot report because the healthcheck is what
    // stopped answering.
    tokio::select! {
        () = stopped() => {}
        joined = &mut serving => {
            housekeeping.abort();
            settled(&bastion).await;
            joined.context("serving")??;
            anyhow::bail!("the server stopped without being asked to");
        }
    }
    housekeeping.abort();
    // Before the drain, not after: aborting the server later stops it
    // accepting, but a request already accepted is still being handled and
    // could otherwise start a command that nothing waits for.
    bastion.stop();
    drop(drain);
    match tokio::time::timeout(DRAIN_WITHIN, &mut serving).await {
        Ok(joined) => joined.context("serving")??,
        Err(_elapsed) => {
            // Aborted rather than left running. A handler still in flight can
            // start a command, and one that starts after the wait below has
            // seen nothing outstanding is a command the record would never
            // finish. Stopping the server first makes what is outstanding a
            // number that only goes down.
            tracing::warn!("requests still open; stopping anyway to record what commands did");
            serving.abort();
            let _ = serving.await;
        }
    }
    settled(&bastion).await;
    Ok(())
}

/// How often a running service reclaims on its own.
///
/// Short enough that a lapsed session's connection is let go of while the
/// service is idle, rather than being held until somebody happens to open or
/// close one; long enough to be beside the point when it is busy.
const RECLAIM_EVERY: Duration = Duration::from_secs(60);

/// How long the server waits for open requests before it stops anyway.
///
/// Short: an ordinary request finishes in well under this, and what is left is
/// a stream whose client has not gone away. Waiting on that is waiting on
/// somebody else's decision.
const DRAIN_WITHIN: Duration = Duration::from_secs(5);

/// How long to wait for readers of commands that are still running.
///
/// Together with the drain this is the whole stop, and a deployment has to
/// allow at least that much before it kills the container — otherwise the kill
/// arrives first and takes the readers with it, which is the loss this exists
/// to prevent.
const STOP_WITHIN: Duration = Duration::from_secs(20);

/// Waits for running commands to finish and accounts for their outcomes.
///
/// What it waits on is commands, not records a client may still collect: a
/// finished run is kept until whoever asked collects it, and holding shutdown
/// open for a client that may never come back would turn every stop into the
/// full deadline.
///
/// Draining HTTP is not enough. A command that outlived its request is read by a
/// task of its own; reclamation turns the settled outcome into its completion
/// entry. A process that stopped as soon as the last response went out would
/// leave the record saying a command was decided and never saying what happened
/// to it, which is the one thing this service exists to avoid.
///
/// Bounded, because stopping has to end. Reclamation yields between runs, so
/// this outer deadline includes both target execution and the bounded recording
/// work. What is left is named rather than dropped silently.
async fn settled<C, S>(bastion: &Bastion<C, S>)
where
    C: ssh_core::clock::Clock + 'static,
    S: ssh_core::connect::CredentialSource + 'static,
{
    const GIVE_UP_AFTER: Duration = STOP_WITHIN;
    const LOOK_AGAIN_EVERY: Duration = Duration::from_millis(250);

    let deadline = tokio::time::Instant::now()
        .checked_add(GIVE_UP_AFTER)
        .unwrap_or_else(tokio::time::Instant::now);
    loop {
        if tokio::time::Instant::now() >= deadline {
            let in_flight = bastion.runs_in_flight_with_authorization();
            let runs: Vec<String> = in_flight
                .iter()
                .map(|(run, authorized)| {
                    format!(
                        "{} session={} authorization={}:{}",
                        run.as_str(),
                        authorized.session().as_str(),
                        authorized.sequence(),
                        authorized.digest().as_str()
                    )
                })
                .collect();
            tracing::warn!(
                still_running = runs.join(","),
                "completion accounting exceeded the shutdown deadline"
            );
            return;
        }

        // The recorder bounds each individual output write. The timeout around
        // a yielding reclamation pass bounds their sum, so a burst of completed
        // runs cannot move the shutdown deadline.
        if tokio::time::timeout_at(deadline, bastion.reclaim())
            .await
            .is_err()
        {
            let in_flight = bastion.runs_in_flight_with_authorization();
            let runs: Vec<String> = in_flight
                .iter()
                .map(|(run, authorized)| {
                    format!(
                        "{} session={} authorization={}:{}",
                        run.as_str(),
                        authorized.session().as_str(),
                        authorized.sequence(),
                        authorized.digest().as_str()
                    )
                })
                .collect();
            tracing::warn!(
                still_running = runs.join(","),
                "completion accounting exceeded the shutdown deadline"
            );
            return;
        }

        if bastion.runs_in_flight().is_empty() {
            return;
        }

        let wake = tokio::time::Instant::now()
            .checked_add(LOOK_AGAIN_EVERY)
            .unwrap_or(deadline)
            .min(deadline);
        tokio::time::sleep_until(wake).await;
    }
}

/// Resolves when the container is asked to stop.
///
/// This binary is PID 1, so nothing else will handle the signal for it. Without
/// this, `docker stop` waits out its whole timeout and then kills the process:
/// a command in flight is cut off mid-run, and the record says it was decided
/// and never says what happened to it. Waiting for requests in flight means a
/// redeploy ends sessions rather than truncating them.
async fn stopped() {
    let interrupt = async {
        // A listener that could not be installed is not an interrupt. Treating
        // the error as one would stop a healthy service because it could not
        // arrange to be told when to stop.
        if let Err(why) = tokio::signal::ctrl_c().await {
            tracing::error!(%why, "no interrupt handler; stopping will rely on SIGTERM");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        // The signal Docker actually sends. A handler that could not be
        // installed leaves this branch pending, so the other one still works.
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(why) => {
                tracing::error!(%why, "no SIGTERM handler; stopping will not be graceful");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("stopping; waiting for requests in flight");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    /// A service bound to IPv6 loopback would otherwise serve correctly and be
    /// reported unhealthy by its own container healthcheck.
    #[test]
    fn probe_targets_the_configured_family_not_a_hardcoded_loopback() {
        let cases = [
            ("0.0.0.0:8080", "127.0.0.1:8080"),
            ("[::]:8080", "[::1]:8080"),
            ("[::1]:9000", "[::1]:9000"),
            ("192.168.1.5:9000", "192.168.1.5:9000"),
        ];
        for (listen, expected) in cases {
            assert_eq!(
                probe_address(listen.parse().unwrap()),
                expected.parse::<SocketAddr>().unwrap(),
                "listen {listen}"
            );
        }
    }

    /// Stands in for the secret store. Assembly is what is under test here, so
    /// what matters is that a credential source is wired in at all.
    struct NoCredentials;

    impl ssh_core::connect::CredentialSource for NoCredentials {
        async fn fetch(
            &self,
            _reference: &ssh_core::registry::CredentialRef,
        ) -> Result<ssh_core::secret::Secret<String>, ssh_core::connect::CredentialError> {
            Err(ssh_core::connect::CredentialError::NotFound)
        }
    }

    fn assembled() -> Router {
        let bastion = Arc::new(Bastion::new(
            Arc::new(ssh_core::clock::TestClock::at(1_000)),
            Registry::from_json("{}").unwrap(),
            Catalog::builtin().unwrap(),
            Engine::builtin().unwrap(),
            NoCredentials,
            settings::bounds(),
        ));
        let ingress = Ingress::new(
            Arc::new(
                crate::ingress::SharedBearer::new(
                    "0123456789abcdef0123456789abcdef".to_owned(),
                    None,
                )
                .unwrap(),
            ),
            Arc::new(
                IdentityVerifier::new(crate::ingress::IdentitySettings {
                    jwks_url: url::Url::parse("http://mcp-gateway:8080/.well-known/jwks.json")
                        .unwrap(),
                    issuer: "https://mcp.cacahuate.org".to_owned(),
                })
                .unwrap(),
            ),
        );
        let proxy = Proxy::new(Arc::new(
            crate::ingress::SharedBearer::new("89abcdef0123456789abcdef01234567".to_owned(), None)
                .unwrap(),
        ));
        router(
            bastion,
            ingress,
            proxy,
            Arc::new(crate::notify::Silence),
            None,
            OptionalSurfaces {
                evaluator: None,
                audit_reader: Arc::new(crate::audit_history::Unavailable),
            },
            &[],
        )
    }

    async fn get_path(path: &str) -> StatusCode {
        assembled()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn health_reports_liveness_and_nothing_else() {
        let response = assembled()
            .oneshot(
                Request::builder()
                    .uri(HEALTH_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn every_landing_path_reaches_the_review_queue() {
        for path in ["/", DASHBOARD_PATH, "/dashboard/"] {
            let response = assembled()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(
                            axum::http::header::AUTHORIZATION,
                            "Bearer 89abcdef0123456789abcdef01234567",
                        )
                        .header("x-authentik-username", "chris")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::LOCATION)
                    .unwrap(),
                "/dashboard/approvals",
                "{path}"
            );
        }
    }

    /// The assembly's whole point: the surface that can reach a host is behind
    /// the gateway, and the probe that cannot is not. A router that mounted the
    /// tools outside the layer, or the healthcheck inside it, would pass every
    /// other test in this crate.
    #[tokio::test]
    async fn the_tools_are_behind_the_gateway_and_the_probe_is_not() {
        assert_eq!(
            get_path(MCP_PATH).await,
            StatusCode::UNAUTHORIZED,
            "the MCP surface answered a request with no gateway credential"
        );
        assert_eq!(get_path(HEALTH_PATH).await, StatusCode::OK);
        assert_eq!(
            get_path("/").await,
            StatusCode::UNAUTHORIZED,
            "the site root pointed at the dashboard without the proxy's credential"
        );
    }

    /// The loopback the transport ships with is kept, and named authorities are
    /// added to it rather than replacing it: a deployment that names the gateway
    /// does not thereby stop answering a loopback probe.
    #[test]
    fn named_hosts_are_added_to_the_loopback_default() {
        let hosts = allowed_hosts(&["mcp-ssh:8080".to_owned()]);
        for loopback in ["localhost", "127.0.0.1", "::1"] {
            assert!(hosts.iter().any(|h| h == loopback), "dropped {loopback}");
        }
        assert!(hosts.iter().any(|h| h == "mcp-ssh:8080"));
        // Naming nothing leaves exactly the default in place.
        assert_eq!(allowed_hosts(&[]), ["localhost", "127.0.0.1", "::1"]);
    }

    // RFC 8037 §A Ed25519 test vector: the PKCS#8 private key and the JWK the
    // gateway would publish for it. Fixed so the two halves cannot drift and no
    // key generation is needed; these are published test vectors, not a secret.
    const SIGNING_KEY_PKCS8: [u8; 48] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c,
        0xae, 0x7f, 0x60,
    ];
    const PUBLIC_KEY_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const KEY_ID: &str = "gateway-1";
    const ISSUER: &str = "https://mcp.cacahuate.org";
    const BEARER: &str = "0123456789abcdef0123456789abcdef";
    // Named here rather than imported from ingress so a change to either the
    // wire contract or the header name fails this test instead of silently
    // agreeing with the code under test.
    const AUDIENCE: &str = "mcp-ssh-rs";
    const IDENTITY_HEADER: &str = "x-mcp-identity";

    #[derive(serde::Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        aud: String,
        iat: u64,
        exp: u64,
    }

    /// Serves the gateway's key set on loopback, the way the real gateway does,
    /// so the ingress can verify the assertion these tests mint.
    async fn serve_keys() -> url::Url {
        let body = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": KEY_ID,
                "x": PUBLIC_KEY_X,
            }]
        })
        .to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        url::Url::parse(&format!("http://{address}/.well-known/jwks.json")).unwrap()
    }

    fn identity_token() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(KEY_ID.to_owned());
        jsonwebtoken::encode(
            &header,
            &Claims {
                sub: "agent-clawde".to_owned(),
                iss: ISSUER.to_owned(),
                aud: AUDIENCE.to_owned(),
                iat: now.saturating_sub(5),
                exp: now.saturating_add(300),
            },
            &jsonwebtoken::EncodingKey::from_ed_der(&SIGNING_KEY_PKCS8),
        )
        .unwrap()
    }

    /// The status of a fully-credentialed POST to the MCP surface arriving with
    /// the given Host and the given trusted-host configuration. The credentials
    /// are real, so the request reaches the transport's Host guard rather than
    /// stopping at the ingress — which is what makes a 403 here mean the guard,
    /// and a non-403 mean the guard let it by.
    /// A fully-credentialed POST to the MCP surface with the given body, Host,
    /// and trusted-host configuration. Real credentials, so the request reaches
    /// the transport and — if the Host is admitted — the MCP handler behind it.
    async fn authenticated_response(
        trusted: &[&str],
        host: &str,
        body: &'static str,
    ) -> axum::response::Response {
        let jwks = serve_keys().await;
        let bastion = Arc::new(Bastion::new(
            Arc::new(ssh_core::clock::TestClock::at(1_000)),
            Registry::from_json("{}").unwrap(),
            Catalog::builtin().unwrap(),
            Engine::builtin().unwrap(),
            NoCredentials,
            settings::bounds(),
        ));
        let ingress = Ingress::new(
            Arc::new(crate::ingress::SharedBearer::new(BEARER.to_owned(), None).unwrap()),
            Arc::new(
                IdentityVerifier::new(crate::ingress::IdentitySettings {
                    jwks_url: jwks,
                    issuer: ISSUER.to_owned(),
                })
                .unwrap(),
            ),
        );
        let proxy = Proxy::new(Arc::new(
            crate::ingress::SharedBearer::new("89abcdef0123456789abcdef01234567".to_owned(), None)
                .unwrap(),
        ));
        let trusted: Vec<String> = trusted.iter().map(|h| (*h).to_owned()).collect();
        let app = router(
            bastion,
            ingress,
            proxy,
            Arc::new(crate::notify::Silence),
            None,
            OptionalSurfaces {
                evaluator: None,
                audit_reader: Arc::new(crate::audit_history::Unavailable),
            },
            &trusted,
        );
        let request = Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header(axum::http::header::HOST, host)
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {BEARER}"),
            )
            .header(IDENTITY_HEADER, identity_token())
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(
                axum::http::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .body(Body::from(body))
            .unwrap();
        app.oneshot(request).await.unwrap()
    }

    async fn authenticated_status(trusted: &[&str], host: &str) -> StatusCode {
        authenticated_response(
            trusted,
            host,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .await
        .status()
    }

    /// The gateway reaches this service by a network name, not by loopback, so
    /// the transport's default Host guard would refuse every one of its calls.
    /// Naming that authority lets it through while the guard still refuses any
    /// other — and with nothing named the default stands, which is the state a
    /// revert of the wiring returns to. The unnamed-host case returning the
    /// transport's 403 (not the ingress's 401) is also what proves the request
    /// was credentialed enough to reach the guard at all.
    #[tokio::test]
    async fn a_named_host_reaches_the_ingress_and_an_unnamed_one_is_refused() {
        assert_ne!(
            authenticated_status(&["mcp-ssh:8080"], "mcp-ssh:8080").await,
            StatusCode::FORBIDDEN,
            "the deployment's trusted host was refused by the transport guard",
        );
        assert_eq!(
            authenticated_status(&["mcp-ssh:8080"], "evil.example").await,
            StatusCode::FORBIDDEN,
            "a host the deployment did not name reached past the transport guard",
        );
        assert_eq!(
            authenticated_status(&[], "mcp-ssh:8080").await,
            StatusCode::FORBIDDEN,
            "a non-loopback host was admitted with no trusted hosts configured",
        );
    }

    /// The principal the ingress attaches to the request has to survive the
    /// trip through the transport into the handler, which reads it back out of
    /// the request parts the transport carries. A credentialed `tools/list`
    /// arrives at the discovery handler and is answered with the catalog rather
    /// than the refusal a handler gives when it cannot see who is calling. This
    /// is the seam the by-hand handler tests cannot reach, and the one that
    /// fails if the principal is read from the wrong place.
    #[tokio::test]
    async fn a_credentialed_discovery_call_reaches_the_handler_with_its_principal() {
        let response = authenticated_response(
            &["mcp-ssh:8080"],
            "mcp-ssh:8080",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !body.contains("no caller identity"),
            "the handler could not see the gateway principal the ingress attached: {body}"
        );
        assert!(
            body.contains("ssh_exec"),
            "tools/list did not return the catalog, so the principal did not reach the handler: {body}"
        );
    }
}
