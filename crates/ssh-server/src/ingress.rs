//! Who is allowed to reach the service, and who they are acting for.
//!
//! Gateway mode verifies a service credential and a signed principal assertion.
//! Standalone mode maps its configured bearer to a fixed local principal.
//! See the design's front-door contract for the deployment boundaries.
//!
//! In gateway mode, two separate facts have to hold before a request reaches a tool:
//!
//! - **The caller is the gateway.** A shared bearer establishes that, and it
//!   rotates, so replacing it does not require a synchronised restart.
//! - **The gateway says who it is acting for.** That arrives as a signed
//!   assertion the gateway mints and this service verifies against the
//!   gateway's published keys. It is not taken on trust from a header, because
//!   the principal is what every audit record attributes work to and what every
//!   policy decision is made about.
//!
//! The two are deliberately not the same check. A leaked bearer alone lets an
//! attacker reach the service; it does not let them name a principal, because
//! they cannot sign for one.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use ssh_core::PrincipalId;
use subtle::ConstantTimeEq as _;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::mcp::AuthenticatedPrincipal;

/// Header the gateway puts its signed identity assertion in.
const IDENTITY_HEADER: &str = "x-mcp-identity";

/// Audience the gateway must mint identity assertions for.
///
/// An assertion minted for a sibling service is not accepted here: without an
/// audience, one upstream could replay a token it was legitimately given to
/// call another, and every service behind the gateway would share one identity
/// domain.
const AUDIENCE: &str = "mcp-ssh-rs";

/// Shortest bearer accepted, in bytes.
///
/// Not a strength estimate — it is the line below which a value is obviously
/// not a generated credential, and catching that at startup is better than
/// discovering it in an access log.
const MINIMUM_BEARER_BYTES: usize = 32;

/// Most JWKS bytes read before giving up.
const MAXIMUM_JWKS_BYTES: usize = 64 * 1024;

/// Tolerance for clock disagreement between the gateway and this service.
const CLOCK_SKEW: u64 = 30;

/// How long fetched keys are reused before being fetched again.
const KEY_CACHE_TTL: Duration = Duration::from_secs(300);

/// How long to wait before fetching again after a key was not found.
///
/// Without this, a token naming a key that does not exist — a stale client, or
/// somebody probing — turns every request into a fetch against the gateway.
const UNKNOWN_KEY_COOLDOWN: Duration = Duration::from_secs(5);

/// A shared credential a trusted peer presents, current and previous.
///
/// Two values so the credential can be rotated without a flag day: the new one
/// is issued, both are accepted while the peer picks it up, and the old one is
/// removed afterwards.
///
/// The gateway and dashboard proxy hold different values: reaching one surface
/// must not confer access to the other.
pub struct SharedBearer {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl SharedBearer {
    pub fn new(current: String, previous: Option<String>) -> Result<Self, IngressError> {
        check_bearer(&current)?;
        let previous = previous
            .as_deref()
            .map(|previous| {
                check_bearer(previous)?;
                if previous == current {
                    return Err(IngressError::BearersIdentical);
                }
                Ok(digest(previous))
            })
            .transpose()?;
        Ok(Self {
            current: digest(&current),
            previous,
        })
    }

    /// Whether a presented value is one of the accepted credentials.
    ///
    /// Digests are compared rather than the credentials themselves, in
    /// constant time. Comparing the values directly returns early when the
    /// lengths differ, which tells a caller how long the real credential is,
    /// and then leaks how long a common prefix is — enough to recover it byte
    /// by byte. A digest is the same size whatever was presented, so the
    /// comparison says only whether they matched.
    ///
    /// Keeping only digests also means the credential is not in memory after
    /// startup to be printed, logged, or dumped.
    #[must_use]
    pub fn accepts(&self, presented: &[u8]) -> bool {
        let presented = digest_bytes(presented);
        let mut matched = self.current.ct_eq(&presented);
        if let Some(previous) = self.previous.as_ref() {
            matched |= previous.ct_eq(&presented);
        }
        matched.into()
    }
}

/// Redacted, because these are derived from credentials.
impl std::fmt::Debug for SharedBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedBearer")
            .field("previous_configured", &self.previous.is_some())
            .finish()
    }
}

fn check_bearer(value: &str) -> Result<(), IngressError> {
    if value.len() < MINIMUM_BEARER_BYTES {
        return Err(IngressError::BearerTooShort {
            minimum: MINIMUM_BEARER_BYTES,
        });
    }
    // What an `Authorization` header can carry is what a credential may be made
    // of. A value with a control character or a non-ASCII byte passes a
    // whitespace check, is configured happily, and can then never be presented
    // in a header this service will read: a service that starts and refuses
    // every request, for a reason nothing reports.
    if value.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(IngressError::BearerNotHeaderSafe);
    }
    Ok(())
}

fn digest(value: &str) -> [u8; 32] {
    digest_bytes(value.as_bytes())
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Where the gateway publishes its signing keys, and what it calls itself.
#[derive(Clone, Debug)]
pub struct IdentitySettings {
    pub jwks_url: Url,
    pub issuer: String,
}

impl IdentitySettings {
    /// Refuses settings this image cannot use before a verifier is built.
    pub fn validate(&self) -> Result<(), IngressError> {
        // HTTP is for a protected internal hop; HTTPS verifies the remote peer.
        if !matches!(self.jwks_url.scheme(), "http" | "https") {
            return Err(IngressError::JwksNotHttp);
        }
        if self.jwks_url.host().is_none()
            || !self.jwks_url.username().is_empty()
            || self.jwks_url.password().is_some()
            || self.jwks_url.query().is_some()
            || self.jwks_url.fragment().is_some()
        {
            return Err(IngressError::JwksUrlUnusable);
        }
        if self.issuer.trim().is_empty() {
            return Err(IngressError::IssuerBlank);
        }
        Ok(())
    }
}

/// Verifies the gateway's identity assertions.
pub struct IdentityVerifier {
    settings: IdentitySettings,
    client: reqwest::Client,
    keys: RwLock<KeyCache>,
    /// Held across a fetch, so a burst of requests is one fetch.
    ///
    /// The cache alone cannot bound this: every request in a burst reads it
    /// before any of them has written a result, so all of them see the same
    /// permission to fetch and all of them go. Holding this while fetching
    /// makes the rest wait for the answer the first is already getting, which
    /// is what stops an unknown key identifier turning a burst against this
    /// service into a burst against the gateway.
    refreshing: Mutex<()>,
}

#[derive(Debug, Default)]
struct KeyCache {
    set: Option<JwkSet>,
    fetched_at: Option<Instant>,
    unknown_key_until: Option<Instant>,
    /// When the gateway may be asked again after a fetch that failed.
    ///
    /// A fetch that errors, answers with something unparseable, or answers
    /// with too much is as good a reason not to ask again immediately as a
    /// key that was not in the answer. Without this, a key set that is down
    /// turns every request into another attempt at it.
    unavailable_until: Option<Instant>,
}

impl IdentityVerifier {
    pub fn new(settings: IdentitySettings) -> Result<Self, IngressError> {
        settings.validate()?;
        let client = reqwest::Client::builder()
            // The gateway is reached directly. A proxy discovered from the
            // environment would send key fetches somewhere else entirely.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| IngressError::HttpClient)?;
        Ok(Self {
            settings,
            client,
            keys: RwLock::new(KeyCache::default()),
            refreshing: Mutex::new(()),
        })
    }

    /// Reads the gateway's keys once, before anything depends on them.
    ///
    /// Not fatal, deliberately. This service and the gateway restart
    /// independently — a host reboot brings both up at once — and a service
    /// that refuses to start because the gateway has not finished starting is
    /// a crash loop that outlasts the condition causing it. What this buys is
    /// the operator hearing about an unreachable or misconfigured key set at
    /// boot rather than from the first agent to be refused.
    pub async fn warm(&self) {
        match self.fetch_keys().await {
            Ok(fetched) => {
                // Counted by what this service could actually verify with, not
                // by what the document contains. A set of keys none of which
                // can check a signature is a misconfiguration that would
                // otherwise be reported as success at boot and discovered as a
                // refusal by every caller afterwards.
                let usable = fetched
                    .keys
                    .iter()
                    .filter(|jwk| check_jwk(jwk).is_ok())
                    .count();
                let mut cache = self.keys.write().await;
                cache.set = Some(fetched);
                cache.fetched_at = Some(Instant::now());
                cache.unavailable_until = None;
                drop(cache);
                if usable == 0 {
                    tracing::error!(
                        url = %self.settings.jwks_url,
                        "the gateway published no key this service can verify with; every request will be refused until this is fixed"
                    );
                } else {
                    tracing::info!(keys = usable, "read the gateway's signing keys");
                }
            }
            Err(why) => {
                tracing::error!(
                    %why,
                    url = %self.settings.jwks_url,
                    "could not read the gateway's signing keys; every request will be refused until this is fixed"
                );
            }
        }
    }

    /// Reads an assertion and returns the principal it names.
    ///
    /// Every failure returns the same error to the caller's side of the wire;
    /// the distinctions here exist for the operator reading logs, not for a
    /// caller learning which part of its forgery was wrong.
    pub async fn verify(&self, token: &str) -> Result<PrincipalId, IdentityError> {
        let header = decode_header(token).map_err(|_| IdentityError::Unverifiable)?;
        if header.alg != Algorithm::EdDSA {
            return Err(IdentityError::Unverifiable);
        }
        let key_id = header.kid.ok_or(IdentityError::Unverifiable)?;
        let jwk = self.key(&key_id).await?;
        check_jwk(&jwk)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| IdentityError::Unverifiable)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.settings.issuer.as_str()]);
        validation.set_audience(&[AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = CLOCK_SKEW;
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| IdentityError::Unverifiable)?
            .claims;

        // An assertion issued in the future is not a clock problem this service
        // can absorb; `leeway` already covers ordinary disagreement.
        let now = unix_now()?;
        if claims.iat > now.saturating_add(CLOCK_SKEW) || claims.exp <= claims.iat {
            return Err(IdentityError::Unverifiable);
        }
        PrincipalId::parse(&claims.sub).map_err(|_| IdentityError::Unverifiable)
    }

    /// The key a token names, fetching if the cache cannot answer.
    async fn key(&self, key_id: &str) -> Result<Jwk, IdentityError> {
        if let Some(answer) = self.cached(key_id).await {
            return answer;
        }

        // Whoever arrives first fetches; the rest wait and then read the cache
        // again, because by then it holds the answer they were about to ask
        // for. Without this, every request in a burst fetches.
        let _refreshing = self.refreshing.lock().await;
        if let Some(answer) = self.cached(key_id).await {
            return answer;
        }

        let fetched = match self.fetch_keys().await {
            Ok(fetched) => fetched,
            Err(why) => {
                let mut cache = self.keys.write().await;
                cache.unavailable_until = Instant::now().checked_add(UNKNOWN_KEY_COOLDOWN);
                return Err(why);
            }
        };
        let mut cache = self.keys.write().await;
        cache.unavailable_until = None;
        cache.set = Some(fetched);
        cache.fetched_at = Some(Instant::now());
        let found = cache
            .set
            .as_ref()
            .and_then(|set| set.find(key_id))
            .cloned()
            .ok_or(IdentityError::UnknownKey);
        if found.is_err() {
            cache.unknown_key_until = Instant::now().checked_add(UNKNOWN_KEY_COOLDOWN);
        }
        found
    }

    /// What the cache can say without fetching, if anything.
    async fn cached(&self, key_id: &str) -> Option<Result<Jwk, IdentityError>> {
        let now = Instant::now();
        let cache = self.keys.read().await;
        match cache.lookup(key_id, now) {
            // What the cache can already answer, it answers. A gateway that is
            // down does not make the keys it published before it went down any
            // less valid, and refusing work this service can still verify would
            // let a caller naming one key that does not exist decide that
            // everybody else's assertions stop working too.
            Lookup::Found(jwk) => Some(Ok(jwk.clone())),
            // A key that is missing from a fresh set is missing. Fetching again
            // immediately would let unknown key identifiers drive traffic at
            // the gateway.
            Lookup::Missing { may_refetch: false } => Some(Err(IdentityError::UnknownKey)),
            // Only where the answer would have to come from a fetch does a key
            // set that just failed to answer matter: the caller is refused
            // either way, and the difference is whether being refused costs the
            // gateway another request.
            Lookup::Missing { may_refetch: true } | Lookup::Stale => cache
                .unavailable_until
                .is_some_and(|until| until > now)
                .then_some(Err(IdentityError::KeysUnavailable)),
        }
    }

    async fn fetch_keys(&self) -> Result<JwkSet, IdentityError> {
        let mut response = self
            .client
            .get(self.settings.jwks_url.clone())
            .send()
            .await
            .map_err(|_| IdentityError::KeysUnavailable)?;
        if !response.status().is_success() {
            return Err(IdentityError::KeysUnavailable);
        }
        // Read in bounded pieces rather than whole: a body is only trusted
        // after it has been parsed, and a response of any size at all can be
        // sent by whatever actually answered on that address.
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IdentityError::KeysUnavailable)?
        {
            let total = body
                .len()
                .checked_add(chunk.len())
                .ok_or(IdentityError::KeysUnavailable)?;
            if total > MAXIMUM_JWKS_BYTES {
                return Err(IdentityError::KeysUnavailable);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| IdentityError::KeysUnavailable)
    }
}

impl KeyCache {
    fn lookup(&self, key_id: &str, now: Instant) -> Lookup<'_> {
        let fresh = self
            .fetched_at
            .and_then(|at| at.checked_add(KEY_CACHE_TTL))
            .is_some_and(|expiry| expiry > now);
        if !fresh {
            return Lookup::Stale;
        }
        let Some(set) = self.set.as_ref() else {
            return Lookup::Stale;
        };
        match set.find(key_id) {
            Some(jwk) => Lookup::Found(jwk),
            None => Lookup::Missing {
                may_refetch: self.unknown_key_until.is_none_or(|until| until <= now),
            },
        }
    }
}

enum Lookup<'a> {
    Found(&'a Jwk),
    Missing { may_refetch: bool },
    Stale,
}

/// The gateway's assertion about who a request is for.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iat: u64,
    exp: u64,
}

fn check_jwk(jwk: &Jwk) -> Result<(), IdentityError> {
    if jwk.common.key_algorithm != Some(KeyAlgorithm::EdDSA) {
        return Err(IdentityError::Unverifiable);
    }
    // A key the gateway published for encryption is not a key it signs with,
    // and using one for the other is the kind of confusion key metadata exists
    // to prevent. A key that declares no use is left alone: saying nothing is
    // not the same as saying the wrong thing.
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|declared| *declared != PublicKeyUse::Signature)
    {
        return Err(IdentityError::Unverifiable);
    }
    // The curve is checked as well as the algorithm: a set that advertises
    // EdDSA over some other curve is not a key this service can verify, and
    // accepting it would depend on the JWT library refusing it later.
    if !matches!(
        &jwk.algorithm,
        AlgorithmParameters::OctetKeyPair(parameters)
            if parameters.curve == EllipticCurve::Ed25519
    ) {
        return Err(IdentityError::Unverifiable);
    }
    // `key_ops` says the same thing as `use`, more precisely, and an entry may
    // carry it with no `use` at all. A key published only to sign with is not
    // one to verify a signature with, and a set that says so should not have to
    // say it twice to be believed.
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return Err(IdentityError::Unverifiable);
    }
    Ok(())
}

fn unix_now() -> Result<u64, IdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|_| IdentityError::Unverifiable)
}

/// The service cannot start with the ingress it was given.
#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("the credential must be at least {minimum} bytes")]
    BearerTooShort { minimum: usize },
    #[error("the credential must contain only visible ASCII")]
    BearerNotHeaderSafe,
    #[error("the current and previous credentials must differ")]
    BearersIdentical,
    #[error("MCP, operator, and evaluator surfaces must use different credentials")]
    BearersSharedAcrossSurfaces,
    #[error("the identity issuer must not be blank")]
    IssuerBlank,
    #[error("the identity key set must use http or https")]
    JwksNotHttp,
    #[error("the identity key set URL must have a host and no credentials, query, or fragment")]
    JwksUrlUnusable,
    #[error("the identity key fetcher could not be built")]
    HttpClient,
}

/// A request did not carry an identity this service could verify.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("the identity assertion did not verify")]
    Unverifiable,
    #[error("the identity assertion names a key the gateway does not publish")]
    UnknownKey,
    #[error("the gateway's keys could not be read")]
    KeysUnavailable,
}

/// What the ingress layer needs to admit a request.
#[derive(Clone)]
pub struct Ingress {
    bearers: Arc<SharedBearer>,
    identity: IdentitySource,
}

#[derive(Clone)]
enum IdentitySource {
    Gateway(Arc<IdentityVerifier>),
    Standalone(PrincipalId),
}

impl Ingress {
    #[must_use]
    pub const fn new(bearers: Arc<SharedBearer>, verifier: Arc<IdentityVerifier>) -> Self {
        Self {
            bearers,
            identity: IdentitySource::Gateway(verifier),
        }
    }

    #[must_use]
    pub const fn standalone(bearers: Arc<SharedBearer>, principal: PrincipalId) -> Self {
        Self {
            bearers,
            identity: IdentitySource::Standalone(principal),
        }
    }
}

/// Authenticates the MCP caller using the explicitly configured identity mode.
///
/// On success the principal is placed in the request's extensions, which is
/// where the MCP surface reads it from. Nothing downstream accepts a principal
/// from any other source, so a request that gets past this layer without one
/// is refused rather than served as nobody.
pub async fn require_mcp(
    State(ingress): State<Ingress>,
    mut request: Request,
    next: Next,
) -> Response {
    // MCP clients use a non-browser HTTP transport in both supported modes.
    if request.headers().contains_key(header::ORIGIN) {
        // Keep the response generic; the operator gets the reason in the log.
        tracing::warn!("refused a request carrying Origin; no browser is a legitimate caller");
        return unauthorized();
    }
    // Every refusal says in the log which check refused it, and none of them
    // say so on the wire. A wrong credential during a rotation and a gateway
    // that cannot be reached are the same answer to a caller and completely
    // different problems for whoever is on call; the log is where that
    // difference belongs. No credential is logged, only which check it failed.
    let Some(presented) = bearer(request.headers()) else {
        tracing::warn!("refused a request with no usable Authorization: Bearer header");
        return unauthorized();
    };
    if !ingress.bearers.accepts(presented.as_bytes()) {
        tracing::warn!("refused a request presenting a bearer that is not configured");
        return unauthorized();
    }
    let principal = match &ingress.identity {
        IdentitySource::Standalone(principal) => {
            if request.headers().contains_key(IDENTITY_HEADER) {
                return unauthorized();
            }
            principal.clone()
        }
        IdentitySource::Gateway(verifier) => {
            let Some(assertion) = single_header(request.headers(), IDENTITY_HEADER) else {
                tracing::warn!("refused a request with no single identity assertion");
                return unauthorized();
            };
            match verifier.verify(assertion).await {
                Ok(principal) => principal,
                Err(why) => {
                    tracing::warn!(%why, "refused a request whose identity did not verify");
                    return unauthorized();
                }
            }
        }
    };
    request
        .extensions_mut()
        .insert(AuthenticatedPrincipal::new(principal));
    next.run(request).await
}

/// The bearer from an `Authorization` header, if there is exactly one.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = single_header(headers, header::AUTHORIZATION.as_str())?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    if token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

/// A header's value, or nothing if it was sent more than once.
///
/// A repeated header is ambiguous: this layer and something in front of it can
/// read different values, which is how a check gets passed with one value and
/// acted on with another.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn unauthorized() -> Response {
    let mut response = refuse(StatusCode::UNAUTHORIZED, "MCP authentication is required");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

/// One shape of refusal, saying nothing about which check failed.
fn refuse(status: StatusCode, message: &'static str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;
    use tower::ServiceExt as _;

    /// The Ed25519 key from RFC 8037 § A, as PKCS#8 and as the JWK the gateway
    /// would publish for it. Fixed rather than generated so the test needs no
    /// key generation and the two halves cannot drift apart.
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

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        iat: u64,
        exp: u64,
    }

    /// A key set whose entry declares only the given operations, and no `use`.
    fn keys_published_only_for(key_id: &str, operations: &[&str]) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "key_ops": operations,
                "alg": "EdDSA",
                "kid": key_id,
                "x": PUBLIC_KEY_X,
            }]
        })
        .to_string()
    }

    fn jwks_body(key_id: &str) -> String {
        keys_published_for(key_id, "sig")
    }

    fn keys_published_for(key_id: &str, declared_use: &str) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": declared_use,
                "alg": "EdDSA",
                "kid": key_id,
                "x": PUBLIC_KEY_X,
            }]
        })
        .to_string()
    }

    /// Serves a key set on loopback and counts how often it was asked for, so
    /// a test can say what the gateway would have seen.
    async fn serve_counted_keys(body: String) -> (Url, Arc<std::sync::atomic::AtomicUsize>) {
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&fetches);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let body = body.clone();
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    body
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (
            Url::parse(&format!("http://{address}/.well-known/jwks.json")).unwrap(),
            fetches,
        )
    }

    /// Serves a key set on loopback, the way the gateway does.
    async fn serve_keys(body: String) -> Url {
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
        Url::parse(&format!("http://{address}/.well-known/jwks.json")).unwrap()
    }

    fn token(subject: &str, issuer: &str, audience: &str, iat: u64, exp: u64) -> String {
        token_naming(KEY_ID, subject, issuer, audience, iat, exp)
    }

    fn token_naming(
        key_id: &str,
        subject: &str,
        issuer: &str,
        audience: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id.to_owned());
        jsonwebtoken::encode(
            &header,
            &TestClaims {
                sub: subject.to_owned(),
                iss: issuer.to_owned(),
                aud: audience.to_owned(),
                iat,
                exp,
            },
            &EncodingKey::from_ed_der(&SIGNING_KEY_PKCS8),
        )
        .unwrap()
    }

    fn now() -> u64 {
        unix_now().unwrap()
    }

    async fn ingress_over(jwks: Url) -> Ingress {
        Ingress::new(
            Arc::new(SharedBearer::new(BEARER.to_owned(), None).unwrap()),
            Arc::new(
                IdentityVerifier::new(IdentitySettings {
                    jwks_url: jwks,
                    issuer: ISSUER.to_owned(),
                })
                .unwrap(),
            ),
        )
    }

    /// Echoes back the principal the layer admitted, so a test can tell "the
    /// request was served" from "the request was served as the right caller".
    async fn admitted(principal: Option<axum::Extension<AuthenticatedPrincipal>>) -> String {
        principal.map_or_else(
            || "nobody".to_owned(),
            |axum::Extension(principal)| principal.get().as_str().to_owned(),
        )
    }

    async fn app(ingress: Ingress) -> Router {
        Router::new()
            .route("/", get(admitted))
            .layer(axum::middleware::from_fn_with_state(
                ingress.clone(),
                require_mcp,
            ))
            .with_state(())
    }

    fn request(headers: Vec<(&'static str, String)>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// Everything a caller can see of an answer. Refusals are compared whole,
    /// because "indistinguishable" is a claim about what the caller receives,
    /// not about a status code.
    #[derive(Debug, PartialEq, Eq)]
    struct Answer {
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: String,
    }

    async fn call(ingress: &Ingress, headers: Vec<(&'static str, String)>) -> Answer {
        let response = app(ingress.clone())
            .await
            .oneshot(request(headers))
            .await
            .unwrap();
        let status = response.status();
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        Answer {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    #[tokio::test]
    async fn standalone_bearer_maps_only_to_the_configured_principal() {
        let ingress = Ingress::standalone(
            Arc::new(SharedBearer::new(BEARER.to_owned(), None).unwrap()),
            PrincipalId::parse("personal-client").unwrap(),
        );
        let authorized = vec![("authorization", format!("Bearer {BEARER}"))];
        let answer = call(&ingress, authorized.clone()).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, "personal-client");
        for headers in [
            vec![],
            vec![("authorization", "Bearer wrong".to_owned())],
            vec![
                ("authorization", format!("Bearer {BEARER}")),
                ("authorization", format!("Bearer {BEARER}")),
            ],
            [
                authorized.clone(),
                vec![(IDENTITY_HEADER, "forged-principal".to_owned())],
            ]
            .concat(),
            [authorized, vec![("origin", "http://localhost".to_owned())]].concat(),
        ] {
            assert_eq!(
                call(&ingress, headers).await.status,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    /// The property the layer exists for: a request the gateway signed for a
    /// principal is served *as that principal*, and nothing downstream has to
    /// trust a header for it.
    #[tokio::test]
    async fn a_signed_request_is_served_as_the_principal_it_names() {
        let ingress = ingress_over(serve_keys(jwks_body(KEY_ID)).await).await;
        let now = now();
        let answer = call(
            &ingress,
            vec![
                ("authorization", format!("Bearer {BEARER}")),
                (
                    IDENTITY_HEADER,
                    token("agent-clawde", ISSUER, AUDIENCE, now, now + 60),
                ),
            ],
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, "agent-clawde");
    }

    /// Each of these is a different way of not being the gateway, and every one
    /// of them must produce the same refusal.
    #[tokio::test]
    async fn nothing_short_of_a_signed_gateway_request_is_admitted() {
        let ingress = ingress_over(serve_keys(jwks_body(KEY_ID)).await).await;
        let now = now();
        let good = token("agent-clawde", ISSUER, AUDIENCE, now, now + 60);

        let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
            ("nothing at all", vec![]),
            (
                "a valid identity but no bearer",
                vec![(IDENTITY_HEADER, good.clone())],
            ),
            (
                "the wrong bearer",
                vec![
                    (
                        "authorization",
                        "Bearer ffffffffffffffffffffffffffffffff".to_owned(),
                    ),
                    (IDENTITY_HEADER, good.clone()),
                ],
            ),
            (
                "a bearer but no identity",
                vec![("authorization", format!("Bearer {BEARER}"))],
            ),
            (
                "an identity signed for another service",
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (
                        IDENTITY_HEADER,
                        token("agent-clawde", ISSUER, "some-other-service", now, now + 60),
                    ),
                ],
            ),
            (
                "an identity from another issuer",
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (
                        IDENTITY_HEADER,
                        token(
                            "agent-clawde",
                            "https://impostor.invalid",
                            AUDIENCE,
                            now,
                            now + 60,
                        ),
                    ),
                ],
            ),
            (
                "an expired identity",
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (
                        IDENTITY_HEADER,
                        token("agent-clawde", ISSUER, AUDIENCE, now - 600, now - 300),
                    ),
                ],
            ),
            (
                "an unsigned identity",
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (
                        IDENTITY_HEADER,
                        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZ2VudC1jbGF3ZGUifQ.".to_owned(),
                    ),
                ],
            ),
        ];

        // Compared whole and against each other, not just against a status: a
        // refusal that named which check failed would still be a 401, and the
        // point of one answer is that a caller cannot tell which part of its
        // request to change next.
        let mut answers: Vec<(&str, Answer)> = Vec::new();
        for (what, headers) in cases {
            let answer = call(&ingress, headers).await;
            assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "admitted {what}");
            answers.push((what, answer));
        }
        let mut answers = answers.iter();
        let (first_case, first) = answers.next().expect("the case list is not empty");
        for (what, answer) in answers {
            assert_eq!(answer, first, "{what} is distinguishable from {first_case}");
        }
    }

    /// A token signed by a key the gateway does not publish must not be
    /// admitted, even though it is a structurally perfect assertion.
    #[tokio::test]
    async fn an_identity_signed_by_an_unpublished_key_is_refused() {
        let ingress = ingress_over(serve_keys(jwks_body("some-other-key")).await).await;
        let now = now();
        let answer = call(
            &ingress,
            vec![
                ("authorization", format!("Bearer {BEARER}")),
                (
                    IDENTITY_HEADER,
                    token("agent-clawde", ISSUER, AUDIENCE, now, now + 60),
                ),
            ],
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    }

    /// A key the gateway publishes for encryption is not one it signs with.
    /// Verifying a signature against it would be exactly the key confusion the
    /// `use` field exists to prevent, and the signature itself would verify —
    /// this is the same key material wearing the wrong label.
    #[tokio::test]
    async fn a_key_published_for_encryption_does_not_verify_signatures() {
        let now = now();
        // Both ways a key set says a key is not for verifying signatures: the
        // older `use`, and `key_ops`, which an entry may carry on its own — so
        // a set that says only the latter is not silently accepted.
        for published in [
            keys_published_for(KEY_ID, "enc"),
            keys_published_only_for(KEY_ID, &["sign"]),
        ] {
            let ingress = ingress_over(serve_keys(published).await).await;
            let answer = call(
                &ingress,
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (
                        IDENTITY_HEADER,
                        token("agent-clawde", ISSUER, AUDIENCE, now, now + 60),
                    ),
                ],
            )
            .await;
            assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        }
    }

    /// A cooldown that only takes effect after a fetch finishes is no cooldown
    /// at all under load: every request in a burst reads the cache before any
    /// of them has written a result, so all of them go. A caller holding the
    /// bearer could then turn one burst here into the same burst against the
    /// gateway, by naming a key that does not exist.
    #[tokio::test]
    async fn a_burst_naming_an_unknown_key_asks_the_gateway_once() {
        let (jwks, fetches) = serve_counted_keys(jwks_body("some-other-key")).await;
        let ingress = ingress_over(jwks).await;
        let now = now();
        let assertion = token("agent-clawde", ISSUER, AUDIENCE, now, now + 60);

        let mut burst = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let ingress = ingress.clone();
            let assertion = assertion.clone();
            burst.spawn(async move {
                call(
                    &ingress,
                    vec![
                        ("authorization", format!("Bearer {BEARER}")),
                        (IDENTITY_HEADER, assertion),
                    ],
                )
                .await
                .status
            });
        }
        while let Some(refused) = burst.join_next().await {
            assert_eq!(refused.unwrap(), StatusCode::UNAUTHORIZED);
        }

        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a burst naming one unknown key was passed on to the gateway more than once"
        );
    }

    /// A key set that cannot answer is a reason not to ask it again yet, the
    /// same as one that answered without the key. Otherwise a gateway having a
    /// bad minute is asked once per request by everything queued behind it,
    /// which is when it can least afford the traffic.
    #[tokio::test]
    async fn a_key_set_that_cannot_answer_is_not_asked_again_immediately() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (StatusCode::INTERNAL_SERVER_ERROR, "no")
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let ingress =
            ingress_over(Url::parse(&format!("http://{address}/.well-known/jwks.json")).unwrap())
                .await;

        let now = now();
        let assertion = token("agent-clawde", ISSUER, AUDIENCE, now, now + 60);
        for _ in 0..8 {
            let answer = call(
                &ingress,
                vec![
                    ("authorization", format!("Bearer {BEARER}")),
                    (IDENTITY_HEADER, assertion.clone()),
                ],
            )
            .await;
            assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        }

        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a key set that had already failed was asked again for every request"
        );
    }

    /// A gateway that has gone down does not invalidate the keys it published
    /// before it went down. Refusing work this service can still verify would
    /// also hand a caller a lever: name one key that does not exist, and
    /// everybody else's assertions stop working for as long as the outage
    /// lasts.
    #[tokio::test]
    async fn keys_already_held_keep_working_while_the_gateway_is_down() {
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let serving = Arc::clone(&answering);
        let body = jwks_body(KEY_ID);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let body = body.clone();
                let serving = Arc::clone(&serving);
                async move {
                    if serving.load(std::sync::atomic::Ordering::SeqCst) {
                        (StatusCode::OK, body)
                    } else {
                        (StatusCode::INTERNAL_SERVER_ERROR, "no".to_owned())
                    }
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let ingress =
            ingress_over(Url::parse(&format!("http://{address}/.well-known/jwks.json")).unwrap())
                .await;

        let now = now();
        let good = |assertion: String| {
            vec![
                ("authorization", format!("Bearer {BEARER}")),
                (IDENTITY_HEADER, assertion),
            ]
        };
        let assertion = token("agent-clawde", ISSUER, AUDIENCE, now, now + 60);

        // The key set is read once and held.
        assert_eq!(
            call(&ingress, good(assertion.clone())).await.status,
            StatusCode::OK
        );

        // The gateway goes down, and somebody names a key that does not exist,
        // which is what puts the fetch path into its cooldown.
        answering.store(false, std::sync::atomic::Ordering::SeqCst);
        let unknown = token_naming(
            "no-such-key",
            "agent-clawde",
            ISSUER,
            AUDIENCE,
            now,
            now + 60,
        );
        assert_eq!(
            call(&ingress, good(unknown)).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Work this service can still verify is still verified.
        let answer = call(&ingress, good(assertion)).await;
        assert_eq!(
            answer.status,
            StatusCode::OK,
            "a held key stopped working because the gateway was unreachable"
        );
        assert_eq!(answer.body, "agent-clawde");
    }

    /// A browser cannot be a legitimate caller, so carrying an `Origin` at all
    /// is disqualifying — this is what closes DNS rebinding.
    #[tokio::test]
    async fn a_request_that_looks_like_a_browsers_is_refused() {
        let ingress = ingress_over(serve_keys(jwks_body(KEY_ID)).await).await;
        let now = now();
        let answer = call(
            &ingress,
            vec![
                ("origin", "https://evil.example".to_owned()),
                ("authorization", format!("Bearer {BEARER}")),
                (
                    IDENTITY_HEADER,
                    token("agent-clawde", ISSUER, AUDIENCE, now, now + 60),
                ),
            ],
        )
        .await;
        // Refused exactly as anything else that is not the gateway: a caller
        // learns that it was refused, not which check refused it.
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer, call(&ingress, vec![]).await);
    }

    /// Rotation is the reason there are two bearers: both work while the
    /// gateway is picking the new one up.
    #[test]
    fn both_bearers_are_accepted_while_one_is_being_retired() {
        let previous = "fedcba9876543210fedcba9876543210";
        let bearers = SharedBearer::new(BEARER.to_owned(), Some(previous.to_owned())).unwrap();
        assert!(bearers.accepts(BEARER.as_bytes()));
        assert!(bearers.accepts(previous.as_bytes()));
        assert!(!bearers.accepts(b"neither-of-those-two-values-here"));
        // A prefix of an accepted value must not be accepted; length is part of
        // the comparison, not something checked separately.
        let prefix: Vec<u8> = BEARER.bytes().take(16).collect();
        assert!(!bearers.accepts(&prefix));
    }

    /// A credential that is obviously not generated, and a rotation pair that
    /// rotates to itself, are configuration mistakes worth refusing to start
    /// over.
    #[test]
    fn unusable_bearer_configuration_is_refused_at_startup() {
        assert!(matches!(
            SharedBearer::new("short".to_owned(), None),
            Err(IngressError::BearerTooShort { .. })
        ));
        assert!(matches!(
            SharedBearer::new(format!("{BEARER} with space"), None),
            Err(IngressError::BearerNotHeaderSafe)
        ));
        // Long enough and no whitespace, yet impossible to present: a header
        // this service reads carries visible ASCII and nothing else.
        assert!(matches!(
            SharedBearer::new(format!("{BEARER}{}", '\u{7f}'), None),
            Err(IngressError::BearerNotHeaderSafe)
        ));
        assert!(matches!(
            SharedBearer::new(BEARER.to_owned(), Some(BEARER.to_owned())),
            Err(IngressError::BearersIdentical)
        ));
    }

    /// A key set URL this image cannot fetch would start the service and fail
    /// every request; it is refused while the reason is still obvious.
    #[test]
    fn an_unusable_key_set_url_is_refused_at_startup() {
        let settings = |url: &str| IdentitySettings {
            jwks_url: Url::parse(url).unwrap(),
            issuer: ISSUER.to_owned(),
        };
        assert!(matches!(
            IdentityVerifier::new(settings("ftp://gateway.invalid/jwks.json")),
            Err(IngressError::JwksNotHttp)
        ));
        // Both halves of userinfo, because a URL carrying a password and no
        // user name is still a URL with a credential in it.
        for with_credentials in [
            "http://user@gateway.invalid/jwks.json",
            "http://:secret@gateway.invalid/jwks.json",
            "http://user:secret@gateway.invalid/jwks.json",
        ] {
            assert!(
                matches!(
                    IdentityVerifier::new(settings(with_credentials)),
                    Err(IngressError::JwksUrlUnusable)
                ),
                "accepted {with_credentials}"
            );
        }
        assert!(
            IdentityVerifier::new(settings("http://mcp-gateway:8080/.well-known/jwks.json"))
                .is_ok()
        );
    }

    /// The bearer is a credential, and the most likely way one escapes is a
    /// struct printed whole.
    #[test]
    fn debug_output_never_contains_a_bearer() {
        let bearers = SharedBearer::new(BEARER.to_owned(), None).unwrap();
        let rendered = format!("{bearers:?}");
        assert!(!rendered.contains(BEARER), "rendered as {rendered}");
    }
}
