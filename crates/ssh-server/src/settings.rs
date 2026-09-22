//! What the process needs from its environment before it can mediate anything.
//!
//! Separate from [`ssh_core::config::Config`], which holds only the listen
//! address, because the healthcheck is a second process reading the same
//! environment: it needs to know where to probe and nothing else. Requiring it
//! to also resolve a registry, a credential set, and the gateway's keys would
//! make an unrelated misconfiguration read as an unhealthy container.

use std::env::VarError;
use std::path::PathBuf;
use std::sync::Arc;

use ssh_core::PrincipalId;
use ssh_core::approval::Windows;
use ssh_core::mediate::Bounds;
use ssh_core::run::Limits;
use ssh_core::session::Lifetime;
use url::Url;

use crate::ingress::{IdentitySettings, IngressError, SharedBearer};

#[derive(Clone, Debug)]
pub enum Authentication {
    Gateway(IdentitySettings),
    Stdio {
        principal: PrincipalId,
        operator: String,
    },
    Standalone {
        principal: PrincipalId,
        operator: String,
    },
}

/// Separately authenticated source allowed to append advisory evaluations.
#[derive(Clone)]
pub struct EvaluatorSettings {
    pub bearers: Arc<SharedBearer>,
    /// Deployment-owned identity; evaluators cannot choose their audit name.
    pub name: String,
}

/// Everything `serve` needs that is not compiled in.
///
/// `Debug` is written by hand: `SharedBearer` redacts itself and most of the
/// rest is a path, a URL, and an issuer name - but the notify endpoint may
/// embed a credential in its path, the way webhook services commonly issue
/// them, so only its presence is shown.
pub struct Settings {
    pub operator_header: axum::http::HeaderName,
    pub file_origin: Option<Url>,
    pub file_root: Option<PathBuf>,
    pub transfers: crate::transfer::TransferSettings,
    pub process: crate::process::ProcessOptions,
    /// Where the host and role registry is read from.
    pub registry: PathBuf,
    /// The MCP credential, current and optional previous value.
    pub bearers: Option<SharedBearer>,
    /// The dashboard proxy credential, or standalone operator password.
    ///
    /// Deliberately a different value from the gateway's. The dashboard decides
    /// whether a flagged command runs, and the gateway is how the agent that
    /// asked reaches this service - so one credential for both surfaces would
    /// let a caller that reached the tools approve its own requests.
    pub proxy_bearers: Option<SharedBearer>,
    /// Optional, separately authenticated advisory-evaluation writer.
    ///
    /// It is neither the agent gateway nor the human review proxy: accepting
    /// either credential here would let a decision participant manufacture
    /// evidence under the evaluator's name.
    pub evaluator: Option<EvaluatorSettings>,
    /// Internal, read-only endpoint for the deployment-owned durable audit
    /// source. Absent leaves historical dashboard views explicitly unavailable.
    pub audit_query: Option<Url>,
    pub audit_labels: Option<crate::audit_history::Labels>,
    /// Explicit identity source for the MCP and human surfaces.
    pub identity: Authentication,
    /// Where to post a note when a command is waiting on a human.
    ///
    /// Absent means nobody is told. That is a supported configuration: the
    /// dashboard still holds every waiting request, and a notifier is a pointer
    /// to it rather than a channel for deciding.
    pub notify: Option<Url>,
    /// The approvals page's address as a human reaches it. Links in notes and
    /// in held tool answers are this address with the waiting request's
    /// identifier as the fragment, and nothing else is derived from it.
    ///
    /// Absent means notes are not sent even if an endpoint is configured, and
    /// held answers name no page: a link that goes nowhere looks like the way
    /// to answer, and is not.
    pub dashboard: Option<Url>,
    /// Optional local human review, independent of upstream account authorization.
    pub review: ssh_core::policy::ReviewMode,
    /// The Host authorities the gateway reaches the MCP surface by, added to
    /// the transport's loopback-only default so a request naming one is not
    /// turned away as a rebinding attempt.
    ///
    /// The gateway addresses this service by a network name rather than by
    /// loopback, so without this the transport's Host guard would refuse every
    /// gateway call before the ingress ever saw it. Naming the authority in the
    /// deployment — beside the URL the gateway is given — keeps the two in step
    /// without compiling a name into the image. Empty leaves the default in
    /// place: loopback only, which is every case that reaches this surface over
    /// loopback and none that reaches it by name.
    pub trusted_hosts: Vec<String>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("registry", &self.registry)
            .field("bearers", &self.bearers)
            .field("proxy_bearers", &self.proxy_bearers)
            .field("evaluator_configured", &self.evaluator.is_some())
            .field("audit_query_configured", &self.audit_query.is_some())
            .field("identity", &self.identity)
            .field("notify_configured", &self.notify.is_some())
            .field("dashboard", &self.dashboard)
            .field("trusted_hosts", &self.trusted_hosts)
            .field("review", &self.review)
            .finish()
    }
}

impl Settings {
    pub const AUTH_MODE_VAR: &'static str = "MCP_SSH_AUTH_MODE";
    pub const STANDALONE_BEARER_VAR: &'static str = "MCP_SSH_BEARER";
    pub const PRINCIPAL_VAR: &'static str = "MCP_SSH_PRINCIPAL";
    pub const OPERATOR_PASSWORD_VAR: &'static str = "MCP_SSH_OPERATOR_PASSWORD";
    pub const OPERATOR_NAME_VAR: &'static str = "MCP_SSH_OPERATOR_NAME";
    pub const REGISTRY_VAR: &'static str = "MCP_SSH_REGISTRY";
    pub const BEARER_VAR: &'static str = "MCP_SSH_GATEWAY_BEARER_CURRENT";
    pub const PREVIOUS_BEARER_VAR: &'static str = "MCP_SSH_GATEWAY_BEARER_PREVIOUS";
    pub const PROXY_BEARER_VAR: &'static str = "MCP_SSH_PROXY_BEARER_CURRENT";
    pub const PREVIOUS_PROXY_BEARER_VAR: &'static str = "MCP_SSH_PROXY_BEARER_PREVIOUS";
    pub const EVALUATOR_BEARER_VAR: &'static str = "MCP_SSH_EVALUATOR_BEARER_CURRENT";
    pub const PREVIOUS_EVALUATOR_BEARER_VAR: &'static str = "MCP_SSH_EVALUATOR_BEARER_PREVIOUS";
    pub const EVALUATOR_NAME_VAR: &'static str = "MCP_SSH_EVALUATOR_NAME";
    pub const AUDIT_LABELS_VAR: &'static str = "MCP_SSH_AUDIT_LABELS";
    pub const AUDIT_QUERY_VAR: &'static str = "MCP_SSH_AUDIT_QUERY_URL";
    pub const NOTIFY_VAR: &'static str = "MCP_SSH_NOTIFY_URL";
    pub const DASHBOARD_VAR: &'static str = "MCP_SSH_DASHBOARD_URL";
    pub const JWKS_VAR: &'static str = "MCP_SSH_IDENTITY_JWKS_URL";
    pub const ISSUER_VAR: &'static str = "MCP_SSH_IDENTITY_ISSUER";
    pub const TRUSTED_HOSTS_VAR: &'static str = "MCP_SSH_TRUSTED_HOSTS";
    pub const OPERATOR_HEADER_VAR: &'static str = "MCP_SSH_OPERATOR_HEADER";
    pub const FILE_ROOT_VAR: &'static str = "MCP_SSH_FILE_ROOT";
    pub const FILE_ORIGIN_VAR: &'static str = "MCP_SSH_FILE_ORIGIN";
    pub const MAX_TRANSFER_VAR: &'static str = "MCP_SSH_MAX_TRANSFER_BYTES";
    pub const TRANSFER_TIMEOUT_VAR: &'static str = "MCP_SSH_TRANSFER_TIMEOUT_SECONDS";
    pub const STAGING_VAR: &'static str = "MCP_SSH_FILE_STAGING";
    pub const REVIEW_VAR: &'static str = "MCP_SSH_REVIEW";

    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_lookup(std::env::var)
    }

    /// Validate only configured surfaces, including credential separation.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, SettingsError>
    where
        F: Fn(&'static str) -> Result<String, VarError>,
    {
        use crate::process::{ProcessOptions, Transport};
        let process = ProcessOptions::from_lookup(&lookup)?;
        let registry = PathBuf::from(required(&lookup, Self::REGISTRY_VAR)?);
        let stdio = process.transport == Transport::Stdio;
        let gateway = match optional(&lookup, Self::AUTH_MODE_VAR)?.as_deref() {
            None | Some("standalone") => false,
            Some("gateway") if !stdio => true,
            _ => {
                return Err(SettingsError::Unusable {
                    var: Self::AUTH_MODE_VAR,
                });
            }
        };
        let incompatible: &[&'static str] = if gateway {
            &[
                Self::STANDALONE_BEARER_VAR,
                Self::PRINCIPAL_VAR,
                Self::OPERATOR_PASSWORD_VAR,
                Self::OPERATOR_NAME_VAR,
            ]
        } else {
            &[
                Self::BEARER_VAR,
                Self::PREVIOUS_BEARER_VAR,
                Self::PROXY_BEARER_VAR,
                Self::PREVIOUS_PROXY_BEARER_VAR,
                Self::JWKS_VAR,
                Self::ISSUER_VAR,
            ]
        };
        for &var in incompatible {
            if optional(&lookup, var)?.is_some() {
                return Err(SettingsError::Unusable { var });
            }
        }
        let current_var = if gateway {
            Self::BEARER_VAR
        } else {
            Self::STANDALONE_BEARER_VAR
        };
        let current = if stdio {
            if optional(&lookup, current_var)?.is_some() {
                return Err(SettingsError::Unusable { var: current_var });
            }
            None
        } else {
            Some(required(&lookup, current_var)?)
        };
        let previous = optional(&lookup, Self::PREVIOUS_BEARER_VAR)?;
        let proxy_var = if gateway {
            Self::PROXY_BEARER_VAR
        } else {
            Self::OPERATOR_PASSWORD_VAR
        };
        let proxy_current = optional(&lookup, proxy_var)?;
        let proxy_previous = optional(&lookup, Self::PREVIOUS_PROXY_BEARER_VAR)?;
        if !gateway
            && proxy_current
                .as_ref()
                .is_some_and(|value| value.len() > 1024)
        {
            return Err(SettingsError::Unusable { var: proxy_var });
        }
        if proxy_current.is_none()
            && (proxy_previous.is_some() || optional(&lookup, Self::OPERATOR_NAME_VAR)?.is_some())
        {
            return Err(SettingsError::Missing { var: proxy_var });
        }
        let review = optional(&lookup, Self::REVIEW_VAR)?
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| SettingsError::Unusable {
                var: Self::REVIEW_VAR,
            })?
            .unwrap_or_default();
        let dashboard = optional_url(&lookup, Self::DASHBOARD_VAR, &["http", "https"])?;
        if review != ssh_core::policy::ReviewMode::Disabled {
            if proxy_current.is_none() {
                return Err(SettingsError::Missing { var: proxy_var });
            }
            if dashboard.is_none() {
                return Err(SettingsError::Missing {
                    var: Self::DASHBOARD_VAR,
                });
            }
        }
        let evaluator_current = optional(&lookup, Self::EVALUATOR_BEARER_VAR)?;
        let evaluator_previous = optional(&lookup, Self::PREVIOUS_EVALUATOR_BEARER_VAR)?;
        let evaluator_name = optional(&lookup, Self::EVALUATOR_NAME_VAR)?;
        if evaluator_current.is_none() && (evaluator_previous.is_some() || evaluator_name.is_some())
        {
            return Err(SettingsError::Unusable {
                var: Self::EVALUATOR_BEARER_VAR,
            });
        }
        if evaluator_current.is_some() && evaluator_name.is_none() {
            return Err(SettingsError::Unusable {
                var: Self::EVALUATOR_NAME_VAR,
            });
        }
        if evaluator_name.as_ref().is_some_and(|name| name.len() > 128) {
            return Err(SettingsError::Unusable {
                var: Self::EVALUATOR_NAME_VAR,
            });
        }
        let agent_values = [current.as_deref(), previous.as_deref()];
        let operator_values = [proxy_current.as_deref(), proxy_previous.as_deref()];
        for (value, var) in [
            (proxy_current.as_deref(), proxy_var),
            (proxy_previous.as_deref(), Self::PREVIOUS_PROXY_BEARER_VAR),
        ] {
            if value.is_some_and(|value| agent_values.iter().flatten().any(|held| *held == value)) {
                return Err(SettingsError::Invalid {
                    var,
                    source: IngressError::BearersSharedAcrossSurfaces,
                });
            }
        }
        for (value, var) in [
            (evaluator_current.as_deref(), Self::EVALUATOR_BEARER_VAR),
            (
                evaluator_previous.as_deref(),
                Self::PREVIOUS_EVALUATOR_BEARER_VAR,
            ),
        ] {
            if value.is_some_and(|value| {
                agent_values
                    .iter()
                    .chain(&operator_values)
                    .flatten()
                    .any(|held| *held == value)
            }) {
                return Err(SettingsError::Invalid {
                    var,
                    source: IngressError::BearersSharedAcrossSurfaces,
                });
            }
        }
        let bearers = bearer_pair(current, previous, current_var, Self::PREVIOUS_BEARER_VAR)?;
        let proxy_bearers = bearer_pair(
            proxy_current,
            proxy_previous,
            proxy_var,
            Self::PREVIOUS_PROXY_BEARER_VAR,
        )?;
        let evaluator = match (
            bearer_pair(
                evaluator_current,
                evaluator_previous,
                Self::EVALUATOR_BEARER_VAR,
                Self::PREVIOUS_EVALUATOR_BEARER_VAR,
            )?,
            evaluator_name,
        ) {
            (Some(bearers), Some(name)) => Some(EvaluatorSettings {
                bearers: Arc::new(bearers),
                name,
            }),
            (None, None) => None,
            _ => {
                return Err(SettingsError::Unusable {
                    var: Self::EVALUATOR_BEARER_VAR,
                });
            }
        };
        let identity = if gateway {
            let identity = IdentitySettings {
                jwks_url: Url::parse(&required(&lookup, Self::JWKS_VAR)?).map_err(|_| {
                    SettingsError::Unusable {
                        var: Self::JWKS_VAR,
                    }
                })?,
                issuer: required(&lookup, Self::ISSUER_VAR)?,
            };
            identity
                .validate()
                .map_err(|source| SettingsError::Invalid {
                    var: if matches!(source, IngressError::IssuerBlank) {
                        Self::ISSUER_VAR
                    } else {
                        Self::JWKS_VAR
                    },
                    source,
                })?;
            Authentication::Gateway(identity)
        } else {
            let principal =
                optional(&lookup, Self::PRINCIPAL_VAR)?.unwrap_or_else(|| "local".to_owned());
            let principal =
                PrincipalId::parse(&principal).map_err(|_| SettingsError::Unusable {
                    var: Self::PRINCIPAL_VAR,
                })?;
            let operator = optional(&lookup, Self::OPERATOR_NAME_VAR)?
                .unwrap_or_else(|| "operator".to_owned());
            if operator.contains(':') || PrincipalId::parse(&operator).is_err() {
                return Err(SettingsError::Unusable {
                    var: Self::OPERATOR_NAME_VAR,
                });
            }
            for (name, var) in [
                (principal.as_str(), Self::PRINCIPAL_VAR),
                (operator.as_str(), Self::OPERATOR_NAME_VAR),
            ] {
                if bearers.as_ref().is_some_and(|b| b.accepts(name.as_bytes()))
                    || proxy_bearers
                        .as_ref()
                        .is_some_and(|b| b.accepts(name.as_bytes()))
                    || evaluator
                        .as_ref()
                        .is_some_and(|e| e.bearers.accepts(name.as_bytes()))
                {
                    return Err(SettingsError::Unusable { var });
                }
            }
            if stdio {
                Authentication::Stdio {
                    principal,
                    operator,
                }
            } else {
                Authentication::Standalone {
                    principal,
                    operator,
                }
            }
        };
        let audit_query = optional_base_url(&lookup, Self::AUDIT_QUERY_VAR)?;
        let audit_labels = optional(&lookup, Self::AUDIT_LABELS_VAR)?
            .map(|raw| {
                crate::audit_history::Labels::parse(&raw).map_err(|_| SettingsError::Unusable {
                    var: Self::AUDIT_LABELS_VAR,
                })
            })
            .transpose()?;
        if audit_query.is_some() != audit_labels.is_some() {
            return Err(SettingsError::Unusable {
                var: Self::AUDIT_LABELS_VAR,
            });
        }
        let configured_header = optional(&lookup, Self::OPERATOR_HEADER_VAR)?;
        if configured_header.is_some() && !gateway {
            return Err(SettingsError::Unusable {
                var: Self::OPERATOR_HEADER_VAR,
            });
        }
        let operator_header = axum::http::HeaderName::from_bytes(
            configured_header
                .as_deref()
                .unwrap_or(crate::dashboard::OPERATOR_HEADER)
                .as_bytes(),
        )
        .map_err(|_| SettingsError::Unusable {
            var: Self::OPERATOR_HEADER_VAR,
        })?;
        if matches!(
            operator_header.as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-mcp-identity"
        ) {
            return Err(SettingsError::Unusable {
                var: Self::OPERATOR_HEADER_VAR,
            });
        }
        let file_root = optional(&lookup, Self::FILE_ROOT_VAR)?.map(PathBuf::from);
        if file_root.is_some() && (!stdio || optional(&lookup, Self::FILE_ORIGIN_VAR)?.is_some()) {
            return Err(SettingsError::Unusable {
                var: Self::FILE_ROOT_VAR,
            });
        }
        let defaults = crate::transfer::TransferSettings::default();
        let max_bytes = positive(&lookup, Self::MAX_TRANSFER_VAR, defaults.max_bytes)?;
        // Network/local outputs and local snapshots each reserve a full allowance.
        if max_bytes.checked_mul(32).is_none() || max_bytes > i64::MAX as u64 {
            return Err(SettingsError::Unusable {
                var: Self::MAX_TRANSFER_VAR,
            });
        }
        let seconds = positive(
            &lookup,
            Self::TRANSFER_TIMEOUT_VAR,
            defaults.timeout.as_secs(),
        )?;
        if seconds > 86400 {
            return Err(SettingsError::Unusable {
                var: Self::TRANSFER_TIMEOUT_VAR,
            });
        }
        let transfers = crate::transfer::TransferSettings {
            max_bytes,
            timeout: std::time::Duration::from_secs(seconds),
            staging: optional(&lookup, Self::STAGING_VAR)?.map_or(defaults.staging, PathBuf::from),
        };
        Ok(Self {
            operator_header,
            file_root,
            transfers,
            file_origin: optional_url(&lookup, Self::FILE_ORIGIN_VAR, &["http", "https"])?,
            process,
            registry,
            bearers,
            proxy_bearers,
            evaluator,
            identity,
            review,
            dashboard,
            audit_query,
            audit_labels,
            notify: optional_url(&lookup, Self::NOTIFY_VAR, &["http", "https"])?,
            trusted_hosts: list(&lookup, Self::TRUSTED_HOSTS_VAR)?,
        })
    }
}

fn positive<F>(lookup: &F, var: &'static str, default: u64) -> Result<u64, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    match lookup(var) {
        Err(VarError::NotPresent) => Ok(default),
        Ok(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => value
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(SettingsError::Unusable { var }),
        _ => Err(SettingsError::Unusable { var }),
    }
}

fn bearer_pair(
    current: Option<String>,
    previous: Option<String>,
    current_var: &'static str,
    previous_var: &'static str,
) -> Result<Option<SharedBearer>, SettingsError> {
    let Some(current) = current else {
        return if previous.is_none() {
            Ok(None)
        } else {
            Err(SettingsError::Missing { var: current_var })
        };
    };
    SharedBearer::new(current.clone(), None).map_err(|source| SettingsError::Invalid {
        var: current_var,
        source,
    })?;
    let var = if previous.is_some() {
        previous_var
    } else {
        current_var
    };
    SharedBearer::new(current, previous)
        .map(Some)
        .map_err(|source| SettingsError::Invalid { var, source })
}

/// What the service will not exceed, until a deployment says otherwise.
///
/// Chosen here rather than read from the environment. Every value below is a
/// bound on what one caller may consume, and a deployment that has not thought
/// about them is better served by ones that were thought about than by none.
/// They become configuration when an operator has a reason to disagree with a
/// specific one, which is a smaller change than exposing knobs nobody has set.
#[must_use]
pub fn bounds() -> Bounds {
    Bounds {
        lifetime: Lifetime {
            // Long enough for one piece of work to span a day, including long
            // pauses between commands, while still bounding an abandoned
            // session.
            //
            // Also has to outlast a command held for a person, with room to
            // spare. The hold is the last thing that touches the session, and
            // the answer is collected by a later attempt in that same session,
            // so deciding and collecting both have to fit inside it or a
            // decision dies with the session that was entitled to make it.
            //
            // Room to spare, because a lapse is only observable *after* the
            // agreement stops being collectable: an agent that returns late
            // learns nothing from a session that ended at the same moment its
            // window did. Somebody agreeing at the last permitted moment is
            // the case that decides this, so the session outlives that by a
            // further collection window — long enough for the attempt that
            // was owed the answer to come back and be told.
            idle: 24 * 60 * 60 * 1_000,
            // A ceiling on the window regardless of activity, so a session in
            // continuous use is still a bounded grant rather than a standing
            // one. It matches the idle window: either way, one day is the most
            // a session can remain usable.
            max: 24 * 60 * 60 * 1_000,
            // Long enough that an agent retrying after a pause is told what its
            // session was for rather than that it never existed.
            grace: 10 * 60 * 1_000,
        },
        // Enough for an agent working several hosts at once; far short of what
        // it takes to exhaust the service by opening sessions.
        sessions_per_principal: 8,
        run: Limits::default(),
        approval: Windows {
            // Long enough that somebody who was away from the keyboard when the
            // request arrived can answer within the hour, and short enough that
            // a question nobody wants stops waiting on its own.
            decide_within: 60 * 60 * 1_000,
            // The agent's turnaround is what this has to cover, not the
            // person's: the window opens when the answer is given rather than
            // when it was asked for. Long enough that an agent which left to
            // tell somebody, and came back, still collects what it was given.
            //
            // An agreement is armed while it lasts — the approved command runs
            // whenever the agent next asks, and nothing recalls it — so this is
            // bounded rather than generous. One that outlives the window is not
            // dropped quietly: the next attempt is told that it lapsed.
            redeem_within: 15 * 60 * 1_000,
        },
        // A human-facing queue is the scarce resource. Keep one session from
        // burying the request that matters while allowing a few related steps.
        waiting_per_session: 4,
    }
}

fn required<F>(lookup: &F, var: &'static str) -> Result<String, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    match lookup(var) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) | Err(VarError::NotPresent) => Err(SettingsError::Missing { var }),
        Err(VarError::NotUnicode(_)) => Err(SettingsError::Unusable { var }),
    }
}

fn optional<F>(lookup: &F, var: &'static str) -> Result<Option<String>, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    match lookup(var) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(SettingsError::Unusable { var }),
    }
}

/// A comma-separated list, trimmed, with empty entries dropped. Absent or all
/// separators yields an empty list — the same as not setting it, because a
/// value that names nothing asked for nothing.
fn list<F>(lookup: &F, var: &'static str) -> Result<Vec<String>, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    let Some(raw) = optional(lookup, var)? else {
        return Ok(Vec::new());
    };
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect())
}

fn optional_url<F>(
    lookup: &F,
    var: &'static str,
    schemes: &[&str],
) -> Result<Option<Url>, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    let Some(raw) = optional(lookup, var)? else {
        return Ok(None);
    };
    let url = Url::parse(&raw).map_err(|_| SettingsError::Unusable { var })?;
    // A URL is not enough: `mailto:` parses. What these settings name is a
    // place on the network, so anything without an allowed scheme and a host
    // is refused under the variable that carries it.
    if !schemes.contains(&url.scheme()) || !url.has_host() {
        return Err(SettingsError::Unusable { var });
    }
    Ok(Some(url))
}

fn optional_base_url<F>(lookup: &F, var: &'static str) -> Result<Option<Url>, SettingsError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    let Some(url) = optional_url(lookup, var, &["http", "https"])? else {
        return Ok(None);
    };
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(SettingsError::Unusable { var });
    }
    Ok(Some(url))
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error(transparent)]
    Process(#[from] crate::process::ProcessError),
    #[error("{var} must be set; the service cannot mediate access without it")]
    Missing { var: &'static str },
    #[error("{var} is set to something this service cannot read")]
    Unusable { var: &'static str },
    #[error("{var} is set to something this service cannot use: {source}")]
    Invalid {
        var: &'static str,
        #[source]
        source: IngressError,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const BEARER: &str = "0123456789abcdef0123456789abcdef";
    const PROXY_BEARER: &str = "89abcdef0123456789abcdef01234567";

    fn standalone() -> HashMap<&'static str, String> {
        HashMap::from([
            (Settings::AUTH_MODE_VAR, "standalone".to_owned()),
            (Settings::REGISTRY_VAR, "registry.json".to_owned()),
            (Settings::STANDALONE_BEARER_VAR, BEARER.to_owned()),
            (Settings::OPERATOR_PASSWORD_VAR, PROXY_BEARER.to_owned()),
        ])
    }

    #[test]
    fn transfer_settings_default_to_two_decimal_gigabytes_and_reject_invalid_values() {
        let mut vars = complete();
        let defaults = Settings::from_lookup(read(&vars)).unwrap().transfers;
        assert_eq!(defaults.max_bytes, 2_000_000_000);
        assert_eq!(defaults.timeout.as_secs(), 1800);
        vars.insert(Settings::MAX_TRANSFER_VAR, "123456789".to_owned());
        vars.insert(Settings::TRANSFER_TIMEOUT_VAR, "3600".to_owned());
        let configured = Settings::from_lookup(read(&vars)).unwrap().transfers;
        assert_eq!(configured.max_bytes, 123456789);
        assert_eq!(configured.timeout.as_secs(), 3600);
        for value in [
            "",
            "0",
            "-1",
            "2GB",
            "18446744073709551616",
            "18446744073709551615",
        ] {
            vars.insert(Settings::MAX_TRANSFER_VAR, value.to_owned());
            assert!(matches!(
                Settings::from_lookup(read(&vars)),
                Err(SettingsError::Unusable {
                    var: Settings::MAX_TRANSFER_VAR
                })
            ));
        }
    }

    #[test]
    fn standalone_starts_without_a_gateway_and_has_fixed_names() {
        let vars = standalone();
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(
            matches!(settings.identity, Authentication::Standalone { principal, operator }
            if principal.as_str() == "local" && operator == "operator")
        );
        assert!(
            settings
                .bearers
                .as_ref()
                .unwrap()
                .accepts(BEARER.as_bytes())
        );
        assert!(
            !settings
                .proxy_bearers
                .as_ref()
                .unwrap()
                .accepts(BEARER.as_bytes())
        );
    }

    #[test]
    fn standalone_configuration_is_explicit_and_credentials_are_separate() {
        let mut vars = standalone();
        vars.remove(Settings::STANDALONE_BEARER_VAR);
        assert!(Settings::from_lookup(read(&vars)).is_err());
        for (var, value) in [
            (Settings::AUTH_MODE_VAR, "automatic"),
            (Settings::BEARER_VAR, BEARER),
            (Settings::JWKS_VAR, "http://gateway.invalid/keys"),
            (Settings::OPERATOR_PASSWORD_VAR, BEARER),
            (Settings::OPERATOR_NAME_VAR, "name:with:colon"),
            (Settings::PRINCIPAL_VAR, BEARER),
            (Settings::OPERATOR_NAME_VAR, PROXY_BEARER),
        ] {
            let mut vars = standalone();
            vars.insert(var, value.to_owned());
            assert!(
                Settings::from_lookup(read(&vars)).is_err(),
                "accepted invalid {var}"
            );
        }
    }

    fn complete() -> HashMap<&'static str, String> {
        HashMap::from([
            (Settings::AUTH_MODE_VAR, "gateway".to_owned()),
            (
                Settings::REGISTRY_VAR,
                "/etc/mcp-ssh/registry.json".to_owned(),
            ),
            (Settings::BEARER_VAR, BEARER.to_owned()),
            (Settings::PROXY_BEARER_VAR, PROXY_BEARER.to_owned()),
            (
                Settings::JWKS_VAR,
                "http://mcp-gateway:8080/.well-known/jwks.json".to_owned(),
            ),
            (Settings::ISSUER_VAR, "https://gateway.example".to_owned()),
        ])
    }

    fn read<'a>(
        vars: &'a HashMap<&'static str, String>,
    ) -> impl Fn(&'static str) -> Result<String, VarError> + 'a {
        move |name| vars.get(name).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn a_complete_environment_is_accepted() {
        let vars = complete();
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert_eq!(
            settings.registry,
            PathBuf::from("/etc/mcp-ssh/registry.json")
        );
        assert!(
            settings
                .bearers
                .as_ref()
                .unwrap()
                .accepts(BEARER.as_bytes())
        );
        assert!(
            matches!(settings.identity, Authentication::Gateway(identity) if identity.issuer == "https://gateway.example")
        );
    }

    /// The service authenticates its only caller and decides what that caller
    /// may reach, so starting without any of these would mean starting without
    /// the thing it exists to do. Every one of them is refused by name, because
    /// "failed to start" is not an answer an operator can act on.
    #[test]
    fn every_setting_the_service_cannot_work_without_is_named_when_it_is_missing() {
        for var in [
            Settings::REGISTRY_VAR,
            Settings::BEARER_VAR,
            Settings::JWKS_VAR,
            Settings::ISSUER_VAR,
        ] {
            let mut vars = complete();
            vars.remove(var);
            let err = Settings::from_lookup(read(&vars)).unwrap_err();
            assert!(
                matches!(err, SettingsError::Missing { var: named } if named == var),
                "{var} missing produced {err:?}"
            );

            // Present but blank is the same failure as absent: a variable set
            // to nothing is a deployment that meant to set it.
            let mut blanked = complete();
            blanked.insert(var, "   ".to_owned());
            assert!(matches!(
                Settings::from_lookup(read(&blanked)).unwrap_err(),
                SettingsError::Missing { .. }
            ));
        }
    }

    /// The dashboard and the MCP surface are separated by their credentials,
    /// so a value accepted on both is a configuration that removed the
    /// boundary; startup refuses it, naming the proxy-side variable that
    /// carries the shared value.
    #[test]
    fn a_credential_shared_between_the_gateway_and_the_proxy_is_refused() {
        for (var, value) in [
            (Settings::PROXY_BEARER_VAR, BEARER),
            (Settings::PREVIOUS_PROXY_BEARER_VAR, BEARER),
        ] {
            let mut vars = complete();
            vars.insert(var, value.to_owned());
            let err = Settings::from_lookup(read(&vars)).unwrap_err();
            assert!(
                matches!(
                    &err,
                    SettingsError::Invalid {
                        var: named,
                        source: IngressError::BearersSharedAcrossSurfaces,
                    } if *named == var
                ),
                "sharing via {var} produced {err:?}"
            );
        }

        // The other direction of a rotation: the gateway's *previous* value
        // reused as the proxy's current one is the same removed boundary.
        let mut vars = complete();
        vars.insert(Settings::PREVIOUS_BEARER_VAR, PROXY_BEARER.to_owned());
        assert!(matches!(
            Settings::from_lookup(read(&vars)).unwrap_err(),
            SettingsError::Invalid {
                var: Settings::PROXY_BEARER_VAR,
                source: IngressError::BearersSharedAcrossSurfaces,
            }
        ));
    }

    #[test]
    fn evaluator_settings_are_optional_and_separately_authenticated() {
        let vars = complete();
        assert!(
            Settings::from_lookup(read(&vars))
                .unwrap()
                .evaluator
                .is_none()
        );

        let evaluator_bearer = "fedcba9876543210fedcba9876543210";
        let mut vars = complete();
        vars.insert(Settings::EVALUATOR_BEARER_VAR, evaluator_bearer.to_owned());
        vars.insert(Settings::EVALUATOR_NAME_VAR, "intent-reviewer".to_owned());
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        let evaluator = settings.evaluator.expect("evaluator configured");
        assert!(evaluator.bearers.accepts(evaluator_bearer.as_bytes()));
        assert!(!evaluator.bearers.accepts(BEARER.as_bytes()));
        assert!(!evaluator.bearers.accepts(PROXY_BEARER.as_bytes()));
        assert_eq!(evaluator.name, "intent-reviewer");
    }

    #[test]
    fn operator_header_is_configurable_but_cannot_name_credentials() {
        let mut vars = complete();
        vars.insert(Settings::OPERATOR_HEADER_VAR, "x-test-operator".to_owned());
        assert_eq!(
            Settings::from_lookup(read(&vars))
                .unwrap()
                .operator_header
                .as_str(),
            "x-test-operator"
        );
        for invalid in ["Authorization", "cookie", "x-mcp-identity", "bad header"] {
            vars.insert(Settings::OPERATOR_HEADER_VAR, invalid.to_owned());
            assert!(Settings::from_lookup(read(&vars)).is_err());
        }
    }

    #[test]
    fn durable_audit_reader_is_optional_and_requires_a_web_base() {
        let vars = complete();
        assert!(
            Settings::from_lookup(read(&vars))
                .unwrap()
                .audit_query
                .is_none()
        );

        let mut configured = complete();
        configured.insert(Settings::AUDIT_QUERY_VAR, "http://loki:3100/".to_owned());
        configured.insert(
            Settings::AUDIT_LABELS_VAR,
            r#"{"service":"ssh"}"#.to_owned(),
        );
        assert_eq!(
            Settings::from_lookup(read(&configured))
                .unwrap()
                .audit_query
                .as_ref()
                .map(Url::as_str),
            Some("http://loki:3100/")
        );

        for value in [
            "ftp://loki:3100/",
            "http://user:secret@loki:3100/",
            "http://loki:3100/a/path",
            "http://loki:3100/?token=secret",
        ] {
            let mut invalid = complete();
            invalid.insert(Settings::AUDIT_QUERY_VAR, value.to_owned());
            assert!(matches!(
                Settings::from_lookup(read(&invalid)).unwrap_err(),
                SettingsError::Unusable {
                    var: Settings::AUDIT_QUERY_VAR
                }
            ));
        }
    }

    #[test]
    fn partial_or_shared_evaluator_settings_are_refused() {
        let evaluator_bearer = "fedcba9876543210fedcba9876543210";
        for (var, value, expected) in [
            (
                Settings::EVALUATOR_NAME_VAR,
                "intent-reviewer",
                Settings::EVALUATOR_BEARER_VAR,
            ),
            (
                Settings::EVALUATOR_BEARER_VAR,
                evaluator_bearer,
                Settings::EVALUATOR_NAME_VAR,
            ),
        ] {
            let mut vars = complete();
            vars.insert(var, value.to_owned());
            assert!(matches!(
                Settings::from_lookup(read(&vars)).unwrap_err(),
                SettingsError::Unusable { var } if var == expected
            ));
        }

        for shared in [BEARER, PROXY_BEARER] {
            let mut vars = complete();
            vars.insert(Settings::EVALUATOR_BEARER_VAR, shared.to_owned());
            vars.insert(Settings::EVALUATOR_NAME_VAR, "intent-reviewer".to_owned());
            assert!(matches!(
                Settings::from_lookup(read(&vars)).unwrap_err(),
                SettingsError::Invalid {
                    var: Settings::EVALUATOR_BEARER_VAR,
                    source: IngressError::BearersSharedAcrossSurfaces,
                }
            ));
        }
    }

    #[test]
    fn evaluator_credentials_are_redacted_from_debug_output() {
        let secret = "fedcba9876543210fedcba9876543210";
        let mut vars = complete();
        vars.insert(Settings::EVALUATOR_BEARER_VAR, secret.to_owned());
        vars.insert(Settings::EVALUATOR_NAME_VAR, "intent-reviewer".to_owned());
        let rendered = format!("{:?}", Settings::from_lookup(read(&vars)).unwrap());
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("evaluator_configured"));
    }

    /// A webhook endpoint commonly carries its credential in the path, and a
    /// settings value is exactly the kind of thing diagnostics format whole -
    /// so the rendered form must say whether a notifier is configured and
    /// nothing about where it points.
    #[test]
    fn debug_output_never_contains_the_notify_endpoint() {
        let mut vars = complete();
        vars.insert(
            Settings::NOTIFY_VAR,
            "http://ntfy/hook/a-secret-token-nobody-may-see".to_owned(),
        );
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        let rendered = format!("{settings:?}");
        assert!(
            !rendered.contains("a-secret-token-nobody-may-see") && !rendered.contains("ntfy"),
            "the notify endpoint reached the debug form: {rendered}"
        );
        assert!(rendered.contains("notify_configured"));
    }

    /// Optional endpoints must use a supported web scheme before serving.
    #[test]
    fn a_notifier_setting_that_could_never_work_is_refused_by_name() {
        for (var, value) in [
            (Settings::NOTIFY_VAR, "ftp://ntfy/mcp-ssh"),
            (Settings::NOTIFY_VAR, "not a url"),
            (Settings::DASHBOARD_VAR, "mailto:chris@example.org"),
            (Settings::DASHBOARD_VAR, "data:text/plain,hello"),
        ] {
            let mut vars = complete();
            vars.insert(var, value.to_owned());
            let err = Settings::from_lookup(read(&vars)).unwrap_err();
            assert!(
                matches!(&err, SettingsError::Unusable { var: named } if *named == var),
                "{var}={value} produced {err:?}"
            );
        }

        let mut vars = complete();
        vars.insert(Settings::NOTIFY_VAR, "http://ntfy/mcp-ssh".to_owned());
        vars.insert(Settings::DASHBOARD_VAR, "https://ssh.example/".to_owned());
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(settings.notify.is_some());
        assert!(settings.dashboard.is_some());
    }

    #[test]
    fn outbound_integrations_accept_https() {
        let mut vars = complete();
        vars.insert(
            Settings::JWKS_VAR,
            "https://gateway.example/keys".to_owned(),
        );
        vars.insert(
            Settings::NOTIFY_VAR,
            "https://notify.example/hook".to_owned(),
        );
        vars.insert(
            Settings::AUDIT_QUERY_VAR,
            "https://loki.example/".to_owned(),
        );
        vars.insert(
            Settings::AUDIT_LABELS_VAR,
            r#"{"service":"ssh"}"#.to_owned(),
        );
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(
            matches!(settings.identity, Authentication::Gateway(identity) if identity.jwks_url.scheme() == "https")
        );
        assert_eq!(settings.notify.unwrap().scheme(), "https");
        assert_eq!(settings.audit_query.unwrap().scheme(), "https");
    }

    /// The previous bearer is the one setting that is genuinely optional: it
    /// exists only while a rotation is in flight.
    #[test]
    fn the_previous_bearer_is_optional_and_accepted_when_present() {
        let previous = "fedcba9876543210fedcba9876543210";
        let mut vars = complete();
        assert!(Settings::from_lookup(read(&vars)).is_ok());

        vars.insert(Settings::PREVIOUS_BEARER_VAR, previous.to_owned());
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(
            settings
                .bearers
                .as_ref()
                .unwrap()
                .accepts(BEARER.as_bytes())
        );
        assert!(
            settings
                .bearers
                .as_ref()
                .unwrap()
                .accepts(previous.as_bytes())
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_a_setting() {
        let mut vars = complete();
        vars.insert(
            Settings::ISSUER_VAR,
            "  https://gateway.example  ".to_owned(),
        );
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(
            matches!(settings.identity, Authentication::Gateway(identity) if identity.issuer == "https://gateway.example")
        );
    }

    #[test]
    fn unusable_ingress_settings_are_refused_by_name() {
        let cases = [
            (
                Settings::BEARER_VAR,
                Settings::BEARER_VAR,
                "short".to_owned(),
            ),
            (
                Settings::PREVIOUS_BEARER_VAR,
                Settings::PREVIOUS_BEARER_VAR,
                "short".to_owned(),
            ),
            (
                Settings::PREVIOUS_BEARER_VAR,
                Settings::PREVIOUS_BEARER_VAR,
                BEARER.to_owned(),
            ),
            (
                Settings::JWKS_VAR,
                Settings::JWKS_VAR,
                "ftp://mcp-gateway.invalid/jwks.json".to_owned(),
            ),
        ];
        for (changed, expected, value) in cases {
            let mut vars = complete();
            vars.insert(changed, value);
            let error = Settings::from_lookup(read(&vars)).unwrap_err();
            assert!(
                matches!(error, SettingsError::Invalid { var, .. } if var == expected),
                "{changed} produced {error:?}"
            );
        }
    }

    #[test]
    fn an_unparseable_key_set_url_is_refused_by_name() {
        let mut vars = complete();
        vars.insert(Settings::JWKS_VAR, "not a url".to_owned());
        assert!(matches!(
            Settings::from_lookup(read(&vars)).unwrap_err(),
            SettingsError::Unusable {
                var: Settings::JWKS_VAR
            }
        ));
    }

    /// Trusted hosts are a list beside the gateway's URL, not a single value:
    /// absent means the transport keeps its loopback-only default, and a set
    /// value is split, trimmed, and stripped of the empty entries a trailing or
    /// doubled comma leaves — so the same nothing whether unset or set to
    /// separators alone.
    #[test]
    fn trusted_hosts_are_an_optional_trimmed_list() {
        let vars = complete();
        assert!(
            Settings::from_lookup(read(&vars))
                .unwrap()
                .trusted_hosts
                .is_empty(),
            "an unset list produced entries"
        );

        for blank in ["", "   ", " , ,"] {
            let mut vars = complete();
            vars.insert(Settings::TRUSTED_HOSTS_VAR, blank.to_owned());
            assert!(
                Settings::from_lookup(read(&vars))
                    .unwrap()
                    .trusted_hosts
                    .is_empty(),
                "{blank:?} produced entries"
            );
        }

        let mut vars = complete();
        vars.insert(
            Settings::TRUSTED_HOSTS_VAR,
            " mcp-ssh:8080 , mcp-ssh ,".to_owned(),
        );
        assert_eq!(
            Settings::from_lookup(read(&vars)).unwrap().trusted_hosts,
            ["mcp-ssh:8080", "mcp-ssh"],
        );
    }

    #[test]
    fn local_review_is_explicit_and_invalid_modes_are_rejected() {
        let vars = complete();
        assert_eq!(
            Settings::from_lookup(read(&vars)).unwrap().review,
            ssh_core::policy::ReviewMode::Disabled
        );

        let mut vars = complete();
        vars.insert(Settings::REVIEW_VAR, "privileged".to_owned());
        vars.insert(
            Settings::DASHBOARD_VAR,
            "https://review.example/dashboard".to_owned(),
        );
        assert_eq!(
            Settings::from_lookup(read(&vars)).unwrap().review,
            ssh_core::policy::ReviewMode::Privileged
        );
        vars.insert(Settings::REVIEW_VAR, "read".to_owned());
        assert!(Settings::from_lookup(read(&vars)).is_err());
    }

    /// The bounds are a deliberate set rather than defaults nobody chose, so
    /// their operating windows are pinned rather than left implicit in
    /// arithmetic at the construction site.
    #[test]
    fn the_shipped_windows_match_the_operating_budget() {
        let bounds = bounds();
        assert_eq!(bounds.lifetime.idle, 24 * 60 * 60 * 1_000);
        assert_eq!(bounds.lifetime.max, 24 * 60 * 60 * 1_000);
        assert_eq!(bounds.approval.decide_within, 60 * 60 * 1_000);
        assert_eq!(bounds.approval.redeem_within, 15 * 60 * 1_000);
    }

    /// The bounds are a deliberate set rather than defaults nobody chose, so
    /// this pins the relationships that would be wrong in any deployment: a
    /// session cannot idle for longer than it may live, a lapsed session must
    /// be remembered for long enough to say so, and a session must outlast a
    /// command held in it.
    #[test]
    fn the_shipped_bounds_are_internally_coherent() {
        let bounds = bounds();
        assert!(bounds.lifetime.idle <= bounds.lifetime.max);
        assert!(bounds.lifetime.grace > 0);
        assert!(bounds.sessions_per_principal > 0);
        // Holding a command is the last thing that touches its session, and the
        // answer is collected by a later attempt in that same session. Deciding
        // and collecting therefore both have to fit inside an idle session, or
        // a person is left entitled to decide something no attempt can act on.
        //
        // And a further collection window beyond that, because a lapse becomes
        // reportable only once the agreement has stopped being collectable, and
        // only while the session is still there to report it in. Sized to the
        // case that decides it: somebody agreeing at the last permitted moment,
        // whose agreement then expires at the latest instant it can.
        assert!(
            bounds.lifetime.idle
                >= bounds.approval.decide_within + 2 * bounds.approval.redeem_within,
            "a lapse could become reportable only after its session had gone"
        );
    }
    #[test]
    fn standalone_http_needs_no_optional_integration() {
        let mut vars = standalone();
        vars.remove(Settings::AUTH_MODE_VAR);
        vars.remove(Settings::OPERATOR_PASSWORD_VAR);
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(settings.proxy_bearers.is_none());
        assert!(settings.evaluator.is_none());
        assert!(settings.audit_query.is_none());
        assert!(matches!(
            settings.identity,
            Authentication::Standalone { .. }
        ));
        vars.insert(Settings::REVIEW_VAR, "all".to_owned());
        assert!(matches!(
            Settings::from_lookup(read(&vars)),
            Err(SettingsError::Missing {
                var: Settings::OPERATOR_PASSWORD_VAR
            })
        ));
        vars.insert(Settings::OPERATOR_PASSWORD_VAR, PROXY_BEARER.to_owned());
        vars.insert(
            Settings::DASHBOARD_VAR,
            "http://localhost:8080/dashboard".to_owned(),
        );
        assert!(Settings::from_lookup(read(&vars)).is_ok());
    }

    #[test]
    fn stdio_uses_launch_authority_and_can_enable_separate_human_review() {
        let mut vars = HashMap::from([
            (Settings::REGISTRY_VAR, "registry.json".to_owned()),
            (
                crate::process::ProcessOptions::TRANSPORT_VAR,
                "stdio".to_owned(),
            ),
            (
                crate::process::ProcessOptions::AUDIT_VAR,
                "file:audit.jsonl".to_owned(),
            ),
        ]);
        let settings = Settings::from_lookup(read(&vars)).unwrap();
        assert!(settings.bearers.is_none());
        assert!(settings.proxy_bearers.is_none());
        assert!(
            matches!(settings.identity, Authentication::Stdio { principal, .. } if principal.as_str() == "local")
        );
        vars.insert(Settings::STANDALONE_BEARER_VAR, BEARER.to_owned());
        assert!(Settings::from_lookup(read(&vars)).is_err());
        vars.remove(Settings::STANDALONE_BEARER_VAR);
        vars.insert(Settings::REVIEW_VAR, "all".to_owned());
        vars.insert(Settings::OPERATOR_PASSWORD_VAR, PROXY_BEARER.to_owned());
        vars.insert(
            Settings::DASHBOARD_VAR,
            "http://localhost:8080/dashboard".to_owned(),
        );
        assert!(
            Settings::from_lookup(read(&vars))
                .unwrap()
                .proxy_bearers
                .is_some()
        );
    }
}
