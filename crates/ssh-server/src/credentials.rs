//! Where the running service gets the keys it authenticates to targets with.
//!
//! The values arrive as environment variables, injected by the deployment.
//! This adapter reads them once at startup and does not write them to disk.
//! This module's whole job is to turn the name the registry uses for a
//! credential into the variable that holds it, and to be unable to do anything
//! else with it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;

use ssh_core::connect::{CredentialError, CredentialSource, usable_credential};
use ssh_core::registry::{CredentialRef, Registry};
use ssh_core::secret::Secret;

/// Prefix on every variable this reads.
///
/// Namespaced so a registry cannot name a credential that resolves to an
/// unrelated variable in the process environment — `PATH`, or the gateway
/// bearer.
const PREFIX: &str = "MCP_SSH_CREDENTIAL_";

/// Credentials read from the process environment, once, at startup.
///
/// Read once rather than on each use. The alternative reads the environment on
/// a request path, which gains nothing — the environment cannot change while
/// the process runs — and makes the set of credentials the service holds
/// depend on when it was asked.
pub struct EnvCredentials {
    held: HashMap<String, Secret<String>>,
}

impl EnvCredentials {
    /// Collects every credential the environment offers.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_pairs(env::vars())
    }

    fn from_pairs<I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let held = pairs
            .into_iter()
            .filter_map(|(name, value)| {
                let suffix = name.strip_prefix(PREFIX)?;
                if suffix.is_empty() || value.is_empty() {
                    return None;
                }
                Some((suffix.to_owned(), Secret::new(value)))
            })
            .collect();
        Self { held }
    }

    /// The variable name a credential reference is read from.
    ///
    /// Upper-cased with everything a variable name cannot carry folded to an
    /// underscore, so `mcp-ssh/dns1/readonly` is held in
    /// `MCP_SSH_CREDENTIAL_MCP_SSH_DNS1_READONLY`. That keeps the name an
    /// operator has to type recognisable, at the cost of not being injective:
    /// `dns1/readonly` and `dns1-readonly` fold together.
    ///
    /// Which is why nothing relies on it being injective. [`Self::unusable`]
    /// checks the registry at startup and refuses to run if two of *its*
    /// references share a variable — the collision that matters is between
    /// references a deployment actually configured, and that is decidable
    /// before anything is served rather than guessed at from the shape of a
    /// name.
    #[must_use]
    pub fn variable(reference: &CredentialRef) -> String {
        reference
            .as_str()
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    /// Everything wrong with this deployment's credentials, before it serves.
    ///
    /// Three things make a registry unusable, and each is silent until somebody
    /// tries to reach the host in question: a reference with no credential
    /// behind it, a credential that is not a key this service could
    /// authenticate with, and two references that read one credential. The
    /// last is the dangerous one — it means a host authenticating with a key
    /// issued for another — and none of them is worth discovering from an
    /// agent's failed command.
    ///
    /// What it does not attempt is whether a key that parses is the *right*
    /// key: only the target can answer that, and a check that cannot be
    /// complete is better bounded at what is decidable here than extended
    /// until it looks like one.
    #[must_use]
    pub fn unusable(&self, registry: &Registry) -> Vec<String> {
        let mut by_variable: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for host in registry.hosts() {
            for role in registry.roles(host) {
                let Ok(target) = registry.resolve(host, role) else {
                    continue;
                };
                let reference = target.credential();
                by_variable
                    .entry(Self::variable(reference))
                    .or_default()
                    .insert(reference.as_str().to_owned());
            }
        }

        let mut wrong = Vec::new();
        for (variable, references) in by_variable {
            let named: Vec<&str> = references.iter().map(String::as_str).collect();
            // Reported with the prefix, because what an operator does about
            // this is set that variable, and a name they cannot paste is a
            // message that tells them to go and work it out.
            if named.len() > 1 {
                wrong.push(format!(
                    "{PREFIX}{variable} would be read for more than one credential: {}",
                    named.join(", ")
                ));
            } else if let Some(held) = self.held.get(&variable) {
                if !usable_credential(held) {
                    wrong.push(format!(
                        "{} names {PREFIX}{variable}, which is not a private key this service can use",
                        named.join(", ")
                    ));
                }
            } else {
                wrong.push(format!(
                    "{} names {PREFIX}{variable}, which this deployment does not hold",
                    named.join(", ")
                ));
            }
        }
        wrong
    }
}

impl CredentialSource for EnvCredentials {
    async fn fetch(&self, reference: &CredentialRef) -> Result<Secret<String>, CredentialError> {
        self.held
            .get(&Self::variable(reference))
            .cloned()
            .ok_or_else(|| {
                // Logged rather than returned: the operator needs to know which
                // registry entry has no credential behind it, and the caller
                // needs only to be refused. The reference is a name, not a
                // value, so recording it costs nothing.
                tracing::warn!(
                    reference = reference.as_str(),
                    "a registry entry names a credential this deployment does not hold"
                );
                CredentialError::NotFound
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn source(pairs: &[(&str, &str)]) -> EnvCredentials {
        EnvCredentials::from_pairs(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
    }

    fn reference(raw: &str) -> CredentialRef {
        CredentialRef::parse(raw).unwrap()
    }

    #[tokio::test]
    async fn a_reference_resolves_to_the_variable_that_holds_it() {
        let source = source(&[("MCP_SSH_CREDENTIAL_DNS1_READONLY", "the-key-material")]);
        let held = source.fetch(&reference("dns1-readonly")).await.unwrap();
        assert_eq!(held.expose(), "the-key-material");
    }

    /// The prefix is what stops a registry from naming its way to a variable
    /// that is not a credential. Without it, an entry referring to `path` or to
    /// the gateway's own bearer would resolve, and the service would try to
    /// authenticate with it.
    #[tokio::test]
    async fn a_reference_cannot_reach_an_unrelated_variable() {
        let source = source(&[
            ("PATH", "/usr/bin"),
            ("MCP_SSH_GATEWAY_BEARER_CURRENT", "the-gateway-credential"),
            ("MCP_SSH_CREDENTIAL_DNS1_READONLY", "the-key-material"),
        ]);
        for name in [
            "path",
            "MCP_SSH_GATEWAY_BEARER_CURRENT",
            "gateway-bearer-current",
        ] {
            assert!(
                source.fetch(&reference(name)).await.is_err(),
                "{name} resolved to something"
            );
        }
    }

    /// A registry entry with no credential behind it is refused rather than
    /// attempted. Which entry it was goes to the log, where the operator can
    /// act on it, rather than to the caller, who cannot.
    #[tokio::test]
    async fn a_credential_this_deployment_does_not_hold_is_refused() {
        let source = source(&[("MCP_SSH_CREDENTIAL_DNS2_READONLY", "another-key")]);
        assert_eq!(
            source.fetch(&reference("dns1-readonly")).await.unwrap_err(),
            CredentialError::NotFound
        );
    }

    /// A real key, made here rather than committed: a throwaway private key in
    /// the repository is still key material in the repository.
    fn a_key() -> String {
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn registry_naming(references: &[(&str, &str)]) -> Registry {
        let hosts: String = references
            .iter()
            .map(|(host, reference)| {
                format!(
                    r#""{host}": {{ "address": "{host}.internal:22", "host_key": "SHA256:AAAA1111", "roles": {{ "readonly": {{ "user": "mcp-ro", "access_class": "read_only", "credential": "{reference}" }} }} }}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        Registry::from_json(&format!("{{{hosts}}}")).unwrap()
    }

    /// The registry's own references carry separators — `mcp-ssh/dns1/readonly`
    /// is the documented shape — so the variable name folds them, and folding
    /// is not injective. What must never happen is two references a deployment
    /// configured reading one credential: that is a host authenticating with a
    /// key issued for another, silently, and looking right in the record.
    ///
    /// It is decidable before anything is served, so it is decided there.
    #[test]
    fn a_registry_whose_references_share_a_credential_is_refused() {
        let source = source(&[("MCP_SSH_CREDENTIAL_DNS1_READONLY", "the-key-material")]);
        let collides = registry_naming(&[("dns1", "dns1/readonly"), ("dns2", "dns1-readonly")]);

        let wrong = source.unusable(&collides);
        let said = wrong.join("; ");
        assert_eq!(wrong.len(), 1, "{said}");
        assert!(
            said.contains("dns1/readonly") && said.contains("dns1-readonly"),
            "the answer does not name both references: {said}"
        );
    }

    /// A reference with nothing behind it is a deployment that will fail the
    /// first time somebody reaches that host. Saying so at startup is the
    /// difference between a configuration mistake and an incident.
    #[test]
    fn a_registry_naming_a_credential_nobody_holds_is_refused() {
        let key = a_key();
        let source = source(&[("MCP_SSH_CREDENTIAL_MCP_SSH_DNS1_READONLY", &key)]);

        assert!(
            source
                .unusable(&registry_naming(&[("dns1", "mcp-ssh/dns1/readonly")]))
                .is_empty(),
            "a registry every credential of which is held was refused"
        );

        let wrong = source.unusable(&registry_naming(&[
            ("dns1", "mcp-ssh/dns1/readonly"),
            ("dns2", "mcp-ssh/dns2/readonly"),
        ]));
        let said = wrong.join("; ");
        assert_eq!(wrong.len(), 1, "{said}");
        assert!(
            said.contains("mcp-ssh/dns2/readonly")
                && said.contains("MCP_SSH_CREDENTIAL_MCP_SSH_DNS2_READONLY"),
            "the answer does not name the reference and the variable to set: {said}"
        );
    }

    /// A credential that is not a key authenticates nothing, so the host it is
    /// configured for can never be reached. That is decidable here, unlike
    /// whether it is the *right* key, which only the target can say — so this
    /// is where the checking stops.
    #[test]
    fn a_credential_that_is_not_a_key_is_refused() {
        let source = source(&[(
            "MCP_SSH_CREDENTIAL_MCP_SSH_DNS1_READONLY",
            "definitely-not-a-private-key",
        )]);

        let wrong = source.unusable(&registry_naming(&[("dns1", "mcp-ssh/dns1/readonly")]));
        let said = wrong.join("; ");
        assert_eq!(wrong.len(), 1, "{said}");
        assert!(
            said.contains("not a private key"),
            "the answer does not say what is wrong with it: {said}"
        );
        assert!(
            !said.contains("definitely-not-a-private-key"),
            "the answer repeated the credential's value: {said}"
        );
    }

    /// A variable set to nothing is not a credential. Holding it would turn a
    /// deployment mistake into an authentication attempt with an empty key,
    /// which fails further from its cause.
    #[tokio::test]
    async fn an_empty_variable_is_not_a_credential() {
        let source = source(&[("MCP_SSH_CREDENTIAL_DNS1_READONLY", "")]);
        assert!(source.fetch(&reference("dns1-readonly")).await.is_err());
    }
}
