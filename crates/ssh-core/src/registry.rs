//! Which hosts exist, which roles they offer, and what to trust when dialing.
//!
//! The registry answers one question: given a host and a role, what address do
//! we connect to, what host key must the target present, and which credential
//! do we authenticate with. It holds credential *references* rather than
//! credential values — the values are fetched from the secret store at use
//! time, so a registry that leaks reveals which credentials exist, not what
//! they are.

use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;

use crate::{HostId, RoleId};

/// Names a credential in the secret store. Not the credential itself.
///
/// Deserialized through its constructor rather than derived, for the same
/// reason as [`HostId`]: configuration is where these values actually come
/// from, so a derived `Deserialize` would make the check below decorative
/// exactly where it matters.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct CredentialRef(String);

impl CredentialRef {
    /// A reference that names nothing cannot be fetched, so it is refused here
    /// rather than at the moment a session tries to authenticate with it.
    pub fn parse(raw: &str) -> Result<Self, Blank> {
        if raw.trim().is_empty() {
            return Err(Blank {
                what: "credential reference",
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host key a target is expected to present.
///
/// Held as the opaque string the operator pinned. This type does not parse or
/// interpret it: comparison happens where the SSH connection is made, against
/// what the target actually presented, and inventing a parser here would create
/// a second opinion about what two keys being equal means.
///
/// It does insist there is *something* to compare. A host configured with an
/// empty pin satisfies the letter of "every host carries a pinned key" while
/// leaving the connection layer nothing to verify against, which is the failure
/// requiring the field was meant to prevent. Whether a non-blank pin is a
/// usable key is decided where it is parsed, and an unusable one refuses the
/// connection.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PinnedHostKey(String);

impl PinnedHostKey {
    pub fn parse(raw: &str) -> Result<Self, Blank> {
        if raw.trim().is_empty() {
            return Err(Blank {
                what: "pinned host key",
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CredentialRef {
    type Error = Blank;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl TryFrom<String> for PinnedHostKey {
    type Error = Blank;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// A configured value that is present but says nothing.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{what} is present but empty")]
pub struct Blank {
    pub what: &'static str,
}

/// Everything needed to open a connection for one (host, role) pair.
///
/// The pair travels with the endpoint it resolved to, because both come from
/// one lookup. A connection's reported identity is then necessarily the
/// identity that chose its address, account and credential: there is no way to
/// pair one host or role's name with another's endpoint, which would report a
/// benign identity while holding a different capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target<'a> {
    host: &'a HostId,
    role: &'a RoleId,
    address: &'a str,
    host_key: &'a PinnedHostKey,
    user: &'a str,
    credential: &'a CredentialRef,
}

impl<'a> Target<'a> {
    /// The host this resolved for.
    #[must_use]
    pub const fn host(&self) -> &'a HostId {
        self.host
    }

    /// The role this resolved for.
    #[must_use]
    pub const fn role(&self) -> &'a RoleId {
        self.role
    }

    #[must_use]
    pub const fn address(&self) -> &'a str {
        self.address
    }

    #[must_use]
    pub const fn host_key(&self) -> &'a PinnedHostKey {
        self.host_key
    }

    /// The account to authenticate as on the target.
    #[must_use]
    pub const fn user(&self) -> &'a str {
        self.user
    }

    #[must_use]
    pub const fn credential(&self) -> &'a CredentialRef {
        self.credential
    }
}

/// What one role on one host resolves to.
///
/// The login account is part of the role rather than derived from it, because
/// the two are configured independently on real targets: a role named
/// `readonly` may log in as `mcp-ro` on one host and `agent` on another, and
/// guessing would authenticate as the wrong account with the right key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct RoleEntry {
    #[serde(deserialize_with = "non_blank")]
    user: String,
    credential: CredentialRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct HostEntry {
    #[serde(deserialize_with = "non_blank")]
    address: String,
    host_key: PinnedHostKey,
    #[serde(deserialize_with = "unique_keys")]
    roles: HashMap<RoleId, RoleEntry>,
}

/// The set of hosts this deployment may reach.
///
/// Keyed by the identifier types rather than by strings, so a name a caller
/// could never construct cannot be configured. Keying by `String` would let a
/// host called `../etc` or `dns1 dns2` load and then be advertised by
/// [`Registry::hosts`] while being permanently unresolvable, which is a worse
/// answer than refusing the file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Registry {
    #[serde(deserialize_with = "unique_keys")]
    hosts: HashMap<HostId, HostEntry>,
}

/// Deserializes a map, refusing a name that appears more than once.
///
/// A map collapses repeated names by keeping the last, silently. That is the
/// wrong answer for both maps here: the file would load, and the name an
/// operator reads on one line would resolve to what a second line says. A
/// duplicated role would hand a nominally read-only label the later, possibly
/// more privileged credential; a duplicated host would silently change which
/// machine is dialled and which key it is checked against.
///
/// The duplicate is almost always a merge or an edit accident rather than an
/// attack, which is exactly why it has to fail loudly: nobody is looking for it.
fn unique_keys<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Eq + std::hash::Hash + fmt::Display,
    V: Deserialize<'de>,
{
    struct Unique<K, V>(std::marker::PhantomData<(K, V)>);

    impl<'de, K, V> serde::de::Visitor<'de> for Unique<K, V>
    where
        K: Deserialize<'de> + Eq + std::hash::Hash + fmt::Display,
        V: Deserialize<'de>,
    {
        type Value = HashMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with no repeated names")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            // Not pre-sized from the size hint: the input decides it, and this
            // runs before anything about the input has been checked.
            let mut out = HashMap::new();
            while let Some((key, value)) = access.next_entry::<K, V>()? {
                if out.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!("{key} appears twice")));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

/// Deserializes a string that has to say something.
///
/// A value that is present but empty is the same failure as a blank pinned key:
/// the entry loads, and the promise it was carrying — an address that can be
/// dialled, an account that can be logged into — is already broken by the time
/// anything tries to use it.
fn non_blank<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    if raw.trim().is_empty() {
        return Err(serde::de::Error::custom("is present but empty"));
    }
    Ok(raw)
}

impl Registry {
    /// Parses a registry from its serialized form.
    pub fn from_json(raw: &str) -> Result<Self, RegistryError> {
        serde_json::from_str(raw).map_err(|source| RegistryError::Malformed {
            detail: source.to_string(),
        })
    }

    /// Resolves a host and role to the facts needed to dial it.
    ///
    /// A host or role that is not configured is refused. There is no fallback
    /// and no default role: the registry is the whole of what this deployment
    /// may reach, so an unmatched lookup means the caller asked for something
    /// the operator did not grant.
    pub fn resolve(&self, host: &HostId, role: &RoleId) -> Result<Target<'_>, ResolveError> {
        // The registry's own keys, not the caller's arguments: what the target
        // reports is then the same lookup that chose its endpoint.
        let (host_id, entry) =
            self.hosts
                .get_key_value(host)
                .ok_or_else(|| ResolveError::UnknownHost {
                    host: host.to_string(),
                })?;
        let (role_id, assigned) =
            entry
                .roles
                .get_key_value(role)
                .ok_or_else(|| ResolveError::UnknownRole {
                    host: host.to_string(),
                    role: role.to_string(),
                })?;
        Ok(Target {
            host: host_id,
            role: role_id,
            address: &entry.address,
            host_key: &entry.host_key,
            user: &assigned.user,
            credential: &assigned.credential,
        })
    }

    /// Hosts in the registry, for discovery.
    pub fn hosts(&self) -> impl Iterator<Item = &HostId> {
        self.hosts.keys()
    }

    /// Roles configured on a host, for discovery.
    pub fn roles(&self, host: &HostId) -> impl Iterator<Item = &RoleId> {
        self.hosts
            .get(host)
            .into_iter()
            .flat_map(|entry| entry.roles.keys())
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("registry is malformed: {detail}")]
    Malformed { detail: String },
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("no host named {host} is configured")]
    UnknownHost { host: String },
    #[error("host {host} has no role named {role}")]
    UnknownRole { host: String, role: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const REGISTRY: &str = r#"{
      "dns1": {
        "address": "dns1.internal:22",
        "host_key": "SHA256:AAAA1111",
        "roles": {
          "readonly": { "user": "mcp-ro", "credential": "mcp-ssh/dns1/readonly" },
          "operator": { "user": "mcp-op", "credential": "mcp-ssh/dns1/operator" }
        }
      },
      "server": {
        "address": "server.internal:22",
        "host_key": "SHA256:BBBB2222",
        "roles": {
          "readonly": { "user": "agent", "credential": "mcp-ssh/server/readonly" }
        }
      }
    }"#;

    fn registry() -> Registry {
        Registry::from_json(REGISTRY).unwrap()
    }

    #[test]
    fn resolves_a_configured_host_and_role() {
        let registry = registry();
        let target = registry
            .resolve(
                &HostId::parse("dns1").unwrap(),
                &RoleId::parse("operator").unwrap(),
            )
            .unwrap();
        assert_eq!(target.address(), "dns1.internal:22");
        assert_eq!(target.host_key().as_str(), "SHA256:AAAA1111");
        assert_eq!(target.credential().as_str(), "mcp-ssh/dns1/operator");
        assert_eq!(target.user(), "mcp-op");
    }

    /// The login account travels with the role, so the same role name on two
    /// hosts can log in as two different accounts. Deriving the account from
    /// the role name instead would authenticate as the wrong one.
    #[test]
    fn the_login_account_comes_from_the_role_on_that_host() {
        let registry = registry();
        let dns1 = registry
            .resolve(
                &HostId::parse("dns1").unwrap(),
                &RoleId::parse("readonly").unwrap(),
            )
            .unwrap();
        let server = registry
            .resolve(
                &HostId::parse("server").unwrap(),
                &RoleId::parse("readonly").unwrap(),
            )
            .unwrap();
        assert_eq!(dns1.user, "mcp-ro");
        assert_eq!(server.user, "agent");
    }

    /// Roles are per host. Resolving a role that exists elsewhere must not
    /// borrow it, or a host configured with only read access would inherit
    /// another host's privileged credential.
    #[test]
    fn does_not_borrow_a_role_from_another_host() {
        let err = registry()
            .resolve(
                &HostId::parse("server").unwrap(),
                &RoleId::parse("operator").unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            ResolveError::UnknownRole {
                host: "server".to_owned(),
                role: "operator".to_owned(),
            }
        );
    }

    #[test]
    fn refuses_an_unconfigured_host() {
        let err = registry()
            .resolve(
                &HostId::parse("nas").unwrap(),
                &RoleId::parse("readonly").unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            ResolveError::UnknownHost {
                host: "nas".to_owned()
            }
        );
    }

    /// Every host must carry a pinned key. A registry entry without one would
    /// otherwise deserialize and then be dialed with nothing to verify against.
    #[test]
    fn refuses_a_host_with_no_pinned_key() {
        let err =
            Registry::from_json(r#"{ "dns1": { "address": "dns1.internal:22", "roles": {} } }"#)
                .unwrap_err();
        let RegistryError::Malformed { detail } = err;
        assert!(detail.contains("host_key"), "unexpected detail: {detail}");
    }

    /// A field that is present but says nothing satisfies the letter of every
    /// "this is required" rule while leaving the thing that requires it with
    /// nothing to work with. Each case here loaded cleanly before, and each one
    /// would have failed later: at the moment a target's key was compared, at
    /// the moment a credential was fetched, or never — for a host that could be
    /// listed by discovery but whose name no caller can even construct.
    #[test]
    fn refuses_configuration_that_would_load_but_be_unusable() {
        let cases = [
            (
                "a blank pinned key leaves nothing to verify a target against",
                r#"{ "dns1": { "address": "a:22", "host_key": "   ", "roles": {} } }"#,
            ),
            (
                "a blank credential reference names nothing to authenticate with",
                r#"{ "dns1": { "address": "a:22", "host_key": "SHA256:X",
                     "roles": { "readonly": { "user": "u", "credential": "" } } } }"#,
            ),
            (
                "a host name no caller can construct could be advertised but never resolved",
                r#"{ "../etc": { "address": "a:22", "host_key": "SHA256:X", "roles": {} } }"#,
            ),
            (
                "and the same for a role name",
                r#"{ "dns1": { "address": "a:22", "host_key": "SHA256:X",
                     "roles": { "read only": { "user": "u", "credential": "c" } } } }"#,
            ),
            (
                "a blank address leaves nothing to dial",
                r#"{ "dns1": { "address": "  ", "host_key": "SHA256:X", "roles": {} } }"#,
            ),
            (
                "a blank login account leaves nobody to authenticate as",
                r#"{ "dns1": { "address": "a:22", "host_key": "SHA256:X",
                     "roles": { "readonly": { "user": "", "credential": "c" } } } }"#,
            ),
        ];
        for (why, raw) in cases {
            assert!(Registry::from_json(raw).is_err(), "should refuse: {why}");
        }
    }

    /// A repeated name in a map is kept silently by the last one that appears,
    /// so the label an operator reads on one line resolves to what a second
    /// line says. For a role that quietly hands a read-only label a privileged
    /// credential; for a host it quietly changes which machine is dialled and
    /// which key it is checked against. Neither is something anyone is looking
    /// for, which is why it has to fail loudly rather than pick a winner.
    #[test]
    fn a_name_that_appears_twice_is_refused_rather_than_resolved_to_the_last() {
        let duplicate_role = r#"{
          "dns1": {
            "address": "dns1.internal:22",
            "host_key": "SHA256:AAAA1111",
            "roles": {
              "readonly": { "user": "mcp-ro", "credential": "mcp-ssh/dns1/readonly" },
              "readonly": { "user": "root", "credential": "mcp-ssh/dns1/root" }
            }
          }
        }"#;
        let duplicate_host = r#"{
          "dns1": {
            "address": "dns1.internal:22",
            "host_key": "SHA256:AAAA1111",
            "roles": {
              "readonly": { "user": "mcp-ro", "credential": "mcp-ssh/dns1/readonly" }
            }
          },
          "dns1": {
            "address": "attacker.internal:22",
            "host_key": "SHA256:CCCC3333",
            "roles": {
              "readonly": { "user": "root", "credential": "mcp-ssh/dns1/root" }
            }
          }
        }"#;

        for (why, raw) in [
            ("a role named twice", duplicate_role),
            ("a host named twice", duplicate_host),
        ] {
            let err = Registry::from_json(raw).unwrap_err();
            let RegistryError::Malformed { detail } = err;
            assert!(
                detail.contains("appears twice"),
                "{why} should be refused as a duplicate, got: {detail}"
            );
        }
    }

    #[test]
    fn reports_hosts_and_their_roles_for_discovery() {
        let registry = registry();
        let mut hosts: Vec<_> = registry.hosts().map(HostId::as_str).collect();
        hosts.sort_unstable();
        assert_eq!(hosts, ["dns1", "server"]);

        let mut roles: Vec<_> = registry
            .roles(&HostId::parse("dns1").unwrap())
            .map(RoleId::as_str)
            .collect();
        roles.sort_unstable();
        assert_eq!(roles, ["operator", "readonly"]);
        assert_eq!(
            registry.roles(&HostId::parse("nas").unwrap()).next(),
            None,
            "an unconfigured host has no roles rather than erroring"
        );
    }
}
