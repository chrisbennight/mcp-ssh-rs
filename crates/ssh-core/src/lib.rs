//! Types shared across the service.

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod approval;
pub mod audit;
pub mod clock;
pub mod command;
pub mod config;
pub mod connect;
pub mod files;
pub mod mediate;
pub mod policy;
pub mod registry;
pub mod run;
pub mod secret;
pub mod session;

/// Administrator-declared account permissions, enforced by the target OS.
/// This label does not classify commands or grant access by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClass {
    ReadOnly,
    Privileged,
}

/// A target host the service can reach.
///
/// `try_from` rather than a derived `Deserialize`: deriving it would let serde
/// build this newtype straight from any string in a configuration file,
/// skipping [`HostId::parse`] entirely. The type exists precisely so that
/// holding one means it was checked, and a deserialization path around the
/// constructor makes that untrue wherever config is the source — which is
/// every real caller.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct HostId(String);

/// A named privilege level on a host, resolving to one credential.
///
/// Distinct from [`HostId`] so the two cannot be transposed: a host selects
/// which machine, a role selects how much privilege on it, and swapping them
/// would select the wrong credential. Deserialized through the constructor for
/// the same reason as [`HostId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RoleId(String);

impl TryFrom<String> for HostId {
    type Error = IdError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl TryFrom<String> for RoleId {
    type Error = IdError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// Identifiers are matched against configured entries, so anything that could
/// escape a lookup — traversal, separators, whitespace, control characters —
/// is refused rather than passed to the registry.
fn validate(raw: &str, what: &'static str, max: usize) -> Result<(), IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty { what });
    }
    if raw.len() > max {
        return Err(IdError::TooLong { what, max });
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(IdError::Charset { what });
    }
    // Dots are allowed because host names contain them, but a component made
    // only of dots is traversal. Refusing `/` alone is not enough: `..` carries
    // the same meaning to anything that later treats the identifier as a path
    // segment, and it passes a character-set check untouched.
    if raw.split('.').any(|component| component.is_empty()) || raw.chars().all(|c| c == '.') {
        return Err(IdError::Traversal { what });
    }
    Ok(())
}

impl HostId {
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        validate(raw, "host", 253)?;
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RoleId {
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        validate(raw, "role", 64)?;
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who a request acts on behalf of.
///
/// Supplied by the gateway from verified identity rather than chosen by the
/// caller. Bounded rather than pattern-matched: it is compared for equality and
/// recorded, never used to select a configured entry, so the traversal rules
/// that apply to [`HostId`] and [`RoleId`] are not the relevant risk here.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn parse(raw: &str) -> Result<Self, IdError> {
        if raw.is_empty() {
            return Err(IdError::Empty { what: "principal" });
        }
        if raw.len() > 256 {
            return Err(IdError::TooLong {
                what: "principal",
                max: 256,
            });
        }
        if raw.chars().any(char::is_control) {
            return Err(IdError::Charset { what: "principal" });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = IdError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("{what} identifier is empty")]
    Empty { what: &'static str },
    #[error("{what} identifier exceeds {max} characters")]
    TooLong { what: &'static str, max: usize },
    #[error("{what} identifier may contain only letters, digits, '-', '_' and '.'")]
    Charset { what: &'static str },
    #[error("{what} identifier contains an empty or dot-only path component")]
    Traversal { what: &'static str },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_realistic_names() {
        assert_eq!(HostId::parse("dns1").unwrap().as_str(), "dns1");
        assert_eq!(
            HostId::parse("parents-server.dacasa.org").unwrap().as_str(),
            "parents-server.dacasa.org"
        );
        assert_eq!(RoleId::parse("read_only").unwrap().as_str(), "read_only");
    }

    /// A host name selects a credential, so each shape here is a way a caller
    /// could try to reach past the registry rather than choose from it.
    ///
    /// `..` and `.` are here because rejecting `/` is not sufficient: they mean
    /// traversal to anything that later treats the identifier as a path
    /// segment, and they pass a character-set check untouched.
    #[test]
    fn rejects_lookup_evasion() {
        for probe in [
            "",
            "..",
            ".",
            "...",
            "a..b",
            ".hidden",
            "trailing.",
            "../etc/passwd",
            "dns1 dns2",
            "dns1\n",
            "dns1;reboot",
        ] {
            assert!(HostId::parse(probe).is_err(), "should reject {probe:?}");
            assert!(RoleId::parse(probe).is_err(), "should reject {probe:?}");
        }
        assert!(HostId::parse(&"h".repeat(254)).is_err());
        assert!(RoleId::parse(&"r".repeat(65)).is_err());
    }

    /// Deserialization must go through the constructor. A derived `Deserialize`
    /// would build these newtypes from any string in a configuration file,
    /// which is where identifiers actually come from, making the validation
    /// above decorative.
    #[test]
    fn deserialization_cannot_bypass_validation() {
        assert!(
            serde_json::from_str::<HostId>(r#""dns1""#).is_ok(),
            "a valid identifier still deserializes"
        );
        for probe in [r#""..""#, r#""dns1 dns2""#, r#""dns1;reboot""#, r#""""#] {
            assert!(
                serde_json::from_str::<HostId>(probe).is_err(),
                "deserialization accepted {probe}"
            );
            assert!(
                serde_json::from_str::<RoleId>(probe).is_err(),
                "deserialization accepted {probe}"
            );
        }
    }
}
