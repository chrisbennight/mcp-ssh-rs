//! Runtime configuration, read from the environment.

use std::env::VarError;
use std::net::SocketAddr;

/// Settings the service needs before it can serve anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP surface binds.
    pub listen: SocketAddr,
}

impl Config {
    pub const LISTEN_VAR: &'static str = "MCP_SSH_LISTEN";
    pub const DEFAULT_LISTEN: &'static str = "0.0.0.0:8080";

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(std::env::var)
    }

    /// Taking the lookup as a parameter lets tests exercise the real parsing
    /// and defaulting rules without mutating the process environment.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&'static str) -> Result<String, VarError>,
    {
        let raw = match lookup(Self::LISTEN_VAR) {
            Ok(raw) => raw,
            Err(VarError::NotPresent) => Self::DEFAULT_LISTEN.to_owned(),
            Err(VarError::NotUnicode(_)) => {
                return Err(ConfigError::Invalid {
                    var: Self::LISTEN_VAR,
                });
            }
        };
        let listen: SocketAddr = raw.parse().map_err(|_| ConfigError::Invalid {
            var: Self::LISTEN_VAR,
        })?;
        // Port 0 parses and binds, to a port the kernel picks. The healthcheck
        // is a separate process reading the same configuration, so it would
        // derive port 0 and probe a port nothing listens on: the container
        // serves correctly and reports itself unhealthy forever. Refusing it at
        // startup turns a silent, permanent misconfiguration into a loud one.
        if listen.port() == 0 {
            return Err(ConfigError::EphemeralPort {
                var: Self::LISTEN_VAR,
            });
        }
        Ok(Self { listen })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{var} must be an address in host:port form")]
    Invalid { var: &'static str },
    #[error("{var} must name a fixed port; port 0 cannot be probed by the healthcheck")]
    EphemeralPort { var: &'static str },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_unset() {
        let config = Config::from_lookup(|_| Err(VarError::NotPresent)).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080".parse().unwrap());
    }

    /// Port 0 binds to a kernel-chosen port, but the healthcheck is a separate
    /// process reading the same configuration and would probe port 0. The
    /// container would serve and report itself unhealthy forever.
    #[test]
    fn refuses_an_ephemeral_port() {
        for raw in ["0.0.0.0:0", "127.0.0.1:0", "[::1]:0"] {
            assert_eq!(
                Config::from_lookup(|_| Ok(raw.to_owned())).unwrap_err(),
                ConfigError::EphemeralPort {
                    var: Config::LISTEN_VAR
                },
                "should refuse {raw}"
            );
        }
    }

    #[test]
    fn refuses_to_start_on_an_unparseable_address() {
        let err = Config::from_lookup(|_| Ok("not-an-address".to_owned())).unwrap_err();
        assert_eq!(
            err,
            ConfigError::Invalid {
                var: Config::LISTEN_VAR
            }
        );
    }
}
