//! Transport and output configuration validated before serving requests.

use std::env::VarError;
use std::fs::{Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Http,
    Stdio,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sink {
    Stdout,
    Stderr,
    File(PathBuf),
}

impl Sink {
    fn parse(value: &str, var: &'static str) -> Result<Self, ProcessError> {
        match value {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => value
                .strip_prefix("file:")
                .filter(|path| !path.is_empty())
                .map(|path| Self::File(PathBuf::from(path)))
                .ok_or(ProcessError::Invalid { var }),
        }
    }

    fn open(&self) -> io::Result<(Box<dyn Write + Send>, Option<Metadata>)> {
        match self {
            Self::Stdout => Ok((Box::new(io::stdout()), None)),
            Self::Stderr => Ok((Box::new(io::stderr()), None)),
            Self::File(path) => {
                match std::fs::metadata(path) {
                    Ok(metadata) if !metadata.is_file() => {
                        return Err(io::Error::other(
                            "output destination must be a regular file",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                let mut options = OpenOptions::new();
                options.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let file = options.open(path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    return Err(io::Error::other(
                        "output destination must be a regular file",
                    ));
                }
                Ok((Box::new(file), Some(metadata)))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessOptions {
    pub transport: Transport,
    pub audit: Sink,
    pub diagnostics: Sink,
}

pub struct Outputs {
    pub audit: Box<dyn Write + Send>,
    pub diagnostics: Box<dyn Write + Send>,
}

impl ProcessOptions {
    pub const TRANSPORT_VAR: &'static str = "MCP_SSH_TRANSPORT";
    pub const AUDIT_VAR: &'static str = "MCP_SSH_AUDIT_SINK";
    pub const LOG_VAR: &'static str = "MCP_SSH_LOG_SINK";

    pub fn from_lookup<F>(lookup: &F) -> Result<Self, ProcessError>
    where
        F: Fn(&'static str) -> Result<String, VarError>,
    {
        let transport = match read(lookup, Self::TRANSPORT_VAR)?.as_deref() {
            None | Some("http") => Transport::Http,
            Some("stdio") => Transport::Stdio,
            _ => {
                return Err(ProcessError::Invalid {
                    var: Self::TRANSPORT_VAR,
                });
            }
        };
        let audit = match read(lookup, Self::AUDIT_VAR)? {
            Some(value) => Sink::parse(&value, Self::AUDIT_VAR)?,
            None if transport == Transport::Http => Sink::Stdout,
            None => return Err(ProcessError::StdioAuditFile),
        };
        let diagnostics = read(lookup, Self::LOG_VAR)?
            .map(|value| Sink::parse(&value, Self::LOG_VAR))
            .transpose()?
            .unwrap_or(Sink::Stderr);
        if transport == Transport::Stdio {
            if !matches!(audit, Sink::File(_)) {
                return Err(ProcessError::StdioAuditFile);
            }
            if diagnostics == Sink::Stdout {
                return Err(ProcessError::ProtocolStdout);
            }
        }
        if audit == diagnostics {
            return Err(ProcessError::SharedSink);
        }
        Ok(Self {
            transport,
            audit,
            diagnostics,
        })
    }

    /// Open both required outputs before any request can be admitted.
    pub fn open_outputs(&self) -> Result<Outputs, ProcessError> {
        let (audit, audit_metadata) = self.audit.open().map_err(ProcessError::Output)?;
        let (diagnostics, diagnostic_metadata) =
            self.diagnostics.open().map_err(ProcessError::Output)?;
        #[cfg(unix)]
        if let (Some(a), Some(d)) = (audit_metadata, diagnostic_metadata) {
            use std::os::unix::fs::MetadataExt as _;
            if a.dev() == d.dev() && a.ino() == d.ino() {
                return Err(ProcessError::SharedSink);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (audit_metadata, diagnostic_metadata);
            if let (Sink::File(a), Sink::File(d)) = (&self.audit, &self.diagnostics) {
                if a.canonicalize().map_err(ProcessError::Output)?
                    == d.canonicalize().map_err(ProcessError::Output)?
                {
                    return Err(ProcessError::SharedSink);
                }
            }
        }
        Ok(Outputs { audit, diagnostics })
    }
}

fn read<F>(lookup: &F, var: &'static str) -> Result<Option<String>, ProcessError>
where
    F: Fn(&'static str) -> Result<String, VarError>,
{
    match lookup(var) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        _ => Err(ProcessError::Invalid { var }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("{var} has an unsupported value")]
    Invalid { var: &'static str },
    #[error("stdio requires MCP_SSH_AUDIT_SINK=file:<path>")]
    StdioAuditFile,
    #[error("stdio reserves stdout for MCP; choose stderr or a file for diagnostics")]
    ProtocolStdout,
    #[error("audit and diagnostic output must use separate destinations")]
    SharedSink,
    #[error("cannot open the configured output: {0}")]
    Output(#[source] io::Error),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn options(values: &[(&str, &str)]) -> Result<ProcessOptions, ProcessError> {
        ProcessOptions::from_lookup(&|name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
                .ok_or(VarError::NotPresent)
        })
    }

    #[test]
    fn stdio_reserves_protocol_stdout_and_requires_audit_file() {
        assert!(matches!(
            options(&[(ProcessOptions::TRANSPORT_VAR, "stdio")]),
            Err(ProcessError::StdioAuditFile)
        ));
        for audit in ["stdout", "stderr"] {
            assert!(
                options(&[
                    (ProcessOptions::TRANSPORT_VAR, "stdio"),
                    (ProcessOptions::AUDIT_VAR, audit)
                ])
                .is_err()
            );
        }
        assert!(matches!(
            options(&[
                (ProcessOptions::TRANSPORT_VAR, "stdio"),
                (ProcessOptions::AUDIT_VAR, "file:audit.jsonl"),
                (ProcessOptions::LOG_VAR, "stdout")
            ]),
            Err(ProcessError::ProtocolStdout)
        ));
        let stdio = options(&[
            (ProcessOptions::TRANSPORT_VAR, "stdio"),
            (ProcessOptions::AUDIT_VAR, "file:audit.jsonl"),
        ])
        .unwrap();
        assert_eq!(stdio.diagnostics, Sink::Stderr);
    }

    #[test]
    fn http_sinks_are_independent_and_conflicts_are_rejected() {
        let http = options(&[]).unwrap();
        assert_eq!(http.audit, Sink::Stdout);
        assert_eq!(http.diagnostics, Sink::Stderr);
        assert!(matches!(
            options(&[(ProcessOptions::LOG_VAR, "stdout")]),
            Err(ProcessError::SharedSink)
        ));
        assert!(
            options(&[
                (ProcessOptions::AUDIT_VAR, "stderr"),
                (ProcessOptions::LOG_VAR, "stdout")
            ])
            .is_ok()
        );
        for (key, value) in [
            (ProcessOptions::TRANSPORT_VAR, "socket"),
            (ProcessOptions::AUDIT_VAR, "none"),
            (ProcessOptions::LOG_VAR, "file:"),
        ] {
            assert!(options(&[(key, value)]).is_err());
        }
    }
    #[test]
    fn opened_sinks_reject_aliases_and_unusable_destinations() {
        let directory =
            std::env::temp_dir().join(format!("mcp-ssh-output-{:x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("audit.jsonl");
        let mut options = ProcessOptions {
            transport: Transport::Stdio,
            audit: Sink::File(path.clone()),
            diagnostics: Sink::File(directory.join(".").join("audit.jsonl")),
        };
        assert!(matches!(
            options.open_outputs(),
            Err(ProcessError::SharedSink)
        ));
        let alias = directory.join("alias.jsonl");
        std::fs::hard_link(&path, &alias).unwrap();
        options.diagnostics = Sink::File(alias);
        assert!(matches!(
            options.open_outputs(),
            Err(ProcessError::SharedSink)
        ));
        options.audit = Sink::File(directory.clone());
        assert!(matches!(
            options.open_outputs(),
            Err(ProcessError::Output(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
