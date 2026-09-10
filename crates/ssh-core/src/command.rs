//! Commands, and how they cross the wire without being reinterpreted.
//!
//! A command is an argument vector here, but SSH does not carry argument
//! vectors: RFC 4254's exec request carries a single string, and the target's
//! login shell parses it. So the service must produce a string whose parse
//! recovers exactly the vector it was given. Everything in this module exists
//! for that one job, because getting it wrong means an argument becomes syntax.

use serde::{Deserialize, Serialize};

/// Largest number of arguments a command may carry.
const MAX_ARGS: usize = 1024;

/// Longest agent-supplied explanation accepted for one command.
const MAX_INTENT_BYTES: usize = 512;

/// Largest rendered command a target can be expected to run.
///
/// The target's sshd hands the whole rendered string to a login shell as a
/// single `-c` argument, and Linux caps one argument of an `execve` at
/// `PAGE_SIZE * 32` — 128 KiB wherever pages are 4 KiB, which is everywhere
/// this service dials. Past that the target does not refuse the command with
/// anything a caller can act on; the exec fails.
const MAX_WIRE_BYTES: usize = 128 * 1024;

/// Largest total size of a command, before quoting.
///
/// Derived from [`MAX_WIRE_BYTES`] rather than picked: quoting expands content
/// fourfold in the worst case, where every byte is a single quote rendered as
/// `'\''`, and each argument costs two quotes and a separator on top. Taking a
/// quarter of the wire limit and subtracting that per-argument overhead means
/// anything accepted here renders to something the target can actually exec —
/// which is what makes "refused before it is sent" true rather than
/// approximately true. A test builds the worst case and measures it.
const MAX_BYTES: usize = MAX_WIRE_BYTES / 4 - MAX_ARGS * 3;

/// What the calling agent says one command is meant to accomplish.
///
/// This is evidence for a human and for advisory evaluation, not a trusted
/// authorization fact. Keeping it in its own type makes that provenance hard
/// to blur with the session purpose or an authenticated user identity. It is
/// bounded because it is stored in every command record and approval request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct CommandIntent(String);

impl CommandIntent {
    pub fn parse(raw: &str) -> Result<Self, CommandIntentError> {
        if raw.trim().is_empty() {
            return Err(CommandIntentError::Blank);
        }
        if raw.len() > MAX_INTENT_BYTES {
            return Err(CommandIntentError::TooLong {
                max: MAX_INTENT_BYTES,
            });
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CommandIntent {
    type Error = CommandIntentError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// A command to run on a target, as an argument vector.
///
/// Serialized as the bare vector rather than as a struct wrapping one. The
/// field name is an implementation detail, and emitting it would make the
/// written form differ from the accepted form: the record writes a command and
/// anything reading it back would be handed a shape `Deserialize` refuses.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Vec<String>")]
pub struct Command {
    argv: Vec<String>,
}

/// Written as the vector, which is what `Deserialize` accepts.
///
/// Hand-written rather than derived, and not `#[serde(transparent)]`, which
/// serde refuses alongside a validating conversion. A derived implementation
/// would emit the field name, so a command written into the record could not be
/// read back out of it.
impl Serialize for Command {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.argv.serialize(serializer)
    }
}

impl Command {
    pub fn new(argv: Vec<String>) -> Result<Self, CommandError> {
        let Some(program) = argv.first() else {
            return Err(CommandError::Empty);
        };
        if program.is_empty() {
            return Err(CommandError::EmptyProgram);
        }
        if argv.len() > MAX_ARGS {
            return Err(CommandError::TooManyArguments { max: MAX_ARGS });
        }
        let total: usize = argv.iter().map(String::len).sum();
        if total > MAX_BYTES {
            return Err(CommandError::TooLarge { max: MAX_BYTES });
        }
        // A NUL cannot survive the crossing at all: the target receives a C
        // string and would silently truncate there. Refusing here means the
        // command that runs is the command that was authorized, rather than a
        // prefix of it.
        if argv.iter().any(|arg| arg.contains('\0')) {
            return Err(CommandError::InteriorNul);
        }
        Ok(Self { argv })
    }

    #[must_use]
    pub fn program(&self) -> &str {
        self.argv.first().map_or("", String::as_str)
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        self.argv.get(1..).unwrap_or_default()
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Renders the vector as a string a POSIX shell parses back into it.
    ///
    /// Every argument is single-quoted, because inside single quotes a POSIX
    /// shell performs no expansion of any kind — no parameters, no command
    /// substitution, no globbing, no escapes. The single quote itself is the
    /// only character that cannot appear, and it is emitted by closing the
    /// quote, escaping one literal quote, and reopening.
    ///
    /// Quoting rather than escaping is deliberate: an escape-based scheme has
    /// to enumerate the characters a shell treats specially, and that list
    /// differs between shells and grows over time. Single quotes need no such
    /// list.
    #[must_use]
    pub fn to_wire(&self) -> String {
        self.argv
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl TryFrom<Vec<String>> for Command {
    type Error = CommandError;

    fn try_from(argv: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(argv)
    }
}

fn shell_quote(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len().saturating_add(2));
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("a command needs at least a program to run")]
    Empty,
    #[error("the program name is empty")]
    EmptyProgram,
    #[error("a command may carry at most {max} arguments")]
    TooManyArguments { max: usize },
    #[error("a command may be at most {max} bytes before quoting")]
    TooLarge { max: usize },
    #[error("a command argument contains a NUL, which cannot cross the wire intact")]
    InteriorNul,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommandIntentError {
    #[error("each command needs the agent's intent; it is shown to a human and recorded")]
    Blank,
    #[error("a command intent is bounded to at most {max} bytes")]
    TooLong { max: usize },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    #[test]
    fn command_intent_is_required_and_bounded() {
        for blank in ["", " ", "\n\t"] {
            assert_eq!(CommandIntent::parse(blank), Err(CommandIntentError::Blank));
        }
        assert!(CommandIntent::parse(&"x".repeat(MAX_INTENT_BYTES)).is_ok());
        assert!(matches!(
            CommandIntent::parse(&"x".repeat(MAX_INTENT_BYTES + 1)),
            Err(CommandIntentError::TooLong { .. })
        ));
        assert!(
            serde_json::from_str::<CommandIntent>(r#""""#).is_err(),
            "deserialization bypassed intent validation"
        );
        assert_eq!(
            CommandIntent::parse("confirm the resolver picked up its config")
                .unwrap()
                .as_str(),
            "confirm the resolver picked up its config"
        );
    }

    /// The contract is not "produces this string" but "a shell parses it back
    /// into the vector we started with". Asserting against a literal would pass
    /// happily while the shell disagreed, so this runs a real one.
    ///
    /// `printf '%s\0'` emits each argument NUL-terminated, which is the only
    /// separator that cannot occur inside an argument — `Command` refuses NUL
    /// precisely because it cannot survive the crossing.
    fn round_trip(argv: &[&str]) {
        let mut printf_argv = vec!["printf", "%s\\0"];
        printf_argv.extend_from_slice(argv);
        let wire = command(&printf_argv).to_wire();

        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&wire)
            .output()
            .expect("running /bin/sh");
        assert!(
            output.status.success(),
            "shell rejected {wire}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut recovered: Vec<String> = output
            .stdout
            .split(|byte| *byte == 0)
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        // split leaves a trailing empty element after the final NUL
        recovered.pop();

        let expected: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(recovered, expected, "wire form was {wire}");
    }

    /// Each of these is a way an argument becomes syntax if quoting is wrong:
    /// word splitting, globbing, command substitution, parameter expansion,
    /// redirection, comments, chaining, and the quote characters themselves.
    #[test]
    fn a_shell_parses_the_wire_form_back_into_the_argument_vector() {
        round_trip(&["plain"]);
        round_trip(&["two words"]);
        round_trip(&["tab\there"]);
        round_trip(&["new\nline"]);
        round_trip(&["*", "?", "[a-z]"]);
        round_trip(&["$HOME", "${PATH}", "$(id -u)", "`id -u`"]);
        round_trip(&["a;b", "a&&b", "a||b", "a|b", "a&"]);
        round_trip(&["a>b", "a<b", "a>>b"]);
        round_trip(&["#comment"]);
        round_trip(&["it's", "\"quoted\"", "'", "''", "\\", "\\'"]);
        round_trip(&["--flag=value with spaces"]);
        round_trip(&["", "after an empty argument"]);
        round_trip(&["unicode: é ñ 中文 🙂"]);
    }

    /// The case the whole module exists for: an argument that is a complete
    /// shell command must arrive as one argument, not be executed.
    ///
    /// Every payload here creates a file and nothing else. The obvious way to
    /// write this test is with a command whose execution would be unmistakable
    /// — `rm -rf /` — and that is exactly wrong: this test runs a real shell,
    /// so the regression it exists to catch is the case where the payload
    /// *does* run, on a developer's machine or a CI runner. A test that proves
    /// quoting works by destroying the host when it does not is one nobody can
    /// afford to run. A file that should not exist is just as decisive.
    #[test]
    fn an_argument_that_looks_like_a_command_stays_an_argument() {
        // Unique per process, so two test binaries running at once cannot see
        // each other's probe and report a failure that did not happen.
        let probe =
            std::env::temp_dir().join(format!("mcp-ssh-quoting-probe-{}", std::process::id()));
        let _ = std::fs::remove_file(&probe);
        let path = probe.display().to_string();

        for payload in [
            format!("; touch {path}"),
            format!("$(touch {path})"),
            format!("`touch {path}`"),
            format!("'; touch {path}; '"),
            format!("x && touch {path}"),
            format!("x | touch {path}"),
        ] {
            round_trip(&[&payload]);
        }

        let ran = probe.exists();
        let _ = std::fs::remove_file(&probe);
        assert!(!ran, "an argument was executed rather than passed");
    }

    /// "Refused before it is sent" has to mean the target can run whatever was
    /// accepted. The target's shell receives the rendered string as one `execve`
    /// argument, which Linux caps, and quoting can quadruple what it was given
    /// — so the bound that matters is on the rendered form, and the bound that
    /// is checked is on the input. This is the case where those two are
    /// furthest apart: every byte a single quote, at both limits at once.
    #[test]
    fn the_largest_accepted_command_still_fits_what_a_target_can_exec() {
        let per_argument = MAX_BYTES / MAX_ARGS;
        let argv: Vec<String> = (0..MAX_ARGS).map(|_| "'".repeat(per_argument)).collect();
        let worst = Command::new(argv).expect("at the limits, not past them");
        let rendered = worst.to_wire().len();
        assert!(
            rendered <= MAX_WIRE_BYTES,
            "the largest command this accepts renders to {rendered} bytes, \
             which a target cannot exec"
        );
    }

    /// A command is written into the audit record, so the form it is written in
    /// has to be a form it can be read back from. These two are separate serde
    /// paths - one derived, one through the validating conversion - and nothing
    /// makes them agree except this.
    #[test]
    fn a_command_reads_back_from_what_it_writes() {
        let original = command(&["systemctl", "restart", "unbound", "--now"]);
        let written = serde_json::to_string(&original).unwrap();
        assert_eq!(written, r#"["systemctl","restart","unbound","--now"]"#);
        let read_back: Command = serde_json::from_str(&written).unwrap();
        assert_eq!(read_back, original);
    }

    #[test]
    fn refuses_commands_that_cannot_be_run_or_carried() {
        assert_eq!(Command::new(vec![]).unwrap_err(), CommandError::Empty);
        assert_eq!(
            Command::new(vec![String::new()]).unwrap_err(),
            CommandError::EmptyProgram
        );
        assert_eq!(
            Command::new(vec!["echo".to_owned(), "a\0b".to_owned()]).unwrap_err(),
            CommandError::InteriorNul
        );
        assert_eq!(
            Command::new(vec!["x".to_owned(); MAX_ARGS + 1]).unwrap_err(),
            CommandError::TooManyArguments { max: MAX_ARGS }
        );
        assert_eq!(
            Command::new(vec!["echo".to_owned(), "x".repeat(MAX_BYTES)]).unwrap_err(),
            CommandError::TooLarge { max: MAX_BYTES }
        );
    }

    #[test]
    fn program_and_arguments_are_distinguishable() {
        let cmd = command(&["docker", "logs", "--tail", "20", "traefik"]);
        assert_eq!(cmd.program(), "docker");
        assert_eq!(cmd.args(), ["logs", "--tail", "20", "traefik"]);
    }

    /// Deserialization goes through the constructor, so a command arriving as
    /// data is bounded and NUL-free like one built in process.
    #[test]
    fn deserialization_cannot_bypass_validation() {
        assert!(serde_json::from_str::<Command>(r#"["echo","hi"]"#).is_ok());
        assert!(
            serde_json::from_str::<Command>("[]").is_err(),
            "an empty command deserialized"
        );
        assert!(
            serde_json::from_str::<Command>(r#"["echo","an argument with spaces"]"#).is_ok(),
            "spaces are ordinary argument content, not a reason to refuse"
        );
        // JSON escape rather than a literal NUL: a raw control byte in source
        // is invisible in review and does not survive routine reformatting.
        assert!(
            serde_json::from_str::<Command>(r#"["echo","a\u0000b"]"#).is_err(),
            "a NUL-bearing command deserialized"
        );
    }
}
