//! What a command is, according to a catalog of the vocabulary we know.
//!
//! Policy cannot decide anything without facts about the command, and this is
//! where those facts come from: which program is being run, how much that
//! program could do, and whether it is a program that runs whatever it is
//! handed.
//!
//! The honest limit, stated once here so it is not mistaken later: a
//! sufficiently creative permitted command defeats this. `tar` can read a file
//! that `cat` would have been refused for, and an interpreter can do anything
//! at all. What contains the outcome is the role credential, not this module. A
//! classification defect is an audit gap; it is not a privilege escalation.
//!
//! Two rules follow from that and are enforced rather than documented:
//!
//! - A command the catalog cannot identify is never assumed benign. It
//!   carries the maximal assessment with the reason on record, so policy can
//!   put it in front of a human rather than run it - and a session whose
//!   ceiling does not reach that assessment refuses it outright. The catalog
//!   is the whole of what this deployment understands, so it grows through
//!   use rather than by guessing at a vocabulary in advance.
//! - Nothing here lowers an assessment. Every signal combines by maximum, and
//!   a site addition that would reduce one is rejected when it is merged.
//!   Lowering is the assisted stage's job, under its own bound.
//!
//! A described program may declare a scope for options the catalog does not
//! list. That is not a guess about an unknown program - it is a statement
//! about a known one: every flag of `grep` shapes output, so enumerating each
//! spelling adds nothing but refusals. The declaration is honest only where no
//! option can exceed the stated scope or every option that does is described
//! (`ss` is safe to declare at read exactly because `-K` is written down as a
//! mutate). It is refused outright on interpreters and subcommand programs,
//! where an undescribed option's arity can move which word is the payload or
//! the subcommand and quietly under-assess the command.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Scope;
use crate::command::Command;

/// The catalog shipped with the service.
const BUILTIN: &str = include_str!("catalog/builtin.json");

/// A versioned catalog of the command vocabulary a deployment understands.
/// Unknown fields are refused rather than ignored. A misspelling in a catalog
/// is not a cosmetic error: `interpretor` silently dropped leaves a program
/// classified at its floor scope, and the catalog would load looking correct.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Refused when blank: the version travels with every assessment so a
    /// recorded decision can be traced to what classified it, and an empty one
    /// records that nothing in particular did.
    #[serde(deserialize_with = "non_blank_version")]
    version: String,
    #[serde(default)]
    programs: HashMap<String, ProgramRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRule {
    /// What the program can do before its arguments are considered.
    scope: Scope,
    /// Whether the program runs whatever it is handed.
    ///
    /// Recorded rather than folded into the scope because the two facts are
    /// used differently: the scope is what policy compares against a ceiling,
    /// while this identifies the case where the program is known and the
    /// payload it was given is the actual unknown.
    #[serde(default)]
    interpreter: bool,
    /// Subcommands that change what the program does.
    ///
    /// When a program has any, one of them is required: `docker` on its own
    /// says nothing about whether the caller means `ps` or `exec`.
    #[serde(default)]
    subcommands: HashMap<String, Scope>,
    /// The program's options: how each one parses, and what it implies.
    ///
    /// Two things are described here, because they are two facts about the same
    /// word. **What an option means**: `journalctl` reads logs, and
    /// `journalctl --rotate` destroys them, so an option can raise the
    /// assessment. **Whether an option takes a separate value**: without that,
    /// nothing can tell the subcommand in `docker ps` from the option value in
    /// `docker --config ps`, and a program's real subcommand can be missed
    /// entirely.
    ///
    /// For a program with subcommands, an option the catalog does not describe
    /// makes the command unclassifiable rather than guessable, because an
    /// undeclared option may or may not consume the word after it and that word
    /// may or may not be the subcommand.
    #[serde(default)]
    options: HashMap<String, OptionRule>,
    /// What an option the catalog does not list is taken to be doing.
    ///
    /// When present, an undescribed option reads as a flag - taking no value -
    /// at this scope, instead of refusing the command. A described option keeps
    /// its own arity and scope, which is how a known-dangerous flag still
    /// raises on a program declared harmless wholesale. Reading an unlisted
    /// option as a flag can misattribute a value word as another flag, and that
    /// only combines upward: every misread word takes at least this scope, and
    /// operands raise nothing.
    ///
    /// Refused on interpreters and subcommand programs - see the module doc.
    #[serde(default)]
    unlisted_options: Option<Scope>,
}

impl ProgramRule {
    /// Reads an option by name, falling back to the unlisted-option
    /// declaration when the catalog does not list it.
    ///
    /// The unlisted reading is a flag: it takes no value and hands nothing
    /// off. It carries the declared scope only where that says more than the
    /// program's floor already does, so a declaration at the floor does not
    /// bury the grounds under a restatement of it for every flag.
    fn option(&self, name: &str) -> Result<OptionRule, String> {
        if let Some(option) = self.options.get(name) {
            return Ok(option.clone());
        }
        let Some(scope) = self.unlisted_options else {
            return Err(name.to_owned());
        };
        // GNU long-option parsing accepts unique abbreviations, so on a
        // program that would otherwise read this spelling as an unlisted
        // flag, a prefix of a described option may BE that option at
        // runtime: `date --se=...` runs `--set`. A unique prefix resolves
        // to its description so the abbreviation carries the raise; an
        // ambiguous one refuses, as the real program would.
        if name.starts_with("--") {
            let mut described = self
                .options
                .iter()
                .filter(|(spelling, _)| spelling.starts_with(name));
            if let Some((_, first)) = described.next() {
                if described.next().is_some() {
                    return Err(name.to_owned());
                }
                return Ok(first.clone());
            }
        }
        Ok(OptionRule {
            takes_value: false,
            optional_value: false,
            payload: false,
            scope: (scope > self.scope).then_some(scope),
        })
    }
}

/// How an option consumes what follows it.
///
/// Compared as a whole when an addition restates a known option, because every
/// part of it decides which words belong to the option and which are read on
/// their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arity {
    /// Takes nothing.
    Flag,
    /// Takes an attached value, and nothing beyond its own argument.
    Attached,
    /// Takes the next word when no value is attached.
    Value,
}

/// What the catalog knows about one option.
impl OptionRule {
    const fn arity(&self) -> Arity {
        if self.takes_value {
            Arity::Value
        } else if self.optional_value {
            Arity::Attached
        } else {
            Arity::Flag
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionRule {
    /// Whether the option consumes the word after it.
    #[serde(default)]
    takes_value: bool,
    /// Whether the option takes a value only when one is attached.
    ///
    /// `journalctl -n` means ten lines and `journalctl -n50` means fifty, so
    /// neither arity above describes it: calling it value-taking would make a
    /// bare `-n` swallow the next word - including a flag that should have
    /// raised the assessment - and calling it a flag would read `-n50` as the
    /// options `-5` and `-0`.
    #[serde(default)]
    optional_value: bool,
    /// Whether the program stops reading its own options here.
    ///
    /// `python3 -c 'import sys' --flag` runs Python with `--flag` in its
    /// `sys.argv`; it is not a Python option and Python never looks at it. Only
    /// the catalog can say which option does this, because a program that takes
    /// a value does not necessarily hand off after it: `python3 -X dev -c ...`
    /// keeps reading, and `-c` does not.
    #[serde(default)]
    payload: bool,
    /// What the option's presence says the command is doing, if anything.
    #[serde(default)]
    scope: Option<Scope>,
}

/// Why an assessment landed where it did.
///
/// Carried because the transcript has to be able to answer "why was this
/// treated as privileged" later, when the catalog has moved on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ground", rename_all = "snake_case")]
pub enum Ground {
    /// The catalog's floor for this program.
    Program { program: String, scope: Scope },
    /// A subcommand the catalog recognises.
    Subcommand { subcommand: String, scope: Scope },
    /// An option the catalog recognises as doing more than the program's floor.
    Option { option: String, scope: Scope },
    /// The program runs whatever it is handed.
    Interpreter { program: String },
    /// The catalog could not identify the command, so the assessment is the
    /// maximal one rather than a judgement about what the command does. What
    /// runs on this ground is a human's answer, not the catalog's.
    Unidentified { reason: Unidentified },
}

/// What the catalog knows about one command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Classification {
    catalog_version: String,
    command: Command,
    program: String,
    assessment: Scope,
    interpreter: bool,
    grounds: Vec<Ground>,
}

impl Classification {
    /// The command these facts are about.
    ///
    /// Read-only, like everything else here, and that is the point: a decision
    /// weighs an assessment *and* the command's own words, so a facts object
    /// whose parts can be set independently lets a caller pair one command's
    /// assessment with another command's arguments. Only classifying a command
    /// produces one of these, and it describes that command or nothing.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Which catalog produced this, so a recorded decision stays readable after
    /// the catalog changes.
    #[must_use]
    pub fn catalog_version(&self) -> &str {
        &self.catalog_version
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The subcommand recognised by the catalog, when this program has one.
    #[must_use]
    pub fn subcommand(&self) -> Option<&str> {
        self.grounds.iter().find_map(|ground| match ground {
            Ground::Subcommand { subcommand, .. } => Some(subcommand.as_str()),
            _ => None,
        })
    }

    /// The most privileged thing this command could be doing.
    #[must_use]
    pub const fn assessment(&self) -> Scope {
        self.assessment
    }

    /// Whether the program runs whatever it is handed.
    #[must_use]
    pub const fn interpreter(&self) -> bool {
        self.interpreter
    }

    /// Why the assessment landed where it did.
    #[must_use]
    pub fn grounds(&self) -> &[Ground] {
        &self.grounds
    }

    /// Whether the catalog identified the command, as opposed to assessing it
    /// maximally because it could not.
    ///
    /// The stage that may *lower* an assessment applies only where this is
    /// true: lowering is a judgement about what an identified invocation does,
    /// and there is no such judgement to make about a command the catalog
    /// could not read.
    #[must_use]
    pub fn identified(&self) -> bool {
        !self
            .grounds
            .iter()
            .any(|ground| matches!(ground, Ground::Unidentified { .. }))
    }

    /// Why identification failed, when it did.
    #[must_use]
    pub fn unidentified(&self) -> Option<&Unidentified> {
        self.grounds.iter().find_map(|ground| match ground {
            Ground::Unidentified { reason } => Some(reason),
            _ => None,
        })
    }
}

impl Catalog {
    /// The catalog shipped with the service.
    ///
    /// Grown from commands the deployment actually issues rather than from a
    /// guess at a complete vocabulary: what it cannot identify is assessed
    /// maximally and lands in front of a human, and what a human keeps
    /// approving is what belongs in here next.
    pub fn builtin() -> Result<Self, CatalogError> {
        Self::from_json(BUILTIN)
    }

    pub fn from_json(raw: &str) -> Result<Self, CatalogError> {
        let catalog: Self =
            serde_json::from_str(raw).map_err(|source| CatalogError::Malformed {
                detail: source.to_string(),
            })?;
        for (name, rule) in &catalog.programs {
            if rule.unlisted_options.is_some() && (rule.interpreter || !rule.subcommands.is_empty())
            {
                return Err(CatalogError::UnreadableUnlisted {
                    program: name.clone(),
                });
            }
        }
        Ok(catalog)
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Folds a site's additions into this catalog.
    ///
    /// Additions may introduce programs and options, and raise what a known one
    /// is assumed to do. They may not reduce an assessment or
    /// un-mark an interpreter: a deployment that could relax the catalog could
    /// quietly turn a privileged command into a read, and the whole point of
    /// classification is that policy sees the more dangerous reading.
    pub fn merge(&mut self, addition: Self) -> Result<(), CatalogError> {
        // Checked in full before anything is applied. Rejecting an addition
        // halfway through would leave some of its raises live under the
        // catalog version that did not contain them, so a recorded decision
        // would name a catalog that never classified that way.
        for (name, added) in &addition.programs {
            let Some(existing) = self.programs.get(name) else {
                continue;
            };
            if added.scope < existing.scope {
                return Err(CatalogError::Lowering {
                    what: format!("program {name}"),
                });
            }
            if existing.interpreter && !added.interpreter {
                return Err(CatalogError::Lowering {
                    what: format!("interpreter marking on {name}"),
                });
            }
            // Giving a program its first subcommand changes how every one of
            // its options is read: the walk then stops at the subcommand, and
            // the flags after it become the subcommand's own, unchecked. A site
            // adding a `logs` subcommand to `journalctl` would turn
            // `journalctl logs --rotate` from a mutate into a read without
            // touching a single scope, so it is refused as the lowering it is.
            if existing.subcommands.is_empty() && !added.subcommands.is_empty() {
                return Err(CatalogError::Lowering {
                    what: format!("how {name}'s options are read, by introducing subcommands"),
                });
            }
            // Declaring a scope for unlisted options turns refusals into runs,
            // so a site may not introduce one - only raise one the built-in
            // catalog already carries. And marking a wildcard program as an
            // interpreter would combine the two states `from_json` refuses.
            match (existing.unlisted_options, added.unlisted_options) {
                (None, Some(_)) => {
                    return Err(CatalogError::Lowering {
                        what: format!(
                            "how {name}'s undescribed options are read, by declaring a scope for them"
                        ),
                    });
                }
                (Some(had), Some(now)) if now < had => {
                    return Err(CatalogError::Lowering {
                        what: format!("what {name}'s unlisted options are taken to be doing"),
                    });
                }
                _ => {}
            }
            if existing.unlisted_options.is_some() && added.interpreter {
                return Err(CatalogError::UnreadableUnlisted {
                    program: name.clone(),
                });
            }
            for (sub, scope) in &added.subcommands {
                if existing.subcommands.get(sub).is_some_and(|had| scope < had) {
                    return Err(CatalogError::Lowering {
                        what: format!("subcommand {name} {sub}"),
                    });
                }
            }
            for (option, rule) in &added.options {
                let Some(had) = existing.options.get(option) else {
                    // A new spelling is not necessarily a new option. Under an
                    // unlisted-option declaration the existing rule already
                    // reads it - as a valueless flag, or as the described
                    // option it abbreviates (`date --se` IS `--set` at
                    // runtime, and an exact description would shadow that
                    // resolution). A description must say at least what that
                    // reading said, in scope and in parse: less scope would
                    // re-assess the spelling downward, and a changed arity
                    // could swallow a described raise - `ss -x -K` falls from
                    // a mutate to a read the moment `-x` learns to take a
                    // value. A spelling the existing rule refuses (an
                    // ambiguous abbreviation) may be described freely: that is
                    // growth from a refusal, as on enumerated programs.
                    if let Ok(today) = existing.option(option) {
                        let read_as = today
                            .scope
                            .map_or(existing.scope, |scope| scope.max(existing.scope));
                        let described_as = rule
                            .scope
                            .map_or(added.scope, |scope| scope.max(added.scope));
                        if described_as < read_as {
                            return Err(CatalogError::Lowering {
                                what: format!(
                                    "option {name} {option}, below what {name} already read that spelling as"
                                ),
                            });
                        }
                        if today.arity() != rule.arity() || today.payload != rule.payload {
                            return Err(CatalogError::Lowering {
                                what: format!("how {name} {option} parses"),
                            });
                        }
                    }
                    continue;
                };
                if had
                    .scope
                    .is_some_and(|had| rule.scope.is_none_or(|added| added < had))
                {
                    return Err(CatalogError::Lowering {
                        what: format!("option {name} {option}"),
                    });
                }
                // Arity is not a permission level, but changing it moves which
                // word is read as the subcommand: redefining `--config` as a
                // flag makes `docker --config ps exec web sh` read `ps` and
                // assess as a read, when what runs is `exec`. So an addition
                // may describe an option the catalog does not carry and may
                // raise what a known one implies, but it may not restate how a
                // known one parses.
                // Every part of how it is read, not just one of them: marking a
                // flag as optional-valued makes it swallow the rest of its
                // bundle, so `journalctl -fr` would read as `-f` with the value
                // `r` and lose whatever `-r` implies, and marking an option as
                // handing off ends the walk at it, so every option after it
                // goes unread.
                if had.arity() != rule.arity() || had.payload != rule.payload {
                    return Err(CatalogError::Lowering {
                        what: format!("how {name} {option} parses"),
                    });
                }
            }
        }

        for (name, added) in addition.programs {
            match self.programs.get_mut(&name) {
                None => {
                    self.programs.insert(name, added);
                }
                Some(existing) => {
                    existing.subcommands.extend(added.subcommands);
                    existing.options.extend(added.options);
                    existing.scope = added.scope;
                    existing.interpreter = added.interpreter;
                    // An addition that says nothing about unlisted options
                    // leaves the declaration alone: silence is not a
                    // withdrawal, or describing one new option would quietly
                    // turn a program's whole vocabulary back into refusals.
                    existing.unlisted_options =
                        added.unlisted_options.or(existing.unlisted_options);
                }
            }
        }
        // Both versions, because a merged catalog is neither one of them and a
        // recorded decision has to be traceable to what actually classified it.
        self.version = format!("{}+{}", self.version, addition.version);
        Ok(())
    }

    /// Turns a command into what the catalog knows about it.
    ///
    /// The caller's own account of the command is not an input. An agent
    /// describing its command as harmless is a claim to be checked against
    /// these facts, not a source of them.
    ///
    /// Always answers. A command the catalog cannot identify is not assumed
    /// benign - it carries the maximal assessment, with the reason on record
    /// as a ground - and it is not turned away here either: whether an
    /// unidentified command runs is policy's question, and under the shipped
    /// policy the answer is a human's.
    pub fn classify(&self, command: &Command) -> Classification {
        self.identify(command)
            .unwrap_or_else(|reason| Classification {
                catalog_version: self.version.clone(),
                command: command.clone(),
                program: command.program().to_owned(),
                assessment: Scope::Privileged,
                interpreter: false,
                grounds: vec![Ground::Unidentified { reason }],
            })
    }

    /// Reads a command against the vocabulary, failing where it cannot.
    fn identify(&self, command: &Command) -> Result<Classification, Unidentified> {
        let program = command.program();
        let Some(rule) = self.programs.get(program) else {
            return Err(Unidentified::UnknownProgram {
                program: program.to_owned(),
            });
        };

        let mut assessment = rule.scope;
        let mut grounds = vec![Ground::Program {
            program: program.to_owned(),
            scope: rule.scope,
        }];

        if rule.interpreter {
            assessment = assessment.max(Scope::Privileged);
            grounds.push(Ground::Interpreter {
                program: program.to_owned(),
            });
        }

        // Options are walked with their arity, so a value that happens to look
        // like an option - `journalctl --since -1h` - is read as the value it
        // is rather than as an option nobody declared.
        let mut arguments = command.args().iter();
        while let Some(argument) = arguments.next() {
            let read = match read_option(rule, argument) {
                Ok(Read::Option(read)) => read,
                // For a program with subcommands this is the subcommand, and
                // the words after it are the subcommand's own - including its
                // options, which this model does not describe. Reading them
                // against the *program's* option rules would let a site raising
                // a global option's scope raise it wherever that spelling
                // appears, which is a different command than the one described.
                //
                // For an interpreter it is the script, and an interpreter runs
                // whatever it is handed: `bash work.sh --flag` passes `--flag`
                // to the script, so reading it against `bash`'s own options
                // would refuse a valid command over a word `bash` never sees.
                Ok(Read::Operand) => {
                    if rule.subcommands.is_empty() && !rule.interpreter {
                        continue;
                    }
                    break;
                }
                // Everything after `--` is an operand, so nothing beyond it is
                // an option to raise an assessment or to refuse.
                Ok(Read::EndOfOptions) => break,
                // A program whose effect is carried by flags is the case that
                // started this: `journalctl` reads and `journalctl --rotate`
                // destroys, and an option nobody described would keep the
                // reading floor. So for a program with no subcommands - where
                // every option is one of these - an undescribed one refuses.
                //
                // A program *with* subcommands has already refused undescribed
                // options ahead of its subcommand, where they would change
                // which word that is. The ones after it belong to the
                // subcommand, and describing those is a per-subcommand option
                // model this does not have.
                Err(unknown) => {
                    if rule.subcommands.is_empty() {
                        return Err(Unidentified::UnknownOption {
                            program: program.to_owned(),
                            option: unknown,
                        });
                    }
                    continue;
                }
            };
            if read.consumes_next {
                arguments.next();
            }
            for (name, scope) in read.named {
                if let Some(scope) = scope {
                    assessment = assessment.max(scope);
                    grounds.push(Ground::Option {
                        option: name.to_owned(),
                        scope,
                    });
                }
            }
            // The option handed the rest of the line to something else:
            // `python3 -c 'work' --flag` puts `--flag` in the program's
            // `sys.argv`, where Python neither reads it nor could.
            if read.payload {
                break;
            }
        }

        if !rule.subcommands.is_empty() {
            let subcommand = find_subcommand(program, rule, command.args())?;
            let scope = rule.subcommands.get(subcommand.as_str()).copied().ok_or(
                Unidentified::UnknownSubcommand {
                    program: program.to_owned(),
                    subcommand: subcommand.clone(),
                },
            )?;
            assessment = assessment.max(scope);
            grounds.push(Ground::Subcommand { subcommand, scope });
        }

        Ok(Classification {
            catalog_version: self.version.clone(),
            command: command.clone(),
            program: program.to_owned(),
            assessment,
            interpreter: rule.interpreter,
            grounds,
        })
    }
}

/// Reads a catalog version, refusing one that identifies nothing.
fn non_blank_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    if raw.trim().is_empty() {
        return Err(serde::de::Error::custom(
            "a catalog version identifies what classified a command, so it cannot be blank",
        ));
    }
    Ok(raw)
}

/// What one argument turned out to be.
enum Read {
    Option(OptionRead),
    /// Not an option: for a program with subcommands, this is the subcommand.
    Operand,
    /// `--`. Everything after it is an operand however it is spelled.
    EndOfOptions,
}

struct OptionRead {
    /// Every option this argument names. A single-dash argument can name
    /// several: `ls -la` is `-l` and `-a`, which is how people actually write
    /// it, and refusing it would make the catalog unusable rather than strict.
    ///
    /// Owned, because a short option in a bundle is not a slice of the argument
    /// it came from: there is no `-a` inside `-la`.
    named: Vec<(String, Option<Scope>)>,
    /// Whether the option takes the *next* argument as its value.
    consumes_next: bool,
    /// Whether the program stops reading its own options after this argument.
    payload: bool,
}

/// Reads one argument against a program's options.
///
/// Returns the option's name when the catalog does not describe it, so the
/// caller can say which one it could not read.
fn read_option(rule: &ProgramRule, argument: &str) -> Result<Read, String> {
    if argument == "--" {
        return Ok(Read::EndOfOptions);
    }
    if !argument.starts_with('-') || argument == "-" {
        return Ok(Read::Operand);
    }
    // `=` separates a name from its value on a long option only. A single-dash
    // argument is read as a bundle whatever it contains, because the `=` in
    // `python3 -cprint("x=1")` is part of the payload and reading it as a
    // separator makes the whole word an option name nobody wrote.
    let attached = argument
        .starts_with("--")
        .then(|| argument.split_once('='))
        .flatten();
    if argument.starts_with("--") {
        let name = attached.map_or(argument, |(name, _)| name);
        let option = rule.option(name)?;
        return Ok(Read::Option(OptionRead {
            named: vec![(name.to_owned(), option.scope)],
            consumes_next: option.takes_value && attached.is_none(),
            payload: option.payload,
        }));
    }

    // A single-dash argument is a bundle of short options, and the first one
    // that takes a value takes the rest of the bundle as that value - `-n50` is
    // `-n` with `50`, not `-n -5 -0`.
    let mut named = Vec::new();
    let mut consumes_next = false;
    // A bundle hands off if any option in it does: `sh -xc 'work'` is `-x` and
    // then `-c`, and what follows belongs to the shell's payload either way.
    let mut payload = false;
    let letters: Vec<char> = argument.chars().skip(1).collect();
    for (position, letter) in letters.iter().enumerate() {
        let name = format!("-{letter}");
        let option = rule.option(name.as_str())?;
        let takes_value = option.takes_value;
        let optional_value = option.optional_value;
        payload |= option.payload;
        named.push((name, option.scope));
        let last = position.saturating_add(1) == letters.len();
        if takes_value {
            // Whatever is left of the bundle is this option's value, so `-n50`
            // is `-n` with `50` rather than three more short options.
            consumes_next = last;
            break;
        }
        if optional_value && !last {
            // An attached value, and only an attached one. Nothing after this
            // argument belongs to it, so a bare `-n` does not reach past its
            // own argument for a value it may not have.
            break;
        }
    }
    Ok(Read::Option(OptionRead {
        named,
        consumes_next,
        payload,
    }))
}

/// Reads a program's arguments the way the program reads them, and returns the
/// word that names its subcommand.
///
/// See the note on [`ProgramRule::options`] for why an undeclared option is a
/// refusal rather than something to skip.
fn find_subcommand(
    program: &str,
    rule: &ProgramRule,
    arguments: &[String],
) -> Result<String, Unidentified> {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        match read_option(rule, argument) {
            Ok(Read::Option(read)) => {
                if read.consumes_next {
                    arguments.next();
                }
                // What follows belongs to whatever the option handed the line
                // to, so no word after this one names a subcommand.
                if read.payload {
                    break;
                }
            }
            Ok(Read::Operand) => return Ok(argument.clone()),
            // `--` is the marker, not the subcommand: what follows it is.
            Ok(Read::EndOfOptions) => {
                return arguments
                    .next()
                    .cloned()
                    .ok_or(Unidentified::MissingSubcommand {
                        program: program.to_owned(),
                    });
            }
            Err(unknown) => {
                return Err(Unidentified::UnknownOption {
                    program: program.to_owned(),
                    option: unknown,
                });
            }
        }
    }
    Err(Unidentified::MissingSubcommand {
        program: program.to_owned(),
    })
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("the catalog could not be read: {detail}")]
    Malformed { detail: String },
    #[error("a catalog addition would lower {what}, and additions may only raise")]
    Lowering { what: String },
    #[error(
        "{program} cannot declare a scope for unlisted options: on an interpreter or a program with subcommands, an undescribed option can move which word is the payload or the subcommand"
    )]
    UnreadableUnlisted { program: String },
}

/// Why the catalog could not identify a command.
///
/// Not an error: an unidentified command still classifies - maximally - and
/// this travels with it as the ground, so the record and the human asked to
/// approve it both see what the catalog could not read.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, Serialize)]
#[serde(tag = "unidentified", rename_all = "snake_case")]
pub enum Unidentified {
    #[error("the catalog does not know the program {program}")]
    UnknownProgram { program: String },
    #[error("{program} needs a subcommand for its effect to be known")]
    MissingSubcommand { program: String },
    #[error("the catalog does not know {program} {subcommand}")]
    UnknownSubcommand { program: String, subcommand: String },
    #[error(
        "the catalog does not describe {program}'s option {option}, so it cannot tell which word is the subcommand"
    )]
    UnknownOption { program: String, option: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::builtin().expect("the built-in catalog parses")
    }

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    fn classify(argv: &[&str]) -> Classification {
        catalog().classify(&command(argv))
    }

    /// Why identification failed, asserting both that it did and that the
    /// command carries the maximal assessment an unidentified one must.
    fn unidentified(argv: &[&str]) -> Unidentified {
        let classification = classify(argv);
        assert_eq!(
            classification.assessment(),
            Scope::Privileged,
            "{argv:?} is unidentified but not maximally assessed"
        );
        assert!(!classification.identified());
        classification
            .unidentified()
            .unwrap_or_else(|| panic!("{argv:?} was identified"))
            .clone()
    }

    fn classify_with(catalog: &Catalog, argv: &[&str]) -> Classification {
        catalog.classify(&command(argv))
    }

    /// The catalog ships as data, so a malformed one would otherwise surface as
    /// a failure to classify anything at runtime.
    #[test]
    fn the_shipped_catalog_is_readable() {
        let catalog = catalog();
        assert!(!catalog.version().is_empty());
    }

    /// The assessment is the most privileged reading of the command, taken from
    /// the program, its subcommand, and what it names.
    #[test]
    fn a_command_is_assessed_by_what_it_could_do() {
        for (argv, expected) in [
            (&["uptime"][..], Scope::Read),
            (&["docker", "ps"][..], Scope::Read),
            (&["docker", "--tls", "logs", "traefik"][..], Scope::Read),
            (&["systemctl", "status", "sshd"][..], Scope::Read),
            (&["docker", "restart", "traefik"][..], Scope::Mutate),
            (&["systemctl", "restart", "sshd"][..], Scope::Mutate),
            (&["docker", "exec", "traefik", "ls"][..], Scope::Privileged),
            (&["sh", "-c", "uptime"][..], Scope::Privileged),
        ] {
            let classification = catalog().classify(&command(argv));
            assert_eq!(classification.assessment, expected, "for {argv:?}");
        }
    }

    #[test]
    fn what_the_catalog_cannot_describe_is_unidentified_and_maximal() {
        assert_eq!(
            unidentified(&["tar", "-cf", "/tmp/x.tar", "/etc"]),
            Unidentified::UnknownProgram {
                program: "tar".to_owned()
            }
        );
        // A path-qualified program is a different string, and the catalog
        // matches strings. Guessing that the trailing component is the real
        // program would make `/tmp/attacker/docker` classify as docker.
        assert_eq!(
            unidentified(&["/usr/bin/docker", "ps"]),
            Unidentified::UnknownProgram {
                program: "/usr/bin/docker".to_owned()
            }
        );
        assert_eq!(
            unidentified(&["docker", "swarm", "init"]),
            Unidentified::UnknownSubcommand {
                program: "docker".to_owned(),
                subcommand: "swarm".to_owned()
            }
        );
        assert_eq!(
            unidentified(&["docker", "--tls"]),
            Unidentified::MissingSubcommand {
                program: "docker".to_owned()
            }
        );
    }

    /// A program whose destructive surface is options, not subcommands, is the
    /// case the subcommand model does not see: reading the journal and
    /// destroying it are the same program with a different flag.
    #[test]
    fn an_option_that_does_more_than_the_program_raises_the_assessment() {
        assert_eq!(
            classify(&["journalctl", "-u", "unbound", "-n", "50"]).assessment,
            Scope::Read
        );
        for destructive in [
            &["journalctl", "--rotate"][..],
            &["journalctl", "--vacuum-size=1M"][..],
            &["journalctl", "--vacuum-time", "1d"][..],
            &["journalctl", "-u", "unbound", "--flush"][..],
        ] {
            assert_eq!(
                classify(destructive).assessment,
                Scope::Mutate,
                "{destructive:?} classified as a read"
            );
        }
    }

    /// Options are read the way the program reads them, so an option's value
    /// is never mistaken for the subcommand - in either direction.
    #[test]
    fn an_option_value_cannot_stand_in_for_the_subcommand() {
        // A value that looks like nothing: the subcommand after it decides.
        assert_eq!(
            classify(&["docker", "--host", "unix:///run/docker.sock", "ps"]).assessment,
            Scope::Read
        );
        // A value that is itself a catalogued subcommand. The command really
        // runs `exec`, and reading `ps` here would under-assess it.
        assert_eq!(
            classify(&["docker", "--config", "ps", "exec", "web", "sh"]).assessment,
            Scope::Privileged
        );
        // The same shape, but what really runs is not catalogued at all. This
        // must refuse rather than report the option value's scope.
        assert_eq!(
            unidentified(&["docker", "--config", "ps", "swarm", "init"]),
            Unidentified::UnknownSubcommand {
                program: "docker".to_owned(),
                subcommand: "swarm".to_owned()
            }
        );
        // Attached values are consumed by the option they are attached to.
        assert_eq!(
            classify(&["docker", "--config=/tmp/cfg", "ps"]).assessment,
            Scope::Read
        );
        // Flags take no value, so the word after one is still the subcommand.
        assert_eq!(
            classify(&["docker", "--tls", "exec", "web", "sh"]).assessment,
            Scope::Privileged
        );
    }

    /// Restating how a known option parses is a way to lower an assessment
    /// without touching a scope: redefining `--config` as taking no value moves
    /// which word is read as the subcommand, and the command's real effect
    /// disappears behind an option's value.
    #[test]
    fn a_site_cannot_redefine_how_a_known_option_parses() {
        let mut catalog = Catalog::builtin().unwrap();
        let before =
            classify_with(&catalog, &["docker", "--config", "ps", "exec", "web", "sh"]).assessment;
        assert_eq!(before, Scope::Privileged);

        let refused = Catalog::from_json(
            r#"{
              "version": "site",
              "programs": {
                "docker": { "scope": "read", "options": { "--config": {} } }
              }
            }"#,
        )
        .unwrap();
        assert!(matches!(
            catalog.merge(refused),
            Err(CatalogError::Lowering { .. })
        ));

        // Every part of the arity, not just whether it takes the next word.
        // Marking a flag as optional-valued makes it swallow the rest of its
        // bundle: `journalctl -fr` would read as `-f` with the value `r`, and
        // whatever `-r` implies would be lost.
        let mut journal = Catalog::builtin().unwrap();
        assert!(matches!(
            journal.merge(
                Catalog::from_json(
                    r#"{
                      "version": "site",
                      "programs": {
                        "journalctl": {
                          "scope": "read",
                          "options": { "-f": { "optional_value": true } }
                        }
                      }
                    }"#,
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));

        // Including whether the option hands the rest of the line to something
        // else. `journalctl -u sshd --rotate` destroys logs, and marking `-u`
        // as a hand-off would end the walk before `--rotate` is ever read.
        assert!(matches!(
            journal.merge(
                Catalog::from_json(
                    r#"{
                      "version": "site",
                      "programs": {
                        "journalctl": {
                          "scope": "read",
                          "options": {
                            "-u": { "takes_value": true, "payload": true }
                          }
                        }
                      }
                    }"#,
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));
        assert_eq!(
            classify_with(&journal, &["journalctl", "-u", "sshd", "--rotate"]).assessment,
            Scope::Mutate
        );
        assert_eq!(
            classify_with(&catalog, &["docker", "--config", "ps", "exec", "web", "sh"]).assessment,
            before
        );

        // Describing an option the catalog does not carry is still allowed:
        // that is how a site's vocabulary grows.
        let accepted = Catalog::from_json(
            r#"{
              "version": "site",
              "programs": {
                "docker": { "scope": "read", "options": { "--new-flag": {} } }
              }
            }"#,
        )
        .unwrap();
        catalog.merge(accepted).unwrap();
        assert_eq!(
            classify_with(&catalog, &["docker", "--new-flag", "ps"]).assessment,
            Scope::Read
        );
    }

    /// After a subcommand the words belong to it, and the program's own option
    /// rules do not describe them. Applying them there would let a site raising
    /// a global option's scope raise it wherever that spelling appears.
    #[test]
    fn a_programs_options_are_not_read_against_its_subcommands_arguments() {
        let mut catalog = Catalog::builtin().unwrap();
        catalog
            .merge(
                Catalog::from_json(
                    r#"{
                      "version": "site",
                      "programs": {
                        "docker": {
                          "scope": "read",
                          "options": { "--debug": { "scope": "privileged" } }
                        }
                      }
                    }"#,
                )
                .unwrap(),
            )
            .unwrap();

        // Before the subcommand, the site's raise applies.
        assert_eq!(
            classify_with(&catalog, &["docker", "--debug", "ps"]).assessment,
            Scope::Privileged
        );
        // After it, the same spelling belongs to the subcommand.
        assert_eq!(
            classify_with(&catalog, &["docker", "ps", "--debug"]).assessment,
            Scope::Read
        );
    }

    /// A digit can be an option in its own right. Treating every digit as a
    /// value would skip one the catalog describes, and accept one it does not.
    #[test]
    fn a_numeric_option_is_read_before_a_number_is_assumed() {
        // `-1` is a real option of `ls` and is read as one.
        assert_eq!(classify(&["ls", "-1"]).assessment, Scope::Read);
        assert_eq!(classify(&["ls", "-l1"]).assessment, Scope::Read);

        // A digit the catalog does not describe is an option nobody described,
        // whether it stands alone or follows a flag that takes no value.
        for refused in [&["journalctl", "-5"][..], &["journalctl", "-x5"][..]] {
            assert_eq!(
                unidentified(refused),
                Unidentified::UnknownOption {
                    program: "journalctl".to_owned(),
                    option: "-5".to_owned()
                },
                "{refused:?} was accepted"
            );
        }

        // An option whose value is optional takes an attached one and nothing
        // else: `-n50` is fifty lines, and a bare `-n` does not reach past its
        // own argument for a value it may not have.
        assert_eq!(classify(&["journalctl", "-n50"]).assessment, Scope::Read);
        assert_eq!(
            classify(&["journalctl", "-n", "--rotate"]).assessment,
            Scope::Mutate,
            "a bare optional-value option swallowed the flag after it"
        );
    }

    /// Giving a program its first subcommand changes how all of its options are
    /// read - the walk stops at the subcommand and the flags after it become
    /// unchecked - so it can lower an assessment without touching a scope.
    #[test]
    fn a_site_cannot_lower_by_giving_a_program_subcommands() {
        let mut catalog = Catalog::builtin().unwrap();
        let before = classify_with(&catalog, &["journalctl", "--rotate"]).assessment;
        assert_eq!(before, Scope::Mutate);

        let refused = Catalog::from_json(
            r#"{
              "version": "site",
              "programs": {
                "journalctl": { "scope": "read", "subcommands": { "logs": "read" } }
              }
            }"#,
        )
        .unwrap();
        assert!(matches!(
            catalog.merge(refused),
            Err(CatalogError::Lowering { .. })
        ));
        assert_eq!(
            classify_with(&catalog, &["journalctl", "--rotate"]).assessment,
            before
        );
    }

    /// `--` ends options: everything after it is an operand, whatever it looks
    /// like. Reading it as an option, or as the subcommand itself, misreads the
    /// command in both directions.
    #[test]
    fn the_end_of_options_marker_is_read_as_one() {
        // The subcommand is what follows the marker, not the marker.
        assert_eq!(classify(&["docker", "--", "ps"]).assessment, Scope::Read);
        // An operand after the marker is not an option, so an undescribed one
        // is not a refusal.
        assert_eq!(
            classify(&["cat", "--", "--not-a-flag"]).assessment,
            Scope::Read
        );
        // The marker is what the program reads, not the text: `--config` takes
        // the `--` as its value, so the options have not ended and the word
        // after it is still the subcommand.
        assert_eq!(
            classify(&["docker", "--config", "--", "exec", "web", "sh"]).assessment,
            Scope::Privileged
        );
    }

    /// A version that identifies nothing defeats the reason for carrying one:
    /// a recorded decision has to be traceable to what classified it.
    #[test]
    fn a_catalog_without_a_version_is_refused() {
        assert!(Catalog::from_json(r#"{"version":"","programs":{}}"#).is_err());
        assert!(Catalog::from_json(r#"{"version":"   ","programs":{}}"#).is_err());
        assert!(Catalog::from_json(r#"{"version":"site-1","programs":{}}"#).is_ok());
    }

    /// An option the catalog does not describe refuses, for two different
    /// reasons that both come out the same way. Before a subcommand it may or
    /// may not consume the next word, so which word is the subcommand is
    /// unknown. On a program whose effect is carried by flags, it may be the
    /// destructive one nobody wrote down - which is the `journalctl --rotate`
    /// case, generalised.
    #[test]
    fn an_option_the_catalog_cannot_read_leaves_the_command_unidentified() {
        assert_eq!(
            unidentified(&["docker", "--unknown-flag", "ps"]),
            Unidentified::UnknownOption {
                program: "docker".to_owned(),
                option: "--unknown-flag".to_owned()
            }
        );
        assert_eq!(
            unidentified(&["journalctl", "--not-a-real-flag"]),
            Unidentified::UnknownOption {
                program: "journalctl".to_owned(),
                option: "--not-a-real-flag".to_owned()
            }
        );
        // A bundle is refused by the letter the catalog cannot read, not by the
        // whole bundle, so the message names something an operator can catalog.
        assert_eq!(
            unidentified(&["systemctl", "-aZ", "status", "sshd"]),
            Unidentified::UnknownOption {
                program: "systemctl".to_owned(),
                option: "-Z".to_owned()
            }
        );
        // An optional value is not a licence to swallow the next word: what
        // follows `journalctl --boot` is read on its own, and an undescribed
        // one refuses rather than disappearing as a value.
        assert_eq!(
            unidentified(&["journalctl", "--boot", "--not-a-real-flag"]),
            Unidentified::UnknownOption {
                program: "journalctl".to_owned(),
                option: "--not-a-real-flag".to_owned()
            }
        );

        // The ordinary reading forms still classify, which is what makes the
        // refusal above affordable rather than a bastion that refuses
        // everything.
        for reading in [
            &["journalctl", "-u", "unbound", "-n", "50"][..],
            &["journalctl", "--since", "yesterday", "--no-pager"][..],
            // A value that looks like an option is read as the value it is.
            &["journalctl", "--since", "-1h"][..],
            &["tail", "-n", "100", "/var/log/syslog"][..],
            &["ls", "-la", "/etc"][..],
            &["df", "-h"][..],
            // An option whose value is optional and attached does not reach
            // past its own argument for one.
            &["df", "--output=source,fstype"][..],
            // A bundle whose last option takes a value takes the next word.
            &["tail", "-qn", "20", "/var/log/syslog"][..],
            // And one that carries the value inside the bundle.
            &["tail", "-n20", "/var/log/syslog"][..],
            // A count attached to an option the catalog calls a flag, which is
            // how an optional-valued option is normally written.
            &["journalctl", "-n50"][..],
            &["journalctl", "-u", "unbound", "-n50"][..],
        ] {
            assert_eq!(
                classify(reading).assessment,
                Scope::Read,
                "{reading:?} did not classify as an ordinary read"
            );
        }
    }

    /// A misspelled field is not a cosmetic error. Ignoring it would leave a
    /// program that was meant to be an interpreter classified at its floor,
    /// with the catalog loading as though it had been described correctly.
    #[test]
    fn a_catalog_field_the_service_does_not_understand_is_refused() {
        assert!(
            Catalog::from_json(
                r#"{"version":"t","programs":{"python3":{"scope":"read","interpretor":true}}}"#
            )
            .is_err(),
            "a misspelled interpreter marking loaded"
        );
        assert!(
            Catalog::from_json(r#"{"version":"t","progams":{}}"#).is_err(),
            "a misspelled top-level field loaded"
        );
        assert!(
            Catalog::from_json(
                r#"{"version":"t","programs":{"python3":{"scope":"read","interpreter":true}}}"#
            )
            .is_ok()
        );
    }

    /// A rejected addition must leave nothing behind. Applying part of one and
    /// then refusing would classify under raises the recorded catalog version
    /// does not contain.
    #[test]
    fn a_refused_addition_changes_nothing() {
        let mut catalog = Catalog::builtin().unwrap();
        let before = catalog.version().to_owned();
        let assessed_before = classify_with(&catalog, &["docker", "exec", "web", "sh"]).assessment;

        // The first entry is a legitimate raise; the second lowers. Whichever
        // order the map is walked in, the raise must not survive the refusal.
        let refused = Catalog::from_json(
            r#"{
              "version": "site",
              "programs": {
                "uptime": { "scope": "privileged" },
                "docker": { "scope": "read", "subcommands": { "exec": "read" } }
              }
            }"#,
        )
        .unwrap();
        assert!(matches!(
            catalog.merge(refused),
            Err(CatalogError::Lowering { .. })
        ));

        assert_eq!(catalog.version(), before, "the version moved");
        assert_eq!(
            classify_with(&catalog, &["docker", "exec", "web", "sh"]).assessment,
            assessed_before
        );
        assert_eq!(
            classify_with(&catalog, &["uptime"]).assessment,
            Scope::Read,
            "a raise from a refused addition survived"
        );
    }

    /// An interpreter is recorded as one, because the later assisted stage has
    /// to be able to find the case where the program is known and the payload
    /// is the unknown.
    #[test]
    fn interpreters_are_identified_as_well_as_assessed() {
        let classification = classify(&["python3", "-c", "print(1)"]);
        assert!(classification.interpreter);
        assert_eq!(classification.assessment, Scope::Privileged);

        let classification = classify(&["docker", "ps"]);
        assert!(!classification.interpreter);
    }

    /// What an interpreter is handed is the payload's, not the interpreter's.
    /// Reading it against the interpreter's own options refuses ordinary
    /// commands over words the interpreter never looks at.
    #[test]
    fn what_an_interpreter_is_handed_is_not_read_as_its_options() {
        for argv in [
            // The words after the command string are `sys.argv`.
            &["python3", "-c", "import sys", "--flag"][..],
            // As are the words after a module, and after a script.
            &["python3", "-m", "http.server", "--bind", "127.0.0.1"][..],
            &["python3", "work.py", "--flag"][..],
            &["bash", "work.sh", "--flag"][..],
            // A bundle hands off if any option in it does.
            &["sh", "-xc", "work", "--flag"][..],
            // The payload can be attached, and an `=` inside it separates
            // nothing: a short argument is a bundle whatever it contains.
            &["python3", "-cprint(\"x=1\")"][..],
            // Options ahead of the hand-off are still the interpreter's.
            &["python3", "-u", "-X", "dev", "-c", "work", "--flag"][..],
        ] {
            let classification = classify(argv);
            assert!(
                classification.identified(),
                "{argv:?} was not identified: {:?}",
                classification.unidentified()
            );
            assert_eq!(classification.assessment, Scope::Privileged);
            assert!(classification.interpreter);
        }

        // Ahead of the hand-off the interpreter reads its own arguments, so an
        // option nobody described still refuses there.
        assert_eq!(
            unidentified(&["python3", "--nope", "-c", "work"]),
            Unidentified::UnknownOption {
                program: "python3".to_owned(),
                option: "--nope".to_owned()
            }
        );

        // A program that is not an interpreter keeps reading its own options
        // after an operand, which is what those programs do.
        assert_eq!(
            classify(&["journalctl", "sshd.service", "--rotate"]).assessment,
            Scope::Mutate
        );
    }

    /// The transcript has to be able to answer "why was this privileged" after
    /// the catalog has moved on, so both the reasons and the catalog's identity
    /// travel with the assessment.
    #[test]
    fn an_assessment_carries_its_reasons_and_its_catalog() {
        let classification = classify(&["docker", "exec", "traefik", "cat", "/etc/shadow"]);
        assert_eq!(classification.catalog_version, catalog().version());
        assert!(classification.grounds.contains(&Ground::Program {
            program: "docker".to_owned(),
            scope: Scope::Read
        }));
        assert!(classification.grounds.contains(&Ground::Subcommand {
            subcommand: "exec".to_owned(),
            scope: Scope::Privileged
        }));
    }

    /// A site may teach the catalog more. It may not teach it less, or a
    /// deployment could quietly reclassify a privileged command as a read and
    /// policy would never see the dangerous reading.
    #[test]
    fn additions_may_raise_an_assessment() {
        let mut catalog = catalog();
        let before = catalog.version().to_owned();
        catalog
            .merge(
                Catalog::from_json(
                    r#"{
                        "version": "site-1",
                        "programs": {
                            "komodo": {"scope": "mutate"},
                            "docker": {"scope": "mutate", "subcommands": {"ps": "mutate"}}
                        }
                    }"#,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            catalog.classify(&command(&["komodo", "deploy"])).assessment,
            Scope::Mutate,
            "a program the site added is now known"
        );
        assert_eq!(
            catalog.classify(&command(&["docker", "ps"])).assessment,
            Scope::Mutate,
            "the site raised a known subcommand"
        );
        assert_ne!(catalog.version(), before, "the merged catalog is traceable");
    }

    /// A program may declare that options the catalog does not list read as
    /// flags at a stated scope. The declaration widens the vocabulary, not the
    /// safety argument: a described option keeps its own arity and scope, so
    /// the known-dangerous flag on a wholesale-harmless program still raises.
    #[test]
    fn a_program_may_declare_what_its_unlisted_options_are_doing() {
        for reading in [
            &["grep", "-rniE", "pattern", "/var/log/syslog"][..],
            &["grep", "--color=auto", "-e", "pattern", "/etc/hosts"][..],
            &["ps", "aux"][..],
            &["ps", "-ef", "--forest"][..],
            &["du", "-sh", "/var/lib/docker"][..],
            &["uname", "-a"][..],
            &["ss", "-tlnp"][..],
            &["dmesg", "-T"][..],
            &["date", "-u", "+%s"][..],
            &["sort", "-u", "notes.txt"][..],
            &["echo", "-n", "ready"][..],
        ] {
            assert_eq!(
                classify(reading).assessment,
                Scope::Read,
                "{reading:?} did not classify as a read"
            );
        }
        // The dangerous spelling on those same programs is described, and the
        // description outranks the declaration.
        for mutating in [
            &["ss", "-K", "dst", "10.0.0.1"][..],
            &["ss", "-D", "/tmp/dump"][..],
            &["dmesg", "-C"][..],
            &["sort", "-o", "/etc/hosts", "/tmp/x"][..],
            &["date", "--set=2030-01-01 00:00:00"][..],
            &["file", "-C", "magic"][..],
        ] {
            assert_eq!(
                classify(mutating).assessment,
                Scope::Mutate,
                "{mutating:?} classified as a read"
            );
        }
        // A flag that launches a caller-named program is beyond a mutation.
        assert_eq!(
            classify(&["sort", "--compress-program=/tmp/evil", "big.txt"]).assessment,
            Scope::Privileged
        );
    }

    /// GNU long options accept unique abbreviations, so on a program whose
    /// unlisted options read as flags, an abbreviation of a described option
    /// must carry the description - `--se=` IS `--set` at runtime - and an
    /// ambiguous abbreviation refuses just as the real program would.
    #[test]
    fn an_abbreviated_long_option_carries_its_full_descriptions_scope() {
        assert_eq!(
            classify(&["date", "--se=2030-01-01 00:00:00"]).assessment,
            Scope::Mutate
        );
        assert_eq!(
            classify(&["sort", "--out", "/etc/hosts", "/tmp/x"]).assessment,
            Scope::Mutate
        );
        assert_eq!(
            classify(&["sort", "--compress-prog=/tmp/evil", "big.txt"]).assessment,
            Scope::Privileged
        );
        // `--console-o` could be --console-off or --console-on; the real
        // program refuses the ambiguity and so does the catalog.
        assert_eq!(
            unidentified(&["dmesg", "--console-o"]),
            Unidentified::UnknownOption {
                program: "dmesg".to_owned(),
                option: "--console-o".to_owned()
            }
        );
        // An abbreviation that prefixes nothing described is an ordinary
        // unlisted flag.
        assert_eq!(
            classify(&["grep", "--recursiv", "pattern", "f"]).assessment,
            Scope::Read
        );
    }

    /// An exact description shadows abbreviation resolution, so describing an
    /// abbreviated spelling with less than the option it abbreviates would
    /// turn `date --se=...` - which IS `--set` at runtime - into a read.
    #[test]
    fn describing_an_abbreviation_cannot_shadow_what_it_abbreviates() {
        let before = classify(&["date", "--se=2030-01-01"]).assessment;
        assert_eq!(before, Scope::Mutate);
        for shadow in [
            r#"{"version":"site","programs":{"date":{"scope":"read","options":{"--se":{}}}}}"#,
            r#"{"version":"site","programs":{"sort":{"scope":"read","options":{"--compress-prog":{"takes_value":true}}}}}"#,
        ] {
            let mut catalog = Catalog::builtin().unwrap();
            assert!(
                matches!(
                    catalog.merge(Catalog::from_json(shadow).unwrap()),
                    Err(CatalogError::Lowering { .. })
                ),
                "accepted {shadow}"
            );
            assert_eq!(
                classify_with(&catalog, &["date", "--se=2030-01-01"]).assessment,
                before,
                "a refused shadow changed the classification"
            );
        }
        // Restating the abbreviation as exactly what it abbreviates says no
        // less, and merges.
        let mut catalog = Catalog::builtin().unwrap();
        catalog
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"date":{"scope":"read","options":{"--se":{"takes_value":true,"scope":"mutate"}}}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&catalog, &["date", "--se=2030-01-01"]).assessment,
            before
        );
    }

    /// Under a declaration every unknown spelling reads as a valueless flag,
    /// so a description that consumes the next word could swallow a described
    /// raise: `ss -x -K dst ...` is a mutate, and would fall to a read the
    /// moment a site taught `-x` to take a value.
    #[test]
    fn describing_an_unlisted_option_cannot_give_it_an_appetite() {
        let mut catalog = Catalog::builtin().unwrap();
        let before = classify_with(&catalog, &["ss", "-x", "-K", "dst", "10.0.0.1"]).assessment;
        assert_eq!(before, Scope::Mutate);
        assert!(matches!(
            catalog.merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"ss":{"scope":"read","options":{"-x":{"takes_value":true}}}}}"#
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));
        assert_eq!(
            classify_with(&catalog, &["ss", "-x", "-K", "dst", "10.0.0.1"]).assessment,
            before
        );
        // A flag-arity description may still raise - that is the raise path.
        catalog
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"ss":{"scope":"read","options":{"-x":{"scope":"mutate"}}}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&catalog, &["ss", "-x"]).assessment,
            Scope::Mutate
        );
    }

    /// A description outranks the declaration, so merely naming a spelling
    /// with less than the declaration said of it would re-classify that
    /// spelling at the program's floor - a lowering by naming alone.
    #[test]
    fn naming_an_unlisted_option_cannot_say_less_than_the_declaration_did() {
        let base = r#"{"version":"base","programs":{"mytool":{"scope":"read","unlisted_options":"mutate"}}}"#;

        let mut catalog = Catalog::from_json(base).unwrap();
        assert!(matches!(
            catalog.merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"mytool":{"scope":"read","options":{"-x":{}}}}}"#
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));
        assert_eq!(
            classify_with(&catalog, &["mytool", "-x"]).assessment,
            Scope::Mutate,
            "the refused description changed the classification"
        );

        // Described at what the declaration said, it merges, and the spelling
        // classifies unchanged.
        catalog
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"mytool":{"scope":"read","options":{"-x":{"scope":"mutate"}}}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&catalog, &["mytool", "-x"]).assessment,
            Scope::Mutate
        );

        // Raising the floor to the declaration first makes a scope-less
        // description equal, not lower, so it is allowed.
        let mut level = Catalog::from_json(base).unwrap();
        level
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"mytool":{"scope":"mutate","options":{"-y":{}}}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&level, &["mytool", "-y"]).assessment,
            Scope::Mutate
        );
    }

    /// A declaration above the program's floor raises, and the raise travels
    /// as a ground so the transcript can say which word caused it.
    #[test]
    fn an_unlisted_option_carries_the_declared_scope() {
        let catalog = Catalog::from_json(
            r#"{
              "version": "t",
              "programs": {
                "mytool": { "scope": "read", "unlisted_options": "mutate" }
              }
            }"#,
        )
        .unwrap();
        let classification = catalog.classify(&command(&["mytool", "-x", "target"]));
        assert_eq!(classification.assessment, Scope::Mutate);
        assert!(classification.grounds.contains(&Ground::Option {
            option: "-x".to_owned(),
            scope: Scope::Mutate
        }));
    }

    /// The declaration is a statement about a known program's own options. It
    /// cannot be made where an unread option could move which word is the
    /// payload or the subcommand, because there it stops being a statement
    /// about options and starts hiding what runs.
    #[test]
    fn unlisted_options_cannot_be_declared_where_they_could_hide_the_command() {
        assert!(matches!(
            Catalog::from_json(
                r#"{"version":"t","programs":{"sh":{"scope":"privileged","interpreter":true,"unlisted_options":"read"}}}"#
            ),
            Err(CatalogError::UnreadableUnlisted { .. })
        ));
        assert!(matches!(
            Catalog::from_json(
                r#"{"version":"t","programs":{"docker":{"scope":"read","subcommands":{"ps":"read"},"unlisted_options":"read"}}}"#
            ),
            Err(CatalogError::UnreadableUnlisted { .. })
        ));
        // Nor by merge: marking a wildcard program as an interpreter would
        // combine the two states refused above.
        let mut catalog = Catalog::builtin().unwrap();
        assert!(matches!(
            catalog.merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"grep":{"scope":"privileged","interpreter":true}}}"#
                )
                .unwrap()
            ),
            Err(CatalogError::UnreadableUnlisted { .. })
        ));
    }

    /// Turning refusals into runs is a lowering however it is spelled, so a
    /// site cannot introduce the declaration or weaken one. It may raise one,
    /// and describing a new option leaves an existing declaration standing.
    #[test]
    fn a_site_may_raise_but_not_introduce_or_weaken_the_declaration() {
        // Introduction: journalctl's undescribed options refuse today, and an
        // addition must not change how they are read.
        let mut catalog = Catalog::builtin().unwrap();
        assert!(matches!(
            catalog.merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"journalctl":{"scope":"read","unlisted_options":"read"}}}"#
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));
        assert!(matches!(
            classify_with(&catalog, &["journalctl", "--not-a-real-flag"]).unidentified(),
            Some(Unidentified::UnknownOption { .. })
        ));

        // Weakening: saying less than the declaration already says.
        let mut strict = Catalog::from_json(
            r#"{"version":"base","programs":{"mytool":{"scope":"read","unlisted_options":"mutate"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            strict.merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"mytool":{"scope":"read","unlisted_options":"read"}}}"#
                )
                .unwrap()
            ),
            Err(CatalogError::Lowering { .. })
        ));

        // Raising is how a site says its build of a program does more than
        // shape output.
        let mut raised = Catalog::builtin().unwrap();
        raised
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"grep":{"scope":"read","unlisted_options":"mutate"}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&raised, &["grep", "-Z", "pattern", "f"]).assessment,
            Scope::Mutate
        );

        // Silence preserves: describing one option does not withdraw the
        // declaration for the rest of the vocabulary.
        let mut described = Catalog::builtin().unwrap();
        described
            .merge(
                Catalog::from_json(
                    r#"{"version":"site","programs":{"grep":{"scope":"read","options":{"--only-new":{}}}}}"#
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            classify_with(&described, &["grep", "-rn", "pattern", "f"]).assessment,
            Scope::Read
        );
    }

    #[test]
    fn additions_may_not_lower_one() {
        for addition in [
            r#"{"version": "site", "programs": {"sh": {"scope": "read", "interpreter": true}}}"#,
            r#"{"version": "site", "programs": {"sh": {"scope": "privileged"}}}"#,
            r#"{"version": "site", "programs": {"docker": {"scope": "read", "subcommands": {"exec": "read"}}}}"#,
        ] {
            let mut catalog = catalog();
            assert!(
                matches!(
                    catalog.merge(Catalog::from_json(addition).unwrap()),
                    Err(CatalogError::Lowering { .. })
                ),
                "should refuse {addition}"
            );
        }
    }
}
