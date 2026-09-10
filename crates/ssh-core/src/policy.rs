//! The decision point: the one thing here that decides.
//!
//! Everything else in this service produces facts. Classification says what a
//! command is; the session says who is asking, on which host, as which role,
//! and up to what ceiling. This turns those facts into one of three answers and
//! records what produced it.
//!
//! Keeping that split is the point. If the catalog could refuse a command on
//! its own, or the execution path could, there would be two authorization
//! systems — one of them unreviewable, and eventually they would disagree.
//!
//! # Why three answers and only two questions
//!
//! Cedar answers allow or deny. "Needs a human" is not a third Cedar answer, so
//! it is not invented inside one: the engine is asked whether the command may
//! run outright, and if not, whether it may run *with approval*. A policy
//! grants each separately, and the difference between "refused" and "waiting
//! for someone" stays something a policy author writes rather than something
//! this code infers.
//!
//! # Simulation
//!
//! There is no observe-only mode, deliberately: policy enforces from the first
//! command that ever runs. What a policy author actually needs — seeing how a
//! policy answers before trusting it — is [`Engine::decide`] itself, which
//! executes nothing. Asking is not running, so simulation is the ordinary call
//! and there is never a window where enforcement is off.

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};

use crate::Scope;
use crate::catalog::{Classification, Ground};
use crate::session::Session;

/// The policy this service ships with.
const DEFAULT_POLICY: &str = include_str!("policy/default.cedar");

/// The rule every engine enforces, whatever a deployment writes.
const CEILING_POLICY: &str = include_str!("policy/ceiling.cedar");

/// What the decision point says about one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Run it.
    Permit,
    /// Run it once a human has agreed.
    NeedsApproval,
    /// Do not run it.
    Deny,
}

/// A decision, and enough of why to reconstruct it later.
///
/// Carries both of its inputs — the classification it decided and the session
/// it was decided for — rather than sitting beside them. A verdict travelling
/// on its own is a verdict about nothing, and whoever recorded or acted on it
/// would have to be trusted to pair it back with the right command and the
/// right session: a permit for a harmless command in one session could be
/// presented alongside a command policy would refuse, or against a session it
/// was never evaluated against. Holding both makes that impossible rather than
/// merely discouraged, which is also why the fields are read-only — a
/// `Decision` comes from [`Engine::decide`] and nowhere else, and is not
/// `Clone`. Recording one consumes it so that one answer from here is one
/// recorded intent and one execution; a copyable answer would hand that count
/// straight back, letting a single permit be presented twice for two receipts
/// without anyone asking policy a second time.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    verdict: Verdict,
    policies: Vec<String>,
    explanation: String,
    classification: Classification,
    session: Session,
}

impl Decision {
    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The policies that produced this, by name.
    ///
    /// Recorded rather than rendered to the caller: an audit record has to be
    /// traceable to the rule that caused it, months later, when the policy has
    /// been edited.
    #[must_use]
    pub fn policies(&self) -> &[String] {
        &self.policies
    }

    /// What to tell the caller.
    ///
    /// Says what would have to be different, and names no engine internals — a
    /// policy identifier means nothing to an agent and everything to whoever
    /// reads the transcript, so the two audiences get different text.
    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    /// What this decision was about.
    #[must_use]
    pub const fn classification(&self) -> &Classification {
        &self.classification
    }

    /// The session this was decided for.
    ///
    /// Held for the same reason as the classification: who was asking, on which
    /// host, as which role, for what purpose and up to what ceiling are all
    /// inputs to the answer, and an answer that travelled without them could be
    /// attributed to a session it was never evaluated against.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }
}

/// Authorizes commands against a policy.
pub struct Engine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl Engine {
    /// The engine as shipped.
    pub fn builtin() -> Result<Self, PolicyError> {
        Self::from_source(DEFAULT_POLICY)
    }

    /// Builds an engine from policy text.
    ///
    /// Policy is data, so a deployment changes what is allowed by replacing
    /// this text rather than by shipping a new binary.
    pub fn from_source(source: &str) -> Result<Self, PolicyError> {
        // The ceiling rule is added to whatever a deployment wrote, not
        // included in the text it replaces. A replacement is how a deployment
        // says what is allowed *within* the ceiling; it is not a way to say
        // there is no ceiling, and leaving the rule in the replaceable text
        // made deleting it a supported edit.
        let combined = format!("{CEILING_POLICY}\n{source}");
        let policies =
            PolicySet::from_str(&combined).map_err(|source| PolicyError::Unreadable {
                detail: source.to_string(),
            })?;

        // Every rule says what it is called. Cedar otherwise numbers them by
        // position, and a decision recorded against `policy2` stops meaning
        // anything the moment somebody inserts a rule above it - which makes
        // the record of why a command was allowed unreadable exactly when it is
        // being audited. Refused at load time, where a deployment can fix it,
        // rather than discovered later in a record nobody can interpret.
        let unnamed: Vec<String> = policies
            .policies()
            .filter(|policy| policy.annotation("id").is_none())
            .map(|policy| policy.id().to_string())
            .collect();
        if !unnamed.is_empty() {
            return Err(PolicyError::Anonymous {
                detail: unnamed.join(", "),
            });
        }

        // And no two rules answer to the same name. A decision naming a rule
        // that two rules share does not say which one acted, which is the same
        // hole as no name at all wearing the appearance of a fix.
        let mut names: Vec<&str> = policies
            .policies()
            .filter_map(|policy| policy.annotation("id"))
            .collect();
        names.sort_unstable();
        let repeated: Vec<String> = names
            .windows(2)
            .filter(|pair| pair.first() == pair.last())
            .filter_map(|pair| pair.first().map(|name| (*name).to_owned()))
            .collect();
        if !repeated.is_empty() {
            return Err(PolicyError::Ambiguous {
                detail: repeated.join(", "),
            });
        }

        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Decides whether a command may run in a session.
    ///
    /// Runs nothing. This is also how a policy is examined before it is
    /// trusted: the answer to "what would happen" is the same call as "what
    /// happens".
    ///
    /// Takes the classification by value because the answer keeps it. A
    /// decision and the classification it was about travel together from here
    /// on, so nothing downstream has to be trusted to keep the two in step.
    pub fn decide(
        &self,
        session: &Session,
        classification: Classification,
    ) -> Result<Decision, PolicyError> {
        // Asked in order, because the answers are not equal: running outright
        // is better than running after waiting for someone, and a policy that
        // grants both should get the cheaper one.
        let mut refusing: Vec<String> = Vec::new();
        for (action, verdict) in [
            ("run", Verdict::Permit),
            ("runWithApproval", Verdict::NeedsApproval),
        ] {
            let answer = self.ask(session, &classification, action)?;
            if answer.allowed {
                // The rules that refused the earlier question belong here too.
                // A command waiting for a human is waiting because something
                // forbade running it outright, and a record naming only the
                // rule that allowed the waiting does not say why it waits.
                let mut policies = refusing;
                for policy in answer.policies {
                    if !policies.contains(&policy) {
                        policies.push(policy);
                    }
                }
                return Ok(Decision {
                    verdict,
                    policies,
                    explanation: permitted_explanation(verdict, &classification),
                    classification,
                    session: session.clone(),
                });
            }
            // Every rule that refused, from both questions. A forbid that
            // applied only to running outright is still part of why this
            // command is not running, and keeping only the last answer's rules
            // would leave it out of the record.
            for policy in answer.policies {
                if !refusing.contains(&policy) {
                    refusing.push(policy);
                }
            }
        }

        // Cedar denies when nothing permits, so an empty or silent policy
        // refuses rather than falls through. When no forbid applied to either
        // question, the refusal *is* the absence of a permit, and there is
        // correctly nothing to name.
        Ok(Decision {
            verdict: Verdict::Deny,
            policies: refusing,
            explanation: refused_explanation(session, &classification),
            classification,
            session: session.clone(),
        })
    }

    /// Puts one question to the engine.
    fn ask(
        &self,
        session: &Session,
        classification: &Classification,
        action: &str,
    ) -> Result<Answer, PolicyError> {
        let principal = uid("Principal", session.principal.as_str())?;
        let action = uid("Action", action)?;
        let resource = uid("Host", session.host.as_str())?;
        let context = context_for(session, classification)?;

        let request =
            Request::new(principal, action, resource, context, None).map_err(|source| {
                PolicyError::Unaskable {
                    detail: source.to_string(),
                }
            })?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());

        // Cedar evaluates each policy independently and reports the ones that
        // could not be evaluated rather than failing the request. Taking the
        // decision anyway means a guard or a forbid that errored was simply
        // absent, while some other permit still answered - which is the
        // fail-open reading of a policy nobody could evaluate. It refuses
        // instead.
        let mut failed = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .peekable();
        if failed.peek().is_some() {
            return Err(PolicyError::Unevaluated {
                detail: failed.collect::<Vec<_>>().join("; "),
            });
        }

        Ok(Answer {
            allowed: response.decision() == cedar_policy::Decision::Allow,
            policies: response
                .diagnostics()
                .reason()
                .map(|id| self.name_of(id))
                .collect(),
        })
    }

    /// What to call a rule in a record.
    ///
    /// Cedar numbers the rules it parses by position, so `policy2` means a
    /// different rule after anyone reorders or replaces the text - and a stored
    /// decision that names one is no longer traceable to what produced it. A
    /// rule that gives itself an `@id` is reported by that name instead, which
    /// survives editing. The shipped rules all carry one.
    fn name_of(&self, id: &cedar_policy::PolicyId) -> String {
        self.policies
            .policy(id)
            .and_then(|policy| policy.annotation("id"))
            .map_or_else(|| id.to_string(), ToOwned::to_owned)
    }
}

/// One answer from the engine, and the rules behind it.
#[derive(Debug, Default)]
struct Answer {
    allowed: bool,
    policies: Vec<String>,
}

/// The subcommand the catalog recognised, if the program has any.
///
/// Read from the grounds rather than carried separately, because the grounds
/// are what the classification already records as its reasons - a second field
/// saying the same thing could disagree with them.
fn subcommand(classification: &Classification) -> Option<String> {
    classification
        .grounds()
        .iter()
        .find_map(|ground| match ground {
            Ground::Subcommand { subcommand, .. } => Some(subcommand.clone()),
            _ => None,
        })
}

/// The facts a policy decides from.
///
/// Scope appears twice on purpose. As a number it can be *ordered*, which is
/// what the ceiling rule needs and what Cedar cannot do with an enum; as a name
/// it can be read, which is what everything else needs. One would make either
/// the rule or the policy text worse.
fn context_for(session: &Session, classification: &Classification) -> Result<Context, PolicyError> {
    Context::from_pairs([
        (
            "role".to_owned(),
            RestrictedExpression::new_string(session.role.as_str().to_owned()),
        ),
        (
            "purpose".to_owned(),
            RestrictedExpression::new_string(session.purpose.as_str().to_owned()),
        ),
        (
            "program".to_owned(),
            RestrictedExpression::new_string(classification.program().to_owned()),
        ),
        (
            "interpreter".to_owned(),
            RestrictedExpression::new_bool(classification.interpreter()),
        ),
        // Whether the catalog identified the command at all. An unidentified
        // one carries the maximal assessment, so the shipped policy already
        // holds it for a human - this is for a deployment that wants to say
        // something stricter, such as refusing them outright.
        (
            "identified".to_owned(),
            RestrictedExpression::new_bool(classification.identified()),
        ),
        // The subcommand, where the catalog found one. Without it `docker ps`
        // and `docker logs` are the same command to a policy: same program,
        // same assessment, nothing to tell them apart. A policy that wants to
        // permit one and not the other has to be able to name it.
        (
            "subcommand".to_owned(),
            RestrictedExpression::new_string(subcommand(classification).unwrap_or_default()),
        ),
        // The argument vector, as the caller wrote it. The design says
        // authorization is evaluated against the command's arguments, and two
        // invocations that classify the same can still differ in what they
        // touch - `docker logs web` and `docker logs vault` are one program,
        // one subcommand and one assessment.
        //
        // A policy reads these as text and nothing here interprets them: what a
        // word in a command line means is a question about the program that
        // reads it, and a rule that matches an operand is a deployment saying
        // it recognises that operand rather than this service claiming to.
        // The command as it will be sent, which is the only ordered and exact
        // form available: Cedar's one collection is a set, and a set has
        // neither order nor repetition, so `docker cp a b` and `docker cp b a`
        // are the same set. A rule that cares which way round a copy goes has
        // to read this.
        (
            "command_line".to_owned(),
            RestrictedExpression::new_string(classification.command().to_wire()),
        ),
        // The same arguments as a set, for the ordinary question of whether a
        // command mentions something at all.
        (
            "arguments".to_owned(),
            RestrictedExpression::new_set(
                classification
                    .command()
                    .args()
                    .iter()
                    .map(|argument| RestrictedExpression::new_string(argument.clone())),
            ),
        ),
        (
            "assessment".to_owned(),
            RestrictedExpression::new_long(rank(classification.assessment())),
        ),
        (
            "ceiling".to_owned(),
            RestrictedExpression::new_long(rank(session.scope)),
        ),
        (
            "assessment_name".to_owned(),
            RestrictedExpression::new_string(name(classification.assessment()).to_owned()),
        ),
        (
            "ceiling_name".to_owned(),
            RestrictedExpression::new_string(name(session.scope).to_owned()),
        ),
    ])
    .map_err(|source| PolicyError::Unaskable {
        detail: source.to_string(),
    })
}

/// Scope as a number, so a policy can compare two of them.
const fn rank(scope: Scope) -> i64 {
    match scope {
        Scope::Read => 0,
        Scope::Mutate => 1,
        Scope::Privileged => 2,
    }
}

const fn name(scope: Scope) -> &'static str {
    match scope {
        Scope::Read => "read",
        Scope::Mutate => "mutate",
        Scope::Privileged => "privileged",
    }
}

fn uid(kind: &str, id: &str) -> Result<EntityUid, PolicyError> {
    // Cedar identifiers are quoted, and the values reaching here are already
    // constrained types — but the quoting is what makes that irrelevant rather
    // than something to reason about.
    EntityUid::from_str(&format!(
        "{kind}::\"{}\"",
        id.replace('\\', "\\\\").replace('"', "\\\"")
    ))
    .map_err(|source| PolicyError::Unaskable {
        detail: source.to_string(),
    })
}

fn permitted_explanation(verdict: Verdict, classification: &Classification) -> String {
    match verdict {
        Verdict::Permit => format!(
            "{} is permitted as {} work",
            classification.program(),
            name(classification.assessment())
        ),
        Verdict::NeedsApproval => match classification.unidentified() {
            // The wait is not about how much the command could do - nobody
            // knows - so the explanation says what is actually being asked:
            // for a human to read what the catalog could not.
            Some(reason) => {
                format!("{reason}, so it is waiting for a human to say whether it may run")
            }
            None => format!(
                "{} is {} work and is waiting for someone to approve it",
                classification.program(),
                name(classification.assessment())
            ),
        },
        Verdict::Deny => String::new(),
    }
}

fn refused_explanation(session: &Session, classification: &Classification) -> String {
    if rank(classification.assessment()) > rank(session.scope) {
        if let Some(reason) = classification.unidentified() {
            return format!(
                "{reason}, so it is treated as {} work, and this session was opened for {} at most; \
                 open a session with {} scope to put it in front of a human",
                name(classification.assessment()),
                name(session.scope),
                name(classification.assessment())
            );
        }
        return format!(
            "{} is {} work and this session was opened for {} at most; \
             open a session with the scope the work actually needs",
            classification.program(),
            name(classification.assessment()),
            name(session.scope)
        );
    }
    // No engine vocabulary: a caller cannot act on "no policy permits this",
    // and naming the machinery tells them nothing they can change.
    //
    // The whole command, not the program and subcommand it summarises. A rule
    // may turn on an operand - which is why the arguments and the ordered
    // command line are in the context at all - so two commands that summarise
    // identically can be refused for different reasons, and an explanation
    // naming only the summary says the same thing about both.
    //
    // What was weighed, and nothing about what would work instead. Which facts
    // a deployment's rules actually turn on is the deployment's business - they
    // may look at the principal, the host, the purpose or the arguments - so
    // promising that another role or a smaller command would be accepted can be
    // simply untrue, and a caller acting on it wastes its time.
    format!(
        "nothing allows the {} role to run {} as {} work on {} for the purpose \"{}\"",
        session.role,
        classification.command().to_wire(),
        name(classification.assessment()),
        session.host,
        session.purpose.as_str()
    )
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("the policy could not be read: {detail}")]
    Unreadable { detail: String },
    #[error("the request could not be put to the policy engine: {detail}")]
    Unaskable { detail: String },
    #[error("a policy could not be evaluated, so the answer is not trustworthy: {detail}")]
    Unevaluated { detail: String },
    #[error(
        "every rule needs an @id so a decision stays traceable to it; these have none: {detail}"
    )]
    Anonymous { detail: String },
    #[error("two rules cannot answer to one name, or a decision cannot say which acted: {detail}")]
    Ambiguous { detail: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::clock::TestClock;
    use crate::command::Command;
    use crate::session::{Lifetime, Purpose, SessionStore};
    use crate::{HostId, PrincipalId, RoleId};

    const LIFETIME: Lifetime = Lifetime {
        idle: 10_000,
        max: 60_000,
        grace: 5_000,
    };

    fn session(ceiling: Scope) -> Session {
        SessionStore::new(TestClock::at(1_000), LIFETIME, 8)
            .open(
                PrincipalId::parse("alice").unwrap(),
                HostId::parse("dns1").unwrap(),
                RoleId::parse("readonly").unwrap(),
                Purpose::parse("find out why the deploy did not take effect").unwrap(),
                ceiling,
            )
            .expect("within the per-principal limit")
    }

    fn command(argv: &[&str]) -> Command {
        Command::new(argv.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    fn classify(argv: &[&str]) -> Classification {
        Catalog::builtin().unwrap().classify(&command(argv))
    }

    fn decide(ceiling: Scope, argv: &[&str]) -> Decision {
        Engine::builtin()
            .unwrap()
            .decide(&session(ceiling), classify(argv))
            .unwrap()
    }

    /// The shipped policy is data, so a broken one would otherwise surface as a
    /// service that refuses everything at runtime.
    #[test]
    fn the_shipped_policy_is_readable() {
        assert!(Engine::builtin().is_ok());
    }

    /// Reading runs; changing things waits for a human. This is the whole
    /// product behaviour of the default policy.
    #[test]
    fn what_the_default_policy_decides() {
        for (ceiling, argv, expected) in [
            (Scope::Read, &["docker", "ps"][..], Verdict::Permit),
            (Scope::Privileged, &["uptime"][..], Verdict::Permit),
            (
                Scope::Mutate,
                &["docker", "restart", "traefik"][..],
                Verdict::NeedsApproval,
            ),
            (
                Scope::Privileged,
                &["docker", "exec", "traefik", "ls"][..],
                Verdict::NeedsApproval,
            ),
            // An interpreter is privileged for what it could be handed, not
            // for anything the arguments say.
            (
                Scope::Privileged,
                &["bash", "-c", "systemctl restart traefik"][..],
                Verdict::NeedsApproval,
            ),
            // A program whose destructive surface is a flag rather than a
            // subcommand still reaches a human.
            (
                Scope::Mutate,
                &["journalctl", "--rotate"][..],
                Verdict::NeedsApproval,
            ),
        ] {
            let decision = decide(ceiling, argv);
            assert_eq!(decision.verdict, expected, "for {argv:?} under {ceiling:?}");
        }
    }

    /// The ceiling is what was declared when the session opened, and what a
    /// human approved if one was asked. Work beyond it is not privileged work
    /// pending approval — it is work nobody agreed to.
    #[test]
    fn a_command_beyond_the_session_ceiling_is_refused_not_queued() {
        for (ceiling, argv) in [
            (Scope::Read, &["docker", "restart", "traefik"][..]),
            (Scope::Read, &["docker", "exec", "traefik", "ls"][..]),
            (Scope::Mutate, &["sh", "-c", "true"][..]),
            (Scope::Read, &["journalctl", "--rotate"][..]),
        ] {
            let decision = decide(ceiling, argv);
            assert_eq!(
                decision.verdict,
                Verdict::Deny,
                "{argv:?} should not be reachable under {ceiling:?}"
            );
        }
    }

    /// An unidentified command is nobody's to run unattended. Assessed
    /// maximally, it waits for a human where the session's ceiling reaches
    /// that assessment and is refused where it does not - and a deployment
    /// that wants the old refuse-outright behavior can name
    /// `context.identified` and write it as policy.
    #[test]
    fn an_unidentified_command_waits_for_a_human_within_the_ceiling() {
        let held = decide(Scope::Privileged, &["tar", "-cf", "/tmp/x", "/etc"]);
        assert_eq!(held.verdict, Verdict::NeedsApproval);
        assert!(
            held.explanation.contains("does not know the program tar"),
            "the wait should say what could not be read: {}",
            held.explanation
        );

        let refused = decide(Scope::Read, &["tar", "-cf", "/tmp/x", "/etc"]);
        assert_eq!(refused.verdict, Verdict::Deny);
        assert!(
            refused
                .explanation
                .contains("does not know the program tar"),
            "the refusal should say what could not be read: {}",
            refused.explanation
        );

        // The undescribed flag, unknown subcommand, and missing subcommand
        // all take the same path as the unknown program.
        for argv in [
            &["journalctl", "--not-a-real-flag"][..],
            &["docker", "swarm", "init"][..],
            &["timedatectl"][..],
        ] {
            assert_eq!(
                decide(Scope::Privileged, argv).verdict,
                Verdict::NeedsApproval,
                "{argv:?} should wait for a human"
            );
        }

        // Even a replacement policy that permits everything cannot run an
        // unidentified command unattended: the non-replaceable rule holds it
        // to the approval path.
        let permissive =
            Engine::from_source("@id(\"everything\")\npermit (principal, action, resource);")
                .unwrap();
        let decision = permissive
            .decide(
                &session(Scope::Privileged),
                classify(&["tar", "-cf", "/tmp/x", "/etc"]),
            )
            .unwrap();
        assert_eq!(decision.verdict, Verdict::NeedsApproval);
        assert!(
            decision
                .policies
                .iter()
                .any(|id| id == "unidentified-never-runs-unattended"),
            "the non-replaceable rule was not what held it: {:?}",
            decision.policies
        );

        let strict = format!(
            "{DEFAULT_POLICY}\n@id(\"no-unidentified\")\nforbid (principal, action, resource) when {{ !context.identified }};\n"
        );
        let engine = Engine::from_source(&strict).unwrap();
        let decision = engine
            .decide(
                &session(Scope::Privileged),
                classify(&["tar", "-cf", "/tmp/x", "/etc"]),
            )
            .unwrap();
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    /// A forbid cannot be relaxed by adding a permit. Otherwise the ceiling
    /// rule would be advisory, and a deployment could grant past what a human
    /// approved without ever editing the rule that says it may not.
    #[test]
    fn a_permissive_addition_cannot_grant_past_the_ceiling() {
        let permissive = format!(
            "{DEFAULT_POLICY}\n@id(\"everything\")\npermit (principal, action, resource);\n"
        );
        let engine = Engine::from_source(&permissive).unwrap();
        let decision = engine
            .decide(
                &session(Scope::Read),
                classify(&["docker", "exec", "traefik", "ls"]),
            )
            .unwrap();
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    /// A deployment writes what is allowed within the ceiling. It does not get
    /// to write that there is no ceiling: replacing the policy text with
    /// something that permits everything must still not reach past what the
    /// session declared.
    #[test]
    fn replacing_the_policy_cannot_remove_the_ceiling() {
        let engine =
            Engine::from_source("@id(\"everything\")\npermit (principal, action, resource);")
                .unwrap();
        let decision = engine
            .decide(
                &session(Scope::Read),
                classify(&["docker", "exec", "traefik", "ls"]),
            )
            .unwrap();

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(
            decision.policies.iter().any(|id| id == "session-ceiling"),
            "the ceiling did not refuse it: {:?}",
            decision.policies
        );
    }

    /// Which way round a copy goes is not something a set can express: Cedar's
    /// only collection is unordered, so `docker cp a b` and `docker cp b a`
    /// have identical arguments. A rule that cares reads the command line,
    /// where each argument is quoted exactly as it will be sent - which is what
    /// lets the pattern below anchor on the operand's position.
    #[test]
    fn a_policy_can_tell_one_direction_from_the_other() {
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"nothing-leaves-the-container\")\n\
             forbid (principal, action, resource)\n\
             when {{ context.command_line like \"*'cp' 'web:*\" }};\n"
        );
        let engine = Engine::from_source(&source).unwrap();

        let into = ["docker", "cp", "local.txt", "web:/tmp/x"];
        let out_of = ["docker", "cp", "web:/tmp/x", "local.txt"];
        assert_eq!(
            engine
                .decide(&session(Scope::Privileged), classify(&into))
                .unwrap()
                .verdict,
            Verdict::NeedsApproval
        );
        let refused = engine
            .decide(&session(Scope::Privileged), classify(&out_of))
            .unwrap();
        assert_eq!(
            refused.verdict,
            Verdict::Deny,
            "the two directions were indistinguishable"
        );
    }

    /// The facts and the command they are about arrive together, so a caller
    /// cannot hand policy one command's assessment beside another command's
    /// words. Pairing a read classification with an interpreter would have the
    /// ceiling and the shipped permit both see a harmless assessment.
    #[test]
    fn the_facts_and_the_command_cannot_disagree() {
        let harmless = classify(&["uptime"]);
        let dangerous = classify(&["bash", "-c", "systemctl restart traefik"]);

        // The only way to ask about a command is with its own facts. A
        // classification is read-only and only classifying produces one, so
        // there is no clone-and-swap: the parts cannot be set independently,
        // which is what a caller would need to pair one command's assessment
        // with another command's words.
        assert_eq!(*harmless.command(), command(&["uptime"]));
        assert_eq!(
            *dangerous.command(),
            command(&["bash", "-c", "systemctl restart traefik"])
        );

        let engine = Engine::builtin().unwrap();
        assert_eq!(
            engine
                .decide(&session(Scope::Read), dangerous)
                .unwrap()
                .verdict,
            Verdict::Deny,
            "an interpreter reached past a read ceiling"
        );
    }

    /// Two rules answering to one name is the same hole as no name at all,
    /// wearing the appearance of having been fixed.
    #[test]
    fn two_rules_cannot_share_a_name() {
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"read-runs\")\n\
             forbid (principal, action, resource)\n\
             when {{ context.program == \"uptime\" }};\n"
        );
        assert!(matches!(
            Engine::from_source(&source),
            Err(PolicyError::Ambiguous { .. })
        ));
    }

    /// A rule that does not say what it is called cannot be attributed later,
    /// so it is refused when the policy loads rather than discovered in a
    /// record nobody can interpret.
    #[test]
    fn a_rule_without_a_name_is_refused() {
        let anonymous = Engine::from_source(
            "permit (principal, action == Action::\"run\", resource)\nwhen { true };",
        );
        assert!(
            matches!(anonymous, Err(PolicyError::Anonymous { .. })),
            "a rule with no name loaded anyway"
        );
        assert!(
            Engine::builtin().is_ok(),
            "the shipped rules all name themselves"
        );
    }

    /// Two invocations can classify identically and still touch different
    /// things. A policy that cannot see the operands cannot tell them apart.
    #[test]
    fn a_policy_can_name_an_argument() {
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"not-the-vault\")\n\
             forbid (principal, action, resource)\n\
             when {{ context.arguments.contains(\"vault\") }};\n"
        );
        let engine = Engine::from_source(&source).unwrap();

        let allowed = engine
            .decide(&session(Scope::Read), classify(&["docker", "logs", "web"]))
            .unwrap();
        assert_eq!(allowed.verdict, Verdict::Permit);

        let refused = engine
            .decide(
                &session(Scope::Read),
                classify(&["docker", "logs", "vault"]),
            )
            .unwrap();
        assert_eq!(
            refused.verdict,
            Verdict::Deny,
            "a policy naming an operand did not reach it"
        );
        assert!(refused.policies.iter().any(|id| id == "not-the-vault"));
    }

    /// A rule is recorded by the name its author gave it. Cedar numbers rules
    /// by position, so a stored decision naming `policy2` stops meaning
    /// anything the moment somebody reorders the file.
    #[test]
    fn a_decision_names_rules_that_survive_editing() {
        let decision = decide(Scope::Read, &["docker", "ps"]);
        assert_eq!(decision.verdict, Verdict::Permit);
        assert!(
            decision.policies.iter().any(|id| id == "read-runs"),
            "the rule is not named by its own identifier: {:?}",
            decision.policies
        );
    }

    /// A command waiting for a human is waiting because something refused to
    /// let it run outright. A record that names only the rule allowing the wait
    /// does not say why it waits.
    #[test]
    fn an_approval_names_what_refused_the_faster_answer() {
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"no-outright-logs\")\n\
             forbid (principal, action == Action::\"run\", resource)\n\
             when {{ context.subcommand == \"logs\" }};\n\
             @id(\"logs-with-approval\")\n\
             permit (principal, action == Action::\"runWithApproval\", resource)\n\
             when {{ context.subcommand == \"logs\" }};\n"
        );
        let engine = Engine::from_source(&source).unwrap();
        let decision = engine
            .decide(&session(Scope::Read), classify(&["docker", "logs", "web"]))
            .unwrap();

        assert_eq!(decision.verdict, Verdict::NeedsApproval);
        // Two rules made this what it is: the one that refused running it
        // outright, and the one that allows it to wait. Naming only the second
        // does not say why it waits.
        assert_eq!(
            decision.policies.len(),
            2,
            "the rule that refused running it outright is missing: {:?}",
            decision.policies
        );
    }

    /// A refusal is for a caller, who can change the role they asked as, the
    /// purpose they gave, or the command - and cannot change anything about the
    /// engine that decided.
    #[test]
    fn a_refusal_says_what_would_have_to_differ() {
        let engine = Engine::from_source("").unwrap();
        let refused = engine
            .decide(&session(Scope::Privileged), classify(&["docker", "ps"]))
            .unwrap();
        assert_eq!(refused.verdict, Verdict::Deny);
        for word in ["policy", "Cedar", "permit", "forbid"] {
            assert!(
                !refused.explanation.contains(word),
                "the refusal names engine machinery ({word}): {}",
                refused.explanation
            );
        }
        assert!(
            refused.explanation.contains("role")
                && refused.explanation.contains("purpose")
                && refused.explanation.contains("'docker' 'ps'"),
            "the refusal does not say what was weighed: {}",
            refused.explanation
        );

        // Two commands a rule can tell apart must not be refused in the same
        // words. A policy may turn on an operand, so an explanation naming only
        // the program and subcommand says the same thing about both - and both
        // of these are refused, so the difference is in what they say rather
        // than in one being allowed.
        let vault = engine
            .decide(
                &session(Scope::Read),
                classify(&["docker", "logs", "vault"]),
            )
            .unwrap();
        let web = engine
            .decide(&session(Scope::Read), classify(&["docker", "logs", "web"]))
            .unwrap();
        assert_eq!(vault.verdict, Verdict::Deny);
        assert_eq!(web.verdict, Verdict::Deny);
        assert_ne!(
            vault.explanation, web.explanation,
            "two refused commands are explained in the same words"
        );
    }

    /// A policy can tell one subcommand from another. Without that, `docker ps`
    /// and `docker logs` are the same command to it - same program, same
    /// assessment - and a deployment cannot permit one without the other.
    #[test]
    fn a_policy_can_name_the_subcommand() {
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"no-logs\")\n\
             forbid (principal, action, resource)\n\
             when {{ context.subcommand == \"logs\" }};\n"
        );
        let engine = Engine::from_source(&source).unwrap();

        let allowed = engine
            .decide(&session(Scope::Read), classify(&["docker", "ps"]))
            .unwrap();
        assert_eq!(allowed.verdict, Verdict::Permit);

        let refused = engine
            .decide(&session(Scope::Read), classify(&["docker", "logs", "web"]))
            .unwrap();
        assert_eq!(
            refused.verdict,
            Verdict::Deny,
            "a policy naming the subcommand did not reach it"
        );
        assert!(
            !refused.policies.is_empty(),
            "the rule that refused should be named"
        );
    }

    /// A policy that cannot be evaluated is not an answer. Cedar reports such a
    /// rule and carries on with the others, so taking the decision anyway means
    /// a guard that errored was simply absent while some permit still spoke.
    #[test]
    fn a_policy_that_cannot_be_evaluated_refuses() {
        // `context.missing` is not in the context this engine builds, so
        // evaluating this rule is an error rather than a false condition.
        let source = format!(
            "{DEFAULT_POLICY}\n\
             @id(\"reads-something-absent\")\n\
             permit (principal, action, resource)\n\
             when {{ context.missing == \"anything\" }};\n"
        );
        let engine = Engine::from_source(&source).unwrap();
        let answered = engine.decide(&session(Scope::Read), classify(&["docker", "ps"]));
        assert!(
            matches!(answered, Err(PolicyError::Unevaluated { .. })),
            "an unevaluable policy was answered anyway: {answered:?}"
        );
    }

    /// Cedar denies when nothing permits, so a policy that says nothing refuses
    /// everything rather than letting it through.
    #[test]
    fn a_policy_that_permits_nothing_refuses_everything() {
        let engine = Engine::from_source("").unwrap();
        let decision = engine
            .decide(&session(Scope::Privileged), classify(&["uptime"]))
            .unwrap();
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    /// A decision has to be traceable to the rule that caused it, and a refusal
    /// has to tell the caller what would have to be different. The two are
    /// separate because they are read by different audiences: the policy name
    /// means nothing to an agent, and the prose means nothing to an auditor.
    #[test]
    fn a_decision_carries_both_its_rule_and_something_actionable() {
        let permitted = decide(Scope::Read, &["docker", "ps"]);
        assert!(
            !permitted.policies.is_empty(),
            "a permit should name the policy that granted it"
        );

        let refused = decide(Scope::Read, &["docker", "exec", "traefik", "ls"]);
        assert!(
            refused.explanation.contains("privileged") && refused.explanation.contains("read"),
            "a refusal should say what exceeded what: {}",
            refused.explanation
        );
        assert!(
            !refused.explanation.contains("policy") && !refused.explanation.contains("Cedar"),
            "a refusal should not hand the caller engine internals: {}",
            refused.explanation
        );
    }

    /// Policy is data. A deployment changes what is allowed by replacing it,
    /// not by shipping a different binary.
    #[test]
    fn a_deployment_can_replace_the_policy() {
        // No ceiling rule of its own: the engine adds that one whatever a
        // deployment writes, and writing it again would be a second copy to
        // keep in step.
        let stricter = r#"
            @id("only-uptime-reads")
            permit (principal, action == Action::"run", resource)
            when { context.assessment == 0 && context.program == "uptime" };
        "#;
        let engine = Engine::from_source(stricter).unwrap();

        let allowed = engine
            .decide(&session(Scope::Read), classify(&["uptime"]))
            .unwrap();
        assert_eq!(allowed.verdict, Verdict::Permit);

        let refused = engine
            .decide(&session(Scope::Read), classify(&["docker", "ps"]))
            .unwrap();
        assert_eq!(
            refused.verdict,
            Verdict::Deny,
            "a read the shipped policy allows is refused by this one"
        );
    }

    #[test]
    fn an_unreadable_policy_is_refused_rather_than_partially_loaded() {
        assert!(matches!(
            Engine::from_source("permit (principal"),
            Err(PolicyError::Unreadable { .. })
        ));
    }
}
