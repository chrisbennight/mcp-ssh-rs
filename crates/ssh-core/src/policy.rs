//! Optional local human review, independent of upstream account authorization.

use crate::AccessClass;
use crate::action::Action;
use crate::command::Command;
use crate::session::Session;

/// Local review requirements apply to configured accounts, never command text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReviewMode {
    #[default]
    Disabled,
    All,
    Privileged,
}

impl std::str::FromStr for ReviewMode {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "all" => Ok(Self::All),
            "privileged" => Ok(Self::Privileged),
            _ => Err(PolicyError::InvalidReviewMode),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Permit,
    NeedsApproval,
    Deny,
}

/// An exact command and session travel with their review decision.
/// Recording consumes this value so it cannot authorize a second execution.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    verdict: Verdict,
    policies: Vec<String>,
    explanation: String,
    action: Action,
    session: Session,
}

impl Decision {
    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    #[must_use]
    pub fn policies(&self) -> &[String] {
        &self.policies
    }

    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    #[must_use]
    pub const fn command(&self) -> &Command {
        self.action.command()
    }

    pub const fn action(&self) -> &Action {
        &self.action
    }

    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }
}

pub struct Engine {
    review: ReviewMode,
}

impl Engine {
    #[must_use]
    pub const fn new(review: ReviewMode) -> Self {
        Self { review }
    }

    /// Account authorization and session binding must precede local review.
    /// A review decision cannot grant a different account or change its class.
    #[must_use]
    pub fn decide(&self, session: &Session, command: Command) -> Decision {
        self.decide_action(session, Action::execute(command))
    }

    pub fn decide_action(&self, session: &Session, action: Action) -> Decision {
        let held = match self.review {
            ReviewMode::Disabled => false,
            ReviewMode::All => true,
            ReviewMode::Privileged => session.access_class == AccessClass::Privileged,
        };
        let (verdict, reason, policy) = if held {
            (
                Verdict::NeedsApproval,
                "This account requires human approval.",
                "local-human-review",
            )
        } else {
            (
                Verdict::Permit,
                "The configured account does not require local human approval.",
                "configured-account",
            )
        };
        Decision {
            verdict,
            policies: vec![policy.to_owned()],
            explanation: reason.to_owned(),
            action,
            session: session.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("review mode must be disabled, all, or privileged")]
    InvalidReviewMode,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::session::{Lifetime, Purpose, SessionStore};
    use crate::{HostId, PrincipalId, RoleId};

    fn session(class: AccessClass) -> Session {
        SessionStore::new(
            TestClock::at(0),
            Lifetime {
                idle: 1000,
                max: 1000,
                grace: 0,
            },
            1,
        )
        .open(
            PrincipalId::parse("caller").unwrap(),
            HostId::parse("target").unwrap(),
            RoleId::parse("account").unwrap(),
            Purpose::parse("Diagnose target").unwrap(),
            class,
        )
        .unwrap()
    }

    #[test]
    fn review_depends_on_account_configuration_and_not_command_content() {
        for class in [AccessClass::ReadOnly, AccessClass::Privileged] {
            for (mode, expected) in [
                (ReviewMode::Disabled, Verdict::Permit),
                (ReviewMode::All, Verdict::NeedsApproval),
                (
                    ReviewMode::Privileged,
                    if class == AccessClass::Privileged {
                        Verdict::NeedsApproval
                    } else {
                        Verdict::Permit
                    },
                ),
            ] {
                for argv in [
                    vec!["uptime"],
                    vec!["sh", "-c", "any shell program"],
                    vec!["unknown-program"],
                ] {
                    let command =
                        Command::new(argv.into_iter().map(str::to_owned).collect()).unwrap();
                    let decision = Engine::new(mode).decide(&session(class), command.clone());
                    assert_eq!(decision.verdict(), expected);
                    assert_eq!(decision.command(), &command);
                    assert_eq!(decision.session().access_class, class);
                }
            }
        }
    }

    #[test]
    fn invalid_review_configuration_is_rejected() {
        assert_eq!("all".parse(), Ok(ReviewMode::All));
        assert!("read".parse::<ReviewMode>().is_err());
    }
}
