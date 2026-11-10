//! Typed inspection states. Missing evidence never stands in for an outcome.
use ssh_core::run::RunState;
use ssh_core::transfer::Failure;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "outcome", rename_all = "snake_case")]
pub enum Execution {
    NotStarted,
    WaitingForAgent,
    Observed(RunState),
    #[default]
    EvidenceMissing,
    UnsupportedLegacy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    NotRequired,
    AwaitingDecision,
    ApprovedOnce,
    Session,
    Expired,
    Refused,
    #[default]
    HistoricalUnconfirmed,
}

impl Execution {
    pub fn from_completion(event: &serde_json::Value) -> Self {
        if let Some(value) = event.get("outcome") {
            return serde_json::from_value::<RunState>(value.clone())
                .map(Self::Observed)
                .unwrap_or(Self::UnsupportedLegacy);
        }
        let Some(raw) = event.get("state").and_then(serde_json::Value::as_str) else {
            return Self::EvidenceMissing;
        };
        let code = raw
            .strip_prefix("exit ")
            .or_else(|| {
                raw.strip_prefix("Exited { code: ")
                    .and_then(|text| text.strip_suffix(" }"))
            })
            .and_then(|text| text.parse().ok());
        if let Some(code) = code {
            return Self::Observed(RunState::Exited { code });
        }
        match raw {
            "Running" => Self::Observed(RunState::Running),
            "Ended" => Self::Observed(RunState::Ended),
            "Refused" => Self::Observed(RunState::Refused),
            "Indeterminate" => Self::Observed(RunState::Indeterminate),
            _ => Self::UnsupportedLegacy,
        }
    }

    pub fn label(self) -> String {
        match self {
            Self::NotStarted => "Not started".to_owned(),
            Self::WaitingForAgent => "Waiting for agent".to_owned(),
            Self::EvidenceMissing => "Completion evidence unavailable".to_owned(),
            Self::UnsupportedLegacy => {
                "Unsupported legacy outcome · inspect recorded result".to_owned()
            }
            Self::Observed(state) => match state {
                RunState::Running => "Running".to_owned(),
                RunState::Exited { code } => format!("Completed · exit {code}"),
                RunState::Ended => "Ended · exit status unavailable".to_owned(),
                RunState::Refused => "Refused to start".to_owned(),
                RunState::Indeterminate => "Outcome unknown".to_owned(),
                RunState::TransferFailed {
                    cause,
                    remote_write_may_be_partial,
                } => {
                    let failure = match cause {
                        Failure::ReplacementUnknown => "Replacement outcome unknown".to_owned(),
                        Failure::StagingCleanupFailed => "Staging cleanup failed".to_owned(),
                        Failure::WorkerStopped | Failure::Cancelled => {
                            "Transfer worker stopped".to_owned()
                        }
                        _ => format!("Transfer failed · {}", cause.code().replace('_', " ")),
                    };
                    format!(
                        "{failure}{}",
                        if remote_write_may_be_partial {
                            " · remote file may be partial"
                        } else {
                            ""
                        }
                    )
                }
            },
        }
    }

    pub fn failed(self) -> bool {
        matches!(
            self,
            Self::Observed(
                RunState::Exited { code: 1.. }
                    | RunState::Refused
                    | RunState::TransferFailed { .. }
            )
        )
    }

    pub fn unknown(self) -> bool {
        matches!(
            self,
            Self::Observed(
                RunState::Indeterminate
                    | RunState::TransferFailed {
                        cause: Failure::ReplacementUnknown,
                        ..
                    }
            )
        )
    }

    pub fn missing(self) -> bool {
        matches!(self, Self::EvidenceMissing | Self::UnsupportedLegacy)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Preset {
    All,
    Waiting,
    WaitingAgent,
    Running,
    Failed,
    Unknown,
    Attention,
    Assessments,
    Evidence,
}

impl Preset {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "" => Self::All,
            "waiting" => Self::Waiting,
            "waiting_agent" => Self::WaitingAgent,
            "running" => Self::Running,
            "failed" => Self::Failed,
            "unknown" => Self::Unknown,
            "attention" => Self::Attention,
            "assessments" => Self::Assessments,
            "evidence" => Self::Evidence,
            _ => return None,
        })
    }

    pub fn includes(
        self,
        execution: Execution,
        approval: Approval,
        assessment: bool,
        attention: bool,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Waiting => approval == Approval::AwaitingDecision,
            Self::WaitingAgent => execution == Execution::WaitingForAgent,
            Self::Running => execution == Execution::Observed(RunState::Running),
            Self::Failed => execution.failed(),
            Self::Unknown => execution.unknown(),
            Self::Attention => attention,
            Self::Assessments => assessment,
            Self::Evidence => execution.missing(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_adaptation_does_not_turn_missing_or_unrecognized_evidence_into_success() {
        for (value, expected) in [
            (
                "Exited { code: 0 }",
                Execution::Observed(RunState::Exited { code: 0 }),
            ),
            ("exit 7", Execution::Observed(RunState::Exited { code: 7 })),
            ("Ended", Execution::Observed(RunState::Ended)),
            ("Refused", Execution::Observed(RunState::Refused)),
            (
                "Indeterminate",
                Execution::Observed(RunState::Indeterminate),
            ),
            ("arbitrary old text", Execution::UnsupportedLegacy),
        ] {
            assert_eq!(
                Execution::from_completion(&serde_json::json!({"state":value})),
                expected
            );
        }
        assert_eq!(
            Execution::from_completion(&serde_json::json!({})),
            Execution::EvidenceMissing
        );
        assert!(!Execution::EvidenceMissing.unknown());
        assert!(Execution::Observed(RunState::Indeterminate).unknown());
    }

    #[test]
    fn presets_distinguish_waiting_failure_unknown_and_missing_evidence() {
        for (execution, failed, unknown, missing) in [
            (
                Execution::Observed(RunState::Exited { code: 0 }),
                false,
                false,
                false,
            ),
            (
                Execution::Observed(RunState::Exited { code: 1 }),
                true,
                false,
                false,
            ),
            (
                Execution::Observed(RunState::Indeterminate),
                false,
                true,
                false,
            ),
            (Execution::EvidenceMissing, false, false, true),
            (
                Execution::Observed(RunState::TransferFailed {
                    cause: Failure::ReplacementUnknown,
                    remote_write_may_be_partial: true,
                }),
                true,
                true,
                false,
            ),
            (Execution::Observed(RunState::Ended), false, false, false),
            (Execution::Observed(RunState::Refused), true, false, false),
        ] {
            assert_eq!(
                Preset::Failed.includes(execution, Approval::NotRequired, false, false),
                failed
            );
            assert_eq!(
                Preset::Unknown.includes(execution, Approval::NotRequired, false, false),
                unknown
            );
            assert_eq!(
                Preset::Evidence.includes(execution, Approval::NotRequired, false, false),
                missing
            );
        }
        assert!(Preset::WaitingAgent.includes(
            Execution::WaitingForAgent,
            Approval::ApprovedOnce,
            false,
            false
        ));
        assert!(!Preset::Running.includes(
            Execution::WaitingForAgent,
            Approval::ApprovedOnce,
            false,
            false
        ));
    }
}
