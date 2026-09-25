use super::*;

fn bounded_ledger() -> Ledger<TestClock> {
    let mut ledger = ledger();
    ledger.limits = super::super::retention::Limits {
        entries: 8,
        readable_bytes: 16 << 10,
        active_proofs: 8,
        proof_bytes: 16 << 10,
        evaluation_ids: 16,
        ..super::super::retention::Limits::default()
    };
    ledger
}

fn artifact(id: &str, receipt: &Receipt) -> EvaluationArtifact {
    EvaluationArtifact::from_draft(
        EvaluationDraft {
            evaluation_id: id.to_owned(),
            decision_digest: receipt.digest().as_str().to_owned(),
            model: "fixture".into(),
            prompt_version: "fixture".into(),
            verdict: EvaluationVerdict::Uncertain,
            confidence: 50,
            rationale: "Synthetic retention evidence".into(),
            side_effects: Vec::new(),
        },
        "fixture".into(),
    )
    .unwrap()
}

#[test]
fn sustained_work_bounds_content_commitments_and_every_index() {
    let ledger = bounded_ledger();
    let session = session();
    for index in 0..1000 {
        let receipt = recorded_run(&ledger, &session, &["true"]);
        let evaluation = ledger.record_evaluation(artifact(&format!("eval-{index}"), &receipt));
        if index < 16 {
            evaluation.unwrap();
        } else {
            assert_eq!(evaluation, Err(AuditError::EvaluationFull));
        }
        ledger
            .record_outcome(outcome_for(&receipt, &"x".repeat(4096)))
            .unwrap();
        drop(receipt);
        ledger.reclaim().unwrap();
        let state = ledger.state.lock().unwrap();
        assert!(state.entries.len() <= 8);
        assert!(state.entries.capacity() <= 16);
        assert_eq!(state.issued.digests.len(), state.entries.len());
        assert!(state.issued.digests.capacity() <= 16);
        assert!(state.readable_bytes <= 16 << 10);
        assert!(state.proofs.is_empty());
        assert!(state.proofs.capacity() <= 16);
        assert!(state.evaluations.issued_ids.len() <= 16);
        assert!(state.evaluations.issued_ids.capacity() <= 32);
        assert!(state.evaluations.evaluated_decisions.len() <= 16);
        assert!(state.evaluations.evaluated_decisions.capacity() <= 32);
        assert!(state.evaluations.readable_decisions.len() <= 8);
        assert!(state.evaluations.readable_decisions.capacity() <= 16);
        assert!(state.evaluations.readable_artifacts.len() <= 8);
        assert!(state.evaluations.readable_artifacts.capacity() <= 16);
    }
    let verified = ledger.verify().unwrap();
    assert_eq!(verified.entries, 8);
    assert!(verified.retired > 1000);
}

#[test]
fn expired_and_retired_authority_still_records_exactly_one_completion() {
    let mut ledger = Ledger::new(TestClock::at(1000));
    ledger.limits.entries = 2;
    ledger.limits.readable_millis = 10;
    let session = session();
    let receipt = recorded_run(&ledger, &session, &["true"]);
    ledger.clock.advance(10);
    ledger.reclaim().unwrap();
    assert!(ledger.entries().is_empty());
    assert_eq!(ledger.verify().unwrap().sealed, 1);
    for _ in 0..10 {
        ledger.record_session_opened(&session).unwrap();
    }
    assert!(ledger.verify().unwrap().retired > receipt.sequence());
    let outcome = outcome_for(&receipt, "complete");
    let replay = outcome_for(&receipt, "complete");
    ledger.record_outcome(outcome).unwrap();
    for _ in 0..10 {
        ledger.record_session_closed(&session).unwrap();
    }
    assert!(matches!(
        ledger.record_outcome(replay),
        Err(AuditError::AlreadyCompleted { .. })
    ));
    assert!(ledger.verify().is_ok());
}

#[test]
fn exhausted_admission_preserves_existing_completion_and_cancelled_receipts_release_capacity() {
    let mut ledger = bounded_ledger();
    ledger.limits.active_proofs = 1;
    let session = session();
    let receipt = recorded_run(&ledger, &session, &["true"]);
    let decision =
        Engine::new(crate::policy::ReviewMode::Disabled).decide(&session, command(&["true"]));
    assert!(matches!(
        ledger.record_intent(decision, intent()),
        Err(AuditError::Full)
    ));
    ledger
        .record_outcome(outcome_for(&receipt, "complete"))
        .unwrap();
    drop(receipt);
    let cancelled = recorded_run(&ledger, &session, &["true"]);
    drop(cancelled);
    let admitted = recorded_run(&ledger, &session, &["true"]);
    ledger
        .record_outcome(outcome_for(&admitted, "complete"))
        .unwrap();
}

#[test]
fn failed_completion_write_does_not_consume_its_replay_guard() {
    struct Sink(AtomicBool);
    impl Records for Sink {
        fn wrote(&self, _: &Entry) -> Result<(), NotRecorded> {
            if self.0.load(Ordering::Relaxed) {
                Err(NotRecorded)
            } else {
                Ok(())
            }
        }
    }
    let sink = Arc::new(Sink(AtomicBool::new(false)));
    let ledger = Ledger::recording_to(TestClock::at(1000), sink.clone());
    let receipt = recorded_run(&ledger, &session(), &["true"]);
    let outcome = outcome_for(&receipt, "complete");
    sink.0.store(true, Ordering::Relaxed);
    assert!(matches!(
        ledger.record_outcome(outcome_for(&receipt, "complete")),
        Err(AuditError::NotRecorded)
    ));
    sink.0.store(false, Ordering::Relaxed);
    ledger.record_outcome(outcome).unwrap();
}

#[test]
fn an_outcome_larger_than_readable_retention_still_records_and_deduplicates() {
    struct Sink(std::sync::atomic::AtomicUsize);
    impl Records for Sink {
        fn wrote(&self, entry: &Entry) -> Result<(), NotRecorded> {
            if let Event::Completed {
                stdout: Recorded::Kept { text, .. },
                ..
            } = &entry.event
            {
                self.0.store(text.len(), Ordering::Relaxed);
            }
            Ok(())
        }
    }
    let sink = Arc::new(Sink(std::sync::atomic::AtomicUsize::new(0)));
    let mut ledger = bounded_ledger();
    ledger.records_to = Some(sink.clone());
    let receipt = recorded_run(&ledger, &session(), &["true"]);
    let output = "x".repeat(64 << 10);
    let recorded = ledger
        .record_outcome(outcome_for(&receipt, &output))
        .unwrap();
    assert_eq!(sink.0.load(Ordering::Relaxed), output.len());
    assert!(matches!(&recorded.entry.event,
        Event::Completed { stdout: Recorded::Kept { text, .. }, .. } if text == &output));
    assert!(
        !ledger
            .entries()
            .iter()
            .any(|entry| entry.sequence == recorded.entry.sequence)
    );
    assert_eq!(ledger.verify().unwrap().sealed, 1);
    assert!(ledger.state.lock().unwrap().readable_bytes <= ledger.limits.readable_bytes);
    assert!(matches!(
        ledger.record_outcome(outcome_for(&receipt, &output)),
        Err(AuditError::AlreadyCompleted { .. })
    ));
}

#[test]
fn capacity_pressure_does_not_retire_altered_evidence() {
    let mut ledger = bounded_ledger();
    ledger.limits.entries = 2;
    let session = session();
    ledger.record_session_opened(&session).unwrap();
    ledger.record_session_closed(&session).unwrap();
    {
        let mut state = ledger.state.lock().unwrap();
        let Held::Intact(entry) = state.entries.front_mut().unwrap() else {
            panic!("missing evidence")
        };
        Arc::make_mut(entry).event = Event::SessionClosed;
    }
    assert_eq!(
        ledger.record_session_opened(&session),
        Err(AuditError::RetentionCorrupt)
    );
    assert_eq!(ledger.verify(), Err(Broken::ContentAltered { at: 0 }));
    assert_eq!(ledger.state.lock().unwrap().issued.total, 2);
}

#[test]
fn concurrent_appending_and_reclamation_share_the_budget() {
    let ledger = Arc::new(bounded_ledger());
    std::thread::scope(|threads| {
        for _ in 0..4 {
            let ledger = Arc::clone(&ledger);
            threads.spawn(move || {
                let session = session();
                for _ in 0..100 {
                    ledger.record_session_opened(&session).unwrap();
                    ledger.reclaim().unwrap();
                }
            });
        }
    });
    let verified = ledger.verify().unwrap();
    assert_eq!(verified.entries, 8);
    assert_eq!(verified.retired, 392);
    assert!(ledger.state.lock().unwrap().readable_bytes <= ledger.limits.readable_bytes);
}

#[test]
fn a_pending_approval_keeps_its_source_proof_after_the_window_moves() {
    let mut ledger = bounded_ledger();
    ledger.limits.entries = 2;
    let session = session_that_can_be_asked_about();
    let held = ledger
        .record_intent(
            Engine::new(crate::policy::ReviewMode::Privileged).decide(&session, command(&["true"])),
            intent(),
        )
        .unwrap();
    let decided = held.deliberation().sequence;
    let approvals = crate::approval::Approvals::new(
        TestClock::at(0),
        crate::approval::Windows {
            decide_within: 1000,
            redeem_within: 1000,
        },
        8,
    );
    let crate::approval::Standing::Waiting(asked) = approvals.ask(&held).unwrap() else {
        panic!("new intent must wait for approval");
    };
    let id = asked.asked().id.clone();
    drop(held);
    for _ in 0..10 {
        ledger.record_session_opened(&session).unwrap();
    }
    assert!(ledger.verify().unwrap().retired > decided);
    let answer = approvals
        .decide(
            &id,
            Approver::Human {
                who: "fixture".into(),
            },
            true,
            |_| true,
        )
        .unwrap();
    ledger.record_answer(&answer).unwrap();
    assert!(approvals.mark_recorded(&id));
    drop(answer);
    let held = ledger
        .record_intent(
            Engine::new(crate::policy::ReviewMode::Privileged).decide(&session, command(&["true"])),
            intent(),
        )
        .unwrap();
    let crate::approval::Standing::Ready(grant) = approvals.ask(&held).unwrap() else {
        panic!("retry must collect the original approval");
    };
    approvals.sweep(|_| true);
    assert!(approvals.is_empty());
    for _ in 0..10 {
        ledger.record_session_opened(&session).unwrap();
    }
    let (receipt, _) = ledger.record_approval(&held, *grant).unwrap();
    drop(held);
    ledger
        .record_outcome(outcome_for(&receipt, "approved completion"))
        .unwrap();
    drop(receipt);
    ledger.reclaim().unwrap();
    assert!(ledger.state.lock().unwrap().proofs.is_empty());
    assert!(ledger.verify().is_ok());
}

#[test]
fn proof_byte_exhaustion_refuses_new_authority_before_writing() {
    let mut ledger = bounded_ledger();
    let session = session();
    let receipt = recorded_run(&ledger, &session, &["true"]);
    ledger.limits.proof_bytes = receipt.authorization.proof.bytes;
    let before = ledger.state.lock().unwrap().issued.total;
    let decision =
        Engine::new(crate::policy::ReviewMode::Disabled).decide(&session, command(&["true"]));
    assert!(matches!(
        ledger.record_intent(decision, intent()),
        Err(AuditError::Full)
    ));
    assert_eq!(ledger.state.lock().unwrap().issued.total, before);
    ledger
        .record_outcome(outcome_for(&receipt, "complete"))
        .unwrap();
}

#[test]
fn failed_approval_recording_preserves_the_same_human_answer_for_retry() {
    use crate::approval::{Approvals, RequestId, Standing, Windows};
    use crate::mediate::MediationError;

    struct Sink(AtomicBool);
    impl Records for Sink {
        fn wrote(&self, _: &Entry) -> Result<(), NotRecorded> {
            if self.0.load(Ordering::Relaxed) {
                Err(NotRecorded)
            } else {
                Ok(())
            }
        }
    }

    fn collect(
        ledger: &Ledger<TestClock>,
        approvals: &Approvals<TestClock>,
        intended: &Intended,
        request: &RequestId,
        explicit: bool,
    ) -> Result<(Receipt, Approver), MediationError> {
        let record = |grant| Ok(ledger.record_approval(intended, grant)?);
        if explicit {
            approvals.redeem_action_with(
                request,
                &intended.decision().session().principal,
                intended.decision().action(),
                intended.agent_intent(),
                record,
            )
        } else {
            let Standing::Ready(recorded) = approvals.ask_with(intended, record)? else {
                panic!("the existing human answer must remain collectable");
            };
            Ok(*recorded)
        }
    }

    for explicit in [false, true] {
        for failure in ["count", "bytes", "sink"] {
            let mut ledger = bounded_ledger();
            let sink = Arc::new(Sink(AtomicBool::new(false)));
            ledger.records_to = Some(sink.clone());
            let session = session_that_can_be_asked_about();
            let intended = ledger
                .record_intent(
                    Engine::new(crate::policy::ReviewMode::Privileged)
                        .decide(&session, command(&["true"])),
                    intent(),
                )
                .unwrap();
            let approvals = Approvals::new(
                TestClock::at(0),
                Windows {
                    decide_within: 1000,
                    redeem_within: 1000,
                },
                8,
            );
            let Standing::Waiting(asked) = approvals.ask(&intended).unwrap() else {
                panic!("new work must wait for approval");
            };
            let id = asked.asked().id.clone();
            drop(intended);
            let answer = approvals
                .decide(
                    &id,
                    Approver::Human {
                        who: "fixture".into(),
                    },
                    true,
                    |_| true,
                )
                .unwrap();
            ledger.record_answer(&answer).unwrap();
            assert!(approvals.mark_recorded(&id));
            drop(answer);
            let blocker = recorded_run(&ledger, &super::session(), &["echo", &"x".repeat(2048)]);
            let retry = ledger
                .record_intent(
                    Engine::new(crate::policy::ReviewMode::Privileged)
                        .decide(&session, command(&["true"])),
                    intent(),
                )
                .unwrap();
            match failure {
                "count" => ledger.limits.active_proofs = 3,
                "bytes" => {
                    ledger.limits.proof_bytes = ledger
                        .state
                        .lock()
                        .unwrap()
                        .proofs
                        .values()
                        .filter_map(Weak::upgrade)
                        .map(|proof| proof.bytes)
                        .sum();
                }
                _ => sink.0.store(true, Ordering::Relaxed),
            }
            assert!(matches!(
                collect(&ledger, &approvals, &retry, &id, explicit),
                Err(MediationError::Audit(
                    AuditError::Full | AuditError::NotRecorded
                ))
            ));
            assert!(
                !ledger
                    .entries()
                    .iter()
                    .any(|entry| matches!(entry.event, Event::Approved { .. }))
            );
            drop(blocker);
            sink.0.store(false, Ordering::Relaxed);
            let (receipt, _) = collect(&ledger, &approvals, &retry, &id, explicit).unwrap();
            assert_eq!(
                approvals.redeem_action(
                    &id,
                    &session.principal,
                    retry.decision().action(),
                    retry.agent_intent()
                ),
                Err(crate::approval::ApprovalError::AlreadyRedeemed)
            );
            let entries = ledger.entries();
            let approved: Vec<_> = entries
                .iter()
                .filter_map(|entry| match &entry.event {
                    Event::Approved { request, .. } => Some(request),
                    _ => None,
                })
                .collect();
            assert_eq!(approved, vec![id.as_str()]);
            ledger
                .record_outcome(outcome_for(&receipt, "complete"))
                .unwrap();
            assert!(ledger.verify().is_ok());
        }
    }
}

#[test]
#[ignore = "audit retention memory measurement; run explicitly with --nocapture"]
fn retention_memory_benchmark() {
    use std::io::Write as _;
    let mut ledger = bounded_ledger();
    ledger.limits.entries = 128;
    ledger.limits.readable_bytes = 1 << 20;
    let session = session();
    let output = "x".repeat(64 << 10);
    let started = std::time::Instant::now();
    for index in 1..=4000 {
        let receipt = recorded_run(&ledger, &session, &["true"]);
        let evaluation = ledger.record_evaluation(artifact(&format!("eval-{index}"), &receipt));
        if index <= 16 {
            evaluation.unwrap();
        } else {
            assert_eq!(evaluation, Err(AuditError::EvaluationFull));
        }
        ledger
            .record_outcome(outcome_for(&receipt, &output))
            .unwrap();
        drop(receipt);
        ledger.reclaim().unwrap();
        if [500, 1000, 2000, 4000].contains(&index) {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let rss = status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            });
            let state = ledger.state.lock().unwrap();
            let value = serde_json::json!({"completed_runs":index, "retained_entries":state.entries.len(), "retained_encoded_bytes":state.readable_bytes, "issued_digests":state.issued.digests.len(), "active_proofs":state.proofs.len(), "evaluation_ids":state.evaluations.issued_ids.len(), "evaluated_decisions":state.evaluations.evaluated_decisions.len(), "readable_decisions":state.evaluations.readable_decisions.len(), "readable_artifacts":state.evaluations.readable_artifacts.len(), "rss_kib":rss, "elapsed_seconds":started.elapsed().as_secs_f64()});
            let mut out = std::io::stdout().lock();
            serde_json::to_writer(&mut out, &value).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }
    assert!(ledger.verify().is_ok());
}
