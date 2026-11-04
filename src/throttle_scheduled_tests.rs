use super::*;

#[test]
fn browser_and_scheduler_share_real_account_cap_without_fake_remote_identity() {
    let store = LockAssertingStore::default();
    let service = SubmissionThrottleService::new(
        store.clone(),
        FixedTimeProvider::new(200),
        SubmissionThrottlePolicy {
            canonical_user_max_submissions: 2,
            remote_addr_max_submissions: 5,
            submission_window_seconds: 300,
            lockout_seconds: 60,
        },
    );
    let first = test_context();
    let second = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "other-request",
        "192.0.2.2",
        "Other browser",
    )
    .unwrap();
    service
        .record_submission(&first, "alice@example.com")
        .unwrap();
    let recorded = service
        .record_scheduled_submission("alice@example.com", &"a".repeat(32))
        .unwrap();
    assert!(recorded.lockout_engaged);
    assert!(matches!(
        service
            .check(&second, "alice@example.com")
            .unwrap()
            .decision,
        SubmissionThrottleDecision::Throttled { .. }
    ));
    assert!(matches!(
        service
            .check_scheduled("alice@example.com", &"b".repeat(32))
            .unwrap()
            .decision,
        SubmissionThrottleDecision::Throttled { .. }
    ));
    assert_eq!(
        service
            .check_scheduled("bob@example.com", &"c".repeat(32))
            .unwrap()
            .decision,
        SubmissionThrottleDecision::Allowed
    );
    let audit = crate::logging::Logger::new(
        crate::config::LogFormat::Text,
        crate::config::LogLevel::Debug,
    )
    .render_with_timestamp(&recorded.audit_events[0], 200);
    assert!(
        audit.contains("canonical_user_only") && audit.contains("submission_origin=\"scheduled\"")
    );
    assert!(
        !audit.contains("remote_addr=")
            && !audit.contains("user_agent=")
            && !audit.contains("request_id=")
    );
    // Both historical browser keys remain exactly the same real keys.
    let records = store.records.lock().unwrap();
    for key in [
        SubmissionThrottleKey::for_canonical_user_and_remote_addr(
            "alice@example.com",
            &first.remote_addr,
        ),
        SubmissionThrottleKey::for_remote_addr("alice@example.com", &first.remote_addr),
    ] {
        assert_eq!(records[&key.key_id].failure_count, 1);
    }
}

#[test]
fn global_scheduler_cap_spans_accounts_without_charging_browser_remote_bucket() {
    let service = SubmissionThrottleService::new(
        LockAssertingStore::default(),
        FixedTimeProvider::new(200),
        SubmissionThrottlePolicy {
            canonical_user_max_submissions: 10,
            remote_addr_max_submissions: 2,
            submission_window_seconds: 300,
            lockout_seconds: 60,
        },
    );
    service
        .record_scheduled_submission("alice@example.com", &"a".repeat(32))
        .unwrap();
    service
        .record_scheduled_submission("bob@example.com", &"b".repeat(32))
        .unwrap();
    let check = service
        .check_scheduled("carol@example.com", &"c".repeat(32))
        .unwrap();
    assert!(matches!(
        check.decision,
        SubmissionThrottleDecision::Throttled {
            retry_after_seconds: 60
        }
    ));
    assert_eq!(
        check.audit_events[0]
            .fields
            .iter()
            .find(|field| field.key == "bucket_kind")
            .unwrap()
            .value,
        "scheduler_global"
    );
    assert_eq!(
        service
            .check(&test_context(), "carol@example.com")
            .unwrap()
            .decision,
        SubmissionThrottleDecision::Allowed
    );
    assert!(service
        .check_scheduled("bad account", &"a".repeat(32))
        .is_err());
    assert!(service
        .check_scheduled("alice@example.com", "unbounded/job/path")
        .is_err());
}
