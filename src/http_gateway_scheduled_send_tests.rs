use std::cell::Cell;

struct Fixture {
    root: std::path::PathBuf,
    gateway: RuntimeBrowserGateway,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-scheduled-runtime-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let gateway = RuntimeBrowserGateway::for_test(&root);
        Self { root, gateway }
    }
    fn claim(&self, sign: bool) -> ClaimedJob {
        let now = SystemTimeProvider.unix_timestamp();
        let created = now - 1;
        let mut request = ComposeRequest::new(
            ComposePolicy::default(),
            "recipient@example.test",
            "Synthetic scheduled subject",
            "Synthetic scheduled body",
        )
        .unwrap();
        if sign {
            request.protection = crate::send::ProtectionIntent {
                sign: true,
                encrypt: false,
                encrypt_to_self: false,
                binding_revision: Some(0),
            };
        }
        let journal =
            crate::send_journal::SendJournal::new(self.gateway.settings_dir.join("send-journal"));
        let store = crate::scheduled_send::ScheduledStore::new(self.root.join("jobs"));
        {
            let mut guard = journal.account_guard("alice@example.com", created).unwrap();
            let staged = store
                .create_staged(
                    &guard,
                    0,
                    crate::scheduled_send::ScheduleInput {
                        due_at: now,
                        account_epoch: 2,
                        private_session: crate::openpgp_personal::PrivateSession {
                            session_id: "a".repeat(64),
                            account_epoch: Some(2),
                            expires_at: now + 28800,
                        },
                        request: &request,
                    },
                    created,
                )
                .unwrap();
            let source = crate::send_journal::mint_intent(created).unwrap();
            guard
                .begin_schedule(&source, &staged.id, &staged.digest)
                .unwrap();
            store
                .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, created)
                .unwrap();
            guard
                .finish_schedule(&source, &staged.id, &staged.digest)
                .unwrap();
        }
        let guard = journal.account_guard("alice@example.com", now).unwrap();
        store.claim_next(&guard, now).unwrap().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
struct NeverSubmit<'a>(&'a Cell<usize>);
impl crate::send::SubmissionBackend for NeverSubmit<'_> {
    fn submit_message(
        &self,
        _: &str,
        _: &ComposeRequest,
    ) -> Result<(), crate::send::SubmissionBackendError> {
        self.0.set(self.0.get() + 1);
        panic!("unavailable scheduled authority must not reach SMTP");
    }
}
struct NeverAppend(Cell<usize>);
impl MessageAppendBackend for NeverAppend {
    fn append_message(
        &self,
        _: &str,
        _: &MessageAppendRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        self.0.set(self.0.get() + 1);
        panic!("unavailable scheduled authority must not reach Sent");
    }
}

#[test]
fn scheduled_runtime_requires_current_account_authority_without_fabricating_browser_session() {
    let mut fixture = Fixture::new();
    let claim = fixture.claim(false);
    let submitted = Cell::new(0);
    let submission = SubmissionService::new(NeverSubmit(&submitted));
    let append = NeverAppend(Cell::new(0));
    let denied = fixture
        .gateway
        .dispatch_scheduled_with_backends(&claim, &submission, &append);
    assert!(matches!(
        denied.decision,
        ScheduledDispatch::Blocked(BlockReason::ServiceUnavailable)
    ));
    fixture.gateway.account_rollout = Some("bob@example.com".into());
    let foreign = fixture
        .gateway
        .dispatch_scheduled_with_backends(&claim, &submission, &append);
    assert!(matches!(
        foreign.decision,
        ScheduledDispatch::Blocked(BlockReason::AccountChanged)
    ));
    assert_eq!(submitted.get(), 0);
    assert_eq!(append.0.get(), 0);
    let journal =
        crate::send_journal::SendJournal::new(fixture.gateway.settings_dir.join("send-journal"));
    assert!(journal
        .receipt(
            claim.account(),
            claim.intent(),
            SystemTimeProvider.unix_timestamp()
        )
        .unwrap()
        .is_none());
}

#[test]
fn scheduled_private_session_read_checks_current_owner_epoch_revocation_expiry_and_idle_without_refresh(
) {
    let fixture = Fixture::new();
    let claim = fixture.claim(true);
    let store = FileSessionStore::new(fixture.gateway.session_dir.clone());
    let now = SystemTimeProvider.unix_timestamp();
    let record = crate::session::SessionRecord {
        session_id: "a".repeat(64),
        account_epoch: Some(2),
        csrf_token: "b".repeat(crate::session::CSRF_TOKEN_HEX_LEN),
        canonical_username: "alice@example.com".into(),
        issued_at: now - 100,
        last_seen_at: now,
        expires_at: claim.private_session().expires_at,
        revoked_at: None,
        remote_addr: "192.0.2.1".into(),
        user_agent: "Synthetic browser".into(),
        factor: crate::auth::RequiredSecondFactor::Totp,
    };
    store.save(&record).unwrap();
    assert_eq!(store.load(&record.session_id).unwrap().unwrap(), record);
    let path = store.session_path(&record.session_id);
    let before = std::fs::read(&path).unwrap();
    fixture
        .gateway
        .scheduled_private_session(&claim, now + 1)
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for kind in ["owner", "epoch", "revoked", "expires", "future", "idle"] {
        let mut changed = record.clone();
        let now = match kind {
            "owner" => {
                changed.canonical_username = "bob@example.com".into();
                now + 1
            }
            "epoch" => {
                changed.account_epoch = Some(3);
                now + 1
            }
            "revoked" => {
                changed.revoked_at = Some(now + 1);
                now + 1
            }
            "expires" => record.expires_at,
            "future" => {
                changed.last_seen_at = now + 2;
                now + 1
            }
            "idle" => record.last_seen_at + fixture.gateway.session_idle_timeout_seconds + 1,
            _ => unreachable!(),
        };
        store.save(&changed).unwrap();
        assert_eq!(store.load(&changed.session_id).unwrap().unwrap(), changed);
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            matches!(
                fixture.gateway.scheduled_private_session(&claim, now),
                Err(BlockReason::SessionExpired)
            ),
            "{kind}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
