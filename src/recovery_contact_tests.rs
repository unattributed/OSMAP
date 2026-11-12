use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs;

const ACCOUNT: &str = "alice@example.test";
const OTHER: &str = "bob@example.test";
const FIRST: &str = "first@recovery.invalid";
const SECOND: &str = "second@recovery.invalid";

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Random(Cell<u8>);
impl RandomSource for Random {
    fn fill_bytes(&self, bytes: &mut [u8]) -> Result<(), crate::session::SessionError> {
        let v = self.0.get();
        self.0.set(v + 1);
        bytes.fill(v);
        Ok(())
    }
}
#[derive(Default)]
struct Mail {
    tokens: RefCell<Vec<String>>,
    addresses: RefCell<Vec<String>>,
    kinds: RefCell<Vec<&'static str>>,
    replies: RefCell<VecDeque<RecoveryContactDelivery>>,
}
impl RecoveryContactNotifier for Mail {
    fn deliver(&self, message: RecoveryContactMessage<'_>, _: Instant) -> RecoveryContactDelivery {
        let (email, kind) = match message {
            RecoveryContactMessage::Verification { email, token, .. } => {
                self.tokens.borrow_mut().push(token.into());
                (email, "proof")
            }
            RecoveryContactMessage::Replaced { email } => (email, "replaced"),
            RecoveryContactMessage::Removed { email } => (email, "removed"),
        };
        self.addresses.borrow_mut().push(email.into());
        self.kinds.borrow_mut().push(kind);
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or(RecoveryContactDelivery::Accepted)
    }
}
struct Fixture {
    _scratch: Scratch,
    store: RecoveryContactStore,
    mail: Mail,
    random: Random,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-recovery-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self {
            _scratch: Scratch(path.clone()),
            store: RecoveryContactStore::new(path),
            mail: Mail::default(),
            random: Random(Cell::new(1)),
        }
    }
    fn change(
        &self,
        account: &str,
        revision: u64,
        now: u64,
        action: RecoveryContactAction,
    ) -> Result<RecoveryContactResult, RecoveryContactError> {
        self.store.mutate_with_random(
            RecoveryContactMutation {
                account,
                expected_revision: revision,
                now,
                deadline: Instant::now() + Duration::from_secs(5),
                action,
            },
            || Ok(()),
            &self.mail,
            &self.random,
        )
    }
    fn begin(&self, account: &str, revision: u64, now: u64, email: &str) -> RecoveryContactResult {
        self.change(
            account,
            revision,
            now,
            RecoveryContactAction::Begin {
                email: email.into(),
            },
        )
        .unwrap()
    }
    fn token(&self) -> String {
        self.mail.tokens.borrow().last().unwrap().clone()
    }
    fn verify(&self, revision: u64, now: u64) -> RecoveryContactResult {
        self.change(
            ACCOUNT,
            revision,
            now,
            RecoveryContactAction::Verify {
                token: self.token(),
            },
        )
        .unwrap()
    }
}

#[test]
fn lifecycle_keeps_verified_until_proof_and_notifies_old_contact() {
    let f = Fixture::new();
    let first = f.begin(ACCOUNT, 0, 100, FIRST);
    assert!(first.snapshot.verified.is_none());
    assert_eq!(first.snapshot.revision, 1);
    let verified = f.verify(1, 101);
    assert_eq!(verified.snapshot.verified.unwrap().email, FIRST);
    let pending = f.begin(ACCOUNT, 2, 160, SECOND);
    assert_eq!(pending.snapshot.verified.unwrap().email, FIRST);
    let replaced = f.verify(3, 161);
    assert_eq!(replaced.snapshot.verified.unwrap().email, SECOND);
    assert!(replaced.snapshot.pending.is_none());
    assert_eq!(
        replaced.snapshot.notice.unwrap().kind,
        RecoveryContactNoticeKind::Replaced
    );
    assert_eq!(f.mail.addresses.borrow().last().unwrap(), FIRST);
    let removed = f
        .change(ACCOUNT, 4, 162, RecoveryContactAction::Remove)
        .unwrap();
    assert!(removed.snapshot.verified.is_none() && removed.snapshot.pending.is_none());
    assert_eq!(
        removed.snapshot.notice.unwrap().kind,
        RecoveryContactNoticeKind::Removed
    );
    assert_eq!(f.mail.addresses.borrow().last().unwrap(), SECOND);
    assert_eq!(
        f.change(
            ACCOUNT,
            5,
            163,
            RecoveryContactAction::Verify { token: f.token() }
        ),
        Err(RecoveryContactError::NoPending)
    );
}

#[test]
fn rotating_token_rejects_old_and_cross_account_proof_and_replay() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    let old = f.token();
    f.change(ACCOUNT, 1, 160, RecoveryContactAction::Resend)
        .unwrap();
    let new = f.token();
    assert!(old != new);
    assert_eq!(
        f.change(
            ACCOUNT,
            2,
            161,
            RecoveryContactAction::Verify { token: old }
        ),
        Err(RecoveryContactError::InvalidToken)
    );
    f.begin(OTHER, 0, 162, SECOND);
    assert_eq!(
        f.change(
            OTHER,
            1,
            163,
            RecoveryContactAction::Verify { token: new.clone() }
        ),
        Err(RecoveryContactError::InvalidToken)
    );
    f.change(
        ACCOUNT,
        3,
        164,
        RecoveryContactAction::Verify { token: new.clone() },
    )
    .unwrap();
    assert_eq!(
        f.change(
            ACCOUNT,
            4,
            165,
            RecoveryContactAction::Verify { token: new }
        ),
        Err(RecoveryContactError::NoPending)
    );
    assert!(f.store.snapshot(OTHER, 165).unwrap().verified.is_none());
}

#[test]
fn token_and_pending_expiry_are_exact_and_resend_does_not_extend_day() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    assert_eq!(
        f.change(
            ACCOUNT,
            1,
            1900,
            RecoveryContactAction::Verify { token: f.token() }
        ),
        Err(RecoveryContactError::Expired)
    );
    let resent = f
        .change(ACCOUNT, 1, 86400, RecoveryContactAction::Resend)
        .unwrap();
    let p = resent.snapshot.pending.unwrap();
    assert_eq!(p.expires_at, 86500);
    assert_eq!(p.token_expires_at, 86500);
    assert!(f.store.snapshot(ACCOUNT, 86500).unwrap().pending.is_none());
    assert_eq!(
        f.change(
            ACCOUNT,
            2,
            86500,
            RecoveryContactAction::Verify { token: f.token() }
        ),
        Err(RecoveryContactError::Expired)
    );
    let next = f.begin(ACCOUNT, 2, 86500, SECOND);
    assert_eq!(next.snapshot.pending.unwrap().created_at, 86500);
}

#[test]
fn five_bad_attempts_invalidate_even_correct_token_then_explicit_resend_recovers() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    let token = f.token();
    for attempt in 0..5 {
        assert_eq!(
            f.change(
                ACCOUNT,
                1 + attempt,
                101 + attempt,
                RecoveryContactAction::Verify {
                    token: "bad".into()
                }
            ),
            Err(RecoveryContactError::InvalidToken)
        );
    }
    let s = f.store.snapshot(ACCOUNT, 110).unwrap();
    assert_eq!(s.pending.unwrap().attempts_remaining, 0);
    assert_eq!(
        f.change(ACCOUNT, 6, 110, RecoveryContactAction::Verify { token }),
        Err(RecoveryContactError::InvalidToken)
    );
    assert_eq!(f.store.snapshot(ACCOUNT, 111).unwrap().revision, 6);
    f.change(ACCOUNT, 6, 160, RecoveryContactAction::Resend)
        .unwrap();
    f.verify(7, 161);
}

#[test]
fn resend_minute_hour_and_day_limits_survive_reopen_and_cannot_use_begin_to_bypass() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    assert_eq!(
        f.change(ACCOUNT, 1, 159, RecoveryContactAction::Resend),
        Err(RecoveryContactError::RateLimited { retry_at: 160 })
    );
    let times = [160, 220, 3700, 3760, 3820, 7300, 7360, 7420, 10900];
    for (i, now) in times.iter().enumerate() {
        f.change(ACCOUNT, i as u64 + 1, *now, RecoveryContactAction::Resend)
            .unwrap();
        if *now == 220 {
            assert_eq!(
                f.change(
                    ACCOUNT,
                    3,
                    280,
                    RecoveryContactAction::Begin {
                        email: SECOND.into()
                    }
                ),
                Err(RecoveryContactError::RateLimited { retry_at: 3700 })
            );
        }
    }
    let reopened = RecoveryContactStore::new(f._scratch.0.clone());
    assert_eq!(
        reopened.mutate(
            RecoveryContactMutation {
                account: ACCOUNT,
                expected_revision: 10,
                now: 10960,
                deadline: Instant::now() + Duration::from_secs(2),
                action: RecoveryContactAction::Resend
            },
            || Ok(()),
            &f.mail
        ),
        Err(RecoveryContactError::RateLimited { retry_at: 86500 })
    );
    f.begin(ACCOUNT, 10, 86500, SECOND);
}

#[test]
fn stale_forms_and_authorization_refusal_have_no_delivery_or_saved_effect() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    assert_eq!(
        f.change(ACCOUNT, 0, 160, RecoveryContactAction::Remove),
        Err(RecoveryContactError::Stale)
    );
    let calls = f.mail.tokens.borrow().len();
    let result = f.store.mutate(
        RecoveryContactMutation {
            account: ACCOUNT,
            expected_revision: 1,
            now: 160,
            deadline: Instant::now() + Duration::from_secs(2),
            action: RecoveryContactAction::Remove,
        },
        || Err(RecoveryContactError::Authentication),
        &f.mail,
    );
    assert_eq!(result, Err(RecoveryContactError::Authentication));
    assert_eq!(f.mail.tokens.borrow().len(), calls);
    assert_eq!(f.store.snapshot(ACCOUNT, 160).unwrap().revision, 1);
}

#[test]
fn refusal_and_ambiguity_never_claim_delivery_or_blindly_send_again() {
    let f = Fixture::new();
    f.mail
        .replies
        .borrow_mut()
        .push_back(RecoveryContactDelivery::Refused);
    let result = f.begin(ACCOUNT, 0, 100, FIRST);
    assert_eq!(result.delivery, Some(RecoveryContactDelivery::Refused));
    assert_eq!(
        f.change(
            ACCOUNT,
            1,
            101,
            RecoveryContactAction::Verify { token: f.token() }
        ),
        Err(RecoveryContactError::InvalidToken)
    );
    f.mail
        .replies
        .borrow_mut()
        .push_back(RecoveryContactDelivery::Unconfirmed);
    f.change(ACCOUNT, 2, 160, RecoveryContactAction::Resend)
        .unwrap();
    let token = f.token();
    for action in [
        RecoveryContactAction::Resend,
        RecoveryContactAction::Begin {
            email: SECOND.into(),
        },
    ] {
        assert_eq!(
            f.change(ACCOUNT, 3, 220, action),
            Err(RecoveryContactError::DeliveryUnconfirmed)
        );
    }
    assert_eq!(f.mail.tokens.borrow().len(), 2);
    f.change(ACCOUNT, 3, 221, RecoveryContactAction::Verify { token })
        .unwrap();
}

#[test]
fn ambiguous_old_notice_survives_later_removal_and_pending_discard() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    f.verify(1, 101);
    f.begin(ACCOUNT, 2, 160, SECOND);
    f.mail
        .replies
        .borrow_mut()
        .push_back(RecoveryContactDelivery::Unconfirmed);
    let changed = f.verify(3, 161);
    assert_eq!(
        changed.snapshot.notice.unwrap().delivery,
        RecoveryContactDelivery::Unconfirmed
    );
    let removed = f
        .change(ACCOUNT, 4, 162, RecoveryContactAction::Remove)
        .unwrap();
    let n = removed.snapshot.notice.unwrap();
    assert!(n.earlier_unconfirmed);
    assert_eq!(n.delivery, RecoveryContactDelivery::Accepted);
    f.begin(ACCOUNT, 5, 220, FIRST);
    let removed = f
        .change(ACCOUNT, 6, 221, RecoveryContactAction::Remove)
        .unwrap();
    assert!(removed.snapshot.notice.unwrap().earlier_unconfirmed);
}

#[test]
fn interrupted_delivery_persists_unknown_before_external_effect_and_contains_resend() {
    struct Crash;
    impl RecoveryContactNotifier for Crash {
        fn deliver(&self, _: RecoveryContactMessage<'_>, _: Instant) -> RecoveryContactDelivery {
            panic!("public synthetic notification interruption")
        }
    }
    let f = Fixture::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.store.mutate(
            RecoveryContactMutation {
                account: ACCOUNT,
                expected_revision: 0,
                now: 100,
                deadline: Instant::now() + Duration::from_secs(2),
                action: RecoveryContactAction::Begin {
                    email: FIRST.into(),
                },
            },
            || Ok(()),
            &Crash,
        )
    }));
    assert!(result.is_err());
    let s = f.store.snapshot(ACCOUNT, 101).unwrap();
    assert_eq!(
        s.pending.unwrap().delivery,
        RecoveryContactDelivery::Unconfirmed
    );
    assert_eq!(
        f.change(ACCOUNT, 1, 160, RecoveryContactAction::Resend),
        Err(RecoveryContactError::DeliveryUnconfirmed)
    );
    f.change(ACCOUNT, 1, 161, RecoveryContactAction::Remove)
        .unwrap();
    assert!(f.store.snapshot(ACCOUNT, 162).unwrap().pending.is_none());
}

#[test]
fn account_lock_spans_authorization_and_does_not_block_other_account() {
    let f = Fixture::new();
    let store = f.store.clone();
    let (entered_rx, release_tx) = {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mail = Mail::default();
            store
                .mutate(
                    RecoveryContactMutation {
                        account: ACCOUNT,
                        expected_revision: 0,
                        now: 100,
                        deadline: Instant::now() + Duration::from_secs(5),
                        action: RecoveryContactAction::Begin {
                            email: FIRST.into(),
                        },
                    },
                    || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                        Ok(())
                    },
                    &mail,
                )
                .unwrap();
        });
        (entered_rx, (release_tx, thread))
    };
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(
        f.store.snapshot(ACCOUNT, 100),
        Err(RecoveryContactError::Busy)
    );
    assert_eq!(
        f.change(ACCOUNT, 0, 100, RecoveryContactAction::Remove),
        Err(RecoveryContactError::Busy)
    );
    f.begin(OTHER, 0, 100, SECOND);
    release_tx.0.send(()).unwrap();
    release_tx.1.join().unwrap();
    assert_eq!(
        f.change(ACCOUNT, 0, 101, RecoveryContactAction::Remove),
        Err(RecoveryContactError::Stale)
    );
}

#[test]
fn corrupted_schema_account_timestamps_and_digest_refuse_without_effects() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    let locked = f.store.file.lock(ACCOUNT).unwrap();
    let bytes = locked.read().unwrap().unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in [
        "version", "account", "future", "expiry", "attempts", "digest", "extra",
    ] {
        let mut v = original.clone();
        match field {
            "version" => v["version"] = 2.into(),
            "account" => v["account"] = OTHER.into(),
            "future" => v["updated_at"] = 1000.into(),
            "expiry" => v["pending"]["expires_at"] = u64::MAX.into(),
            "attempts" => v["pending"]["attempts"] = 6.into(),
            "digest" => v["pending"]["token_digest"] = "raw malformed".into(),
            _ => v["unexpected"] = true.into(),
        }
        locked.write(&serde_json::to_vec(&v).unwrap()).unwrap();
        drop(locked.read().unwrap());
        assert_eq!(
            decode(ACCOUNT, locked.read().unwrap(), 101).err(),
            Some(RecoveryContactError::Unavailable)
        );
    }
    locked.write(&bytes).unwrap();
    drop(locked);
    assert_eq!(
        f.store.snapshot(ACCOUNT, 99),
        Err(RecoveryContactError::Unavailable)
    );
    assert_eq!(f.mail.tokens.borrow().len(), 1);
}

#[test]
fn token_and_private_addresses_do_not_escape_debug_or_raw_persisted_token() {
    let f = Fixture::new();
    let s = f.begin(ACCOUNT, 0, 100, FIRST);
    let token = f.token();
    let debug = format!(
        "{s:?} {:?}",
        RecoveryContactAction::Verify {
            token: token.clone()
        }
    );
    assert!(!debug.contains(FIRST) && !debug.contains(&token) && !debug.contains(ACCOUNT));
    let bytes = f.store.file.lock(ACCOUNT).unwrap().read().unwrap().unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains(&token));
    assert!(digest(ACCOUNT, &token) != digest(OTHER, &token));
    assert_eq!(
        f.change(ACCOUNT, 1, u64::MAX, RecoveryContactAction::Remove),
        Err(RecoveryContactError::Invalid)
    );
}

#[test]
fn proof_expiring_during_authorization_never_activates() {
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    let result = f.store.mutate(
        RecoveryContactMutation {
            account: ACCOUNT,
            expected_revision: 1,
            now: 1899,
            deadline: Instant::now() + Duration::from_secs(3),
            action: RecoveryContactAction::Verify { token: f.token() },
        },
        || {
            std::thread::sleep(Duration::from_millis(1050));
            Ok(())
        },
        &f.mail,
    );
    assert_eq!(result, Err(RecoveryContactError::Expired));
    let s = f.store.snapshot(ACCOUNT, 1901).unwrap();
    assert!(s.verified.is_none());
    assert_eq!(s.revision, 1);
}

#[test]
fn notifier_returning_accepted_after_original_deadline_is_unconfirmed() {
    struct Late;
    impl RecoveryContactNotifier for Late {
        fn deliver(
            &self,
            _: RecoveryContactMessage<'_>,
            deadline: Instant,
        ) -> RecoveryContactDelivery {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            RecoveryContactDelivery::Accepted
        }
    }
    let f = Fixture::new();
    let result = f
        .store
        .mutate(
            RecoveryContactMutation {
                account: ACCOUNT,
                expected_revision: 0,
                now: 100,
                deadline: Instant::now() + Duration::from_millis(100),
                action: RecoveryContactAction::Begin {
                    email: FIRST.into(),
                },
            },
            || Ok(()),
            &Late,
        )
        .unwrap();
    assert_eq!(result.delivery, Some(RecoveryContactDelivery::Unconfirmed));
    assert_eq!(
        f.change(ACCOUNT, 1, 160, RecoveryContactAction::Resend),
        Err(RecoveryContactError::DeliveryUnconfirmed)
    );
}

#[cfg(unix)]
#[test]
fn registered_consistency_consumes_real_verified_records_without_creating_locks_or_files() {
    use std::os::unix::fs::MetadataExt;
    fn remove_fixture_lock(root: &std::path::Path) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "lock") {
                fs::remove_file(path).unwrap();
            }
        }
    }
    fn observed(
        root: &std::path::Path,
    ) -> std::collections::BTreeMap<PathBuf, (Vec<u8>, u64, u64, u32)> {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                (
                    path.clone(),
                    (
                        fs::read(&path).unwrap(),
                        metadata.dev(),
                        metadata.ino(),
                        metadata.mode(),
                    ),
                )
            })
            .collect()
    }
    let f = Fixture::new();
    let uid = crate::openbsd::effective_uid();
    let gid = crate::openbsd::effective_gid();
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 100, FIRST, uid, gid),
        Ok(false)
    );
    assert!(
        !f._scratch.0.exists(),
        "read-only missing observation must not create a store"
    );
    f.begin(ACCOUNT, 0, 100, FIRST);
    f.verify(1, 101);
    remove_fixture_lock(&f._scratch.0);
    let before = observed(&f._scratch.0);
    assert!(!before.is_empty());
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 102, FIRST, uid, gid),
        Ok(true)
    );
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 102, SECOND, uid, gid),
        Ok(false)
    );
    assert_eq!(
        f.store.registered_consistency(OTHER, 102, FIRST, uid, gid),
        Ok(false)
    );
    assert_eq!(
        observed(&f._scratch.0),
        before,
        "veto must not publish or lock even a missing account"
    );
    f.change(ACCOUNT, 2, 103, RecoveryContactAction::Remove)
        .unwrap();
    remove_fixture_lock(&f._scratch.0);
    let removed = observed(&f._scratch.0);
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 104, FIRST, uid, gid),
        Ok(false)
    );
    assert_eq!(observed(&f._scratch.0), removed);
}

#[cfg(unix)]
#[test]
fn registered_consistency_refuses_wrong_group_permissive_directory_and_symlink_record() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.begin(ACCOUNT, 0, 100, FIRST);
    f.verify(1, 101);
    let uid = crate::openbsd::effective_uid();
    let gid = crate::openbsd::effective_gid();
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 102, FIRST, uid, gid.wrapping_add(1)),
        Err(RecoveryContactError::Unavailable)
    );
    fs::set_permissions(&f._scratch.0, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 102, FIRST, uid, gid),
        Err(RecoveryContactError::Unavailable)
    );
    fs::set_permissions(&f._scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let path = fs::read_dir(&f._scratch.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    let retained = path.with_extension("retained");
    fs::rename(&path, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &path).unwrap();
    assert_eq!(
        f.store
            .registered_consistency(ACCOUNT, 102, FIRST, uid, gid),
        Err(RecoveryContactError::Unavailable)
    );
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    assert!(retained.is_file());
}
