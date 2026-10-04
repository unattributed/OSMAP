use super::*;
use crate::session::{
    FileSessionStore, SessionService, SessionStore, SessionToken, SystemRandomSource,
};
impl TimeProvider for &Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Fixture {
    scratch: Scratch,
    gateway: RuntimeBrowserGateway,
    rate: crate::password_change_rate::Store,
    epoch: Arc<Epoch>,
    clock: Clock,
    context: AuthenticationContext,
    session: ValidatedSession,
    token: SessionToken,
}
impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::new();
        let gateway = RuntimeBrowserGateway::for_test(&scratch.0);
        let session_dir = scratch.0.join("sessions");
        std::fs::create_dir(&session_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = Clock(AtomicU64::new(100));
        let epoch = Arc::new(Epoch::new());
        let context = context();
        let service = SessionService::new(
            FileSessionStore::new(&session_dir),
            &clock,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(epoch.clone());
        let issued = service
            .issue_with_epoch(
                &context,
                "alice@example.test",
                RequiredSecondFactor::Totp,
                Some(3),
            )
            .unwrap();
        let session = ValidatedSession {
            record: issued.record,
            audit_event: issued.audit_event,
        };
        let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
        Self {
            scratch,
            gateway,
            rate,
            epoch,
            clock,
            context,
            session,
            token: issued.token,
        }
    }
    fn store(&self) -> FileSessionStore {
        FileSessionStore::new(self.scratch.0.join("sessions"))
    }
    fn prepared(&self) -> password_change::Prepared<'_> {
        let primary = Primary::new(&self.epoch);
        let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
        prepare(
            &primary,
            &factor,
            &self.epoch,
            &self.rate,
            &self.clock,
            (&self.context, &self.session, request()),
        )
        .authorization
        .unwrap()
    }
}
#[test]
fn stored_revocation_after_preparation_refuses_original_snapshot_consumption() {
    let f = Fixture::new();
    let prepared = f.prepared();
    let mut revoked = f
        .store()
        .load(&f.session.record.session_id)
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(100);
    f.store().save(&revoked).unwrap();
    let calls = AtomicUsize::new(0);
    let result = f.gateway.password_dispatch_for_test(
        &f.context,
        &f.token,
        prepared,
        (f.epoch.clone(), &f.clock),
        |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result, Err(Error::Authentication));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn actual_current_store_positive_dispatch_holds_lock_and_preserves_session_bytes() {
    let f = Fixture::new();
    let path = f.store().session_path(&f.session.record.session_id);
    let bytes = std::fs::read(&path).unwrap();
    let calls = AtomicUsize::new(0);
    f.gateway
        .password_dispatch_for_test(
            &f.context,
            &f.token,
            f.prepared(),
            (f.epoch.clone(), &f.clock),
            |action| {
                assert_eq!(action.session_id(), f.session.record.session_id);
                assert_eq!(action.account(), "alice@example.test");
                let concurrent =
                    SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800)
                        .with_epoch_authority(f.epoch.clone());
                assert!(matches!(
                    concurrent.with_guarded_validated_session(&f.context, &f.token, |_| {
                        panic!("contending callback must not run")
                    }),
                    Err(crate::session::GuardedSessionError::Unavailable)
                ));
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
fn changed_or_missing_current_store_record_and_epoch_refuse_zero_dispatch() {
    for field in 0..6 {
        let f = Fixture::new();
        let prepared = f.prepared();
        let mut r = f
            .store()
            .load(&f.session.record.session_id)
            .unwrap()
            .unwrap();
        match field {
            0 => r.expires_at = 100,
            1 => r.account_epoch = Some(4),
            2 => r.canonical_username = "bob@example.test".into(),
            3 => r.account_epoch = None,
            4 => {
                std::fs::remove_file(f.store().session_path(&r.session_id)).unwrap();
            }
            _ => {
                f.epoch.value.store(4, Ordering::SeqCst);
            }
        }
        if field < 4 {
            f.store().save(&r).unwrap();
        }
        let calls = AtomicUsize::new(0);
        assert!(f
            .gateway
            .password_dispatch_for_test(
                &f.context,
                &f.token,
                prepared,
                (f.epoch.clone(), &f.clock),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            )
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn disabled_runtime_refuses_without_store_creation_or_callback() {
    let f = Fixture::new();
    let prepared = f.prepared();
    let root = f.scratch.0.join("new-runtime");
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let calls = AtomicUsize::new(0);
    assert_eq!(
        gateway.with_password_change_dispatch(&f.context, &f.token, prepared, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        Err(Error::Unavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!root.exists());
}

#[test]
fn private_record_corruption_oversize_links_and_permissions_refuse_zero_callback() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for scenario in 0..7 {
        let f = Fixture::new();
        let prepared = f.prepared();
        let path = f.store().session_path(&f.session.record.session_id);
        let content = std::fs::read(&path).unwrap();
        match scenario {
            0 => {
                std::fs::write(&path, [content.as_slice(), b"account_epoch=3\n"].concat()).unwrap()
            }
            1 => std::fs::write(&path, vec![b'x'; 8192]).unwrap(),
            2 => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
            3 => std::fs::hard_link(&path, f.scratch.0.join("duplicate")).unwrap(),
            4 => {
                let target = f.scratch.0.join("target");
                std::fs::write(&target, &content).unwrap();
                std::fs::remove_file(&path).unwrap();
                symlink(target, &path).unwrap();
            }
            5 => std::fs::write(
                &path,
                String::from_utf8(content)
                    .unwrap()
                    .replace("factor=totp", "factor=invalid"),
            )
            .unwrap(),
            _ => std::fs::set_permissions(
                f.store().lock_path(),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
        }
        let before = std::fs::read(&path).unwrap();
        let calls = AtomicUsize::new(0);
        assert_eq!(
            f.gateway.password_dispatch_for_test(
                &f.context,
                &f.token,
                prepared,
                (f.epoch.clone(), &f.clock),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            ),
            Err(Error::Unavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}
struct SharedClock(Arc<AtomicU64>);
impl TimeProvider for SharedClock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct DelayedAuthority {
    epoch: Arc<Epoch>,
    clock: Arc<AtomicU64>,
    calls: AtomicUsize,
    on: usize,
    at: u64,
}
impl EpochAuthority for DelayedAuthority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        self.epoch.admit(account, epoch)?;
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.on {
            self.clock.store(self.at, Ordering::SeqCst);
        }
        Ok(())
    }
}
#[test]
fn absolute_expiry_during_guard_epoch_callback_refuses_before_dispatch() {
    let f = Fixture::new();
    let prepared = f.prepared();
    let mut stored = f
        .store()
        .load(&f.session.record.session_id)
        .unwrap()
        .unwrap();
    stored.expires_at = 150;
    f.store().save(&stored).unwrap();
    let time = Arc::new(AtomicU64::new(100));
    let clock = SharedClock(time.clone());
    let authority = Arc::new(DelayedAuthority {
        epoch: f.epoch.clone(),
        clock: time,
        calls: AtomicUsize::new(0),
        on: 0,
        at: 150,
    });
    let calls = AtomicUsize::new(0);
    assert_eq!(
        f.gateway.password_dispatch_for_test(
            &f.context,
            &f.token,
            prepared,
            (authority, &clock),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        ),
        Err(Error::Authentication)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn idle_expiry_during_last_permit_epoch_callback_refuses_before_dispatch() {
    let f = Fixture::new();
    f.clock.0.store(1800, Ordering::SeqCst);
    let prepared = f.prepared();
    let time = Arc::new(AtomicU64::new(1899));
    let clock = SharedClock(time.clone());
    let authority = Arc::new(DelayedAuthority {
        epoch: f.epoch.clone(),
        clock: time,
        calls: AtomicUsize::new(0),
        on: 1,
        at: 1900,
    });
    let calls = AtomicUsize::new(0);
    assert_eq!(
        f.gateway.password_dispatch_for_test(
            &f.context,
            &f.token,
            prepared,
            (authority, &clock),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        ),
        Err(Error::Authentication)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn consumed_callback_error_releases_lock_without_persisting_or_reissuing_permit() {
    let f = Fixture::new();
    let path = f.store().session_path(&f.session.record.session_id);
    let before = std::fs::read(&path).unwrap();
    let calls = AtomicUsize::new(0);
    assert_eq!(
        f.gateway.password_dispatch_for_test(
            &f.context,
            &f.token,
            f.prepared(),
            (f.epoch.clone(), &f.clock),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), Error>(Error::Unavailable)
            }
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(path).unwrap(), before);
    let service = SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800)
        .with_epoch_authority(f.epoch.clone());
    assert!(service
        .with_guarded_validated_session(&f.context, &f.token, |_| ())
        .is_ok());
}

#[test]
fn authenticated_receipt_returns_after_guard_drop_and_revokes_only_old_sessions() {
    use crate::account_mutation::{
        Outcome as MutationOutcome, Request as MutationRequest, Verifier,
    };
    use crate::session::BrowserRevocation;
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let key = [17_u8; 32];
    let receipt = f
        .gateway
        .password_dispatch_for_test(
            &f.context,
            &f.token,
            f.prepared(),
            (f.epoch.clone(), &f.clock),
            |dispatch| {
                let request = MutationRequest::issue(dispatch, &key, 100).unwrap();
                let bytes = request
                    .response(
                        MutationOutcome::Changed {
                            epoch: 4,
                            changed_at: "19700101000140".into(),
                        },
                        &key,
                        100,
                    )
                    .unwrap();
                // Actual callback holds the session lock; parent cleanup cannot run here.
                let concurrent =
                    SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800);
                assert!(matches!(
                    concurrent.with_guarded_validated_session(&f.context, &f.token, |_| ()),
                    Err(crate::session::GuardedSessionError::Unavailable)
                ));
                f.epoch.value.store(4, Ordering::SeqCst);
                Ok(Verifier::default()
                    .terminal_response(request, &bytes, &key, 100)
                    .unwrap())
            },
        )
        .unwrap();
    // This is a codec/lock integration control, not SQL password mutation proof.
    let service = SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800)
        .with_epoch_authority(f.epoch.clone());
    // A concurrent login authenticated at the new epoch enters after lock release.
    let new_login = service
        .issue_with_epoch(
            &f.context,
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(4),
        )
        .unwrap();
    let new_path = f.store().session_path(&new_login.record.session_id);
    let new_bytes = std::fs::read(&new_path).unwrap();
    assert_eq!(
        service.revoke_password_change_sessions(receipt, deadline),
        BrowserRevocation::OldSessionsRevoked { count: 1 }
    );
    assert_eq!(
        f.store()
            .load(&f.session.record.session_id)
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(100)
    );
    assert_eq!(std::fs::read(new_path).unwrap(), new_bytes);
    assert!(service.validate(&f.context, &f.token).is_err());
    assert!(service.validate(&f.context, &new_login.token).is_ok());
}
