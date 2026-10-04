use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicU64;

const KEY: [u8; 32] = [17; 32];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "osmap-password-sessions-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Clock(AtomicU64);
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn receipt(outcome: Outcome) -> TerminalReceipt {
    let request =
        crate::account_mutation::tests::issue("public-old-value", "public-new-passphrase", 3, 100)
            .unwrap();
    let bytes = request.response(outcome, &KEY, 110).unwrap();
    crate::account_mutation::Verifier::default()
        .terminal_response(request, &bytes, &KEY, 110)
        .unwrap()
}
fn changed() -> TerminalReceipt {
    receipt(Outcome::Changed {
        epoch: 4,
        changed_at: "19700101000150".into(),
    })
}
fn service(p: &Path) -> SessionService<FileSessionStore, Clock, SystemRandomSource> {
    SessionService::new(
        FileSessionStore::new(p),
        Clock(AtomicU64::new(110)),
        SystemRandomSource,
        3600,
        1800,
    )
}
fn record(ch: char, account: &str, epoch: Option<u64>) -> SessionRecord {
    SessionRecord {
        session_id: ch.to_string().repeat(64),
        csrf_token: "f".repeat(64),
        canonical_username: account.into(),
        account_epoch: epoch,
        issued_at: 1,
        expires_at: 1000,
        last_seen_at: 100,
        revoked_at: None,
        remote_addr: "127.0.0.1".into(),
        user_agent: "Public/Test".into(),
        factor: RequiredSecondFactor::Totp,
    }
}
fn populate(p: &Path) {
    let store = FileSessionStore::new(p);
    for r in [
        record('a', "alice@example.test", Some(3)),
        record('b', "alice@example.test", Some(2)),
        record('c', "alice@example.test", None),
        record('d', "alice@example.test", Some(4)),
        record('e', "bob@example.test", Some(3)),
    ] {
        store.save(&r).unwrap();
    }
}
fn snapshot(p: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|s| s == "session"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(p).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}
#[test]
fn cleanup_revokes_current_all_old_and_legacy_preserving_new_epoch_and_bob() {
    let p = Scratch::new();
    populate(&p.0);
    let s = service(&p.0);
    let new_path = s.session_store.session_path(&"d".repeat(64));
    let bob_path = s.session_store.session_path(&"e".repeat(64));
    let new_before = fs::read(&new_path).unwrap();
    let bob_before = fs::read(&bob_path).unwrap();
    assert_eq!(
        s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
        BrowserRevocation::OldSessionsRevoked { count: 3 }
    );
    for ch in ['a', 'b', 'c'] {
        assert_eq!(
            s.session_store
                .load(&ch.to_string().repeat(64))
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(110)
        );
    }
    assert_eq!(fs::read(new_path).unwrap(), new_before);
    assert_eq!(fs::read(bob_path).unwrap(), bob_before);
}
#[test]
fn cleanup_nonblocking_lock_contention_contains_without_writes_or_deadlock() {
    let p = Scratch::new();
    populate(&p.0);
    let s = service(&p.0);
    let before = snapshot(&p.0);
    let held = s.session_store.guarded_lock().unwrap();
    let began = Instant::now();
    assert_eq!(
        s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
        BrowserRevocation::Contained { count: 0 }
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(snapshot(&p.0), before);
    drop(held);
    assert!(matches!(
        s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
        BrowserRevocation::OldSessionsRevoked { count: 3 }
    ));
}
#[test]
fn cleanup_expired_deadline_wall_expiry_and_rollback_remain_contained() {
    for now in [109, 400] {
        let p = Scratch::new();
        populate(&p.0);
        let s = service(&p.0);
        s.time_provider.0.store(now, Ordering::SeqCst);
        let before = snapshot(&p.0);
        assert_eq!(
            s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
            BrowserRevocation::Contained { count: 0 }
        );
        assert_eq!(snapshot(&p.0), before);
    }
    let p = Scratch::new();
    populate(&p.0);
    let s = service(&p.0);
    let before = snapshot(&p.0);
    for deadline in [
        Instant::now() - Duration::from_secs(1),
        Instant::now() + Duration::from_secs(61),
    ] {
        assert_eq!(
            s.revoke_password_change_sessions(changed(), deadline),
            BrowserRevocation::Contained { count: 0 }
        );
        assert_eq!(snapshot(&p.0), before);
    }
}
#[test]
fn cleanup_known_refused_changes_nothing_and_contained_never_becomes_success() {
    let p = Scratch::new();
    populate(&p.0);
    let s = service(&p.0);
    let before = snapshot(&p.0);
    assert_eq!(
        s.revoke_password_change_sessions(receipt(Outcome::KnownRefused), Instant::now()),
        BrowserRevocation::KnownRefused
    );
    assert_eq!(snapshot(&p.0), before);
    assert_eq!(
        s.revoke_password_change_sessions(
            receipt(Outcome::Contained),
            Instant::now() + Duration::from_secs(5)
        ),
        BrowserRevocation::Contained { count: 3 }
    );
}
#[test]
fn cleanup_malformed_duplicate_or_symlink_snapshot_refuses_before_first_write() {
    for variant in 0..3 {
        let p = Scratch::new();
        populate(&p.0);
        let s = service(&p.0);
        let path = s.session_store.session_path(&"e".repeat(64));
        match variant {
            0 => {
                let mut text = fs::read_to_string(&path).unwrap();
                text.push_str("canonical_username=alice@example.test\n");
                fs::write(&path, text).unwrap();
            }
            1 => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(s.session_store.session_path(&"a".repeat(64)), &path)
                    .unwrap();
            }
            _ => {
                fs::write(&path, "invalid").unwrap();
            }
        }
        let before = snapshot(&p.0);
        assert_eq!(
            s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
            BrowserRevocation::Contained { count: 0 }
        );
        assert_eq!(snapshot(&p.0), before);
    }
}
struct ExpireAfterWrite(PathBuf);
impl TimeProvider for ExpireAfterWrite {
    fn unix_timestamp(&self) -> u64 {
        if snapshot(&self.0)
            .iter()
            .any(|(_, b)| std::str::from_utf8(b).unwrap().contains("revoked_at=110"))
        {
            400
        } else {
            110
        }
    }
}
#[test]
fn cleanup_partial_revocation_expiry_remains_contained_without_retry() {
    let p = Scratch::new();
    populate(&p.0);
    let s = SessionService::new(
        FileSessionStore::new(&p.0),
        ExpireAfterWrite(p.0.clone()),
        SystemRandomSource,
        3600,
        1800,
    );
    assert_eq!(
        s.revoke_password_change_sessions(changed(), Instant::now() + Duration::from_secs(5)),
        BrowserRevocation::Contained { count: 1 }
    );
}
#[test]
fn compatibility_all_user_revocation_would_revoke_new_epoch_and_cannot_be_used() {
    let p = Scratch::new();
    populate(&p.0);
    let s = service(&p.0);
    let context = AuthenticationContext::new(
        crate::auth::AuthenticationPolicy::default(),
        "public-mutation-request",
        "127.0.0.1",
        "Public/Test",
    )
    .unwrap();
    s.revoke_all_for_user(&context, "alice@example.test")
        .unwrap();
    assert_eq!(
        s.session_store
            .load(&"d".repeat(64))
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(110)
    );
}
