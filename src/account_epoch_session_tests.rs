use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
struct Authority(Mutex<Option<u64>>);
impl crate::account_admission::EpochAuthority for Authority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == "alice@example.test" && *self.0.lock().unwrap() == Some(epoch) {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
struct Clock;
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        100
    }
}
fn context() -> AuthenticationContext {
    AuthenticationContext {
        request_id: "synthetic".into(),
        remote_addr: "127.0.0.1".into(),
        user_agent: "synthetic".into(),
    }
}
fn root(label: &str) -> PathBuf {
    let p = PathBuf::from("/tmp").join(format!(
        "osmap-session-epoch-{label}-{}-{}",
        std::process::id(),
        SESSION_TMP_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
#[test]
fn authenticated_epoch_capture_cannot_be_replaced_after_credential_change() {
    let p = root("issue");
    let authority = Arc::new(Authority(Mutex::new(Some(2))));
    let service = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(authority.clone());
    assert!(service
        .issue(&context(), "alice@example.test", RequiredSecondFactor::Totp)
        .is_err());
    // Simulates credential mutation between primary authentication and TOTP.
    *authority.0.lock().unwrap() = Some(3);
    assert!(service
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(2)
        )
        .is_err());
    assert!(fs::read_dir(&p).unwrap().all(|e| e
        .unwrap()
        .path()
        .extension()
        .is_none_or(|v| v != "session")));
    *authority.0.lock().unwrap() = None;
    assert!(service
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(3)
        )
        .is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn persisted_bound_session_rechecks_epoch_without_mutating_refused_record() {
    let p = root("validate");
    let authority = Arc::new(Authority(Mutex::new(Some(2))));
    let service = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(authority.clone());
    let issued = service
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(2),
        )
        .unwrap();
    assert_eq!(issued.record.account_epoch, Some(2));
    let path = FileSessionStore::new(&p).session_path(&issued.record.session_id);
    let before = fs::read(&path).unwrap();
    let restarted = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(authority.clone());
    assert!(restarted.validate(&context(), &issued.token).is_ok());
    for state in [Some(3), None] {
        *authority.0.lock().unwrap() = state;
        assert!(restarted.validate(&context(), &issued.token).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let removed = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    );
    assert!(removed.validate(&context(), &issued.token).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn legacy_session_accepted_only_without_enabled_admission_no_downgrade() {
    let p = root("legacy");
    let legacy = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    );
    let issued = legacy
        .issue(&context(), "alice@example.test", RequiredSecondFactor::Totp)
        .unwrap();
    assert_eq!(issued.record.account_epoch, None);
    assert!(legacy.validate(&context(), &issued.token).is_ok());
    let enabled = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(Arc::new(Authority(Mutex::new(Some(0)))));
    assert!(enabled.validate(&context(), &issued.token).is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn persisted_epoch_roundtrip_rejects_duplicate_malformed_or_maximum() {
    let p = root("parse");
    let a = Arc::new(Authority(Mutex::new(Some(7))));
    let s = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(a);
    let issued = s
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(7),
        )
        .unwrap();
    let text = serialize_session_record(&issued.record);
    assert_eq!(parse_session_record(&text).unwrap().unwrap(), issued.record);
    for suffix in [
        "account_epoch=7\n",
        "account_epoch=invalid\n",
        "account_epoch=18446744073709551615\n",
    ] {
        assert!(parse_session_record(&(text.clone() + suffix)).is_err());
    }
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn session_epoch_bounds_refuse_before_save_and_allow_last_readable_epoch() {
    let p = root("upper-bound");
    struct CountedAuthority {
        epoch: Mutex<u64>,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl crate::account_admission::EpochAuthority for CountedAuthority {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if account == "alice@example.test" && *self.epoch.lock().unwrap() == epoch {
                Ok(())
            } else {
                Err(crate::account_admission::Error::Refused)
            }
        }
    }
    let authority = Arc::new(CountedAuthority {
        epoch: Mutex::new(u64::MAX),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let service = SessionService::new(
        FileSessionStore::new(&p),
        Clock,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(authority.clone());
    assert!(service
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(u64::MAX)
        )
        .is_err());
    assert!(fs::read_dir(&p).unwrap().all(|e| e
        .unwrap()
        .path()
        .extension()
        .is_none_or(|v| v != "session")));
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    *authority.epoch.lock().unwrap() = u64::MAX - 1;
    let issued = service
        .issue_with_epoch(
            &context(),
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(u64::MAX - 1),
        )
        .unwrap();
    assert_eq!(issued.record.account_epoch, Some(u64::MAX - 1));
    assert!(service.validate(&context(), &issued.token).is_ok());
    assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
    fs::remove_dir_all(p).unwrap();
}
