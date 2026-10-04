use super::*;
use std::fs;
use std::sync::atomic::Ordering;
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0; 12];
        getrandom::getrandom(&mut random).unwrap();
        let p = std::env::temp_dir().join(format!(
            "osmap-rate-{}",
            random
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        ));
        fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn exact_account_threshold_across_sources_success_restart_and_cooldown() {
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    for i in 0..4 {
        let ip = format!("127.0.0.{}", i + 1);
        assert!(!store
            .admit("alice@example.test", &ip, 100 + i)
            .unwrap()
            .failed(100 + i)
            .unwrap());
    }
    store
        .admit("alice@example.test", "127.0.0.5", 104)
        .unwrap()
        .confirm()
        .unwrap(); // success never resets failures
    let reload = Store::new(t.0.join("rate"));
    assert!(reload
        .admit("alice@example.test", "127.0.0.6", 105)
        .unwrap()
        .failed(105)
        .unwrap());
    assert!(matches!(
        reload.admit("alice@example.test", "127.0.0.7", 1004),
        Err(Error::Throttled)
    ));
    assert!(reload
        .admit("alice@example.test", "127.0.0.7", 1005)
        .is_ok());
}
#[test]
fn exact_source_threshold_across_accounts_and_equivalent_ipv6_representation() {
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    for i in 0..10 {
        let account = format!("person{i}@example.test");
        let source = if i % 2 == 0 { "::1" } else { "0:0:0:0:0:0:0:1" };
        assert_eq!(
            store
                .admit(&account, source, 100)
                .unwrap()
                .failed(100)
                .unwrap(),
            i == 9
        );
    }
    assert!(matches!(
        store.admit("different@example.test", "::1", 101),
        Err(Error::Throttled)
    ));
    assert!(store.admit("different@example.test", "::2", 101).is_ok());
}
#[test]
fn rate_clock_rollback_corrupt_and_unsafe_source_refuse_without_reset() {
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    store
        .admit("alice@example.test", "127.0.0.1", 100)
        .unwrap()
        .failed(100)
        .unwrap();
    assert!(matches!(
        store.admit("alice@example.test", "127.0.0.2", 99),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store.admit("alice@example.test", "untrusted-source", 101),
        Err(Error::Invalid)
    ));
    let account = store.files.lock("account:alice@example.test").unwrap();
    account.write(b"{broken").unwrap();
    drop(account);
    assert!(matches!(
        store.admit("alice@example.test", "127.0.0.1", 101),
        Err(Error::Unavailable)
    ));
    let bytes: Vec<_> = fs::read_dir(t.0.join("rate"))
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                Some((p.clone(), fs::read(p).unwrap()))
            } else {
                None
            }
        })
        .collect();
    assert!(matches!(
        store.admit("alice@example.test", "127.0.0.1", 102),
        Err(Error::Unavailable)
    ));
    for (p, b) in bytes {
        assert_eq!(fs::read(p).unwrap(), b);
    }
}
#[test]
fn partial_dual_publication_contains_all_admission_and_disjoint_request_cannot_clear() {
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    let a = store.admit("alice@example.test", "127.0.0.1", 100).unwrap();
    let b = store.admit("bob@example.test", "127.0.0.2", 100).unwrap();
    store.fail_source_publication.store(true, Ordering::SeqCst);
    assert_eq!(a.failed(100), Err(Error::Unavailable));
    store.fail_source_publication.store(false, Ordering::SeqCst);
    assert_eq!(b.failed(100), Err(Error::Unavailable));
    let restarted = Store::new(t.0.join("rate"));
    assert!(matches!(
        restarted.admit("other@example.test", "127.0.0.3", 101),
        Err(Error::Unavailable)
    ));
    assert_eq!(restarted.healthy(), Err(Error::Unavailable));
}
#[test]
fn concurrent_account_or_source_is_immediate_refusal_not_extra_credential_admission() {
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    let first = store.admit("alice@example.test", "127.0.0.1", 100).unwrap();
    assert!(matches!(
        store.admit("alice@example.test", "127.0.0.2", 100),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store.admit("bob@example.test", "127.0.0.1", 100),
        Err(Error::Unavailable)
    ));
    drop(first);
    assert!(store.admit("alice@example.test", "127.0.0.2", 100).is_ok());
}
#[cfg(unix)]
#[test]
fn private_rate_files_modes_symlink_and_corrupt_safety_preserve_refusal() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let t = Scratch::new();
    let store = Store::new(t.0.join("rate"));
    store
        .admit("alice@example.test", "127.0.0.1", 100)
        .unwrap()
        .failed(100)
        .unwrap();
    assert_eq!(
        fs::metadata(t.0.join("rate")).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for e in fs::read_dir(t.0.join("rate")).unwrap() {
        assert_eq!(
            e.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let safe = store.files.lock("publication-safety").unwrap();
    safe.write(b"{broken").unwrap();
    drop(safe);
    assert!(matches!(
        store.admit("alice@example.test", "127.0.0.1", 100),
        Err(Error::Unavailable)
    ));
    let sentinel = t.0.join("sentinel");
    fs::write(&sentinel, b"owned sentinel").unwrap();
    let link = t.0.join("unsafe");
    symlink(&sentinel, &link).unwrap();
    assert!(matches!(
        Store::new(link).admit("alice@example.test", "127.0.0.1", 100),
        Err(Error::Unavailable)
    ));
    assert_eq!(fs::read(sentinel).unwrap(), b"owned sentinel");
}
#[cfg(unix)]
#[test]
fn oversized_and_hardlinked_records_refuse_and_preserve_exact_existing_bytes() {
    use std::os::unix::fs::PermissionsExt;
    for hardlink in [false, true] {
        let t = Scratch::new();
        let store = Store::new(t.0.join("rate"));
        store
            .admit("alice@example.test", "127.0.0.1", 100)
            .unwrap()
            .failed(100)
            .unwrap();
        let mut key = Sha256::new();
        key.update(b"osmap-password-stepup-rate-v1\0account:alice@example.test");
        let name = format!("{:x}.json", key.finalize());
        let path = t.0.join("rate").join(name);
        if hardlink {
            fs::hard_link(&path, t.0.join("duplicate")).unwrap();
        } else {
            fs::write(&path, vec![b'x'; 2048]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            store.admit("alice@example.test", "127.0.0.1", 101),
            Err(Error::Unavailable)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
