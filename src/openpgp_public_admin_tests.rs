use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    account: CanonicalUsername,
    store: PublicAdminStore,
}
impl Fixture {
    fn new() -> Self {
        // Shared gate TMPDIR can have writable ancestry. Match the production
        // private-path checks using an owned child of sticky-root /tmp.
        let root = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-public-admin-test-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let home = root.join("account");
        let state = root.join("state");
        for path in [&home, &state] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        write_new(&home.join("pubring.kbx"), b"synthetic public fixture").unwrap();
        write_new(&home.join("trustdb.gpg"), b"synthetic trust fixture").unwrap();
        let worker = root.join("worker");
        fs::write(&worker, b"#!/bin/sh\nprintf '%s\\n' '{\"version\":1,\"ok\":true,\"protocol\":\"openpgp\",\"gpgme_version\":\"2.0.1\",\"engine_version\":\"2.5.18\",\"keys\":[]}'\n").unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
        let engine = root.join("engine");
        fs::write(&engine, b"#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let account = CanonicalUsername::parse("alice@example.test").unwrap();
        let store = PublicAdminStore::from_operator_mappings(
            state,
            worker,
            engine,
            vec![AccountHome {
                account: account.clone(),
                home: home.clone(),
            }],
        )
        .unwrap();
        Self {
            root,
            home,
            account,
            store,
        }
    }
    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn snapshots_are_actual_keybox_revisions_and_foreign_accounts_refuse() {
    let fixture = Fixture::new();
    let result = fixture
        .store
        .snapshot(&fixture.account, fixture.deadline())
        .unwrap();
    assert_eq!(result.revision, digest(b"synthetic public fixture"));
    assert_eq!(result.inventory.keys().unwrap().len(), 0);
    assert!(matches!(
        fixture.store.snapshot(
            &CanonicalUsername::parse("bob@example.test").unwrap(),
            fixture.deadline()
        ),
        Err(AdminError::Invalid)
    ));
}
#[test]
fn account_lock_serializes_snapshot_and_mutation() {
    let fixture = Fixture::new();
    let held = fixture.store.locks.lock(fixture.account.as_str()).unwrap();
    assert!(matches!(
        fixture.store.snapshot(&fixture.account, fixture.deadline()),
        Err(AdminError::Busy)
    ));
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &digest(b"synthetic public fixture"),
            &"A".repeat(40),
            b"synthetic",
            fixture.deadline()
        ),
        Err(AdminError::Busy)
    ));
    drop(held);
    // A concurrent fork can briefly inherit the CLOEXEC lock descriptor before
    // exec closes it. Assert bounded release rather than an instantaneous race.
    let deadline = fixture.deadline();
    let resumed = loop {
        let result = fixture.store.snapshot(&fixture.account, deadline);
        if !matches!(result, Err(AdminError::Busy)) || Instant::now() >= deadline {
            break result;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(resumed.is_ok(), "lock release result: {resumed:?}");
}
#[test]
fn stale_invalid_and_expired_requests_never_change_actual_files() {
    let fixture = Fixture::new();
    let fp = "A".repeat(40);
    let revision = digest(b"synthetic public fixture");
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &"0".repeat(64),
            &fp,
            b"synthetic",
            fixture.deadline()
        ),
        Err(AdminError::Stale)
    ));
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &revision,
            &"A".repeat(64),
            b"synthetic",
            fixture.deadline()
        ),
        Err(AdminError::Invalid)
    ));
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &revision,
            &fp,
            &vec![0; 65537],
            fixture.deadline()
        ),
        Err(AdminError::Invalid)
    ));
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &revision,
            &fp,
            b"synthetic",
            Instant::now()
        ),
        Err(AdminError::Expired)
    ));
    assert_eq!(
        fs::read(fixture.home.join("pubring.kbx")).unwrap(),
        b"synthetic public fixture"
    );
    assert_eq!(
        fs::read(fixture.home.join("trustdb.gpg")).unwrap(),
        b"synthetic trust fixture"
    );
}
#[test]
fn worker_delta_refusal_discards_staging_and_actual_state_is_preserved() {
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.store.import_public(
            &fixture.account,
            &digest(b"synthetic public fixture"),
            &"A".repeat(40),
            b"synthetic",
            fixture.deadline()
        ),
        Err(AdminError::Unavailable)
    ));
    assert_eq!(
        fs::read(fixture.home.join("pubring.kbx")).unwrap(),
        b"synthetic public fixture"
    );
    assert!(!fs::read_dir(&fixture.store.directory)
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("stage-")));
}
#[test]
fn replaced_symlink_keybox_is_refused_and_not_followed() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.home.join("pubring.kbx")).unwrap();
    std::os::unix::fs::symlink(
        fixture.home.join("trustdb.gpg"),
        fixture.home.join("pubring.kbx"),
    )
    .unwrap();
    assert!(matches!(
        fixture.store.snapshot(&fixture.account, fixture.deadline()),
        Err(AdminError::Invalid)
    ));
    assert_eq!(
        fs::read(fixture.home.join("trustdb.gpg")).unwrap(),
        b"synthetic trust fixture"
    );
}
#[test]
fn unconfirmed_durability_disables_future_admission() {
    let fixture = Fixture::new();
    fixture.store.unconfirmed.store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.store.snapshot(&fixture.account, fixture.deadline()),
        Err(AdminError::Unconfirmed)
    ));
}

#[test]
#[ignore = "actual native helper-store transaction with disposable public/private keys"]
fn native_crypto_public_admin_store_transaction() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let path = |name| PathBuf::from(std::env::var_os(name).expect("native fixture path"));
    let worker = path("OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER");
    let engine = path("OSMAP_CRYPTO_NATIVE_ENGINE");
    let alice = path("OSMAP_CRYPTO_NATIVE_ALICE_HOME");
    let bob = path("OSMAP_CRYPTO_NATIVE_BOB_HOME");
    let afp = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
    let bfp = std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap();
    let account = CanonicalUsername::parse("alice@example.test").unwrap();
    let root = worker.parent().unwrap();
    assert!(root.starts_with("/tmp") && alice.starts_with(root) && bob.starts_with(root));
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    let state = root.join("public-admin-state");
    fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
    let store = PublicAdminStore::from_operator_mappings(
        state.clone(),
        worker,
        engine,
        vec![AccountHome {
            account: account.clone(),
            home: alice.clone(),
        }],
    )
    .unwrap();
    let deadline = || Instant::now() + Duration::from_secs(10);
    let trustdb = fs::read(alice.join("trustdb.gpg")).unwrap();
    let private = fs::read_dir(alice.join("private-keys-v1.d"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), fs::read(path).unwrap())
        })
        .collect::<Vec<_>>();
    let original = store.snapshot(&account, deadline()).unwrap();
    assert!(matches!(
        store.remove_public(&account, &original.revision, &afp, deadline()),
        Err(AdminError::Unavailable)
    ));
    let removed = store
        .remove_public(&account, &original.revision, &bfp, deadline())
        .unwrap();
    assert_ne!(removed.revision, original.revision);
    assert!(!removed
        .inventory
        .keys()
        .unwrap()
        .iter()
        .any(|key| key.primary.fingerprint == bfp));
    let public = std::process::Command::new("/usr/local/bin/gpg")
        .args(["--no-options", "--homedir"])
        .arg(&bob)
        .args(["--batch", "--no-autostart", "--export", &bfp])
        .output()
        .unwrap();
    assert!(public.status.success() && public.stdout.len() <= 65536);
    assert!(matches!(
        store.import_public(
            &account,
            &original.revision,
            &bfp,
            &public.stdout,
            deadline()
        ),
        Err(AdminError::Stale)
    ));
    let imported = store
        .import_public(
            &account,
            &removed.revision,
            &bfp,
            &public.stdout,
            deadline(),
        )
        .unwrap();
    assert!(imported
        .inventory
        .keys()
        .unwrap()
        .iter()
        .any(|key| key.primary.fingerprint == bfp));
    assert_eq!(fs::read(alice.join("trustdb.gpg")).unwrap(), trustdb);
    for (path, bytes) in private {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let fresh = store.snapshot(&account, deadline()).unwrap();
    assert_eq!(fresh.revision, imported.revision);
    let secret = std::process::Command::new("/usr/local/bin/gpg")
        .args(["--no-options", "--homedir"])
        .arg(&bob)
        .args(["--batch", "--no-autostart", "--export-secret-keys", &bfp])
        .output()
        .unwrap();
    assert!(secret.status.success() && secret.stdout.len() <= 65536);
    assert!(matches!(
        store.import_public(&account, &fresh.revision, &bfp, &secret.stdout, deadline()),
        Err(AdminError::Unavailable)
    ));
    assert_eq!(
        store.snapshot(&account, deadline()).unwrap().revision,
        fresh.revision
    );
    assert!(!fs::read_dir(&state).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("stage-")));
    drop(store);
    fs::remove_dir_all(state).unwrap();
}
