use super::*;
use std::os::unix::fs::symlink;

const ALICE: &str = "alice@recovery.invalid";
const BOB: &str = "bob@recovery.invalid";
struct FixedClock(u64);
impl TimeProvider for FixedClock {
    fn unix_timestamp(&self) -> u64 {
        self.0
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-recovery-sessions-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn store(&self) -> FileSessionStore {
        FileSessionStore::new(&self.0)
    }
    fn populate(&self) {
        for record in [
            record('a', ALICE, Some(3), None),
            record('b', ALICE, None, None),
            record('c', ALICE, Some(2), Some(90)),
            record('d', BOB, Some(9), None),
        ] {
            self.store().save(&record).unwrap();
        }
    }
    fn owner(&self) -> (u32, u32) {
        let metadata = fs::metadata(&self.0).unwrap();
        (metadata.uid(), metadata.gid())
    }
    fn revoke(&self) -> Result<RecoveryRevocation, RecoveryRevocationFailure> {
        let (uid, gid) = self.owner();
        revoke_with_clock(&self.0, uid, gid, ALICE, 3, 100, until(), &FixedClock(100))
    }
    fn verify(&self) -> Result<RecoveryRevocation, RecoveryRevocationFailure> {
        let (uid, gid) = self.owner();
        verify_recovery_sessions(&self.0, uid, gid, ALICE, 3, 100, until())
    }
    fn bytes(&self, ch: char) -> Vec<u8> {
        fs::read(self.store().session_path(&ch.to_string().repeat(64))).unwrap()
    }
    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut records = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "session")
            })
            .map(|path| {
                (
                    path.file_name().unwrap().to_str().unwrap().into(),
                    fs::read(&path).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        records.sort();
        records
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn record(ch: char, account: &str, epoch: Option<u64>, revoked: Option<u64>) -> SessionRecord {
    SessionRecord {
        session_id: ch.to_string().repeat(64),
        csrf_token: "f".repeat(64),
        canonical_username: account.into(),
        account_epoch: epoch,
        issued_at: 1,
        expires_at: 1000,
        last_seen_at: 80,
        revoked_at: revoked,
        remote_addr: "127.0.0.1".into(),
        user_agent: "synthetic-recovery".into(),
        factor: RequiredSecondFactor::Totp,
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn revokes_legacy_and_bound_target_sessions_with_owned_readback_and_foreign_preservation() {
    let scratch = Scratch::new();
    scratch.populate();
    let foreign = scratch.bytes('d');
    let already_revoked = scratch.bytes('c');
    let expected_owner = scratch.owner();
    assert_eq!(
        scratch.verify().unwrap_err().stage,
        RecoveryRevocationStage::Readback
    );
    assert_eq!(
        scratch.revoke(),
        Ok(RecoveryRevocation {
            matched: 3,
            newly_revoked: 2,
            verified: 3
        })
    );
    assert_eq!(scratch.bytes('d'), foreign);
    assert_eq!(scratch.bytes('c'), already_revoked);
    for ch in ['a', 'b'] {
        let path = scratch.store().session_path(&ch.to_string().repeat(64));
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), expected_owner);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let parsed = parse_session_record(std::str::from_utf8(&fs::read(path).unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let expected = record(ch, ALICE, if ch == 'a' { Some(3) } else { None }, Some(100));
        assert_eq!(parsed, expected);
    }
    let bytes = scratch.snapshot();
    assert_eq!(
        scratch.verify(),
        Ok(RecoveryRevocation {
            matched: 3,
            newly_revoked: 0,
            verified: 3
        })
    );
    assert_eq!(scratch.snapshot(), bytes);
    assert_eq!(scratch.revoke().unwrap().newly_revoked, 0);
    assert_eq!(scratch.snapshot(), bytes);
}

#[test]
fn newer_target_epoch_is_a_contradiction_before_any_session_write() {
    let scratch = Scratch::new();
    scratch.populate();
    scratch
        .store()
        .save(&record('e', ALICE, Some(4), None))
        .unwrap();
    let before = scratch.snapshot();
    assert_eq!(
        scratch.revoke(),
        Err(RecoveryRevocationFailure {
            stage: RecoveryRevocationStage::Snapshot,
            attempted_writes: 0,
            completed_writes: 0
        })
    );
    assert_eq!(scratch.snapshot(), before);
}

#[test]
fn malformed_duplicate_missing_and_oversized_records_refuse_the_entire_snapshot_without_writes() {
    for bad in [
        b"not-a-session\n".to_vec(),
        [
            serialize_session_record(&record('e', BOB, None, None)).as_bytes(),
            b"factor=totp\n",
        ]
        .concat(),
        serialize_session_record(&record('e', BOB, None, None))
            .replace("revoked_at=\n", "")
            .into_bytes(),
        serialize_session_record(&record('e', BOB, None, None))
            .replace("issued_at=1", "issued_at=900")
            .into_bytes(),
        vec![b'x'; MAX_RECORD_BYTES + 1],
    ] {
        let scratch = Scratch::new();
        scratch.populate();
        let path = scratch.store().session_path(&"e".repeat(64));
        fs::write(&path, bad).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = scratch.snapshot();
        assert_eq!(
            scratch.revoke().unwrap_err().stage,
            RecoveryRevocationStage::Snapshot
        );
        assert_eq!(scratch.snapshot(), before);
    }
}

#[test]
fn symlink_hardlink_and_permissive_session_files_refuse_before_mutation() {
    for kind in ["symlink", "hardlink", "permissions"] {
        let scratch = Scratch::new();
        scratch.populate();
        let target = scratch.store().session_path(&"e".repeat(64));
        let foreign = scratch.store().session_path(&"d".repeat(64));
        match kind {
            "symlink" => symlink(&foreign, &target).unwrap(),
            "hardlink" => fs::hard_link(&foreign, &target).unwrap(),
            _ => fs::set_permissions(&foreign, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        let before = scratch.snapshot();
        assert_eq!(
            scratch.revoke().unwrap_err().stage,
            RecoveryRevocationStage::Snapshot
        );
        assert_eq!(scratch.snapshot(), before);
    }
}

#[test]
fn unknown_or_unsafe_store_and_lock_are_never_created_repaired_or_followed() {
    let empty = Scratch::new();
    assert_eq!(
        empty.revoke().unwrap_err().stage,
        RecoveryRevocationStage::Lock
    );
    assert!(!empty.store().lock_path().exists());
    for kind in [
        "directory-mode",
        "lock-mode",
        "lock-symlink",
        "lock-payload",
    ] {
        let scratch = Scratch::new();
        scratch.populate();
        let before = scratch.snapshot();
        match kind {
            "directory-mode" => {
                fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "lock-mode" => fs::set_permissions(
                scratch.store().lock_path(),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            "lock-symlink" => {
                fs::remove_file(scratch.store().lock_path()).unwrap();
                symlink(
                    scratch.store().session_path(&"d".repeat(64)),
                    scratch.store().lock_path(),
                )
                .unwrap();
            }
            _ => fs::write(scratch.store().lock_path(), b"foreign").unwrap(),
        }
        assert_eq!(
            scratch.revoke().unwrap_err().stage,
            RecoveryRevocationStage::Lock
        );
        assert_eq!(scratch.snapshot(), before);
    }
}

#[test]
fn nonblocking_runtime_lock_prevents_concurrent_recovery_session_writes() {
    let scratch = Scratch::new();
    scratch.populate();
    let before = scratch.snapshot();
    let store = scratch.store();
    let held = store.guarded_lock().unwrap();
    assert_eq!(
        scratch.revoke().unwrap_err().stage,
        RecoveryRevocationStage::Lock
    );
    assert_eq!(scratch.snapshot(), before);
    drop(held);
    assert_eq!(scratch.revoke().unwrap().newly_revoked, 2);
}

#[test]
fn interrupted_partial_revocation_is_observable_and_readonly_verification_never_repairs_it() {
    let scratch = Scratch::new();
    scratch.populate();
    // Represents a process interruption after one durable physical revocation.
    // The normal record writer creates the actual on-disk partial state.
    scratch
        .store()
        .save(&record('a', ALICE, Some(3), Some(100)))
        .unwrap();
    let before = scratch.snapshot();
    let failed = scratch.verify().unwrap_err();
    assert_eq!(failed.stage, RecoveryRevocationStage::Readback);
    assert_eq!(failed.attempted_writes, 0);
    assert_eq!(failed.completed_writes, 0);
    assert_eq!(scratch.snapshot(), before);
}

#[test]
fn input_owner_deadline_and_account_refusals_leave_all_records_unchanged() {
    let scratch = Scratch::new();
    scratch.populate();
    let (uid, gid) = scratch.owner();
    let before = scratch.snapshot();
    for (account, epoch, now, deadline) in [
        ("", 3, 100, until()),
        ("alice\nforged=true", 3, 100, until()),
        (ALICE, 3, 0, until()),
        (ALICE, 3, 100, Instant::now()),
        (ALICE, 3, 100, Instant::now() + Duration::from_secs(61)),
    ] {
        let failed = revoke_recovery_sessions(&scratch.0, uid, gid, account, epoch, now, deadline)
            .unwrap_err();
        assert_eq!(failed.stage, RecoveryRevocationStage::Input);
        assert_eq!(failed.completed_writes, 0);
        assert_eq!(scratch.snapshot(), before);
    }
    assert!(
        revoke_recovery_sessions(&scratch.0, uid.wrapping_add(1), gid, ALICE, 3, 100, until())
            .is_err()
    );
    assert_eq!(scratch.snapshot(), before);
}

#[test]
fn ordinary_foreign_session_touched_at_expiry_or_after_callers_sample_is_preserved() {
    let scratch = Scratch::new();
    scratch.populate();
    let mut foreign = record('d', BOB, Some(9), None);
    foreign.last_seen_at = foreign.expires_at;
    scratch.store().save(&foreign).unwrap();
    let before = scratch.bytes('d');
    assert_eq!(scratch.revoke().unwrap().newly_revoked, 2);
    assert_eq!(scratch.bytes('d'), before);
    assert_eq!(scratch.verify().unwrap().verified, 3);
}

#[test]
fn revocation_samples_clock_after_lock_and_accepts_target_issued_after_callers_sample() {
    let scratch = Scratch::new();
    scratch.populate();
    let mut target = record('a', ALICE, Some(3), None);
    target.issued_at = 101;
    target.last_seen_at = 101;
    scratch.store().save(&target).unwrap();
    let (uid, gid) = scratch.owner();
    let before = scratch.snapshot();
    let failed = revoke_with_clock(
        &scratch.0,
        uid,
        gid,
        ALICE,
        3,
        100,
        until(),
        &FixedClock(99),
    )
    .unwrap_err();
    assert_eq!(failed.stage, RecoveryRevocationStage::Snapshot);
    assert_eq!(failed.attempted_writes, 0);
    assert_eq!(scratch.snapshot(), before);
    assert_eq!(
        revoke_with_clock(
            &scratch.0,
            uid,
            gid,
            ALICE,
            3,
            100,
            until(),
            &FixedClock(102)
        )
        .unwrap()
        .newly_revoked,
        2
    );
    assert_eq!(
        scratch
            .store()
            .load(&"a".repeat(64))
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(102)
    );
}

#[test]
fn already_contained_epoch_authority_refuses_old_sessions_while_control_account_remains_usable() {
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock;
    impl TimeProvider for Clock {
        fn unix_timestamp(&self) -> u64 {
            100
        }
    }
    struct Authority(AtomicU64);
    impl crate::account_admission::EpochAuthority for Authority {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            if (account == BOB && epoch == 9)
                || (account == ALICE && epoch == self.0.load(Ordering::SeqCst))
            {
                Ok(())
            } else {
                Err(crate::account_admission::Error::Refused)
            }
        }
    }
    let scratch = Scratch::new();
    let authority = std::sync::Arc::new(Authority(AtomicU64::new(3)));
    let service = SessionService::new(scratch.store(), Clock, SystemRandomSource, 3600, 1800)
        .with_epoch_authority(authority.clone());
    let context = AuthenticationContext {
        request_id: "synthetic-recovery".into(),
        remote_addr: "127.0.0.1".into(),
        user_agent: "synthetic".into(),
    };
    let target = service
        .issue_with_epoch(&context, ALICE, RequiredSecondFactor::Totp, Some(3))
        .unwrap();
    let control = service
        .issue_with_epoch(&context, BOB, RequiredSecondFactor::Totp, Some(9))
        .unwrap();
    assert!(service.validate(&context, &target.token).is_ok());
    assert!(service.validate(&context, &control.token).is_ok());
    let control_before =
        fs::read(scratch.store().session_path(&control.record.session_id)).unwrap();
    // Durable native containment is supplied by the coordinator; this typed
    // authority models its admission refusal while exercising real issuance,
    // validation, physical revocation and readback on the existing file store.
    authority.0.store(0, Ordering::SeqCst);
    assert!(service.validate(&context, &target.token).is_err());
    assert!(service
        .issue_with_epoch(&context, ALICE, RequiredSecondFactor::Totp, Some(3))
        .is_err());
    assert_eq!(scratch.revoke().unwrap().newly_revoked, 1);
    assert_eq!(
        scratch
            .store()
            .load(&target.record.session_id)
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(100)
    );
    assert_eq!(
        fs::read(scratch.store().session_path(&control.record.session_id)).unwrap(),
        control_before
    );
    authority.0.store(4, Ordering::SeqCst);
    assert!(service.validate(&context, &target.token).is_err());
    assert!(service
        .issue_with_epoch(&context, ALICE, RequiredSecondFactor::Totp, Some(3))
        .is_err());
    assert!(service
        .issue_with_epoch(&context, ALICE, RequiredSecondFactor::Totp, Some(4))
        .is_ok());
    assert!(service.validate(&context, &control.token).is_ok());
}

/// This discriminator must run explicitly as root on OpenBSD. It only touches
/// its fresh /tmp namespace; it never reads configured account/session paths.
#[test]
#[ignore = "native OpenBSD root-only disposable cross-owner session fixture"]
fn native_root_session_revocation_preserves_runtime_ownership() {
    assert_eq!(std::env::consts::OS, "openbsd", "native OpenBSD required");
    assert_eq!(crate::openbsd::effective_uid(), 0, "native root required");
    let (uid, gid) =
        crate::openbsd::osmap_runtime_identity().expect("configured runtime principal required");
    assert!(uid != 0 && uid != u32::MAX && gid != u32::MAX);

    struct NativeFixture {
        root: PathBuf,
        root_identity: (u64, u64),
        session_identity: (u64, u64),
        owner: u32,
        group: u32,
        removed: bool,
    }
    impl NativeFixture {
        fn cleanup(&mut self) -> Result<(), ()> {
            let root = fs::symlink_metadata(&self.root).map_err(|_| ())?;
            let sessions = self.root.join("sessions");
            let directory = fs::symlink_metadata(&sessions).map_err(|_| ())?;
            if !root.is_dir()
                || root.uid() != 0
                || root.mode() & 0o7777 != 0o700
                || (root.dev(), root.ino()) != self.root_identity
                || !directory.is_dir()
                || (directory.dev(), directory.ino()) != self.session_identity
                || directory.uid() != self.owner
                || directory.gid() != self.group
                || directory.mode() & 0o7777 != 0o700
            {
                return Err(());
            }
            let root_entries = fs::read_dir(&self.root)
                .map_err(|_| ())?
                .map(|entry| entry.map(|entry| entry.file_name()).map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            if root_entries != [std::ffi::OsString::from("sessions")] {
                return Err(());
            }
            let expected: BTreeSet<_> = [
                SESSION_LOCK_FILE.to_string(),
                format!("{}.session", "a".repeat(64)),
                format!("{}.session", "b".repeat(64)),
                format!("{}.session", "c".repeat(64)),
            ]
            .into_iter()
            .collect();
            let entries = fs::read_dir(&sessions)
                .map_err(|_| ())?
                .map(|entry| entry.map_err(|_| ()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut observed = BTreeSet::new();
            for entry in &entries {
                let name = entry.file_name().into_string().map_err(|_| ())?;
                if !expected.contains(&name) || !observed.insert(name) {
                    return Err(());
                }
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| ())?;
                if !metadata.is_file()
                    || metadata.uid() != self.owner
                    || metadata.gid() != self.group
                    || metadata.mode() & 0o7777 != 0o600
                    || metadata.nlink() != 1
                {
                    return Err(());
                }
            }
            if observed != expected {
                return Err(());
            }
            for entry in entries {
                fs::remove_file(entry.path()).map_err(|_| ())?;
            }
            fs::remove_dir(&sessions).map_err(|_| ())?;
            fs::remove_dir(&self.root).map_err(|_| ())?;
            self.removed = true;
            Ok(())
        }
    }
    impl Drop for NativeFixture {
        fn drop(&mut self) {
            if !self.removed && self.cleanup().is_err() {
                eprintln!("native_root_session_fixture cleanup=RETAINED_UNCERTAIN");
            }
        }
    }
    fn chown(path: &Path, owner: u32, group: u32) {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        crate::openbsd::private_file_set_owner(&file, owner, group).unwrap();
    }

    let root = Path::new("/tmp").join(format!(
        "osmap-r4-root-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let sessions = root.join("sessions");
    fs::create_dir(&sessions).unwrap();
    fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700)).unwrap();
    let store = FileSessionStore::new(&sessions);
    for session in [
        record('a', ALICE, Some(3), None),
        record('b', ALICE, None, None),
        record('c', BOB, Some(9), None),
    ] {
        store.save(&session).unwrap();
    }
    let foreign = fs::read(store.session_path(&"c".repeat(64))).unwrap();
    for entry in fs::read_dir(&sessions).unwrap() {
        chown(&entry.unwrap().path(), uid, gid);
    }
    chown(&sessions, uid, gid);
    let root_metadata = fs::symlink_metadata(&root).unwrap();
    let session_metadata = fs::symlink_metadata(&sessions).unwrap();
    let mut fixture = NativeFixture {
        root,
        root_identity: (root_metadata.dev(), root_metadata.ino()),
        session_identity: (session_metadata.dev(), session_metadata.ino()),
        owner: uid,
        group: gid,
        removed: false,
    };
    let now = crate::totp::SystemTimeProvider.unix_timestamp();
    assert_eq!(
        revoke_recovery_sessions(&sessions, uid, gid, ALICE, 3, now, until()),
        Ok(RecoveryRevocation {
            matched: 2,
            newly_revoked: 2,
            verified: 2
        })
    );
    assert_eq!(
        fs::read(store.session_path(&"c".repeat(64))).unwrap(),
        foreign
    );
    for letter in ['a', 'b'] {
        let path = store.session_path(&letter.to_string().repeat(64));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let parsed = parse_session_record(std::str::from_utf8(&fs::read(path).unwrap()).unwrap())
            .unwrap()
            .unwrap();
        assert!(parsed.revoked_at.is_some_and(|at| at >= now));
    }
    assert_eq!(
        verify_recovery_sessions(&sessions, uid, gid, ALICE, 3, now, until())
            .unwrap()
            .verified,
        2
    );
    fixture
        .cleanup()
        .expect("exact owned native fixture cleanup");
}
