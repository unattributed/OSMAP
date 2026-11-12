use super::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct PolicyFixture {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
}
impl PolicyFixture {
    fn new(value: serde_json::Value) -> Self {
        // Keep the positive authority fixture outside a gate's writable TMPDIR.
        let root = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-retention-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            path: root.join("retention.json"),
            root,
        };
        fixture.write(value);
        fixture
    }
    fn write(&self, value: serde_json::Value) {
        fs::write(&self.path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn provider(&self) -> FileMailboxRetentionPolicy {
        FileMailboxRetentionPolicy::new(Some(self.path.clone()), crate::openbsd::effective_uid())
    }
    fn decision(&self, account: &str, mailbox: &str) -> RetentionDecision {
        self.provider().decision(
            account,
            mailbox,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
    }
}
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn rule(account: &str, mailbox: &str, revision: u64, permission: &str) -> serde_json::Value {
    serde_json::json!({"account":account,"mailbox_name":mailbox,"revision":revision,"permanent_delete":permission})
}
fn document() -> serde_json::Value {
    serde_json::json!({"version":1,"rules":[
        rule("alice@example.test", "Deleted", 9, "allowed"),
        rule("bob@example.test", "Deleted", 4, "denied")
    ]})
}

#[test]
fn actual_file_permission_is_account_folder_exact_and_missing_never_permits() {
    let fixture = PolicyFixture::new(document());
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Allowed { revision: 9 }
    ));
    assert!(matches!(
        fixture.decision("bob@example.test", "Deleted"),
        RetentionDecision::Denied
    ));
    for (account, mailbox) in [
        ("foreign@example.test", "Deleted"),
        ("alice@example.test", "Trash"),
        ("alice@example.test", "deleted"),
    ] {
        assert!(matches!(
            fixture.decision(account, mailbox),
            RetentionDecision::Unavailable
        ));
    }
    let none = FileMailboxRetentionPolicy::new(None, crate::openbsd::effective_uid());
    assert!(matches!(
        none.decision(
            "alice@example.test",
            "Deleted",
            std::time::Instant::now() + std::time::Duration::from_secs(1)
        ),
        RetentionDecision::Unavailable
    ));
    fs::remove_file(&fixture.path).unwrap();
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Unavailable
    ));
}

#[test]
fn corrupt_unknown_duplicate_and_invalid_rules_cannot_supply_retention_authority() {
    let fixture = PolicyFixture::new(document());
    for value in [
        serde_json::json!({"version":2,"rules":[rule("alice@example.test","Deleted",9,"allowed")]}),
        serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",0,"allowed")]}),
        serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",9,"yes")]}),
        serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",9,"allowed"),rule("alice@example.test","Deleted",10,"denied")]}),
        serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",9,"allowed")],"fallback_allow":true}),
        serde_json::json!({"version":1,"rules":[{"account":"alice@example.test","mailbox_name":"Deleted","revision":9,"permanent_delete":"allowed","extra":true}]}),
    ] {
        fixture.write(value);
        assert!(matches!(
            fixture.decision("alice@example.test", "Deleted"),
            RetentionDecision::Unavailable
        ));
    }
    for bytes in [
        b"not JSON".as_slice(),
        br#"{"version":1,"version":1,"rules":[]}"#.as_slice(),
    ] {
        fs::write(&fixture.path, bytes).unwrap();
        assert!(matches!(
            fixture.decision("alice@example.test", "Deleted"),
            RetentionDecision::Unavailable
        ));
    }
    fs::write(&fixture.path, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Unavailable
    ));
}

#[test]
fn insecure_foreign_owner_symlink_and_hardlink_files_refuse_without_rewriting() {
    let fixture = PolicyFixture::new(document());
    let original = fs::read(&fixture.path).unwrap();
    for mode in [0o620, 0o602, 0o666] {
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            fixture.decision("alice@example.test", "Deleted"),
            RetentionDecision::Unavailable
        ));
        assert_eq!(fs::read(&fixture.path).unwrap(), original);
    }
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
    let foreign = FileMailboxRetentionPolicy::new(
        Some(fixture.path.clone()),
        crate::openbsd::effective_uid().wrapping_add(1),
    );
    assert!(matches!(
        foreign.decision(
            "alice@example.test",
            "Deleted",
            std::time::Instant::now() + std::time::Duration::from_secs(1)
        ),
        RetentionDecision::Unavailable
    ));
    let link = fixture.root.join("symlink.json");
    symlink(&fixture.path, &link).unwrap();
    let provider = FileMailboxRetentionPolicy::new(Some(link), crate::openbsd::effective_uid());
    assert!(matches!(
        provider.decision(
            "alice@example.test",
            "Deleted",
            std::time::Instant::now() + std::time::Duration::from_secs(1)
        ),
        RetentionDecision::Unavailable
    ));
    fs::hard_link(&fixture.path, fixture.root.join("hardlink.json")).unwrap();
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Unavailable
    ));
    assert_eq!(fs::read(&fixture.path).unwrap(), original);
}

#[test]
fn file_policy_changes_are_loaded_fresh_and_expired_deadline_cannot_allow() {
    let fixture = PolicyFixture::new(document());
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Allowed { revision: 9 }
    ));
    fixture.write(
        serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",10,"denied")]}),
    );
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Denied
    ));
    fixture.write(serde_json::json!({"version":1,"rules":[rule("alice@example.test","Deleted",11,"allowed")]}));
    assert!(matches!(
        fixture.decision("alice@example.test", "Deleted"),
        RetentionDecision::Allowed { revision: 11 }
    ));
    assert!(matches!(
        fixture.provider().decision(
            "alice@example.test",
            "Deleted",
            std::time::Instant::now() - std::time::Duration::from_millis(1)
        ),
        RetentionDecision::Unavailable
    ));
}

#[test]
fn writable_or_symlinked_ancestor_cannot_host_authoritative_policy() {
    let fixture = PolicyFixture::new(document());
    let nested = fixture.root.join("private");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let path = nested.join("retention.json");
    fs::copy(&fixture.path, &path).unwrap();
    let provider =
        FileMailboxRetentionPolicy::new(Some(path.clone()), crate::openbsd::effective_uid());
    let deadline = || std::time::Instant::now() + std::time::Duration::from_secs(1);
    assert!(matches!(
        provider.decision("alice@example.test", "Deleted", deadline()),
        RetentionDecision::Allowed { revision: 9 }
    ));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        provider.decision("alice@example.test", "Deleted", deadline()),
        RetentionDecision::Unavailable
    ));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = fixture.root.join("alias");
    symlink(&nested, &alias).unwrap();
    let provider = FileMailboxRetentionPolicy::new(
        Some(alias.join("retention.json")),
        crate::openbsd::effective_uid(),
    );
    assert!(matches!(
        provider.decision("alice@example.test", "Deleted", deadline()),
        RetentionDecision::Unavailable
    ));
    let provider = FileMailboxRetentionPolicy::new(
        Some(std::path::PathBuf::from("relative.json")),
        crate::openbsd::effective_uid(),
    );
    assert!(matches!(
        provider.decision("alice@example.test", "Deleted", deadline()),
        RetentionDecision::Unavailable
    ));
    assert!(path.exists());
}
