use super::*;
#[cfg(unix)]
struct Fixture {
    root: PathBuf,
    path: PathBuf,
    provider: Provider,
}
#[cfg(unix)]
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = std::path::Path::new("/tmp").join(format!(
            "osmap-sender-authority-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("authority.json");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let provider = Provider::new(Some(path.clone()), std::fs::metadata(&path).unwrap().uid());
        let fixture = Self {
            root,
            path,
            provider,
        };
        fixture.write("desk@example.test");
        fixture
    }
    fn write(&self, address: &str) {
        std::fs::write(&self.path, serde_json::to_vec(&serde_json::json!({"version":1,"accounts":[
            {"account":"alice@example.test","revision":1,"identities":[{"id":"desk","address":address}]},
            {"account":"bob@example.test","revision":1,"identities":[{"id":"other","address":"bob-desk@example.test"}]}
        ]})).unwrap()).unwrap();
    }
}
#[cfg(unix)]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn canonical_sender_is_legacy_authority_without_an_alias_inventory() {
    let provider = Provider::default();
    let snapshot = provider.snapshot("alice@example.test").unwrap();
    assert_eq!(snapshot.identities.len(), 1);
    assert_eq!(
        provider.authorize("alice@example.test", None).unwrap(),
        "alice@example.test"
    );
    let alias =
        crate::identity_preferences::CapturedSender::new("desk", "desk@example.test").unwrap();
    assert_eq!(
        provider.authorize("alice@example.test", Some(&alias)),
        Err(Error::NotAuthorized)
    );
    assert!(provider.snapshot("*@example.test").is_err());
}
#[cfg(unix)]
#[test]
fn current_authority_binds_captured_id_address_and_account_without_retargeting() {
    let f = Fixture::new();
    let selected = f.provider.snapshot("alice@example.test").unwrap();
    assert_eq!(selected.identities.len(), 2);
    assert!(selected.get("other").is_err());
    let capture =
        crate::identity_preferences::CapturedSender::new("desk", "desk@example.test").unwrap();
    assert_eq!(
        f.provider
            .authorize("alice@example.test", Some(&capture))
            .unwrap(),
        "desk@example.test"
    );
    assert_eq!(
        f.provider.authorize("bob@example.test", Some(&capture)),
        Err(Error::NotAuthorized)
    );
    f.write("replacement@example.test");
    assert_eq!(
        f.provider.authorize("alice@example.test", Some(&capture)),
        Err(Error::NotAuthorized)
    );
    std::fs::write(&f.path, b"corrupt").unwrap();
    assert_eq!(
        f.provider.authorize("alice@example.test", Some(&capture)),
        Err(Error::Unavailable)
    );
    assert_eq!(
        f.provider.authorize("alice@example.test", None).unwrap(),
        "alice@example.test"
    );
}
#[cfg(unix)]
#[test]
fn entire_inventory_is_strict_bounded_and_duplicate_authority_is_refused() {
    let f = Fixture::new();
    for value in [
        serde_json::json!({"version":2,"accounts":[]}),
        serde_json::json!({"version":1,"accounts":[],"from":"invented@example.test"}),
        serde_json::json!({"version":1,"accounts":[{"account":"alice@example.test","revision":0,"identities":[]}]}),
        serde_json::json!({"version":1,"accounts":[{"account":"alice@example.test","revision":1,"identities":[{"id":"desk","address":"a@example.test"},{"id":"desk","address":"b@example.test"}]}]}),
        serde_json::json!({"version":1,"accounts":[{"account":"alice@example.test","revision":1,"identities":[{"id":"canonical","address":"a@example.test"}]}]}),
        serde_json::json!({"version":1,"accounts":[{"account":"alice@example.test","revision":1,"identities":[{"id":"desk","address":"alice@example.test"}]}]}),
        serde_json::json!({"version":1,"accounts":[{"account":"alice@example.test","revision":1,"identities":[]},{"account":"bob@example.test","revision":1,"identities":[{"id":"bad","address":"bad\nBcc:foreign@example.test"}]}]}),
    ] {
        std::fs::write(&f.path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            f.provider.snapshot("alice@example.test"),
            Err(Error::Unavailable)
        );
    }
    std::fs::write(&f.path, vec![b'x'; MAX_BYTES + 1]).unwrap();
    assert_eq!(
        f.provider.snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
}
#[cfg(unix)]
#[test]
fn authority_file_permissions_links_and_foreign_owner_are_not_browser_authority() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let f = Fixture::new();
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        f.provider.snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let foreign = Provider::new(
        Some(f.path.clone()),
        std::fs::metadata(&f.path).unwrap().uid().wrapping_add(1),
    );
    assert_eq!(
        foreign.snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
    let linked = f.root.join("hardlink");
    std::fs::hard_link(&f.path, &linked).unwrap();
    assert_eq!(
        f.provider.snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
    std::fs::remove_file(linked).unwrap();
    let linked = f.root.join("symlink");
    symlink(&f.path, &linked).unwrap();
    assert_eq!(
        Provider::new(Some(linked), std::fs::metadata(&f.path).unwrap().uid())
            .snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
    std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        f.provider.snapshot("alice@example.test"),
        Err(Error::Unavailable)
    );
}
