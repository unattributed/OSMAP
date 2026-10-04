#[test]
fn sender_identity_preference_legacy_bytes_and_corrupt_profiles_preserve_authority() {
    let (path, store) = store();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(path);
    store
        .save(
            "alice@example.test",
            0,
            &IdentityPreferences::new("Public", Some("reply@example.test")).unwrap(),
        )
        .unwrap();
    assert_eq!(
        store.file.read("alice@example.test").unwrap().unwrap(),
        br#"{"version":1,"revision":1,"display_name":"Public","reply_to":"reply@example.test"}"#
    );
    let lock = store.file.lock("alice@example.test").unwrap();
    for invalid in [
        br#"{"version":1,"revision":1,"display_name":"","reply_to":"","primary_identity":"desk"}"#.as_slice(),
        br#"{"version":1,"revision":1,"display_name":"","reply_to":"","sender_profiles":[{"id":"canonical","display_name":"","reply_to":""}]}"#,
        br#"{"version":1,"revision":1,"display_name":"","reply_to":"","sender_profiles":[{"id":"desk","display_name":"","reply_to":"","address":"invented@example.test"}]}"#,
        br#"{"version":1,"revision":1,"display_name":"","reply_to":"","sender_profiles":[{"id":"desk","display_name":"","reply_to":""},{"id":"desk","display_name":"","reply_to":""}]}"#,
        br#"{"version":1,"revision":18446744073709551615,"display_name":"","reply_to":""}"#,
    ] {
        lock.write(invalid).unwrap();
        let before = lock.read().unwrap();
        if store.load("alice@example.test").is_ok() { assert_eq!(store.load("alice@example.test").unwrap().revision, u64::MAX); }
        else { assert_eq!(store.load("alice@example.test"), Err(IdentityPreferencesError::Corrupt)); }
        assert_eq!(lock.read().unwrap(), before);
    }
    drop(lock);
    let before = store.file.read("alice@example.test").unwrap();
    assert_eq!(
        store.save(
            "alice@example.test",
            u64::MAX,
            &IdentityPreferences::default()
        ),
        Err(IdentityPreferencesError::Corrupt)
    );
    assert_eq!(store.file.read("alice@example.test").unwrap(), before);
    assert_eq!(store.load("bob@example.test").unwrap().revision, 0);
}
