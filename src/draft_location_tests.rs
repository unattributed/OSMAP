use super::*;
struct Owned(PathBuf);
impl Owned {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "osmap-draft-preference-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn persistent_cas_restart_and_account_isolation() {
    let owned = Owned::new();
    let store = Store::new(&owned.0);
    assert_eq!(
        store.load("alice@example.com").unwrap(),
        Preference::default()
    );
    let saved = store
        .save("alice@example.com", 0, Location::Working)
        .unwrap();
    assert_eq!(
        Store::new(&owned.0).load("alice@example.com").unwrap(),
        saved
    );
    assert_eq!(
        store.save("alice@example.com", 0, Location::Default),
        Err(Error::Stale)
    );
    assert_eq!(
        store.load("bob@example.com").unwrap(),
        Preference::default()
    );
    assert_eq!(
        store.save("alice@example.com", u64::MAX, Location::Default),
        Err(Error::Invalid)
    );
    assert_eq!(store.load("alice@example.com").unwrap(), saved);
}
#[test]
fn corrupt_preference_refuses_without_default_or_reset() {
    let owned = Owned::new();
    let store = Store::new(&owned.0);
    store
        .save("alice@example.com", 0, Location::Working)
        .unwrap();
    let path = std::fs::read_dir(&owned.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"invalid").unwrap();
    assert_eq!(store.load("alice@example.com"), Err(Error::Unavailable));
    assert_eq!(
        store.save("alice@example.com", 1, Location::Default),
        Err(Error::Unavailable)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"invalid");
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        store.load("alice@example.com").unwrap().location,
        Location::Working
    );
}

#[test]
fn stale_cas_never_qualifies_storage_and_failure_never_publishes_choice() {
    let owned = Owned::new();
    let store = Store::new(&owned.0);
    let saved = store
        .save("alice@example.com", 0, Location::Default)
        .unwrap();
    let initialized = std::cell::Cell::new(false);
    assert_eq!(
        store.save_qualified("alice@example.com", 0, Location::Working, || {
            initialized.set(true);
            Ok(())
        }),
        Err(Error::Stale)
    );
    assert!(!initialized.get());
    assert_eq!(
        store.save_qualified("alice@example.com", 1, Location::Working, || Err(
            Error::Unavailable
        )),
        Err(Error::Unavailable)
    );
    assert_eq!(store.load("alice@example.com").unwrap(), saved);
}
