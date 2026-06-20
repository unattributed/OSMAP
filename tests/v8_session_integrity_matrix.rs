use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::logging::LogEvent;
use osmap::session::{
    FileSessionStore, RandomSource, SessionError, SessionRecord, SessionService, SessionStore,
    SessionToken, CSRF_TOKEN_HEX_LEN, SESSION_ID_HEX_LEN, SESSION_TOKEN_HEX_LEN,
};
use osmap::totp::TimeProvider;

#[derive(Debug, Clone)]
struct FixedTimeProvider {
    now: Rc<Cell<u64>>,
}

impl FixedTimeProvider {
    fn new(now: u64) -> Self {
        Self {
            now: Rc::new(Cell::new(now)),
        }
    }

    fn set(&self, now: u64) {
        self.now.set(now);
    }
}

impl TimeProvider for FixedTimeProvider {
    fn unix_timestamp(&self) -> u64 {
        self.now.get()
    }
}

#[derive(Debug, Clone)]
struct SequencedRandomSource {
    next: Cell<u8>,
}

impl SequencedRandomSource {
    fn new(seed: u8) -> Self {
        Self {
            next: Cell::new(seed),
        }
    }
}

impl RandomSource for SequencedRandomSource {
    fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError> {
        let value = self.next.get();
        self.next.set(value.wrapping_add(1));
        for byte in buffer {
            *byte = value;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct MemorySessionStore {
    records: std::rc::Rc<RefCell<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    fn get(&self, session_id: &str) -> Option<SessionRecord> {
        self.records.borrow().get(session_id).cloned()
    }

    fn active_count_for_user(&self, canonical_username: &str) -> usize {
        self.records
            .borrow()
            .values()
            .filter(|record| record.canonical_username == canonical_username)
            .filter(|record| record.revoked_at.is_none())
            .count()
    }
}

impl SessionStore for MemorySessionStore {
    fn save_unlocked(&self, record: &SessionRecord) -> Result<(), SessionError> {
        self.records
            .borrow_mut()
            .insert(record.session_id.clone(), record.clone());
        Ok(())
    }

    fn load_unlocked(&self, session_id: &str) -> Result<Option<SessionRecord>, SessionError> {
        Ok(self.records.borrow().get(session_id).cloned())
    }

    fn list_for_user_unlocked(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<SessionRecord>, SessionError> {
        let mut records: Vec<SessionRecord> = self
            .records
            .borrow()
            .values()
            .filter(|record| record.canonical_username == canonical_username)
            .cloned()
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
        Ok(records)
    }
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn context(request_id: &str) -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        request_id,
        "127.0.0.1",
        "Firefox/V8-Session-Integrity",
    )
    .expect("authentication context should be valid")
}

fn service_with_store(
    store: MemorySessionStore,
    time: FixedTimeProvider,
    random: SequencedRandomSource,
) -> SessionService<MemorySessionStore, FixedTimeProvider, SequencedRandomSource> {
    SessionService::new(store, time, random, 3600, 600)
}

fn event_field<'a>(event: &'a LogEvent, key: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.as_str())
}

fn assert_hex(value: &str, expected_len: usize, label: &str) {
    assert_eq!(value.len(), expected_len, "{label} length changed");
    assert!(
        value.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{label} should be hex"
    );
}

fn assert_audit_redacts_session_secret(event: &LogEvent, session_id: &str, token: &SessionToken) {
    assert!(
        event_field(event, "session_id").is_none(),
        "raw session_id must not be present in audit fields"
    );
    assert!(
        event_field(event, "session_token").is_none(),
        "raw session token must not be present in audit fields"
    );
    assert!(
        event_field(event, "token").is_none(),
        "generic raw token field must not be present in audit fields"
    );

    let session_ref = event_field(event, "session_ref").expect("session_ref should be present");
    assert_ne!(
        session_ref, session_id,
        "session_ref must not equal raw session_id"
    );
    assert!(
        !session_ref.contains(token.as_str()),
        "session_ref must not contain raw bearer token"
    );
    assert!(
        session_ref.starts_with("asr-"),
        "session_ref should use audit-session-ref prefix"
    );
}

#[test]
fn v8_session_integrity_fixture_inventory_is_complete() {
    for relative in [
        "tests/fixtures/session_integrity/MANIFEST.md",
        "tests/fixtures/session_integrity/lifecycle.env",
        "tests/fixtures/session_integrity/timeout_cases.tsv",
        "tests/fixtures/session_integrity/revocation_cases.tsv",
        "docs/V8_SESSION_INTEGRITY_MATRIX.md",
        "maint/security/osmap-v8-session-integrity-gate.sh",
    ] {
        assert!(repo_path(relative).is_file(), "missing {relative}");
    }

    assert!(include_str!("fixtures/session_integrity/lifecycle.env").contains("alice@example.com"));
    assert!(include_str!("fixtures/session_integrity/timeout_cases.tsv").contains("idle timed out"));
    assert!(include_str!("fixtures/session_integrity/revocation_cases.tsv").contains("revoke_all"));
}

#[test]
fn v8_session_integrity_matrix_rejects_invalid_tokens_and_redacts_debug() {
    assert!(SessionToken::new("").is_err());
    assert!(SessionToken::new("a").is_err());
    assert!(SessionToken::new("g".repeat(SESSION_TOKEN_HEX_LEN)).is_err());
    assert!(SessionToken::new("a".repeat(SESSION_TOKEN_HEX_LEN + 1)).is_err());

    let valid = SessionToken::new("a".repeat(SESSION_TOKEN_HEX_LEN)).expect("valid token");
    assert_eq!(valid.as_str(), "a".repeat(SESSION_TOKEN_HEX_LEN));
    let debug = format!("{valid:?}");
    assert!(debug.contains("<redacted>"));
    assert!(
        !debug.contains(valid.as_str()),
        "debug output must not expose raw session token"
    );
}

#[test]
fn v8_session_integrity_matrix_issues_validates_and_refreshes_sessions() {
    let store = MemorySessionStore::default();
    let time = FixedTimeProvider::new(1000);
    let random = SequencedRandomSource::new(0x42);
    let service = service_with_store(store.clone(), time.clone(), random);

    let issued = service
        .issue(
            &context("req-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("session should issue");
    assert_hex(
        issued.token.as_str(),
        SESSION_TOKEN_HEX_LEN,
        "session token",
    );
    assert_hex(&issued.record.session_id, SESSION_ID_HEX_LEN, "session id");
    assert_hex(&issued.record.csrf_token, CSRF_TOKEN_HEX_LEN, "csrf token");
    assert_ne!(issued.token.as_str(), issued.record.session_id);
    assert_ne!(issued.record.session_id, issued.record.csrf_token);
    assert_eq!(issued.record.issued_at, 1000);
    assert_eq!(issued.record.expires_at, 4600);
    assert_eq!(issued.record.last_seen_at, 1000);
    assert_eq!(issued.record.revoked_at, None);
    assert_eq!(issued.record.canonical_username, "alice@example.com");
    assert_eq!(issued.audit_event.action, "session_issued");
    assert_eq!(
        event_field(&issued.audit_event, "canonical_username"),
        Some("alice@example.com")
    );
    assert_audit_redacts_session_secret(
        &issued.audit_event,
        &issued.record.session_id,
        &issued.token,
    );

    time.set(1100);
    let validated = service
        .validate(&context("req-validate"), &issued.token)
        .expect("session should validate");
    assert_eq!(validated.record.session_id, issued.record.session_id);
    assert_eq!(validated.record.last_seen_at, 1100);
    assert_eq!(validated.audit_event.action, "session_validated");
    assert_eq!(
        event_field(&validated.audit_event, "canonical_username"),
        Some("alice@example.com")
    );
    assert_audit_redacts_session_secret(
        &validated.audit_event,
        &validated.record.session_id,
        &issued.token,
    );

    let persisted = store
        .get(&issued.record.session_id)
        .expect("validated session should be persisted");
    assert_eq!(persisted.last_seen_at, 1100);
    assert_eq!(persisted.revoked_at, None);
}

#[test]
fn v8_session_integrity_matrix_revokes_expired_and_idle_sessions() {
    let expired_store = MemorySessionStore::default();
    let expired_time = FixedTimeProvider::new(1000);
    let expired_service = service_with_store(
        expired_store.clone(),
        expired_time.clone(),
        SequencedRandomSource::new(0x51),
    );
    let expired = expired_service
        .issue(
            &context("req-expired-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("expired fixture session should issue");
    expired_time.set(4601);
    let expired_error = expired_service
        .validate(&context("req-expired-validate"), &expired.token)
        .expect_err("expired session should fail closed");
    assert!(
        matches!(expired_error, SessionError::StoreFailure { ref reason } if reason.contains("expired")),
        "unexpected expired-session error: {expired_error:?}"
    );
    assert_eq!(
        expired_store
            .get(&expired.record.session_id)
            .expect("expired session should persist revocation")
            .revoked_at,
        Some(4601)
    );

    let idle_store = MemorySessionStore::default();
    let idle_time = FixedTimeProvider::new(1000);
    let idle_service = service_with_store(
        idle_store.clone(),
        idle_time.clone(),
        SequencedRandomSource::new(0x52),
    );
    let idle = idle_service
        .issue(
            &context("req-idle-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("idle fixture session should issue");
    idle_time.set(1601);
    let idle_error = idle_service
        .validate(&context("req-idle-validate"), &idle.token)
        .expect_err("idle session should fail closed");
    assert!(
        matches!(idle_error, SessionError::StoreFailure { ref reason } if reason.contains("idle timed out")),
        "unexpected idle-session error: {idle_error:?}"
    );
    assert_eq!(
        idle_store
            .get(&idle.record.session_id)
            .expect("idle session should persist revocation")
            .revoked_at,
        Some(1601)
    );
}

#[test]
fn v8_session_integrity_matrix_revokes_current_other_and_all_sessions() {
    let store = MemorySessionStore::default();
    let time = FixedTimeProvider::new(2000);
    let random = SequencedRandomSource::new(0x61);
    let service = service_with_store(store.clone(), time.clone(), random);

    let current = service
        .issue(
            &context("req-current-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("current session should issue");
    time.set(2001);
    let other = service
        .issue(
            &context("req-other-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("other session should issue");
    time.set(2002);
    let third = service
        .issue(
            &context("req-third-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("third session should issue");
    time.set(2003);
    let unrelated = service
        .issue(
            &context("req-unrelated-issue"),
            "bob@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("unrelated session should issue");

    time.set(2100);
    let logout = service
        .revoke_by_token(&context("req-logout"), &current.token)
        .expect("logout-style revoke should succeed");
    assert_eq!(logout.audit_event.action, "session_revoked");
    assert_eq!(logout.record.revoked_at, Some(2100));
    assert_audit_redacts_session_secret(
        &logout.audit_event,
        &logout.record.session_id,
        &current.token,
    );
    assert!(
        service
            .validate(&context("req-validate-revoked"), &current.token)
            .is_err(),
        "revoked current session must not validate"
    );

    time.set(2200);
    let revoked_except = service
        .revoke_all_for_user_except(
            &context("req-revoke-except"),
            "alice@example.com",
            &third.record.session_id,
        )
        .expect("revoke except current should succeed");
    assert_eq!(revoked_except.len(), 1);
    assert_eq!(revoked_except[0].record.session_id, other.record.session_id);
    assert_eq!(
        store
            .get(&third.record.session_id)
            .expect("third session should remain active")
            .revoked_at,
        None
    );
    assert_eq!(
        store
            .get(&unrelated.record.session_id)
            .expect("unrelated user session should remain active")
            .revoked_at,
        None
    );

    time.set(2300);
    let revoked_all = service
        .revoke_all_for_user(&context("req-revoke-all"), "alice@example.com")
        .expect("revoke all should succeed");
    assert_eq!(revoked_all.len(), 1);
    assert_eq!(revoked_all[0].record.session_id, third.record.session_id);
    assert_eq!(store.active_count_for_user("alice@example.com"), 0);
    assert_eq!(store.active_count_for_user("bob@example.com"), 1);
}

#[test]
fn v8_session_integrity_matrix_lists_and_expires_user_sessions() {
    let store = MemorySessionStore::default();
    let time = FixedTimeProvider::new(3000);
    let service = service_with_store(
        store.clone(),
        time.clone(),
        SequencedRandomSource::new(0x71),
    );

    let old = service
        .issue(
            &context("req-old-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("old session should issue");
    time.set(3005);
    let new = service
        .issue(
            &context("req-new-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("new session should issue");

    time.set(6601);
    let listed = service
        .list_for_user("alice@example.com")
        .expect("session listing should succeed");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].session_id, new.record.session_id);
    assert_eq!(listed[1].session_id, old.record.session_id);
    assert_eq!(
        store
            .get(&old.record.session_id)
            .expect("old session should be present")
            .revoked_at,
        Some(6601)
    );
    assert_eq!(
        store
            .get(&new.record.session_id)
            .expect("new session should be present")
            .revoked_at,
        Some(6601)
    );
}

#[test]
fn v8_session_integrity_matrix_persists_without_raw_bearer_token() {
    let mut session_dir = std::env::temp_dir();
    session_dir.push(format!(
        "osmap-v8-session-integrity-{}-{}",
        std::process::id(),
        4242
    ));
    if session_dir.exists() {
        fs::remove_dir_all(&session_dir).expect("old temp session directory should be removable");
    }

    let store = FileSessionStore::new(&session_dir);
    let time = FixedTimeProvider::new(7000);
    let random = SequencedRandomSource::new(0x81);
    let service = SessionService::new(store, time, random, 3600, 600);

    let issued = service
        .issue(
            &context("req-file-issue"),
            "alice@example.com",
            RequiredSecondFactor::Totp,
        )
        .expect("file-backed session should issue");
    let session_path = session_dir.join(format!("{}.session", issued.record.session_id));
    let content = fs::read_to_string(&session_path).expect("session file should be readable");

    assert!(content.contains(&issued.record.session_id));
    assert!(content.contains(&issued.record.csrf_token));
    assert!(
        !content.contains(issued.token.as_str()),
        "persisted session record must not contain raw bearer token"
    );

    let loaded = FileSessionStore::new(&session_dir)
        .load(&issued.record.session_id)
        .expect("session file should load")
        .expect("session record should exist");
    assert_eq!(loaded.session_id, issued.record.session_id);
    assert_eq!(loaded.csrf_token, issued.record.csrf_token);
    assert_eq!(loaded.canonical_username, "alice@example.com");

    fs::remove_dir_all(&session_dir).expect("temp session directory should be cleaned up");
}
