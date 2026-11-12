//! Optional remembered key permission. Authentication is always separate. Only
//! hashes and public account/deadline metadata live in the web service RAM.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;

const COOKIE: &str = "__Host-osmap_key_access";
const LIMIT: usize = 256;
const REMEMBER_SECONDS: u64 = 8 * 60 * 60;
struct Lease {
    account: String,
    until: u64,
}
#[derive(Default)]
pub(super) struct RememberedKeys(Mutex<BTreeMap<[u8; 32], Lease>>);

fn now() -> u64 {
    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
}
fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn token(request: &HttpRequest) -> Option<&str> {
    let mut values = request
        .headers
        .get("cookie")?
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == COOKIE).then_some(value)
        });
    let value = values.next()?;
    (values.next().is_none() && valid_token(value)).then_some(value)
}

fn valid_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn cookie(value: &str, seconds: u64, secure: bool) -> String {
    format!(
        "{COOKIE}={value}; Path=/; Max-Age={seconds}; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn revoke_account_remembered_keys(
        &self,
        session: &ValidatedSession,
    ) -> (String, bool) {
        let confirmed = if let Ok(mut leases) = self.remembered_keys.0.lock() {
            let had_permission = leases
                .values()
                .any(|lease| lease.account == session.record.canonical_username);
            leases.retain(|_, lease| lease.account != session.record.canonical_username);
            !had_permission || self.gateway.lock_personal_key(session)
        } else {
            false
        };
        (cookie("", 0, self.policy.secure_session_cookie), confirmed)
    }
    pub(super) fn forget_browser_key(&self, request: &HttpRequest) -> (String, bool) {
        let mut confirmed = true;
        // Remove web authority before touching the helper. Even if it is down,
        // a copied cookie can no longer restore permission through this web service.
        if let Some(cookies) = request.headers.get("cookie") {
            if let Ok(mut leases) = self.remembered_keys.0.lock() {
                for value in cookies.split(';').filter_map(|part| {
                    let (name, value) = part.trim().split_once('=')?;
                    (name == COOKIE && valid_token(value)).then_some(value)
                }) {
                    if let Some(lease) = leases.remove(&hash(value)) {
                        confirmed &= self
                            .gateway
                            .forget_remembered_key(&lease.account, value.as_bytes());
                    }
                }
            } else {
                confirmed = false;
            }
        }
        (cookie("", 0, self.policy.secure_session_cookie), confirmed)
    }

    pub(super) fn remember_browser_key(
        &self,
        request: &HttpRequest,
        session: &ValidatedSession,
    ) -> Result<String, ()> {
        if !self.forget_browser_key(request).1 {
            return Err(());
        }
        // Remembered credentials are never issued on an HTTP deployment.
        if !self.policy.secure_session_cookie {
            return Err(());
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| ())?;
        let value: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut leases = self.remembered_keys.0.lock().map_err(|_| ())?;
        let time = now();
        leases.retain(|_, lease| lease.until > time);
        if leases.len() >= LIMIT {
            return Err(());
        }
        let until = self
            .gateway
            .remember_personal_key(session, value.as_bytes())
            .filter(|until| *until > time && *until <= time.saturating_add(REMEMBER_SECONDS))
            .ok_or(())?;
        leases.insert(
            hash(&value),
            Lease {
                account: session.record.canonical_username.clone(),
                until,
            },
        );
        Ok(cookie(&value, until.saturating_sub(now()), true))
    }

    pub(super) fn resume_browser_key(&self, request: &HttpRequest, session: &ValidatedSession) {
        let Some(value) = token(request) else { return };
        let Ok(mut leases) = self.remembered_keys.0.lock() else {
            return;
        };
        let time = now();
        leases.retain(|_, lease| lease.until > time);
        let key = hash(value);
        let Some(lease) = leases.get(&key) else {
            return;
        };
        if lease.account != session.record.canonical_username {
            return;
        }
        // Hold the map lock across restoration so logout cannot race it into
        // recreating a grant after remembered authority has been removed.
        if !self.gateway.resume_personal_key(session, value.as_bytes()) {
            leases.remove(&key);
            self.gateway
                .forget_remembered_key(&session.record.canonical_username, value.as_bytes());
        }
        // No cookie refresh and no recomputation of the absolute unlock deadline.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(cookies: &str) -> HttpRequest {
        parse_http_request(&format!("POST /logout HTTP/1.1\r\nHost: localhost\r\nCookie: {cookies}\r\nContent-Length: 0\r\n\r\n"), &HttpPolicy::default()).unwrap()
    }
    #[test]
    fn remembered_cookie_is_host_only_secure_bounded_and_opaque() {
        let value = "a".repeat(64);
        let header = cookie(&value, 123, true);
        assert_eq!(header, format!("__Host-osmap_key_access={value}; Path=/; Max-Age=123; HttpOnly; SameSite=Strict; Secure"));
        assert!(!header.contains("Domain="));
        assert_eq!(
            token(&request(&format!("{COOKIE}={value}"))),
            Some(value.as_str())
        );
        for bad in [
            "a".repeat(63),
            "A".repeat(64),
            "a".repeat(65),
            "not-a-token".into(),
        ] {
            assert!(token(&request(&format!("{COOKIE}={bad}"))).is_none());
        }
        assert!(token(&request(&format!("{COOKIE}={value}; {COOKIE}={value}"))).is_none());
    }
    #[test]
    fn logout_without_auth_session_revokes_all_presented_duplicate_capabilities() {
        let app = super::super::tests::app();
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        for value in [&first, &second] {
            app.remembered_keys.0.lock().unwrap().insert(
                hash(value),
                Lease {
                    account: "alice@example.test".into(),
                    until: now() + 100,
                },
            );
        }
        let response = app.handle_request(
            &request(&format!("{COOKIE}={first}; {COOKIE}={second}")),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 503);
        assert!(response
            .audit_events
            .iter()
            .any(|event| event.action == "personal_key_logout_cleanup_unconfirmed"));
        assert!(
            app.remembered_keys.0.lock().unwrap().is_empty(),
            "copied cookie cannot resume after logout, even when helper is unavailable"
        );
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie"
                && value.starts_with(&format!("{COOKIE}=;"))
                && value.contains("Max-Age=0")));
    }
    #[test]
    fn non_tls_deployment_never_creates_remembered_authority() {
        let app = super::super::tests::app();
        assert!(!app.policy.secure_session_cookie);
        assert!(app.remembered_keys.0.lock().unwrap().is_empty());
        let session = super::super::tests::StubGateway::validated_session();
        assert!(app.remember_browser_key(&request(""), &session).is_err());
        assert!(app.remembered_keys.0.lock().unwrap().is_empty());
        assert!(token(&request("osmap_session=synthetic")).is_none());
    }
    #[test]
    fn authenticated_logout_requires_csrf_before_revoking_key_permission() {
        let app = super::super::tests::app();
        let value = "c".repeat(64);
        let session = super::super::tests::StubGateway::validated_session();
        app.remembered_keys.0.lock().unwrap().insert(
            hash(&value),
            Lease {
                account: session.record.canonical_username.clone(),
                until: now() + 100,
            },
        );
        let mut req = request(&format!(
            "osmap_session={}; {COOKIE}={value}",
            "a".repeat(64)
        ));
        req.headers
            .insert("origin".into(), "http://localhost".into());
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.body = b"csrf_token=wrong".to_vec();
        assert_eq!(
            app.handle_request(&req, "127.0.0.1").response.status_code,
            403
        );
        assert!(app
            .remembered_keys
            .0
            .lock()
            .unwrap()
            .contains_key(&hash(&value)));
        req.body = format!("csrf_token={}", session.record.csrf_token).into_bytes();
        let response = app.handle_request(&req, "127.0.0.1");
        assert_eq!(
            response.response.status_code, 503,
            "unavailable helper cleanup is explicit"
        );
        assert!(app.remembered_keys.0.lock().unwrap().is_empty());
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Set-Cookie"
                && value.starts_with("osmap_session=;")
                && value.contains("Max-Age=0")));
    }
    #[test]
    fn explicit_session_revocation_removes_only_this_accounts_remembered_records() {
        let app = super::super::tests::app();
        let session = super::super::tests::StubGateway::validated_session();
        for (token, account) in [
            ("a".repeat(64), session.record.canonical_username.clone()),
            ("b".repeat(64), "other@example.test".into()),
        ] {
            app.remembered_keys.0.lock().unwrap().insert(
                hash(&token),
                Lease {
                    account,
                    until: now() + 100,
                },
            );
        }
        app.revoke_account_remembered_keys(&session);
        let records = app.remembered_keys.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records.contains_key(&hash(&"b".repeat(64))));
    }
}
