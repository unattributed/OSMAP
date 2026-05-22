# V3 Session Lifecycle Evidence

## Scope

`OSMAP-WSTG-SESS-006` records the Slice 3 evidence lane for the remaining WSTG
session-management rows:

- `WSTG-v42-SESS-01`, session management schema
- `WSTG-v42-SESS-04`, exposed session variables
- `WSTG-v42-SESS-07`, session timeout
- `WSTG-v42-SESS-08`, session puzzling
- `WSTG-v42-SESS-09`, session hijacking and stale-token reuse

Cookie attributes, session fixation, CSRF, and cache behavior remain covered by
the existing `OSMAP-WSTG-SESS-001` through `OSMAP-WSTG-SESS-005` checks.

## Dynamic Evidence

The WSTG runner logs in through the real password-plus-TOTP browser path,
loads `/mailboxes` to prove protected-route access, posts a valid CSRF-bound
logout, and then retries the old session cookie against `/mailboxes`.

The old cookie must not return protected mailbox content. A synthetic stale
cookie must also fail closed.

The committed evidence is redacted: raw session cookies, `Set-Cookie` bearer
values, and CSRF token values must be absent.

## Static Evidence

The static evidence ties the browser behavior to the session model:

- `DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS` defines the default idle timeout
- `timeout_reason` enforces absolute expiry and idle timeout during validation
  and listing
- `validate_session_rejects_expired_records` proves absolute expiry rejection
- `validate_session_auto_revokes_idle_records` proves idle-timeout rejection
- `list_sessions_auto_revokes_idle_records` proves listing updates idle state
- `simultaneous_session_validations_do_not_corrupt_last_seen` proves concurrent
  validation safety
- `logout_racing_with_validation_leaves_session_revoked` proves logout wins
  over stale token reuse
- `revoke_all_racing_with_listing_leaves_all_sessions_revoked` proves
  revoke-all/list races settle to revoked state
- `revoke_all_for_user_except_preserves_current_session` proves the selected
  concurrent-session policy

Version 3 intentionally allows concurrent browser sessions. The policy relies
on bounded lifetime, idle timeout, visible session metadata, and user-driven
revocation instead of silent eviction. OSMAP does not add remembered-device
cookies. The phrase remembered-device cookies is an explicit release marker:
OSMAP avoids persistent device identifiers.

Raw bearer tokens are not written to the session store. Browser-visible
metadata uses normalized device labels and session references rather than raw
bearer values.
