# V3 Authorization And Account Isolation

## Scope

This document records the Slice 2 authorization and account-isolation evidence
model for `OSMAP-WSTG-ATHZ-001`.

OSMAP does not expose a browser-controlled user identifier on mailbox, message,
attachment, draft, send, search, or bulk-action routes. The authenticated
session record supplies `canonical_username`, and route parameters are limited
to mailbox names, UIDs, draft IDs, selected attachment parts, and action
fields inside that user's namespace.

## Dynamic Fixture

The WSTG runner uses one primary authenticated account and one secondary
controlled mailbox fixture. This secondary controlled mailbox fixture is
prepared through host-assisted mail delivery:

- the primary account logs in with password plus TOTP
- the host-assisted fixture injects one secondary `INBOX` message with an
  attachment, one secondary `Sent` message, and one generated secondary-only
  mailbox containing a unique message and attachment
- the primary session probes the secondary UID values and the secondary-only
  mailbox/UID tuple through message, attachment, sent-mail, all-mailbox search,
  and mailbox-name tampering routes
- evidence passes only when the secondary subjects and attachment marker are
  absent from primary-session responses
- route authorization bypass probes with no cookie and a stale cookie must not
  return protected mailbox content

The fixture report is redacted and must not include passwords, password hashes,
TOTP material, session cookies, CSRF tokens, private message bodies, attachment
bodies, provider secrets, or host secrets.

## Static Boundary

The static boundary evidence covers routes where destructive live mutation is
not required for every release candidate:

- mailbox and message list routes call `list_for_validated_session`
- message view routes call `fetch_for_validated_session`
- attachment routes call `download_for_validated_session`
- send routes call `submit_for_validated_session`
- draft routes call owner-scoped load, save, list, and `delete_draft`
- draft storage keeps owner namespaces separate, including
  `file_draft_store_scopes_loads_by_owner`
- search rejects mailbox names that are not in the validated user's mailbox
  list through `message_search_mailbox_rejected`
- bulk move throttling uses
  `MessageMoveThrottleKey::for_canonical_user_and_remote_addr`
- helper grants include grant canonical_username binding for mailbox, UID,
  part, and mutation operations

## Release Expectation

`OSMAP-WSTG-ATHZ-001` maps WSTG authorization bypass, privilege escalation, and
IDOR coverage for the OSMAP browser surface. Developer runs may skip it without
credentials or host access, but V3 release mode must provide the authenticated,
TOTP-backed, host-assisted negative evidence.
