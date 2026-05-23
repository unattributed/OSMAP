# Version 3 Form Route And State-Transition Evidence

## Scope

OSMAP does not expose a JSON/REST API, GraphQL API, or separate frontend/backend
API layer. It exposes browser form routes that eventually call bounded local
mail-system commands where needed.

Mapped WSTG rows:

- `OSMAP-WSTG-BUSL-005`
- `WSTG-v42-BUSL-01` business logic data validation
- `WSTG-v42-BUSL-02` ability to forge requests
- `WSTG-v42-BUSL-03` integrity checks
- `WSTG-v42-BUSL-05` number-of-times/function-use limits
- `WSTG-v42-BUSL-06` workflow circumvention
- `WSTG-v42-BUSL-07` defenses against application misuse
- `OSMAP-WSTG-APIT-001`
- `WSTG-v42-APIT-01` GraphQL

## Form Route Evidence

`OSMAP-WSTG-BUSL-005` records static evidence for browser form-backed route
and state-transition controls:

- state-changing form routes require authenticated sessions, valid CSRF, and
  same-origin request metadata via `require_valid_csrf`
- cross-origin form attempts are covered by
  `authenticated_post_routes_reject_cross_origin_headers`
- duplicate URL-encoded fields are covered by
  `rejects_duplicate_urlencoded_fields`
- tampered and mismatched mailbox/UID pairs are covered by
  `message_move_rejects_tampered_invalid_uid_without_success_redirect` and
  `message_move_rejects_mismatched_mailbox_uid_tuple`
- bulk misuse limits are covered by
  `bulk_move_rejects_oversized_selection_before_moving`
- draft lifecycle transitions are covered by
  `draft_delete_removes_saved_draft`
- send/draft transition integrity is covered by
  `send_success_deletes_draft_after_accepted_handoff` and
  `send_failure_preserves_draft`
- session revocation state changes are covered by
  `session_revoke_all_sessions_clears_current_cookie`

## GraphQL Applicability

`OSMAP-WSTG-APIT-001` records the GraphQL applicability decision.

GraphQL is not applicable. OSMAP has no GraphQL endpoint, no GraphQL dependency,
no schema, and no resolver layer. OSMAP uses browser form routes rather than API routes.

Future trigger: if OSMAP adds JSON/REST API routes, GraphQL, or another
non-browser form state-transition protocol, the affected rows must move from
static proof to dynamic negative tests.
