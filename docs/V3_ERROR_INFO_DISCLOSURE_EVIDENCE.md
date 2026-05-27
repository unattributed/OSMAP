# V3 Error Handling And Information Disclosure Evidence

`OSMAP-WSTG-INFO-003` records the Slice 9 evidence lane for stack-trace,
route-inventory, execution-path, and architecture mapping coverage.

Mapped WSTG rows:

- `WSTG-v42-ERRH-02`
- `WSTG-v42-INFO-06`
- `WSTG-v42-INFO-07`
- `WSTG-v42-INFO-10`

## Stack-Trace And Error Leakage

The runner probes unauthenticated bad routes and malformed query inputs, then
fails if a response exposes panic text, stack backtraces, Rust source
locations, unwrap/expect diagnostics, private filesystem paths, or Python-style
tracebacks. stack traces are not browser-visible: public error bodies use
stable generic messages, while detailed failure reasons stay in structured
audit events and redacted WSTG evidence.

The static proof ties this to the router's generic branches:

- missing routes emit `http_route_not_found` and the browser text
  `The requested path does not exist in the current OSMAP browser slice.`
- invalid request context emits the browser text
  `Request context could not be validated.`
- route-level backend failures are rendered through stable public reason
  helpers such as `public_reason_message`

## Route And Entry-Point Inventory

The browser entry points are explicit in `src/http_runtime.rs`:

- `GET /healthz`
- `GET /login`
- `POST /login`
- `GET /`
- `GET /mailboxes`
- `GET /mailbox`
- `GET /search`
- `GET /message`
- `GET /attachment`
- `GET /compose`
- `GET /drafts`
- `GET /draft`
- `GET /sessions`
- `GET /settings`
- `POST /message/move`
- `POST /messages/move`
- `POST /messages/archive`
- `POST /send`
- `POST /drafts/save`
- `POST /drafts/delete`
- `POST /sessions/revoke`
- `POST /settings`
- `POST /logout`

## Architecture Inventory

OSMAP is a focused Rust browser access layer behind the nginx edge. Public
HTTPS and response-header policy terminate at the nginx edge. Authentication
and session decisions use local auth, TOTP, filesystem-backed session state,
and CSRF-bound browser forms. Mailbox reads and moves cross a mailbox helper
or doveadm boundary. Sending hands off through sendmail to the existing
Postfix, Dovecot, and Rspamd mail stack.

There is no JSON/GraphQL API surface in this lane; state changes are browser
form-backed routes.
