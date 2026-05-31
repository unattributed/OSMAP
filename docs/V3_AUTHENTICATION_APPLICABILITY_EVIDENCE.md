# V3 Authentication Applicability Evidence

`OSMAP-WSTG-ATHN-005` records the Version 3 WSTG authentication-feature
evidence lane for default credentials, authentication-schema bypass,
remember-password behavior, password-policy applicability, security questions,
and password change or reset functionality.

Mapped WSTG rows:

- `WSTG-v42-ATHN-02`
- `WSTG-v42-ATHN-04`
- `WSTG-v42-ATHN-05`
- `WSTG-v42-ATHN-07`
- `WSTG-v42-ATHN-08`
- `WSTG-v42-ATHN-09`

## Default Credentials

OSMAP has no default credentials because it has no browser-local account
database, seeded browser accounts, installer-created users, or application
administrator account. Mailbox credentials are the primary identity input and
are verified by the configured mail-stack authentication backend.

## Authentication Bypass

OSMAP has no browser authentication bypass route. Protected browser routes are
served only after session-cookie validation through `require_validated_session`,
and unauthenticated requests to protected pages redirect to `/login` rather
than rendering mailbox, session, or settings state.

`OSMAP-WSTG-ATHN-005` probes protected routes without a session and fails if
they render authenticated content.

## Remember Password

OSMAP has no remember-password feature. The login form submits mailbox
credentials for immediate backend authentication, the submitted password is
bounded by `DEFAULT_PASSWORD_MAX_LEN`, and the browser session cookie is the
only browser-side continuity token.

## Password Policy

OSMAP has no browser password policy surface. It neither creates passwords nor
changes mailbox passwords. The applicable browser-side control is bounded input
handling before backend authentication: usernames and passwords must be
non-empty, bounded, and free of control characters. Password-strength,
rotation, and mailbox lifecycle policy remain external mail-stack controls.

## Security Questions

OSMAP has no security questions. It does not collect challenge answers or use
knowledge-based recovery as an authentication factor.

## Password Change Or Reset

OSMAP has no browser password change or reset functionality. Account recovery
is intentionally operator-controlled outside OSMAP so the browser application
does not add a weaker automated recovery path around mailbox credentials or
`RequiredSecondFactor::Totp`.
