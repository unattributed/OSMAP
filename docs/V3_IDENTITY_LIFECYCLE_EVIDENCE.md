# V3 Identity Lifecycle Evidence

`OSMAP-WSTG-IDNT-001` records the Version 3 WSTG identity-lifecycle evidence
lane for role definitions, registration, account provisioning, and username
policy.

Mapped WSTG rows:

- `WSTG-v42-IDNT-01`
- `WSTG-v42-IDNT-02`
- `WSTG-v42-IDNT-03`
- `WSTG-v42-IDNT-05`

## Role Definitions

OSMAP has a single browser end-user role. The browser application lets an
authenticated mailbox user read mail, send mail, manage bounded drafts, manage
bounded mailbox actions, edit narrow display settings, and revoke browser
sessions. Operator administration, mail-stack administration, service
configuration, DNS, and host lifecycle work remain outside the browser
application.

There is no mixed user/admin mega-interface and no browser role-management
route in the reviewed OSMAP surface.

## Registration

User registration is not applicable to OSMAP. The application has no
self-service registration, signup, invitation, account-creation, or recovery
chain. The login form accepts mailbox credentials plus TOTP for an existing
mailbox identity.

There is no self-service registration in the reviewed OSMAP browser surface.

`OSMAP-WSTG-IDNT-001` probes common registration and signup paths and fails if
any of them becomes a served registration form.

## Account Provisioning

Account provisioning is not a browser-facing OSMAP feature. Existing account
credentials and mail storage patterns remain authoritative, and mailbox
account provisioning remains an operator-controlled mail-stack process outside
OSMAP.

There is no browser account provisioning surface in OSMAP.

`OSMAP-WSTG-IDNT-001` probes common provisioning, invitation, user-management,
and role-management paths and fails if any of them becomes a served identity
administration surface.

## Username Policy

Mailbox credentials are the primary identity input for OSMAP browser login.
The submitted username is bounded before backend authentication: it must be
non-empty, must not exceed `DEFAULT_USERNAME_MAX_LEN`, and must not contain
control characters. Backend authentication then resolves the canonical mailbox
identity through Dovecot rather than through an OSMAP-local account database.
