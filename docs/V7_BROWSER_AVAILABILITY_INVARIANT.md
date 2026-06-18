# V7 Browser Availability Invariant

Status: Satisfied in production on 2026-06-19

OSMAP is unusable when nginx cannot reach the browser backend. V7 therefore
cannot be called complete solely because the binary starts, `/healthz` passes,
or a short post-deployment probe succeeds.

The production browser-entry invariant is:

- `osmap_serve` and `osmap_mailbox_helper` report healthy;
- the backend listens only on the reviewed loopback address;
- `GET /` returns `303` with `Location: /login`;
- `GET /login` returns `200` and the OSMAP login page;
- invalid and successful `POST /login` requests do not terminate the server;
- the same checks still pass after login submission and after a hold period;
- an unexpected browser-entry failure triggers bounded service recovery and an
  operator-visible failure if recovery does not restore the invariant.

The repo-owned OpenBSD check and recovery command is:

```text
/usr/local/libexec/osmap/osmap-login-availability.ksh --recover
```

It sends only unauthenticated local `GET` requests and never handles, records,
or synthesizes credentials, cookies, TOTP codes, CSRF tokens, or mailbox
content. Install it from
`maint/openbsd/libexec/osmap-login-availability.ksh` and run it once per minute
through the host's bounded cron wrapper.

V7 closure requires a real operator login test because only the operator can
safely exercise the successful password-plus-TOTP path without disclosing
credentials. A successful GET-only deployment check is insufficient evidence.

The production closure test completed at `2026-06-18T18:43:20Z`. A fresh
Firefox password-plus-TOTP login issued a session and rendered the mailbox.
The backend remained healthy and nginx recorded no new upstream errors.

This test also closed the earlier login-path failure. The failure was caused
by V6 session locking calling `flock(2)` while the enforced serve pledge
profile omitted the required `flock` promise. Commit `c937c5c` adds that
promise and preserves the existing session lock.
