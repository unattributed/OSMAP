# Internal admin reader compatibility

The Rust backend remains an internal/local component. These files are reviewed
installation examples, not an installed service or automatic provisioner.
`client.cnf.example` matches the fixed client path used by the backend;
`select-grants.sql` lists only its current column-level reads. Choose and
privately provision SQL authentication and the service OS identity at deployment.
Keep the client file root/service-readable and all admin factor/replay/session/
throttle/generation roots owner-only. The public Web receives no SQL credential
or access to those roots. Do not install these examples during fixture testing.

Existing hashes stay byte-for-byte in SQL. Verification accepts bcrypt `$2b$`
and `$2y$` at costs 10–12; a temporary in-memory `$2y$` verification copy uses the
OpenBSD-compatible `$2b$` marker. No PHP or predecessor application runs.
[Openwall documents their equivalence](https://www.openwall.com/crypt/).

Read-only system scope requires both `admin.superadmin=1` and an active `ALL`
grant. Either indicator alone refuses; explicit domain admins retain their
listed scope. Authority changes observed by the backend revoke old sessions.
External changes reverted between observations still require a future writer
that advances revocation synchronously. A remote entry also needs verified
per-client identity rather than this internal/local UID throttle source.
