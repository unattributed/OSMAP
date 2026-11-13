# OpenBSD Service Guidance

For mailbox locations and quota, use [account-based mail storage](MAIL_STORAGE.md).
The mail stack owns per-account paths and limits; OSMAP reuses its authenticated
Rust/helper report. The historical named storage volume service is retired.
Documents remains removed from product scope; retained data is preserved.

## Purpose

This directory carries the first repo-owned OpenBSD operator scaffolding for
the split OSMAP runtime:

- one web-facing `serve` process
- one local-only `mailbox-helper` process
- one shared Unix socket boundary between them

The goal is to make the current Version 1 deployment shape reviewable and
repeatable without pretending packaging or `rc.d` integration is already final.

## Files

- `osmap-serve.env.example`
- `osmap-mailbox-helper.env.example`
- `libexec/osmap-serve-run.ksh`
- `libexec/osmap-mailbox-helper-run.ksh`
- `rc.d/osmap_serve`
- `rc.d/osmap_mailbox_helper`

These files are intentionally non-secret and are meant to be copied into
operator-managed paths such as `/etc/osmap/`, `/usr/local/libexec/osmap/`, and
`/etc/rc.d/`.

## Suggested Runtime Split

The current least-privilege OpenBSD posture is:

- `nginx` stays at the public TLS edge
- OSMAP `serve` runs as `_osmap`
- production `serve` refuses non-loopback listeners so browser HTTP cannot be
  exposed directly outside the reviewed TLS edge
- OSMAP `mailbox-helper` runs as `vmail`
- browser auth uses a dedicated Dovecot auth listener such as
  `/var/run/osmap-auth`
- mailbox helper lookups use a dedicated Dovecot userdb listener such as
  `/var/run/osmap-userdb`
- mailbox helper startup also needs `OSMAP_DOVEADM_AUTH_SOCKET_PATH` so the
  helper can derive the one trusted local caller identity from the auth-socket
  owner before it accepts mailbox requests
- mailbox helper startup also needs `OSMAP_TRUSTED_WEB_RUNTIME_UID`, and that
  value must match the dedicated `_osmap` UID expected on the host
- the browser runtime reaches the helper over one local Unix socket

For the validated `mail.blackbagsecurity.com` edge move from Roundcube to
OSMAP, the reviewed host-specific browser-edge and PF artifacts now live under
`maint/openbsd/mail.blackbagsecurity.com/`.

The example env files in this directory use:

- `/var/lib/osmap` as the web runtime state root
- `/var/lib/osmap-helper` as the helper state root
- `/var/lib/osmap-helper/run/mailbox-helper.sock` as the shared helper socket
- `/var/log/osmap/serve.log` as the web runtime service log
- `/var/log/osmap/mailbox-helper.log` as the mailbox-helper service log

That keeps the mailbox helper's writable tree separate from the browser
runtime's state while still making the helper boundary explicit. Nginx logs are
edge evidence only; OSMAP daemon diagnostics and structured security events must
be available in the OSMAP-owned service logs.

## Socket Ownership Expectations

The mailbox helper currently creates its Unix socket with mode `0660`.

That means operators should make the socket directory and socket ownership
story explicit. One conservative pattern is:

- own the helper state root by `vmail`
- put `_osmap` and `vmail` in one shared group used only for this socket
- make `/var/lib/osmap-helper` and `/var/lib/osmap-helper/run` searchable by
  that shared group

The important property is not one specific group name. It is that `_osmap`
can connect to the helper socket without giving unrelated users access.

## Service Startup Order

Start the helper before the web-facing runtime.

A conservative operator sequence is:

1. install the example env files into `/etc/osmap/` and adjust paths as needed
2. create the state directories with ownership that matches the selected
   runtime users and shared socket group
3. create `/var/log/osmap` and the two service log files with ownership that
   matches the selected runtime users
4. install the launcher and `rc.d` examples into their operator-managed paths
5. start `osmap_mailbox_helper`
6. confirm the helper socket exists at the configured path
7. start `osmap_serve`
8. keep nginx pointed at the loopback HTTP listener

## Browser Entry Availability

Production is not healthy unless the browser entry path works end to end:

- `GET /` returns `303` with `Location: /login`
- `GET /login` returns `200` and the OSMAP login page

Install `libexec/osmap-login-availability.ksh` as
`/usr/local/libexec/osmap/osmap-login-availability.ksh`. Run
`--check-only` during deployment validation and run `--recover` once per minute
through the host's bounded cron wrapper. Recovery restarts only `osmap_serve`
and then rechecks both browser paths. Persistent failure remains non-zero and
operator-visible.

GET-only checks do not prove the authentication path. Every production release
also requires an operator-controlled password-plus-TOTP login followed by
service, listener, root redirect, and login-page revalidation.

### Account authority after Dovecot configuration changes

The persistent Rust `osmap_account_password` service pins the protected Dovecot
configuration and authentication endpoint it observes at startup. Even a valid
read-only `user_query` metadata addition changes that snapshot. A running process
and HTTP200 login form can therefore coexist with refused account admission.

After an authorized Dovecot configuration change/reload on a host using this
service, refresh dependencies in this order:

1. Restart `osmap_account_password` to validate and observe the current Dovecot
   configuration. Preserve its existing configuration, keys and epoch store.
2. Restart `osmap_serve` afterward: its account client pins the admission socket
   identity and must observe the replacement endpoint.
3. As the existing Web identity, run the matching Rust ignored test
   `account_admission_runtime::tests::native_installed_epoch_readiness`, using
   the configured admission key and current active account epoch. Require its
   fixed `INSTALLED_EPOCH_READINESS=PASS` marker and one actual passing test.
   This read-only check submits no password, consumes no TOTP and changes no
   credential. Do not reset an epoch or disable custody checks to make it pass.
4. Verify one fresh owner password-plus-TOTP sign-in before accepting the journey.

Mailbox/report rendering tests remain useful within their own scope and cannot
replace this admission check. Crypto/inventory services need no restart for this
dependency refresh. This procedure does not authorize a mail configuration change
or mail-service interruption by itself.

The `rc.d` examples assume:

- `/usr/local/bin/osmap` is the installed OSMAP binary
- `/etc/osmap/osmap-serve.env` holds the browser-facing env file
- `/etc/osmap/osmap-mailbox-helper.env` holds the helper env file
- the helper env file includes both `OSMAP_DOVEADM_AUTH_SOCKET_PATH` and
  `OSMAP_DOVEADM_USERDB_SOCKET_PATH`
- the helper env file also includes `OSMAP_TRUSTED_WEB_RUNTIME_UID`, typically
  set from `id -u _osmap`
- `/usr/local/libexec/osmap/` holds the launcher scripts

Those launchers source the env file and then execute one explicit OSMAP CLI
mode so the final process table stays readable as:

- `/usr/local/bin/osmap serve`
- `/usr/local/bin/osmap mailbox-helper`

That keeps `rc.d` supervision and `pgrep` matching more honest than a generic
shell wrapper name alone.

## Validation Notes

The quickest local checks after wiring the env files are:

- run `OSMAP_RUN_MODE=bootstrap` with the same production env to confirm config
  validity before daemon startup
- or use the example `rc.d` scripts' `configtest` action after installation
- check that the helper socket appears at the configured path
- check that `/var/log/osmap/serve.log` and
  `/var/log/osmap/mailbox-helper.log` exist and receive OSMAP events
- check that `_osmap` can connect to that socket without needing broader mail
  storage authority
- keep `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only` for first host dry runs, then
  move to `enforce`

For repo-owned live-host validation commands, use
`maint/live/osmap-host-validate.ksh` from the standard host checkout.

If the validating workstation can reach `mail.blackbagsecurity.com` over SSH
and the host-side checkout is already `~/OSMAP`, the repo also provides
`maint/live/osmap-run-v1-closeout-over-ssh.sh` to invoke the current
authoritative V1 closeout wrapper remotely and fetch the resulting summary
report back to the local machine.

## Bounded Toronto recovery-contact activation

`provision-recovery-contact.py` prepares the existing native account pair for the
explicitly authorized Duncan rollout on Toronto. It is an operational repair
method, not the independent-host installer (that portability work remains open).
Run its read-only preflight first with `--expected-host mail.blackbagsecurity.com
--account "$RECOVERY_ACCOUNT"`; `--apply` then creates previously absent
root/Web purpose-key copies, matched enrollment, epoch-zero state and the dedicated
hash identity. Existing state refuses before publication. Retain its structured
receipt on the host, read it back and hash it before removing any staged source.
Partial births remain retained for exact-owned recovery.

Install the matching reviewed `account-passwd` and existing rc entry separately.
Start and verify the account service before appending complete Web client settings,
the Duncan-only rollout selector and recovery-contact delivery configuration.
Restart OSMAP Web only. A fresh Duncan password-plus-TOTP login is required because
legacy sessions have no account epoch. No owner password/factor/contact is changed
by provisioning, and no obsd1 record or key is copied. Controlled installed QA and
owner contact proof are separate outcomes.

This contact rollout creates neither SQL writer credentials nor factor-reset
configuration. Those operations remain separately unqualified; a visible related
account form is not evidence that its backend operation is ready. Public mail
services and their configuration are preserved. Test actual native startup and
recovery-contact submission before claiming contact readiness.

Use the reviewed optimized helper artifact. Its one-time installed-library
verification has a finite 30-second startup budget; request deadlines are unchanged.
A born process, early `rcctl check` or newly bound socket alone is not readiness.
Verify a real signed account-admission response before starting Web, then require
the public TLS login entry200 before a credential-backed journey. Web captures
account client capability at startup; after replacing/restarting its account
helper, restart Web only after that authority is ready.

Retain the env file's root ownership, Web-readable group and 0640 mode when
replacing it; private Web key copies remain Web-owned 0600. Enable the OSMAP account
service and preserve all other service order while placing it immediately before
Web. The current process-only rc check does not prove reboot readiness. This
repair's installed contact/persistence results qualify its controlled current-host
journey, not boot sequencing or an independent-host installation.
