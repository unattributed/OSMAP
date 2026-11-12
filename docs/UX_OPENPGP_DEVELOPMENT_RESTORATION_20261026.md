# Local development OpenPGP restoration, 2026-10-26

The owner reported that Duncan's previously approved Proton recipient key was
missing from the installed UI, with OpenPGP unavailable and import/policy changes
disabled. This is a regression to resolve before S04-03 readiness.

The local-development cutover replaced the frontend environment with a profile
that omitted all nine OpenPGP helper configuration values. It also selected a
new settings root without preserving the existing account binding record. The
three helpers remain healthy. The original revision 5 account/recipient binding
record still exists in the previous settings root; the new binding directory is
absent. Missing configuration and an empty store explain the observed UI without
establishing key deletion. The existing encrypted key homes are separate from
both frontend settings roots.

The bounded correction restores only the three previously configured helper
triples and copies the exact existing Duncan binding record into the absent
development binding directory. The original record remains retained. Existing
development settings, session authority, password results, TOTP and replay state
are preserved. The frontend may restart; the mail backend and OpenPGP helpers
remain running. No password, policy selection, trust decision, key import,
private-key handling or mail transmission is part of this restoration.

Qualification uses the same native Rust client library as installed Web
`558a165e…`: authenticated inventory read, public-administration snapshot,
account-private binding read, recipient encryption preflight and encryption of
fixed synthetic content in memory through the actual crypto helper. No message
is submitted. Configuration and binding bytes are checked, together with the
pre-existing development state. A refusal stops the dependent action and retains
the named observation; successful service startup alone does not qualify
encryption or browser mutation.

The initial native probe correctly refused with `INVENTORY_CONFIG` against the
installed environment. An earlier invocation could not traverse the operator's
private home directory; the root-owned probe was then installed in the existing
libexec directory. That preparation failure did not exercise any helper or
change account state. Restoration and post-correction qualification are pending.

The selective restoration completed successfully. The current profile retains
all previous non-OpenPGP bytes and adds the nine original entries. Original and
restored binding SHA256 are both
`1b52463893a01899e692e53dd5773077211ab61e2496f26d138f7df0a219ffdd`.
The pre-existing development-state checksum verification passed while Web was
stopped. The native probe then confirmed two public keys, an authenticated admin
snapshot, the original account and recipient binding at revision 5, successful
recipient encryption preflight and actual native encryption of synthetic content.
No SMTP submission, password change, key import/removal or policy mutation ran.

Installed Web PID 81887 held the executable inode matching `558a165e…` and the
loopback listener. Certificate-verified public HTTPS login returned 200. Web,
account service, all three OpenPGP helpers, Dovecot, Postfix and MariaDB were
healthy after restoration. The root-only backup is
`/var/backups/osmap-openpgp-restoration-20261026-01`. Whole-action elapsed time was
not separately measured; the execution had a 120-second technical bound.
Independent actual-result review SHA256:
`5953a9d7d2a660011f773f2d2b841ff5648f9a935c02e4bfdd59d015de5793be`.

Refreshing the existing browser should now show the original account/recipient
and available inventory. Browser key/policy mutation still requires the owner's
current password and a fresh authenticator code; no owner-authority operation
was impersonated for this restoration. This native qualification does not claim
a new delivered email or owner usability acceptance. The development profile
example now includes the existing helper triples and the binding-preservation
requirement so a future profile installation does not repeat the omission.
