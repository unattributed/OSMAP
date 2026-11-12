# Account-based mail storage and quota

OSMAP uses the authenticated mailbox account's existing Dovecot userdb mapping.
Mailbox paths and quota limits belong to the mail stack, not to a named OSMAP
service. Adding an account must not require an OSMAP source edit or rc script.
Documents is removed from the current product scope. Retained Documents data
must not be deleted as part of disabling its UI or retiring old infrastructure.

## Existing SQL userdb integration

Preserve the host's database connection, password query, UID/GID convention and
authentication settings. For a PostfixAdmin mailbox table using the existing
`maildir`, `quota` and `active` fields, the relevant user lookup is:

```sql
SELECT CONCAT('/var/vmail/', maildir) AS home,
       CONCAT('maildir:/var/vmail/', maildir) AS mail,
       2000 AS uid,
       2000 AS gid,
       quota AS osmap_configured_quota,
       CONCAT('*:bytes=', quota) AS quota_rule
FROM mailbox
WHERE username = '%u' AND active = '1'
```

The shared vmail UID/GID above is a deployment example, not a required OSMAP
identity. Use the actual mail stack's owner IDs. The mailbox path and quota are
resolved separately for each username. Zero quota is unlimited; an absent
reporting field is unreported, not zero. Never accept a browser-supplied native
path or UID as authority.

Dovecot 2.3's existing quota plugin can use `quota = count:User quota` with
`quota_vsizes = yes`, a per-user `quota_rule`, and the plugin enabled for the
actual mail-writing protocols. Validate the installed version's syntax with
`doveconf` before applying configuration. Query the effective userdb and native
quota result for each test account. Prove over-quota refusal with a disposable
local message; configured limits alone do not prove enforcement. No external
message or real-user quota exhaustion is required.

For Maildir homes containing dot-files such as the existing `.dovecot.sieve`
symlink, set `maildir_stat_dirs = yes`. Otherwise native mailbox enumeration
and the count quota backend can mistake that file for a mailbox and refuse.
Preserve the Sieve file and verify the actual un-overridden native quota query.

OSMAP's Rust storage report reads mailbox message sizes and configured quota
through the existing authenticated helper. Its displayed usage is message
size, excluding disk overhead. It does not claim that a successful report
independently proves quota enforcement.

## Replacing a historical account volume

First locate and retain every source home, filesystem image, external index and
control directory, and the exact configuration. An absent mounted path is not
an empty mailbox. Work from a verified copy before changing the live mapping.

Preserve raw message bytes, mailbox GUIDs, UIDVALIDITY/UIDNEXT, message UIDs,
message GUIDs, flags and subscriptions. External Maildir control/index layouts
can store Inbox metadata under `.INBOX`; copying these directories into a
colocated Maildir without translating Inbox metadata creates a new Inbox
identity. Compare actual native views before and after the translation.

Cut over only the verified account location, preserve the previous home and
image, and refresh the mail stack's configuration without a public-service
stop. After an authorized Dovecot configuration change, follow the existing
[account authority refresh](README.md#account-authority-after-dovecot-configuration-changes)
procedure; stale account-service configuration can refuse otherwise valid
logins. A rollback after new writes requires delta reconciliation, not a blind
switch to an older mailbox.

Retire the old mount script and fstab entries only after verified ordinary
storage works. Keep retained images and backups private. Do not reuse an
unknown vnode device or delete backing data during service cleanup.

## Required verification

- Two dedicated development accounts resolve distinct mailbox paths and limits.
- Their actual native quotas reject an oversized local save.
- Their Rust/helper reports and page projections match their own native facts.
- Foreign-account helper responses and forged account authority are refused.
- Removed Documents routes cannot read or mutate retained Documents state.
- The migrated mailbox's bytes, identities, flags and subscriptions are preserved.
- Current signed admission and ordinary password-plus-TOTP login remain valid.

Native and helper tests do not constitute owner browser UAT or production
security-release approval.
