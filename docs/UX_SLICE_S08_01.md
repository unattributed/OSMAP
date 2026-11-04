# S08-01 — Documents and authoritative account storage

## Current reporting delivery — operator simplification, 2026-11-05

Mailbox migration is set aside. The immediate delivery reports the signed-in
account's existing message-size total and configured quota using two existing
Dovecot reads through the authenticated Rust helper. `MailStorageReport` is
separate from enforcement-qualified `QuotaStatus` and cannot enable writes.
Missing quota, explicitly unlimited quota and failed reads stay distinct.

On obsd1, the metadata-only userdb query addition exposes the existing
PostfixAdmin `quota` column as `osmap_configured_quota`; the original home, mail,
UID and GID read back unchanged. Authentication queries and database privileges
are unchanged. Bounded Dovecot reload and service checks passed. A fresh native
read observed 172605611 virtual message bytes and 102400000 configured quota
bytes. The UI labels message bytes separately from filesystem overhead and
states that enforcement has not been verified. The reporting code includes
native parser, signed helper round-trip, account-isolation and both-page tests.
Matching installed qualification is pending; this is not full slice acceptance.

Current reporting-source validation: five backend/authenticated-helper tests,
the dashboard/General route regression, storage rendering and welcome tests pass.
The full local library suite passes 2232 tests with 87 explicit native ignores;
strict Clippy and the unchanged CWE guard pass. Matching OpenBSD focused tests
pass five cases; the installed smoke is explicitly ignored until dispatched.
Two installation-check failures are retained separately: an OpenBSD shell role
selector failed, then an immediate HTTPS check failed after both candidate
processes loaded. Both attempts restored the previous binary and running roles;
configuration and crypto-agent readbacks match. The second probe's initial
HTTP code was not retained and remains unknown. Independent reassessment reuses
the established bounded readiness polling before another installation attempt.

## Outcome and scope

Complete the existing account-private Documents journey: upload, list, folders,
search, sort, views, exact isolated download, Bin, restore and confirmed retention
cleanup. Documents and ordinary mail consume one authoritative account quota.
Dashboard and General Settings reuse the same account-scoped storage reads.
Document payload totals are labelled separately from stored MIME usage and are
not added onto the shared total. Keep Folders in the primary navigation and
provide a qualified secondary Documents destination.

Source baseline: `0c31a1ff7618ca82dff15f98a189bd301e0058e7`.
Root owns integration, HTTP wiring, the ledger and the single native/host/Git
queue. The existing helper engineer owns Documents summary/native tests; the UI
engineer owns shared storage presentation; the independent reviewer checks source,
native and installation evidence. No new Python tooling or dependency is planned.

## Actual starting conditions

On obsd1, Duncan's PostfixAdmin quota is 102400000 bytes (100 units using its
1024000 multiplier), not production mail's displayed 200 units. The local quota
plugin is disabled. A scoped read with maildir_stat_dirs=yes measures 172605611
virtual bytes over 26 mailboxes and 475 messages; the unqualified wildcard read
hits the existing dovecot.sieve non-directory. Never activate an insufficient
limit or infer authoritative quota from partial metadata. The owner has been
asked to select a development quota or retain the existing over-quota refusal.

Existing Some(QuotaStatus) is an enforcement attestation, not advisory usage.
Preserve that meaning. Reuse current Rust stores, authenticated helper operations,
Dovecot tools and owned disposable fixtures. Retain the 2026-10-06 first-save,
transport, cleanup and concurrency qualification gaps recorded in the ledger.
Native config/readiness alone is not proof of concurrent reservation enforcement.

## T01–T09

| Task | Required observation |
| --- | --- |
| T01 | Fresh local quota/config/schema/command inventory and a bounded reuse map. |
| T02 | Rust account isolation, validated index summaries, limits, CSRF, stale IDs/revisions, and unsafe MIME/name refusal. |
| T03 | Real native first upload, exact download, folders and Bin/restore lifecycle. |
| T04 | Concurrent ordinary-mail and Documents writes cannot bypass the common limit; absent authority refuses writes. |
| T05 | Composed HTTP/helper ownership, maximum-size transfer, forced attachment isolation and negative requests. |
| T06 | Interrupted changes retain explicit uncertainty; inspection reconciles without repeating a save or releasing unproved reservations. |
| T07 | Bin stays charged; only confirmed eligible deletion releases authoritative storage. |
| T08 | Matching installed artifacts, user-specific display, service/state preservation and independent review. |
| T09 | Owner uploads, finds, downloads, bins and restores a controlled file and checks storage. |

Tests remain NOT_RUN until actual matching receipts are recorded. Root uses the
existing bounded native runner and exact-owned scratch cleanup; no public mail
stop/reload/configuration mutation is authorized by an isolated fixture. A required
live quota activation must be prepared and independently reviewed before obtaining
any additional approval required by the existing public-service boundary. Native
operations and cleanup have finite deadlines; two failures at one boundary require
combined reassessment. No credentials, owner key operation, production mail change,
automatic retry of ambiguous writes or frozen-plan modification is in scope.

Private evidence root:
`/home/foo/Downloads/osmap-ux-s08/completion-20261104/`.
Earlier accepted S07 and folder evidence remain intact. S08-01 and owner acceptance
remain open until the outcome and all required tests are complete.

## Observed failure and smallest safe correction — 2026-11-04

The local Rust suite initially passed 2211 tests (87 explicit native ignores).
Focused storage/HTTP tests establish account isolation, validated summaries and
read-only propagation into dashboard and General Settings. These are source
results, not installed Documents acceptance.

The first native bundle omitted compile-time fixture resources; no test ran.
The corrected bundle compiled on obsd1 in 123 seconds. Its first test stopped at
the owned userdb bind because the nested temporary path exceeded SUN_LEN, before
any backend write. Root and the independent reviewer inspected both failures
and reused the matching binary with the existing short TMPDIR=/tmp recipe.
Both setup failures remain retained separately.

That run passed first upload/exact download, Bin/restore, confirmed expunge and
pre-dispatch refusal. The next cross-mailbox concurrency check FAILED: three
12-KiB candidates were all accepted after a 48-KiB seed under a 64-KiB limit.
Independent stored virtual bytes and the native counter both read 86016 bytes
against 65536. This is a demonstrated admission race, not stale reporting. The
test took 2.47 seconds; its state is retained. IMAP/LMTP participation remains
unqualified and the all-writer requirement is not met.

The safety correction keeps enforcement-qualified QuotaStatus unavailable for
every driver without a demonstrated shared concurrent authority. No driver is
currently qualified. Count/dict/maildir/fs configuration strings cannot enable
Documents writes by themselves. Focused Rust regression proves refusal before
native mailbox lookup/create/save/move, with no pending Store record; existing
read/download/reconciliation code is preserved. This correction is not a
completed Documents implementation or a quota-infrastructure solution.

The ignored native first-upload fixture still uses count and therefore refuses
before its lifecycle under the corrected current source. It must use a genuinely
qualified authority before it can provide a current positive result. The exact
older source archive 2ee81b0a, compiled test binary ba13f4b1 and native3 log remain
the retained race reproducer; no assertion was weakened to turn that failure green.

Read-only topology inspection shows all active mailbox lookups use fixed
UID/GID 2000 on /var FFS, with no filesystem quota configured in the observed fstab/mount data. A filesystem quota for
that shared UID would combine accounts and cannot satisfy the account boundary.
The smallest native hard-limit candidate is separate per-account filesystem
ownership and FFS hard quota, with Dovecot fs reporting and control/index
headroom. That changes mail-storage infrastructure and accounting units; it
needs an isolated native proof and a concrete reviewed rollout before any
additional public-configuration authority is sought. A new OSMAP-only mutex or
Rust quota broker would not cover ordinary mail writers and is not proposed.

Increasing Duncan's quota alone cannot repair the race. No quota, account,
public mail configuration, service restart or owner key/password change has
been performed. Five checked service roles remain healthy. T04 is FAIL; native
chain, installation and T09 remain open. Do not request owner functional UAT
while the shared authority is unresolved.

Normal source preservation retained a first pre-push refusal: the full Rust
suite passed 2213 tests (0 failures, 87 explicit native ignores), then strict
Clippy rejected a collapsible cleanup conditional in the native fixture. The
conditional was collapsed without changing ownership or cleanup behaviour;
strict all-target Clippy and formatting then passed. The ordinary final push
hook remains mandatory. Signed source preservation is independent of the
failed native quota requirement and does not complete this slice.

## Authorized continuation — 2026-11-04

The owner explicitly directs autonomous S08 completion with full authority. This
resolves the proposed obsd1-only native storage/quota authority question. Root
first qualifies a fresh disposable 64 MiB FFS vnode volume using existing UID1000,
with no passwd/group changes. A root-only Rust preparation sets a finite user
hard quota; nonroot native workers exercise save/read/concurrency/expunge. Index
and control files live on a different filesystem. The expected observation is
that physical allocated bytes cannot exceed the hard limit, refused saves leave
no visible complete candidate, and confirmed expunge restores capacity. Full
Documents/helper/HTTP, IMAP and LMTP qualification follow; no driver is admitted
from configuration or this narrower first test alone.

Each native stage is bounded to 130 seconds; compilation to 600 seconds. Root
verifies the exact new image/device/mount before format and quota operations,
retains diagnostics on failure, and tears down only that owned volume. Two
failures at one functional boundary require combined independent reassessment.
After proof, a reviewed Duncan-only migration may use a distinct numeric UID,
500 local PostfixAdmin units (512000000 bytes), user-only FFS hard quota and
separate Dovecot index/control filesystem. Preserve mail availability, other
accounts and rollback data. No production mail host change or mailbox sync.
Prior failures and cumulative unknown costs remain unchanged.

### Native hard-quota progress

The first carrier stopped before device allocation because dd was under /bin,
not /usr/bin. The exact failure and empty owned namespace are retained. The
corrected reviewed carrier created a fresh 64 MiB FFS image and root preparation
passed. Matching native Rust88e45ee0 passed nonroot serial save/exact fetch,
three native writes within the kernel ceiling, expunge and capacity reuse in
0.56 seconds. The three concurrent candidates were all refused; protocol-specific
refusal qualification and mixed IMAP/LMTP/Documents paths remain pending.

Fresh live inventory identifies the existing helper as vmail UID2000. The
smaller reviewed rollout candidate therefore preserves UID2000 and uses an
account-exclusive filesystem: quotas are scoped by filesystem and UID together.
Other accounts remain on /var. Native mail index/control stay on another
filesystem. The unmounted backing mountpoint must be root-owned and unwritable
so absent mounting cannot permit unconstrained fallback. This supersedes the
proposed distinct-UID migration, preserving existing native privilege boundaries.
A small read-only unprivileged Rust worker performs Q_GETQUOTA outside the
parent sandbox; the parent receives only bounded existing QuotaStatus JSON.
Six focused pure worker/probe tests pass; no product driver is enabled yet.

### Current integration result

The later native protocol test passes actual IMAP APPEND, LMTP and native saves,
including quota-specific refusals, concurrent mixed writers, exact stored-byte
reconciliation and capacity reuse after expunge. The real Documents Store then
passes upload/download/reopen/folders/Bin/restore/delete and wrong-limit refusal
without save or pending metadata. Two native mailbox-backup rounds preserve
GUIDs, UID validity/next, message UIDs/GUIDs, flags, dates, subscriptions and raw
message hashes. These isolated results qualify the FFS candidate; they do not
enable the installed account by themselves.

The actual helper confinement plan and read-only worker pass in a separate
sealed child. The first maximum-size helper upload exposed an additional real
integration defect: native save succeeded, but the helper required a hexadecimal
message GUID while Dovecot returned an opaque Maildir GUID. The uploading record
and stored message are retained. Reuse the existing bounded MessageVersion
parser and reconcile the original ID/size/hash without repeating its append,
then qualify a fresh maximum-size journey. Preserve the earlier setup refusals
and native failures separately; no deadline or ownership restriction is relaxed.

The reviewed live layout keeps UID2000 and a root-owned filesystem mount root,
with Duncan's Maildir in its account-owned child and INDEX/CONTROL off-device.
The absent underlying mountpoint stays root-owned and unwritable. Native startup
must verify the existing image and quota before exposing the account directory;
it must never create a replacement volume or fall back to the old mail store.
Installed migration, HTTP qualification and owner acceptance remain open.

### Native startup and failure qualification

The unused final UID2000 profile now passes native edquota limit provisioning,
private-chroot quotacheck, filesystem mounting, quota activation and the actual
read-only Rust worker. Its measured10240 allocated bytes equal the independently
summed Maildir directory and controlled8KiB file. The kernel hard limit is
512000000 bytes. The live Duncan userdb still points to the original Maildir;
this is not completed migration or installed Documents acceptance.

The first limit-application check refused before edquota or fstab publication:
native od pads decimal fields with zeroes. All raw quota consumers now validate
eight bounded decimal fields and normalize explicitly in base10. The corrected
consumer passed on the actual retained producer text before the second native
application. Both attempts and the unchanged-state readback remain recorded.

Composed startup review also corrected rc.subr's default30-second daemon timer
and stop signal fallback for this one-shot filesystem action. Actual root-to-
vmail doas required authentication; the script instead uses the demonstrated
native root su-m transition, with fixed/admitted command arguments and no doas
policy expansion. Native startup passed after those concrete prerequisites.

A controlled unused-profile failure confirms live writers prevent maintenance
stop, root0700 blocks vmail traversal, and unhealthy mounted startup refuses
repair while leaving root-only access. Exact unused/no-open-descriptor recovery
then passes the ordinary cold-start path. Userdb, permanent fstab, probe bytes
and checked mail/OSMAP services remain consistent. No reboot claim is made.

Local current Rust QA passes2253 tests,0failures, with87 explicit native/external
ignores; strict all-target Clippy passes. A narrow additional native HTTP test
uses the real parser, Runtime gateway, authenticated helper and native backend
with synthetic post-auth sessions. It does not claim login/TOTP, public TLS,
browser rendering or the standalone helper accept loop. Its native result and
actual account cutover remain pending.

The added native HTTP composition journey now passes in18.57seconds on matching
OpenBSD source/binary: one exact10MiB upload through parser/Runtime/peer-helper/
native storage, exact download and forced-download headers, CSRF/Origin refusal,
foreign-account404, Bin/restore and confirmed deletion. Native saves total one;
private session/control cleanup and final native absence pass. The documented
post-auth, daemon/TLS/browser scope limitations remain. Owner data migration and
matching installed account journey are still open.

### Operator simplification — 2026-11-04 UTC

The owner asks whether this is over engineered and directs the simplest method
for reading existing Postfix/Dovecot reporting data. Mailbox migration is set
aside for this reporting result. The first migration inventory failed before
probe removal or backup: jq producers emitted null fields. No owner mail was
copied or moved, and the original data/mapping remain authoritative.

Deliver a distinct read-only MailStorageReport through the existing authenticated
Rust helper: complete account-scoped Dovecot virtual-message bytes plus the
PostfixAdmin configured quota exposed as one readonly native userdb scalar.
Missing limits, explicit zero/unlimited and failed/partial measurements remain
distinct. Reported message bytes exclude disk overhead; configured quota is not
an enforcement claim. Neither this report nor its presence enables Documents
writes. Reuse existing Dashboard/General storage views and account checks.
No new daemon, SQL broker, storage volume, quota-plugin activation or mailbox
move is required for reporting. Documents' full shared-quota write outcome and
T09 remain OPEN; do not relabel this narrower useful result slice completion.

Normal preservation gates retained two source delivery refusals: the new binary
needed its Cargo target admission record refreshed, then the CWE guard required
native FFI to remain in the existing reviewed openbsd.rs boundary. The manifest
record was refreshed without dependencies/features/lock changes; narrow typed
native wrappers now centralize FFI without changing the guard allowlist. Earlier
native receipts remain tied to their exact earlier binaries.
