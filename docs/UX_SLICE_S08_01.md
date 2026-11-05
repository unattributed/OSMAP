# S08-01 — Documents and authoritative account storage

## Storage sidebar UAT correction — 2026-11-05

Owner UAT showed correct measured values in the dashboard card while the shared
sidebar still hardcoded `Usage unavailable`. This was a presentation wiring
defect. The sidebar now reuses the same already-loaded account snapshot on the
dashboard and General Settings, with compact message bytes, configured quota
and an over-configured-quota indicator. It adds no helper query, cache, database
or service. Pages without a loaded report offer `View storage`; an attempted
failed read remains unavailable. Exact account checks suppress foreign values.
Qualified quota and advisory reporting remain distinct, with unlimited and
unreported configured limits handled separately.

Focused Rust validation passes three rail cases, one real route regression,
12 welcome cases and 10 General Settings cases; strict all-target Clippy and
formatting pass. Independent source and installer/qualification review is GO.
The matching OpenBSD build passed. Web-only installation loaded main SHA256
`17a1395f9a87fa57ff955fd9f49eb67d376bb93faa67eb5a80c4a234e02f21cd`.
Configuration, account-service PID, mailbox-helper PID and crypto-agent PIDs
compare unchanged. HTTPS login returned200 and all nine checked roles run.
No Dovecot reload or account-service/mailbox-helper/crypto restart was needed.

Matching OpenBSD test SHA256
`6060c10a7e48a61d9f5fae28393a4f327936a4bbca5b7e19a0b78039c583d137`
actually ran the existing installed report case as the Web principal: one PASS,
zero failures in0.11seconds. It now requires current signed account-epoch
admission as well as the actual Runtime/authenticated-helper read, both owned
page sidebars and two foreign-page refusals. Fresh native values remain
172605611 message bytes and102400000 configured quota bytes. No owner session,
password or TOTP is used; owner HTTP/browser acceptance is not inferred.

Private receipts in `sidebar-20261105` under the existing sprint root:

- `source.tar`: SHA256 `bc539761137ec208a2c5d5f29a3d89790fbe3dcc40e190f84cd80ff42a407cd1`.
- `install.log`: SHA256 `e84488763980daf8c6d868a195c04c2ee7d6b51a0388d87e2a90a5693af99a90`.
- `qualify.log`: SHA256 `e8e8ce7f2a7200e621508dc8ea8609e2f5095acc7d4e0e92146b94692d999fb3`.

The previous owner `Login successful` confirmation remains recorded below.
The owner subsequently states `UAT = PASS` (2026-11-05, Asia/Bangkok), accepting
the installed storage sidebar correction. Signed implementation1af693c passed
normal delivery gates, including2235 Rust tests with zero failures and87 explicit
native/external ignores. Fresh fetched branch equality and clean status were
verified. Full Documents shared-quota and broader S08 acceptance remain open;
the owner explicitly directs continuing unfinished S08 work.

## Current continuation — 2026-11-05

### Remaining activation decision

The configured200MiB report and global Documents filename search are implemented and installed; earlier pending-choice/search notes below are historical. Full Documents writes remain safely unavailable on the original active mailbox because the database scalar is advisory. Current source requires a qualified shared mail/Documents authority; the count-driver path remains disabled after its demonstrated concurrent overshoot. The separate200MiB native filesystem is prepared but unmapped.

The smallest existing activation route is an obsd1-only Duncan mailbox backup/two-pass cutover into that account-exclusive filesystem, exact home/mail/quota mapping with INDEX/CONTROL outside the volume, and effective native quota coverage. Toronto remains unchanged. This crosses the earlier set-aside migration/mail-configuration boundary, so root has asked for an explicit cutover decision while independently completing scheduling and notifications. No migration or quota-plugin activation is inferred from the numeric quota answer. After approval, reuse the existing native lifecycle/mixed-writer proofs and require actual installed upload/exact download/search/Bin/restore and preserved native identities before UAT.

### Owner-selected 200 MiB development quota

The owner selects **200 MiB** for Duncan on obsd1. A single conditional native
MariaDB update changed only the active account's quota from102400000 to209715200
bytes. Affected-row count was one and independent readback matched. Credential,
account epoch, mailbox mapping, Dovecot configuration and OSMAP configuration
observations remain unchanged; Toronto was not changed. No password, TOTP or
browser session was used. Private result `quota-200mib.log` SHA256
`156eb5bc16e64c6e061b6c86034b3e72b39ae0c41db66d19585437d142855073`
retains the exact operation and comparisons.

The matching installed Rust report/admission case passes1case/0failures in
0.11seconds with172605611 message bytes and209715200 configured quota bytes.
Its receipt `quota200-qualify.log` SHA256 is
`e6a2dcbda2e595426f8f1097b182e2611e9b73caedd25aca47882c062ddbf08b`.
This establishes reporting and current signed admission, not browser acceptance
or enforcement on the active original mailbox.

The separate, unused vnd3 Documents profile now also reports209715200 bytes
through the actual native kernel quota worker. Native edquota changed only that
filesystem's UID2000 hard limit from500000 to204800 KiB. Kernel usage compared
unchanged, the temporary fstab discovery entry was restored exactly, current
userdb remained on the original mailbox and all nine checked roles run.
The account-specific rc check passes with409600 raw512-byte blocks. Independent
review approved the corrected recipe's original-mapping/advisory guard before
containment. No owner message was migrated and no public mail configuration or
service was changed. Previous512000000-byte preparation receipts remain history.
Full Documents activation and acceptance remain open.

After accepting the sidebar, the owner directs completion of unfinished S08.
Reuse the existing Documents store, native quota worker and qualified fixture
journeys. The current advisory userdb scalar must coexist with the seven native
filesystem-authority fields without becoming write authority. Source correction
and focused malformed/missing/duplicate/worker-argument regressions are required.

Page09's global Documents search adapter remains missing even though the
Documents page already has filename search. Extend the existing bounded All
search and category navigation using the authenticated Documents index, active
files only, case-insensitive filenames, deterministic ordering and existing
opaque selection/download routes. Keep mail filters scoped to messages and
explicitly label unavailable versus zero results. No file body/content indexing,
new search store or privilege is needed. Essential tests cover owned results,
foreign/corrupt/unconfirmed index refusal, Bin/pending exclusion, escaped names,
pagination/category links, empty queries, request bounds and unchanged index.

The existing 102400000-byte configured limit is below measured existing mail;
the owner has a pending quota choice before any mailbox migration or write
activation. Refresh the corrected existing inventory read first; preserve the
failed null-field inventory and do not replay old worker/userdb admissions.
S08-03/04 reuse assessments can proceed independently while that choice is
pending. Full Documents acceptance and whole-S08 closure remain open.

### Search and current native reporting compatibility

The Documents authority parser now accepts the one optional native
`osmap_configured_quota` scalar alongside its seven required fields. It remains
advisory and never enters filesystem worker authority. Fourteen focused Rust
cases pass, including malformed/duplicate/unknown/overflow refusal.

Global Documents filename search is implemented through the existing
owner-validated index and selection/download route. All search includes bounded
Documents results; Bin, pending and unconfirmed records cannot become active
results. Focused shared search regressions pass101 tests with zero failures and
two explicit native ignores. Strict Clippy passes. Independent source review is
GO. OpenBSD product build9f9c4cf4 and test buildaae65338 pass. The changed native
journey passes1case/0failures in18.77seconds on a freshly activated32MiB kernel
quota: exact10MiB upload/download, CSRF/origin refusal, foreign404, owner-only
filename search, Bin exclusion, restore and confirmed deletion/cleanup. Native
post-auth sessions do not qualify login/TOTP, public TLS or browser rendering.

The fresh read-only source inventory passes26 mailboxes/475 messages, raw hashes,
subscriptions and Sieve/non-mail accounting, with unchanged mapping/configuration
and checked mail services. This is not a quiescent snapshot or migration parity.
Its first run refused unsupported string-format native stat output before any
backup/copy; numeric flags correct that observed utility contract. Both private
receipts remain. No owner message was copied, moved, removed or reauthenticated.

The first new build archive omitted existing tests/ MIME fixtures referenced by
Rust include_str and failed compilation before any native journey. The corrected
archive includes those unchanged fixtures; source code is unchanged. No product
result is inferred from compilation or packaging. A later dispatcher used the
wrong absolute vnconfig path and refused before control creation. Actual command
discovery corrected it. The next native run exposed the fixture producer's old
four-extra-field cap; its explicit cap/allowlist now admits the fifth advisory
field, with product assertions unchanged. The next native run verified that
eight-field output but refused missing live kernel quota on the reused volume,
before upload. Historical preparation and a mount flag were insufficient.
Combined independent reassessment selects the existing fresh64MiB FFS setup and
actual kernel quota readback before another journey. Retained namespaces and
failures remain private; no owner mail operation or configuration change ran.
No new Python tooling is used.

Installed Web36687 and mailbox-helper74933 both load9f9c4cf4. Configuration,
account-service PID and crypto-agent PIDs remain unchanged; HTTPS login200 and
nine roles pass. Matchingaae65338 test passes the installed signed current-epoch
admission, Runtime/helper storage report, both owned rails and two foreign-page
refusals in0.11seconds. Message bytes172605611 and configured quota102400000
remain unchanged. Product source is identical to its main compiler receipt;
only cfg(test) fixture code differs in the final test build. Rollback would
restore on-disk17a1395f and restart Web/helper, not the historical helper391cdc
inode/PID. No rollback was needed. Owner quota selection, installed Documents
write journey and full-S08 acceptance remain pending.

## Owner login regression and service recovery — 2026-11-05


Owner UAT reported sign-in failure using the saved Proton Pass credentials.
Server logs classified the requests as primary-stage `backend_unavailable`
from `account-helper`, before TOTP verification. This was not a logged wrong-
password result, and no password/TOTP reset was performed.

The storage metadata edit/reload changed the protected Dovecot configuration
after the persistent account service had captured its startup snapshot. Its
intended snapshot recheck consequently refused admission. The storage/report
test had explicitly excluded authentication; the deployment omitted this
dependency refresh and therefore did not establish login readiness.

The existing credential-free signed epoch-admission test reproduced FAIL in
0.02seconds. Restarting `osmap_account_password` against current configuration,
then restarting dependent `osmap_serve`, restored the authority chain. The same
test actually ran one case with zero failures in3.10seconds. Protected account
configuration, keys, epoch state, TOTP files, installed binaries and Dovecot SQL
bytes compare unchanged across recovery. Six relevant service roles and HTTPS
login availability pass; no password was submitted and no TOTP was consumed by
agent testing. The owner subsequently confirmed a fresh MFA sign-in:
`Login successful`. Login recovery is now functionally confirmed; this does not
accept the remaining Documents or S08 functionality.

Private receipts under `login-20261105` in the existing sprint root:

- `epoch-before.log`, SHA256 `a44f743663a32c9c10610377bcc12e00ae3fd0c8cac5aa6ddbaa50d21ff90e0f`.
- `recovery.log`, SHA256 `6e69bb9c3db8ede1e68e84c7f490ec594a36475a713305f23dac13c591e6337a`.

The OpenBSD deployment instructions now require account-authority reobservation,
Web endpoint refresh, signed epoch readiness and owner MFA login after an
authorized Dovecot configuration change. Snapshot validation remains intact.

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
Matching installed reporting qualification now passes as recorded below; this
is not full Documents slice acceptance.

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

### Installed report result

The instrumented third installation passed. Both Web and mailbox-helper loaded
main binary SHA256
`391cdc7499f7b88e025ff54194923c7765cc373b4a72ffca364b3d8f3d42d6ff`.
Its retained readiness probes returned HTTP502 followed by HTTP200; this
establishes that interval for this attempt, not the earlier unknown code. Eight
service roles, unchanged configuration and unchanged crypto-agent PIDs passed.

The exact ignored OpenBSD test
`http::http_gateway::storage_native_tests::native_installed_mail_storage_report`
actually ran one case with zero failures in 0.09seconds. As the existing Web UID,
it used the production Runtime factory and authenticated installed helper,
compared fresh native values, rendered both full pages and rejected two foreign
projections. No owner session was fabricated or read; owner HTTP/browser/login
UAT is not claimed. The local route regression separately verifies authenticated
page wiring, foreign-session suppression and anonymous redirect.

Private receipts under the existing sprint root:

- `report1/native-installed.log`, SHA256 `cbe5962e23cd9662c2f69abcc734a48a305f40a28f40a6145434d1f5aeecf779`.
- `report1/install3-dispatch.log`, SHA256 `9f97d84670d2b69059a5f54bc2838101c7c3d9cb51be03927054301ef3728b83`.
- `report1/metadata-dispatch.log`, SHA256 `d4140bc7c3fd4b74b80a2ab55b8ea0b79a9d403dc36f6a55c3f5e1b6f53d4b81`.

Independent source/carrier/result review is GO for this reporting scope. Owner
visual review is simply to refresh `/mailboxes` and
`/settings?section=general`: the current observation displays164.6MiB of messages
and97.7MiB configured quota, with exact bytes and enforcement-unverified text.
Mailbox migration remains set aside; the original Documents enforcement and
other S08 obligations remain open. Existing native filesystem experiments are
retained separately and do not supply reporting authority or owner acceptance.

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

The corrected no-root compatibility control now passes on OpenBSD:
`isolated_openbsd_quota_plugin_without_account_root_preserves_ordinary_mail`,
one test/zero failures in0.34seconds, matching test SHA256
`5da218a4661e8139cd51a3d1e1ad925c30b85216767ee2ebd6ff5baf0ccfb07e`.
With the quota plugin loaded but no account quota root, actual native save/fetch
preserves the exact controlled4096-byte message; Documents authority remains
unavailable, reserved Documents folders stay absent and owned cleanup passes.
The fixture's previous blanket `-u` assertion was corrected only for the exact
owned `doveadm user` query; negative foreign-account/socket/unscoped-command
checks pass. Native outcomes are retained privately before interpretation.
This proves ordinary Doveadm compatibility, not live IMAP/LMTP or owner cutover.
