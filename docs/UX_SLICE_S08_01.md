2026-11-06 — **Account-generic storage UAT ACCEPTED / PASS.** Owner explicitly states “UAT = PASS” and “UAT approved” after reviewing the signed-in storage screenshots and the presentation explanation. Dashboard and General Settings show matching 165.1 MiB message usage and 200.0 MiB configured quota; other pages intentionally offer View storage without an extra query. This accepts the current storage correction. Fresh credential entry is not separately asserted. Documents remains removed; remaining S08-03 checks and whole-sprint acceptance are unchanged. Documentation-only record; no host, mailbox, quota or runtime changes.

Account-generic storage engineering is complete and ready for owner UAT. Signed
implementation4b794e2 and test-only baseline correction5e6889d passed the normal
developer security-check and were published to feat/ux-completion-20260929.
Fresh fetch confirmed source equality at5e6889d (zero ahead/behind). The full Rust
library run passed2335tests, zero failures,90explicit ignores; integration tests,
strict all-target Clippy, formatting, dependency/advisory and repository delivery
checks passed. Local nginx and credential-dependent checks retain their reported
skips; this is not complete production WSTG or owner login acceptance. Native
account/storage qualification below is independent of those local skips.

Normal delivery first refused publication: the full Rust run passed2334cases but one legacy UX baseline still expected Documents503. The source-owned retirement contract requires404; the test-only baseline and PAGE07 removed-scope classification were corrected with independent review. This does not change the installed runtime binary. The original full-hook failure is retained in private push-source.log; the corrected full gate passes in push-corrected.log. No hook was bypassed and no remote history was rewritten.

## Account-generic mail storage qualification — 2026-11-06

The owner explicitly superseded the former Documents scope: Documents remains
removed, and ordinary mail-stack storage replaces the named account volume.
The mail stack now resolves the operator development account through its existing
PostfixAdmin maildir and 209715200-byte quota. A generic SQL userdb query and
Dovecot count quota apply per account; no account-specific OSMAP daemon remains.
The obsolete host rc script and two fstab entries were removed after parity.
The source rc example is removed and its guide is marked historical.

Retained-image reconciliation established 469 message files (the old home had
earlier state and was not merged), 28 mailbox records and 26 subscriptions.
Native before/candidate/live comparisons preserve exact raw SHA256 manifests,
mailbox GUID/UIDVALIDITY/UIDNEXT, message UID/GUID/flags/received date and
subscriptions. External Inbox metadata required translating its .INBOX control
and index files into the ordinary Maildir root. The original image, old home,
external metadata and private recovery copies remain retained. The read-only
examination copy was unmounted and its exact vnode detached.

Two disposable native accounts used distinct maildirs and 1 MiB/2 MiB limits.
Each accepted one local message, refused a 3 MiB save with native Quota exceeded,
and retained exactly one message. Runtime/helper report checks as the Web UID
returned 130/157 bytes and the correct independent limits. The migrated account
reported 173140207 message bytes and 209715200 configured quota bytes. Each test
also exercised dashboard/General/sidebar projections and foreign-report refusal.
Signed helper grant owner/operation/nonce and foreign-response regressions pass.
These native accounts do not require widening the password-mutation rollout.
They are diagnostic accounts, not an owner password-plus-TOTP login assertion.
Their exact temporary SQL rows were removed after verification; their local
test mail is retained privately, and no owner data was changed by cleanup.

Matching native source37 passes 12 focused cases plus five storage protocol/
parser cases (three reused) and the three installed reports. Its test SHA256 is
f8e72a4b6a02efd2925d8ff7f8595cc93e5bfbb02339a504b9cc512a8d940345;
installed Web SHA256 is
f0a0564be1c9ce56b1e8d073e263025bb9a782749dd84cf104b611fbae1063e8.
Loaded executable inode matches. The existing helper remains protocol-compatible.
After the authorized Dovecot reload, account authority and Web dependencies were
refreshed; native signed epoch admission passes without submitting a password,
consuming TOTP or changing a credential. Account credential/TOTP/quota SQL-row
and epoch digests match; the userdb location/configuration intentionally changed. Dovecot/Postfix/MariaDB master PIDs and GPG-agent PIDs
are unchanged. HTTPS login is 200 and all nine relevant services pass checks.
Toronto production was not changed. Fresh owner browser login is still UAT.

The Rust correction calls the existing signed report directly, without loading
a Documents index or filesystem quota. Removed Documents HTTP/search routes
return 404 before retained-store reads or mutation; retained data is untouched.
No new protocol, service, account-specific code or Python tooling was introduced.
The existing repository metadata generators and delivery hooks remain in use.

Failures were retained rather than erased: initial native enumeration omitted
the helper's maildir_stat_dirs flag; actual native count quota then demonstrated
the same Sieve-symlink issue. Combined review supported generic
maildir_stat_dirs=yes, preserving Sieve and allowing real quota calculation.
A first included-test comment convention compile failure, a GET-with-body fixture
parse refusal, an initial quota expectation using the wrong native JSON shape,
and a missing explicit readiness-account variable were corrected at their own
boundaries. None justified credential resets, deletion or relaxed account checks.
The matching changed tests and native queries pass. Raw native failures and
recovery material remain private; durations not measured across the original
continuation are UNKNOWN. Normal signed delivery gates and owner UAT are separate.

Independent source/configuration/parity review: /root/s08_selection_review.
Prior accepted S08 results and pending S08-03 owner checks remain unchanged.

## 2026-11-06 — Authorized account-generic mail storage correction

Owner approves native mail-stack storage/quota, authenticated-account Rust reporting, safe retirement of Duncan-specific storage, and two-account verification. Documents remains removed. Current prerequisite: retained image clone hashes match original, read-only examination contains469 message files, and candidate raw hashes match. External control/index layout requires Inbox metadata translation; full native reference equality is required before cutover. Root owns host/Git and data preservation; runtime engineer removes active Documents/report dependencies; selection reviewer independently checks source/config/results. Required tests are retained raw/identity/flags/subscription parity, two dedicated accounts with distinct paths/limits and native quota refusal, authenticated helper report/account isolation, retired Documents zero-write routes, current signed admission and preserved login. Native operational failures remain private and summarized; no new Python tooling or Toronto changes. Existing S08 acceptance is preserved. Engineering IN_PROGRESS, tests not claimed complete. See maint/openbsd/MAIL_STORAGE.md.

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

### Approved activation — 2026-11-05

The owner explicitly approves the obsd1-only Duncan Documents cutover, including backup, identity preservation, verification and rollback; Toronto/mail remains unchanged. The numeric quota remains200MiB. Earlier set-aside/pending-decision notes below are historical. Root now proceeds with fresh prerequisites, a reviewed Duncan-only writer-quiescence and mapping recipe, and actual installed Rust Store/helper lifecycle before owner UAT.

Fresh native preflight observes26 mailboxes,475 messages and172605611 virtual message bytes, with169742KiB allocated in the old home. These are observations, not permanent expected counts. The original home/mail mapping and live credentials remain unchanged; the prepared vnd3 profile is healthy and separate. The first inventory command omitted the already-qualified maildir_stat_dirs=yes option and refused at the existing .dovecot.sieve file before any mail write. The corrected native consumer passes; both private receipts are retained.

The private native hold primitive passes actual userdb and LMTP qualification: Duncan administrative lookup succeeds unchanged, his IMAP/LMTP lookups temporarily fail, the unaffected account matches its three service baselines, and an actual LMTP RCPT returns451 before DATA. The first private instance inherited128 descriptors against its measured1000 requirement and exhausted descriptors before auth started. A fresh carrier changes only its own descriptor limit to1024; the second check passes without changing live SQL/configuration or sending DATA. Both private masters exited; fresh exact-command and protected-file open-reference checks report zero. The successful result receiptSHA256 is061efd44a9cb6d03d8761f7b446b697ecb531929f2c51490148bf8def950a67a. This qualifies a new-lookup hold primitive, not live reload adoption, writer drainage or completed migration.

The new ignored installed Rust lifecycle probe compiles on OpenBSD in source14, libtest SHA256d802ba0dd46732967689b0a86d27f3c070e1c31ba8b76fff0adea99e56b59177. It remains NOT RUN until the actual shared authority/mapping is activated. It uses the installed Runtime/helper as the Web UID, current signed admission, one generated4KiB binary and exact upload/reopened-download/Bin/restore/generated-ID deletion with original index preservation. First use may create the two reserved native document mailboxes. It does not fabricate a browser session or qualify owner HTTP/MFA.

Initial online native backup now passes with26mailboxes,475messages and26subscriptions. Complete canonical source-before, source-after and target manifests match SHA256ee0e46ba91813565189a0b69580d9124ef58c82913d7e2968f087ababe2563d3; their comparison includes GUIDs, UIDVALIDITY/UIDNEXT, message UIDs/GUIDs, persistent flags, internal dates and per-message raw-byte hashes. Copied Sieve/non-mail content, owner/mode and relative link also match. The complete original-home archive is retained privately, SHA256ae4ff1bad8e86f25d87d49af46352209844a4bfd47817d2760f9561d840f5720. Active userdb/configuration remain unchanged, native200MiB quota readback passes and nine live roles run. Independent readback confirms private master and protected-file open references are zero.

The first normal push of signeda2eccb3 passed2325Rust tests with zero failures/89explicit ignores, then refused the real development-account literal in the new ignored native test. The publication guard is unchanged. The test now requires separate explicit canonical read and mutation account selections that match before configuration/helper access; the private run recipe fixes both to the authorized account on obsd1. Matching source15 compiles to libtestbcb04aea7f6a179b62ead0334dd07c06f17558eb32ea7ef48dfb0984d8f1231d. Actual Web-UID runs confirm missing and mismatched mutation selections refuse before configuration/Store access and any write. Positive installed Documents execution remains pending final cutover. Source14 is retained as an earlier compiler result, not qualification of the revised probe; production main13 remains unchanged.

Before backup, root preserved and removed only the exact8192-byte synthetic provisioning probe, verified against its original device/inode/owner/mode/link-count/hash receipt, copied bytes and zero descriptor references. The backup's genuinely-empty target guard was retained. Source review caught the earlier unsupported stat formatter before dispatch; the executed candidate uses the qualified numeric flag field and explicitly checks the portable Sieve link. Private result/parity receipts are564c3aa589bc28176e3c73706da0302f27ece9c4828c8702c0ea9355387e2bdf andf5da81318ef4b7473db6a453766bfc5927a1531c05b7523d3f19e0dd9b381f7b. This is an unexposed online seed; the final hold, quiescent delta, mapping change and installed Documents journey remain pending.

### Completed cutover and first installed Documents observation — 2026-11-05

The approved Duncan-only obsd1 cutover completed in 61 seconds. The final held
source, destination and retained post-release source compare exactly: 26
mailboxes, 475 messages and 26 subscriptions, including native identities,
persistent flags, internal dates, raw-message hashes and Sieve content. The
canonical inventory remains SHA256
`ee0e46ba91813565189a0b69580d9124ef58c82913d7e2968f087ababe2563d3`.
The quiesced original-home archive is retained privately, SHA256
`580a5028b0773a69b05c2d10780f54ab5a4b9198bcce5791d76d5acaf616afad`.
The original home and earlier archive are also retained.

The active native userdb now maps only this development account to its prepared
filesystem with the existing external index/control paths and 209715200-byte
shared quota. The already admitted SQL and quota configuration files were
updated; the account service, mailbox helper and Web were constructed afresh.
All nine checked roles run, the login page returns HTTPS200 and an unaffected
account's actual native INBOX access succeeds. Private-instance process and
protected-file reference checks independently report zero. Toronto was not
contacted or changed. The owner's updates were acknowledged; no reboot was
performed or qualified by this work.

The first cutover attempt stopped before its final backup or release because a
generic exit-zero check rejected Dovecot's exact exit68/no-users-kicked response.
The original configuration was restored and independently verified. The changed
attempt reuses the existing exact native acknowledgement contract, including
empty stderr and separate zero-session/writer checks. No arbitrary nonzero
result was admitted. Both attempts remain retained. Final result SHA256 is
`04663238bbcd20fa23e5c32909b1f08d04ce045ae099581097379d286491b8a4`;
independent source and result review give scoped cutover GO.

The first actual installed Rust Documents journey then refused upload with
`PreDispatchUnavailable` in 0.44 seconds. No document-body Save was dispatched;
the Store removed its explicit no-write pending record and no reserved Documents
mailbox appeared. Signed account admission, initial finite quota observation,
post-run epoch/configuration preservation and service checks passed. The new
mapping remains active; there was no upload replay or old-mapping rollback.
This is a Documents functional failure, not slice readiness.

Read-only native fetch returned an empty successful JSON array with both the
current arguments and `maildir_stat_dirs=yes`; absent reserved-mailbox status
returned the established exit68/empty-stdout response. These observations rule
out changing lookup order as a supported correction. The previous isolated
Store fixture precreated its reserved mailboxes, leaving first-use provisioning
unexercised. The existing Rust case now starts them absent, and fixed helper
diagnostics retain stage, native exit and stream lengths without native output,
identifiers or content. Focused backend tests pass15/0; matching native first-use
qualification and diagnosis remain pending. No new Python tooling was added.

### Isolated first-use qualification and retained fixture closure — 2026-11-05

The first isolated native16 Store case starts both reserved mailboxes absent.
Actual native creation, upload, exact download, Bin, restore and confirmed
deletion complete before its final allocation assertion fails; the single Store
case remains FAIL in2.12seconds. Its comparison used the allocation measured
before first-use Bin creation, so retained directory allocation could conceal
the payload's released blocks. This is a fixture-baseline failure, not evidence
of a weakened or exceeded native hard quota. The original stage output and
fixture remain preserved; no owner mailbox or public configuration was used.

Safe disposition of that retained vnd2 fixture first refused before quota-off:
the closure assumed an unsupported `mount -p` interface. Quota, mount and device
state were retained. The changed closure uses the actual default native mount
row, requiring the exact device, mountpoint and FFS type, with positive and
wrong-device/type/duplicate/missing-row consumer checks. Reviewed carrier
`db0c87446ecf1e2f344b843e594790a5ec8c0d9b794a5c46445154467282e09d`
then passes quota-off, exact descriptor/process absence, unmount and same-image
detach. Result SHA256 is
`4d4e27ef1e6a29ee2e5ee5bed0c754cfaf43ab12f826eac0bf0ab9a562a6bd9e`.
The image, control directory, original failure and closure receipts are retained;
cleanup PASS does not change the native16 functional FAIL.

The sole test correction measures current allocation after the second Bin
operation, immediately before confirmed deletion, and still requires a strict
post-delete decrease. Fixture source SHA256
`dda70fd4e892aaf4b3e813beb9c137d96042f7ead106d04fecdf528e9cc74b40`
and backend source
`1d3a282d05a20f134e80ed37e1c2cac3a63c90b8727be9c0516e51465fd29eb3`
match retained source17. No quota limit, authority requirement or refusal was
relaxed; strict all-target Clippy and independent source review pass.

A fresh native17 namespace then passes the actual first-use Store journey with
reserved mailboxes initially absent, native Active/Bin creation, upload/exact
download/reopen, folder placement, Bin/restore, confirmed deletion and the
wrong-worker-limit/no-save refusal. Carrier SHA256 is
`1db70b494f3f4be9be82d333bdc98a2b510e360743c301d8e890f491d9aa3a0f`;
matching libtest SHA256 is
`ee5eb0bae58b7b8bc301e54204fb972233140f3b80436cff5c49d185fcfb4c5d`.
Root quota preparation/off and exact-owned descriptor/process absence,
unmount and detach also pass. The32MiB fixture image and diagnostics remain
retained. Result SHA256 is
`c07af47b4a1ef42efd8fdb82fe090f2725f1e1c83dc74ee0ff0adfcd2c34a629`.
Both isolated continuations preserve the owner vnd3 association and leave public
configuration unchanged; they do not repeat the mailbox cutover.

Combined root/author/independent reassessment retains installed15's actual
pre-Save refusal and native16's distinct baseline failure under the same
Documents outcome. Native17 narrows the first-use fixture gap; it does not
explain or turn the installed15 failure into PASS. The next changed installed17
diagnostic journey must observe the actual helper/native stage and typed result
before inferring a product correction or installed readiness. There is no
automatic replay of an uncertain Save, no new quota authority, allowance reset
or additional test framework. Installed Documents completion and owner T09
remain open.

The notification continuation is signed and synchronized at
`88c6b5f4742bc7cdd0dffc4d98b7816a7ea84c2d` after 2325 Rust tests passed and all
normal delivery gates completed. Signature verification, fresh exact origin
equality, zero ahead/behind and clean status passed at that checkpoint. Later
Documents diagnostics and these records remain a separate pending delivery.

### Installed read-only lookup discriminator — 2026-11-05

After the fresh isolated first-use PASS, diagnostic-only main17 was installed
atomically for Web and mailbox helper. Both loaded executable identities match
SHA256 `251944c348fafaa7bb8c30bc32a9209e13b25c4b63f0592e4bd4a0c6b0eaceef`.
Configuration, account epoch, account service, crypto agents and grant metadata
compare unchanged; nine roles and HTTPS200 pass. No recovery was needed.

The changed installed17 attempt still refused upload before any Save or reserved
mailbox creation, in 0.47 seconds. Its post-offset, identity-checked helper
observation is `append_exact_id_lookup / NATIVE_LOOKUP_UNAVAILABLE`. The result
manifest SHA256 is
`7e0256381560f70f62b442a1bfb5e0ea981c89fcb8e1ca9f33a75c58ea09fe54`.
This narrows the failure to lookup but does not distinguish native execution,
nonzero exit or result parsing. Exact native read-only fetch with cleared
environment still returns an empty successful JSON array. Checked recent native
logs contain no matching Dovecot pledge/crash record; that limited negative
observation does not prove confinement correctness.

Combined independent review of installed15/17 therefore selects a refined fixed
lookup diagnostic and the existing authenticated helper `inspect` operation.
The subsequent ignored Rust discriminator used the actual Web identity, current signed
account admission and a fresh opaque lookup selector. It constructed no Store,
did not change the index, create a folder or Save a body, and fabricated no owner
session. Its actual result and the independently reviewed next product discriminator
are recorded below; no new API or broader confinement was introduced.

### Installed Documents engineering ready — 2026-11-05

S08-01 is **UAT_READY** for the approved obsd1 account. Essential implementation,
source, native, deployed, recovery and independent-review stages pass. This
current result supersedes earlier pending installed-diagnosis wording while
preserving every failed attempt. Owner T09 remains **NOT_RUN**; full S08 remains
open. The developer security gate passes; normal signed commit/push hooks and
fresh remote equality remain required before the final delivery report.

Diagnostic main17 installed successfully, but its installed lifecycle refused
before Save in0.47seconds (manifest
`7e0256381560f70f62b442a1bfb5e0ea981c89fcb8e1ca9f33a75c58ea09fe54`).
Combined independent reassessment of installed15/17 selected finer fixed lookup
observations and the existing authenticated read-only inspect discriminator
before further mutation. No permissions, confinement or helper API were widened;
no ambiguous Save was replayed and no failure/cost history was reset.

Matching main18 Web/helper SHA256
`6cb784557bfbbcd7edd503aecd9825cdf84bd333704334cbad043cc9d2f6a9db`
installed with no recovery. Configuration, epoch, account service, crypto agents
and grant metadata compare unchanged; nine roles and HTTPS200 pass. Matching
libtest SHA256 is
`ceaa9d9579cc1a09944d3e6336e14ada9ea92ddbfe5bb697367c5731b935347e`.
The actual WebUID/current signed admission/sealed-helper read-only lookup passes
in0.14seconds without writes or an owner session (manifest
`1ae036c20308df471c6288d3560d0ab4799a3de88452a133c06c46fec5e2307f`).
Its two reserved-mailbox lookup scopes do not imply that either mailbox existed.

The installed lifecycle then passes1case/0failures in2.26seconds: absent reserved
mailbox creation, one4096-byte binary upload, reopen/exact download, Bin and
in-Bin download refusal, restore and confirmed generated-ID cleanup. Original
records/folders, signed epoch, services and the finite209715200-byte shared quota
are preserved (manifest
`de3020811829875d338b5bd34140da08ec2f2b073de6b2cbee9ed9acf94b6faf`).
A separately reviewed existing-folder journey passes in2.08seconds with one fresh
nonce and confirmed deletion (manifest
`1d1227a473d55c5a96b64ace434fe55100d72d72c94fa2a66e29b555d39787ac`).
These are actual installed Runtime/helper/native journeys; owner HTTP/login,
visual acceptance and private-key operations were not exercised. Historical
installed15/17 root cause remains **UNKNOWN**; later success does not establish
stability or a causal explanation.

Current focused source15/0, strict all-target Clippy18 (45seconds) and formatting
checks pass. Scoped independent source/native/installed review is GO. Retained
FFS mixed IMAP/LMTP/Documents enforcement, real native HTTP10MiB/isolation,
reconciliation and retention proofs qualify the unchanged corresponding paths;
the earlier concurrent count-driver failure remains retained and that driver is
still disabled. Isolated first-use17 and both fixture-closure outcomes remain
separate evidence. No owner retention clock or browser acceptance is inferred.

The remaining owner check is the ordinary Documents upload/download, folder,
search, Bin and restore journey. Notifications controls and scheduled-send T09
also remain pending; engineering readiness does not accept those slices.

Final source qualification adds the missing restore-deadline assertion to the
existing Rust Store test: expiry plus one second refuses with unchanged Bin
metadata, while the exact 30-day boundary restores the original bytes. The
focused case passes. This uses synthetic timestamps, not a 30-day elapsed-time
experiment, and does not prohibit earlier explicit confirmed deletion. Native
Bin charging and confirmed-expunge release are separate passing observations.
The change is entirely inside `cfg(test)` after the installed18 build; production
Rust remains the reviewed installed source. The complete developer gate passes
2326 Rust tests, zero failures and89 explicit native/external ignores, including
its normal security, Clippy and WSTG-mapping checks. Its retained log is
`cutover-20261105/security-final18.log`; the added clock assertion also passes
`cutover-20261105/retention-boundary.log`. Ordinary final push checks will cover
the complete checkpoint again without bypass.

### Historical activation decision

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
