# S08-01 — Documents and authoritative account storage

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
