# Current Project Status

## Purpose

This document is the current public-safe status record for OSMAP. It exists so
README.md, docs/README.md, historical version files, and later sprint records do
not leave maintainers guessing which statements are current and which are
provenance.

Historical version documents remain valid as evidence records for the slices
that produced them. When a historical document conflicts with this file, the
current README, or the latest version closeout record, treat the historical
statement as provenance rather than current release posture.

## Current source posture

### Agent-owned delivery correction, 2026-10-14

The operator approves all six independent-auditor recommendations and delegates
end-to-end technical delivery. `UX_PLAN_AMENDMENT_R3.md` records execution
authority, dependency/sizing corrections and the approved Folders navigation
overlay while preserving the R2 requirements and reference bytes. The latest
ledger entry contains named owners, all-slice remaining actions and provisional
effort ranges. Human acceptance is engaged only after the submitted scope's
agent-owned development, matching deployed functional QA and independent audit
PASS; it is not a debugging assignment for the operator.

Signed source `afc02239b832a2ebc7904f99549740d824d10809` and its predecessor
`7c2345525e37a8986b4719429ae18bcf3454c5a5` are synchronized to the UX branch.
Folder Move has native proof but matching installation remains pending. Crypto
activation failed at startup and rollback startup; original worker/launcher
bytes were restored. A later read-only observation found a live public helper
without its expected wrapper supervision. Operational restoration is the first
integration objective; neither full outage nor successful deployment is inferred.
These are retained observations, not a fresh service-health claim.

GitHub issue77 closes only approved-reference lock/promotion. Issue78 remains
open for the functional Folders journey. No whole-sprint or epic acceptance is
established by these records. Acceptance reconciliation links existing evidence
without repeating a baseline QA campaign.

### S08-02 private folder Move engineering, 2026-10-14

Private leaf folders can be moved beneath another permitted private parent using
the existing typed Rename/helper/completion mechanism. The request and helper
grant bind both current parent identities; protected/system, cycle, stale and
cross-account restrictions remain. One matching confined OpenBSD case passes
populated Rename and Move with folder/message identity, exact content,
Label/Snooze continuity, account isolation, uncertain-result recovery and current
fixture cleanup. Installation and the operator's combined folder-lifecycle UAT
remain pending. The earlier failed fixture's cleanup remains unconfirmed.

Operator engineering request [#78](https://github.com/unattributed/OSMAP/issues/78)
assigns the Documents-to-Folders navigation/page change, Inbox hierarchy, folder
management and movement of complete emails including attachments to S08-02,
before combined acceptance and affected S09 visual checks. These requested
navigation changes are not yet installed. Existing bulk Labels are implemented;
their current installed/human journey still needs qualification.

### Private key-agent recovery engineering, 2026-10-14

The installed obsd1 account's expected binding, public encryption subkey and
private-key file metadata were present, but its native agent socket refused
connections. A socket pathname did not establish a running agent. The repair
checks a bounded live connection and the same owned peer before private
operations, and the existing native launcher recovers only an exact abandoned
socket under its stopped-helper prerequisite and exclusive launcher lock.
Native Pinentry and the 300-second cache policy remain unchanged.

One matching OpenBSD qualification passes stale private-operation refusal with
no plaintext, public Encrypt/Verify availability, bounded agent recovery and
real signing afterward. Existing recipient, self-decryption, signature and Bcc
privacy checks also pass. This is source/native evidence; signed synchronization,
installation and actual account reading remain separate pending outcomes.

Operator UAT separately establishes first-message Proton receipt, readable
PGP-encrypted content and reported Bcc privacy. A second message has actual
readable Thunderbird Bcc delivery and a matching OSMAP encrypted Sent row.
These supersede the old unexecuted-provider statement for their exact cases.
OSMAP's own decryption, verified signatures, encrypted return and full S07/epic
acceptance remain open. No agent provider Send occurred.

### S07 encrypted-Bcc engineering, 2026-10-14

The configured Crypto runtime was restored and an authenticated public-only
Encrypt operation passed without a private unlock, policy change or Send.
The encrypted-Bcc implementation resolves hidden recipients through the same
approved key and policy checks as visible recipients. Actual OpenBSD fixtures
prove two intended recipients decrypt, an excluded sender receives no plaintext,
both recipient key IDs are hidden, and the real submission backend with a
disposable capture emits exact private wire bytes with Bcc only in its envelope. Explicit
self decryption, signature/tamper and attachment checks also pass.

These are source/native engineering results, retained under osmap-ux-s07/
encrypted-bcc-20261014. Synchronization and installation require their own
matching records. Browser/provider receipt, private-key availability and
human acceptance remain separate; this does not close S07 or the epic.

### Installed ordinary-mail repair, 2026-10-14

Signed source `90461aa1f6530ce16f0c86bdc6e456d80f19dc17` is synchronized on
`feat/ux-completion-20260929`. Matching image
`11085bca5ecaf7f382426098e4cecc939ad0fc54a5688dfa40a0f92994074814` is installed
on the authoritative Toronto mailbox helper and obsd1 development web. This
supersedes the source-only/deployment statements in the older checkpoints below.

The reproduced ordinary Pre-send refusal on unavailable unused public-key
inventory is repaired while retaining Required protection and stale-revision
enforcement. Real controlled password/TOTP login and exactly three original,
reply and forward submissions passed installed Inbox/Sent/body/attachment
checks. Independent authoritative inspection verified all six MIME copies and
reply threading. The retained Draft survived the actual upgrade. Four Star/read
toggle-and-restore actions, subject/unread-filter context and a controlled Bin
move/Restore also have bounded actual results. Test selector failures remain
retained; the restored message's new Inbox UID and unchanged payload were
independently reconciled. No provider mail was sent.

All six required development services are healthy. Four fixed startup hooks are
installed; one actual abandoned auth socket recovered through normal startup,
preserving application/configuration. This is not a full-device reboot claim.
Ordinary self-mail UAT: fresh Compose to your canonical account address, turn all
three OpenPGP selections off, Save Draft, Resume, Pre-send check, Send once,
then compare Inbox and Sent. Current account signing/encryption are Optional;
the Proton recipient's Required encryption policy is preserved. Protected
provider delivery, full CORE acceptance and original sprint/epic closure remain
open. See `UX_FUNCTIONAL_BASELINE.md` and the latest execution-ledger entries.

### Public inventory engineering checkpoint, 2026-10-01

Resumed the preserved work after signed checkpoint `f70d74c`. OpenPGP Settings
and Key Management now expose authenticated read-only inventory presentation,
full public fingerprints and public metadata, with distinct unavailable/empty
states and account-owner checks. Signing/encryption policies, account/recipient
bindings and all key mutations remain unavailable. The candidate service stays
disabled pending full service isolation and release qualification. Native
candidate inventory, confinement, size-limit and signed-client tests passed on
obsd1, along with the previously pending folder metadata/create fixtures.
See the latest
`UX_EXECUTION_LEDGER.md` entry for actual validation and signed-delivery state;
this is partial S04/S05 engineering, not completion of those slices or the epic.
No deployment, remote synchronization or strict-release qualification is claimed.


### Approved UX reference correction, 2026-09-30 UTC

The operator explicitly identified `osmap-ux-final-approved-20260919/images/`
as the authoritative design and instructed continued engineering. The 25 PNGs,
README and approval lock now live byte-for-byte under `docs/design/`; outer and
inner checksums verify. `UX_PLAN_AMENDMENT_R2.md` records revision 2, all 27
pages (including retained Login/TOTP), changed requirements and sequencing.
The earlier S00–S03-01A work used the four revision-1 annotated images instead.
Its recorded functional/native tests remain valid for their stated scope;
**those visual checks do not establish conformity to the final approved bundle**.
S01/S02 layout comparison is reopened, and the new per-page controls remain
pending in `maint/ux/approved_pages.json`. No complete-epic, release, deployment
or independent human acceptance is claimed. The historical progress below is
retained with this qualification.

### Full-functional UX engineering intake, 2026-09-29

The operator requested a codified full-functional UX epic against four supplied
mockups, including every-page dark mode and missing runtime OpenPGP/account/mail
capabilities. `UX_FULL_FUNCTIONAL_EPIC.md` and
`UX_FULL_FUNCTIONAL_SLICES.md` define 12 sprints and 48 slices. All were
initially NOT_STARTED. The operator's 2026-09-29 autonomous mandate now
authorizes engineering across the epic on parrot-2TB and obsd1. The signed
plan anchor and all original reference hashes verify. S00-01/02/03 have signed
source deliveries; S00-04 is delivered as `85e1701`. S01-01 implements
persistent light/dark/system preferences and has passed local gate verification.
S01-02 adds the native icon rail, account menu and validated archive shortcut.
S01-03 adds compact disclosures, clearer errors, settings cards, truthful
capability labels and reader/draft reflow; local acceptance gates pass.
S01-04 verifies current HTML route states, all appearance modes, responsive
reflow, keyboard controls, computed contrast, forced colours, Firefox and
synthetic account persistence through process restart. The exact S01 source
`eb0277d` passes isolated native OpenBSD library and hostile-rendering tests on
obsd1. S02-01 checkpoint A adds real unread/starred filters, stable ordering,
50-row result windows, query preservation and mailbox/UID selection. Five
synthetic browser journeys and 92 visual/reflow/forced-colour captures pass.
Checkpoint B adds strict structured native message identity and attachment
metadata, explicit read/star forms and identity-bound idempotent helper writes.
Checkpoint C replaces wide tables with compact accessible message rows,
bounded header previews and native disclosures for sorting and secondary
actions. 588 library tests, six state-control and six navigation journeys pass.
74 full-page theme/reflow/expanded/forced-colour/Firefox checks pass. The exact
checkpoint B source passed native library and hostile-rendering tests; its
disposable mail test required corrections for the intentionally cleared command
environment and OpenBSD directory group inheritance. Corrected exact-source
native helper qualification now passes on exact checkpoint C: 588 library
tests, two hostile-rendering checks and the isolated signed-helper native test.
Checkpoint D adds actual bounded text previews, decorative sender initials,
the bounded current-page selection menu and native global search/shortcuts.
593 local library tests, nine navigation and six state-control journeys pass;
82 theme/reflow/forced-colour/Firefox captures and 88 shell captures verify the
shared-header change. Exact D native qualification passes on signed `a86e40e`:
593 library tests, two hostile-rendering checks and the isolated signed-helper
test with actual native previews. S02-01 engineering is delivered within its
recorded result and action limits.
S02-02 now coordinates list/search and reader with fresh stored-identity checks,
preserved query/filter/sort/page context, off-page locate links and body-first
narrow views. 596 library tests, six reader journeys in each of Edge/Firefox,
nine list journeys, six state-control journeys and 86 final visual checks pass.
Exact E native qualification passes on signed `da16175`: 596 library tests,
two hostile-rendering checks and the isolated signed-helper native test;
standard checkout and services unchanged.
S02-03 strengthens all browser move actions with mandatory stored mailbox and
message identity, atomic fail-closed mail-action quotas, one shared native
mutation gate and bounded pre-read/write/confirmation. Archive, move, Bin and
Restore to Inbox share one form contract; bulk selections contain at most ten
identities, stop on failure and distinguish confirmed/uncertain/unattempted
work. Bin is a reversible move to an existing Trash mailbox. Successful
navigation clears the action selection and reads fresh counts; caller-supplied
success query parameters no longer produce completion claims. Old forms and
incompatible helpers refuse the upgraded mutation protocol without fallback.
Local checks and synthetic visual/browser evidence are recorded under S02
checkpoint F. Exact signed F passed native qualification on obsd1: 607 library
tests, two hostile-rendering checks and the signed-helper reversible move and
flag test. Standard checkout and services unchanged.
S02-04 adds authenticated escaped stored-source text, contextual return links,
identity-bound attachment reads from one checked snapshot, sandboxed forced
downloads, bounded To/Cc reader details and useful empty/error/read-only retry
states. 611 library tests and five source/download journeys in each of Edge
and Firefox pass. Source represents stored headers and MIME body text, not a
byte-exact original wire export. Existing source/download size limits remain.
Common acceptance, V14, strict Clippy and 108 visual captures pass locally.
Exact signed G `61bfb09` passed native qualification on obsd1: 611 library
tests, two hostile-rendering checks and the isolated signed-helper source,
attachment, flags and reversible move test. S02 engineering is delivered.
S03-01 checkpoint A adds a canonical sender allowlist, bounded bare/display-name
address parsing, envelope deduplication, Reply-To-aware reply-all with self
exclusion, checked original-message threading and versioned draft persistence
for that thread. 623 library tests, strict Clippy, common acceptance and V14
pass. Five reply journeys pass in each of Edge/Firefox; 54 visual, contrast,
forced-colour and simulated-reflow captures verify. Exact signed-source native
qualification follows; contacts and full S03-01 acceptance remain in progress.
Independent human accessibility acceptance
and deployment remain separate.
D01–D06 are recorded
as delegated engineering decisions in `UX_DECISIONS.md`. Independent human
identity/accessibility and final release acceptance remain separate.
See `UX_AGENT_EXECUTION_CONTRACT.md` and `UX_EXECUTION_LEDGER.md`.
Native qualification is limited to the exact S01 and S02 snapshots/checks above;
no UX deployment or full live-mail workflow qualification is claimed.
The operator reports Roundcube completely removed; the UX epic does not include
Roundcube migration, coexistence or restoration.

### Earlier TOTP administrative-closeout record

As of 2026-09-15, the approved TOTP lifecycle continuation contains Slice 02
(planned rotation), Slice 03 (recovery), and Slice 04 (integration closeout).
Slice 02 was delivered as signed commit `77dc836` and continuation was approved.
Slice 03 recovery implementation and local qualification are complete with a
short-lived signed operator-approval boundary; its signed delivery is recorded
in the sprint handoff. Both commits are synchronized through PR #61. Slice 04
native synthetic checks passed on obsd1. Operator-reported initial enrollment
and planned rotation were reconciled through read-only factor digests.
The operator subsequently accepted the delivery and directed closure and sync.
Slice 04 and the sprint are administratively closed with deferred controlled
recovery validation and unverified live-account cleanup, not full validation
acceptance. No slices remain open in this sprint. These residuals are tracked in
`TOTP_LIFECYCLE_SPRINT.md`; they are not passed checks. A separate
reserved-account test-custody mode preserves real-user identity requirements;
it does not establish production recovery qualification.
See `TOTP_LIFECYCLE_OBSD1_EVIDENCE.md`.
No new production qualification
is claimed. `mail.blackbagsecurity.com` is now the Vultr instance;
the former LAN host is `obsd1.blackbagsecurity.com` at `192.168.1.44`. Earlier
deployment records below describe their assessed host at the recorded time.
See [TOTP_LIFECYCLE_SPRINT.md](TOTP_LIFECYCLE_SPRINT.md) for controlling sprint
status and evidence boundaries.

The operator selected obsd1 at `192.168.1.44` for current sprint validation;
SSH access and its system hostname were confirmed. Vultr is not this sprint's
validation target or completion dependency. Resulting host evidence must be
identified as obsd1 evidence.

The repository now contains completed governance, hardening, OpenPGP foundation,
and WSTG assurance work through V13. Earlier README language that described the
project as only post-V9 is stale.

The current authoritative status chain is:

1. V9 selected-cohort release-candidate closeout.
2. V10 governance, claims-boundary, acceptance, documentation, and fail-closed
   assumption triage.
3. V11 runtime fail-closed closure for the refined high-relevance assumption
   queue.
4. V12 non-cryptographic OpenPGP secure foundation through Slice 14 closeout
   readiness.
5. V13 WSTG assurance integrity, adversarial validation, and production
   deployment closeout.

## Version status summary

| Version | Current status | Current claim boundary |
| --- | --- | --- |
| V4 | Historical hostile-content safety release evidence remains the formal tagged release baseline. | Bounded hostile-content containment only, not broad malware or hostile-mail safety. |
| V5 | Boundary hardening evidence and production deployment records exist. | Identity, Host, origin, response, and trusted HTML boundary hardening only. |
| V6 | Production readiness passed and was later reconciled by V9 for selected-cohort no-Roundcube operation. | Selected-cohort readiness only, not broad Roundcube retirement. |
| V7 | Production availability reopening is closed for the tested selected-user path. | Tested path and current rendering policy only. |
| V8 | Regression matrices and mandatory CI enforcement are complete. | Source stabilization and regression protection, not a new production deployment by itself. |
| V9 | Selected-cohort release-candidate gate passed at `a8915c0993b96a9d53de083dc84cb7520aef0097`. | Selected-cohort release candidate under documented limitations. |
| V10 | Governance, acceptance, documentation status, and fail-closed assumption triage are gate-visible. | Governance and claims-boundary control, not runtime feature expansion. |
| V11 | Refined high-relevance runtime fail-closed closure is documented and gated. | Runtime hardening for selected assumption paths, not broad public release readiness. |
| V12 | OpenPGP foundation completed through Slice 14 closeout readiness. | Non-cryptographic foundation only. No decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, browser controls, or decrypted rendering. |
| V13 | WSTG assurance integrity and adversarial validation are completed and deployed. | WSTG assurance upgrade, live validation, and deployment evidence under the explicit residual limits in the V13 closeout. |

## Current production and deployment records

V9 recorded the selected-cohort release-candidate decision while production was
still running the PR #19 binary:

- V9 selected-cohort release-candidate commit:
  `a8915c0993b96a9d53de083dc84cb7520aef0097`
- V9 production runtime source:
  `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- V9 production binary SHA256:
  `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

V13 later records a reviewed production deployment:

- V13 final reviewed commit:
  `7009b15322c4e7795c797c1387b403e0f4935adb`
- V13 live and staged binary SHA256:
  `333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963`
- V13 release run:
  `osmap-wstg-20260627-204207`
- V13 credentialed release outcome:
  `42 pass`, `0 fail`, `0 warning`, `0 skip`, and `4 justified not-applicable`

The V13 closeout remains the current production deployment evidence reference.
Source sync alone must still not be described as deployment.

## Active gates

Developer and acceptance gates now include:

```sh
make security-check
make acceptance-check
make v10-check
make v11-check
make v12-check
make v13-check
```

Strict release validation remains separate:

```sh
OSMAP_SECURITY_PROFILE=release make release-check
```

The strict release path remains evidence-dependent and may fail safely when live
host, credentialed WSTG, TLS, supply-chain, or sanitized evidence inputs are
missing or stale.

## OpenPGP status

OpenPGP is no longer merely a design-only investigation. V12 created a bounded,
non-cryptographic implementation foundation:

- requirement and claims boundary;
- public key inventory and dependency diagnostics;
- explicit account-to-full-fingerprint binding model;
- helper protocol scaffold;
- GPGME readiness and availability gates;
- compile and link scaffold;
- protocol-only helper invocation scaffold;
- typed Rust helper-client planning boundary;
- helper-client integration gate;
- capability policy, outbound preflight, and inbound security-state models;
- Slice 14 closeout readiness audit.

V12 does not enable runtime cryptography. OSMAP must not claim working OpenPGP
decryption, signature verification, signing, encryption, PGP/MIME handling,
passphrase handling, private-key access, browser OpenPGP controls, key
discovery, WKD, keyserver lookup, or decrypted-content rendering until later
slices implement and evidence those functions.

## Current residual limitations

The current project still does not claim:

- complete Roundcube replacement for all users;
- general hostile-email safety;
- malware prevention beyond the explicitly tested mail-stack boundary;
- attachment preview safety;
- broad URL reputation or phishing protection;
- unbounded MIME, mailbox, archive-recursion, or document-sanitization safety;
- full ASVS verification;
- universal production readiness outside the documented deployed scope;
- OpenPGP runtime cryptographic operations.

## Documentation maintenance rule

Any future slice that changes current release posture, production deployment,
OpenPGP capability, WSTG assurance, or selected-cohort scope must update this
file, the root README, docs/README.md, KNOWN_LIMITATIONS.md, and the relevant
version closeout document in the same change stream.

<!-- v15-slice-03e-status:start -->
## Current V15 assurance status

V15 Slice 04 closes every policy in the fixed 37-case HTTP differential corpus. The signed implementation commit is `158f61d3735712faac019cae97f7ef3e26787973`, the assessed policy/harness commit is `6e28ae4ed8b83584ba5df1e522e17b358e5e8ebd`, and the deployed OpenBSD binary SHA-256 is `d7426c8b51bed05f535da7195246a04365c3c5f39967a0170e64f350761cc85e`. Offline and live campaigns both report 37 cases, zero required-policy failures, zero measured cases, and zero cardinality violations. Historical Slice 03 conclusions and evidence remain accepted. See [V15_HTTP_DIFFERENTIAL_ASSURANCE.md](V15_HTTP_DIFFERENTIAL_ASSURANCE.md).
<!-- v15-slice-03e-status:end -->
