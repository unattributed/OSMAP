# OSMAP UX sprint and slice catalog

Normative plan revision 2; governed by `UX_FULL_FUNCTIONAL_EPIC.md` and
`UX_AGENT_EXECUTION_CONTRACT.md`. This is a work breakdown, not completion
evidence. Twelve sprints, four slices each: 48 total. Initial state is NOT_STARTED
for every slice at initial publication. Progress remains in the ledger.
`UX_PLAN_AMENDMENT_R2.md` and `maint/ux/approved_pages.json` add the final
25 PNG / 27-page requirements without removing earlier functional obligations.

## Ordering and sizing

Default execution is S00 through S11, and -01 through -04 within each sprint.
Each slice depends on its predecessor; each sprint depends on acceptance of
the preceding sprint. The explicit decision gates are additional dependencies.
Do not parallelize agents or skip/reorder slices without operator approval.
A blocked decision can be worked around only through an approved dependency
change, not by silently taking a different slice.

Revision-2 ordering: after the separate signed reference correction, finish the
preserved bounded S03-01 contact checkpoint, then reconcile S01/S02 visuals
before continuing page acceptance. Resume S03 and subsequent sprints against
the final bundle. Existing tests remain valid only for their recorded scope;
earlier visual completion is reopened. Signed engineering checkpoints may
continue under the autonomous mandate; independent acceptance remains pending.

Each row specifies deliverable, likely source boundary, and discriminating
acceptance checks. Exact permitted files and test commands are frozen in the
slice work order before implementation. A slice that grows beyond a reviewable
commit must be split by an approved plan amendment, not hidden partial delivery.
Every row also inherits the full common gate, evidence and rollback contract.
Documentation-only slices do not claim runtime behavior.

## S00 — Intake, architecture and executable acceptance design

Goal: remove ambiguity before implementation. No live writes.
Read: V12 requirements/helper/preflight/inbound models, V14 UX specification,
current source/routes, TOTP SOPs, administrative-user engineering request.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S00-01 | Inventory every final reference control and current implementation; capture baseline synthetic light-page screenshots; retain UX01–17 and expand all 27 approved pages | Verify exact 25 PNGs plus approval lock/README; preserve Login/TOTP implementation; enumerate every page/route/error; no assumed parity from historical evidence |
| S00-02 | Decide D01/D02/D03: interaction architecture, crypto execution/data flow, key custody, supported PGP/MIME profile and dependency plan | Operator-approved ADRs; browser versus host plaintext path explicit; no unapproved CSP/script addition; review key isolation, passphrase availability, crash/core/swap risks |
| S00-03 | Decide D04/D05/D06: identity authority, ancillary semantics, retention/quotas, deployment scope; define threat model and state migrations | Approved finite action inventory; concrete resource/time/rate limits, privilege map and test accounts; document conflicts and fail-closed outcomes; no assumed live authority |
| S00-04 | Build acceptance matrix and synthetic fixtures; record page/viewport/state visual baselines; reconcile prior TOTP follow-up evidence through separate scoped documentation | Every UX control maps to case + owning slice; entry/exit and negative tests defined; source/provenance pinned; all decisions needed for S01 accepted |

S00 completion requires decisions and tests to be specified, not merely a copy
of this epic. Its fixture harness may render synthetic UI but cannot contact mail hosts.

## S01 — Shared shell, design system and every-page appearance

Goal: working persistent light/dark/system mode first. No new mail authority.
Likely boundaries: `src/http_support.rs`, `src/http_ui.rs`, `src/settings.rs`,
settings gateway/routes, route tests and local asset helpers.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S01-01 | Theme tokens, persistent preference, system default; define authenticated versus pre-login storage and precedence | Light/dark/system survives navigation, reload and logout as specified; invalid input defaults safely; account isolation, CSRF and setting migration/concurrent-update tests |
| S01-02 | Approved labelled sidebar, top bar/search, account and theme controls, welcome dashboard, responsive shell and collapse under D01 | Real navigation/actions; accessible names, selected state, focus order; no external resources or invented dashboard facts; long data does not overflow |
| S01-03 | Shared headings, compact security/status components, forms, menus and notices; settings search is section-scoped | Truthful runtime-derived labels; no copied example trust state; source and message content cannot inject layout or security badges |
| S01-04 | Theme every HTML surface while preserving current Login/TOTP layout and behaviour | Final bundle and retained-auth comparison; 360/768/1440 plus reference dimensions; contrast 4.5:1 normal, 3:1 large and meaningful UI/focus; keyboard and forced colours |

Theme choice is not a security preference and must never toggle sanitization,
remote content, TLS, authentication or encryption policy.

## S02 — Inbox and secure reader workflows

Goal: compact mailbox scanning and functional reader actions without state loss.
Likely boundaries: mailbox models/helper, HTTP mail routes, rendering and UI.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S02-01 | Bounded search/filter/sort, selected message, unread/read/star state and attachment metadata in approved Inbox/Sent/Search rows | Empty/single/multiple results, stale UID, stable ordering and bounded pagination; per-account IDs; all pictured filters tracked; document/people categories depend on S03/S08 |
| S02-02 | Coordinated list and reader navigation under D01 with selected row, headers, history/back behavior and persisted query context | Search/filter/list changes preserve reader as approved; keyboard/mobile order; account/folder switches cannot show stale cross-account content |
| S02-03 | Approved Archive/Bin tabs and archive/move/bin/restore, bounded bulk actions; separately confirmed policy-permitted permanent delete | CSRF, ownership, duplicate/stale submissions, partial failure and limits; no implicit expunge; missing retention authority refuses permanent delete; counters/selection reconcile |
| S02-04 | Reader body, explicit escaped source, isolated attachment downloads, reply action links and required empty/error/retry states | Source is authorized/escaped/no-store, not active HTML; filenames and size limits enforced; remote content remains blocked; retry cannot duplicate a mutation |

Labels and snooze controls are not marked complete until S08; normal reader
work cannot claim crypto before S06/S07.

## S03 — Full compose, drafts and attachments

Goal: finish non-cryptographic authoring against approved pages 04/06 and the
compatible C functional annotations; crypto integration follows S07.
Likely boundaries: compose/draft/mail gateways, MIME/submission, UI and upload limits.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S03-01 | Authorized sender identities, address/contact selection, To/Cc/Bcc, reply/reply-all/forward and quoted context | Identity allowlist; no arbitrary From impersonation; deduplicate/exclude self per approved policy; header-injection rejection and correct reply threading |
| S03-02 | Save/resume/discard, close/minimize/expand, draft list filters/sort, approved auto-save preferences, safe failure preservation and concurrency | Draft owner isolation, stale writes, form errors, interrupted navigation and auto-save races; every pictured action has a real outcome; discard confirmation and bounded retention |
| S03-03 | Working formatting/link/list/image/emoji controls and preview under D01/D05 | Approved rich-text or constrained authoring semantics, not decorative buttons; hostile markup/URLs rejected; no remote image fetch; preview and delivered MIME agree |
| S03-04 | Upload/list/remove attachments, attachment metadata and ordinary send/Sent-copy reconciliation | Per-file/aggregate limits, filename/path checks, interrupted upload cleanup; MIME interoperability, Bcc confidentiality; ambiguous send never silently retries/duplicates |

A delivery failure cannot be hidden behind success UI. A successfully submitted
message with failed Sent storage requires an explicit reconciled state.

## S04 — Account settings, password and governed recovery

Goal: actual account functionality, not reassuring placeholder cards.
Likely boundaries: settings, session/recovery services, narrow privileged account
adapter, authenticated UI; no general PostfixAdmin replacement.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S04-01 | Distinct approved Settings 10–20, section search/navigation, profile/preferences and accurate status; sessions page 24 | Each pictured preference persists and affects its owning workflow; unknown status remains unknown; Security is within Settings, Privacy & Security is distinct; truthful session metadata/revocation |
| S04-02 | Page 22 own-account password change, authoritative backend and step-up; independent accessible Show/Hide on current/new/confirmation | Per-field visibility never submits/logs/persists values; wrong/stale credentials, CSRF, races and partial failure; revoke per D04 and verify actual mail authentication |
| S04-03 | Recovery contact add/verify/change/remove with proof lifecycle and notifications | One-use expiring tokens stored safely; no enumeration/token leakage; replay, resend limits, pending versus verified, old-contact notification and revocation behavior |
| S04-04 | Controlled real-user recovery coordinator joining identity verification, containment, session revocation and TOTP tooling | Independent identity-policy review; negative and interrupted recovery tests; no email-only MFA bypass, auto retry or auto old-factor restore; clear manual escalation and audit reconciliation |

Human identity attestations cannot be produced by an agent. Test-account custody
is useful rehearsal evidence but insufficient to qualify real-user recovery.

## S05 — Isolated runtime OpenPGP and key management

Goal: auditable crypto authority and usable account bindings, after D02/D03.
Likely boundaries: V12 helper/client scaffolds, GPGME helper build/service,
account policy store, reviewed native confinement and public-key settings.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S05-01 | Extend versioned bounded helper protocol for real operations with narrow authorized data transport and separate metadata | No arbitrary paths/commands; cross-account request denial, length/time/concurrency bounds, malformed/unknown result refusal; no body/key/passphrase logs; old scaffold invariants preserved |
| S05-02 | Public-key import/list/remove, full-fingerprint binding, explicit recipient trust, capability/policy UI and private-key provisioning SOP | Collision/ambiguous binding, expired/revoked/unsupported keys, import limits, deletion/rotation safety; public material only in browser; private custody/unlock tested with disposable fixtures |
| S05-03 | GPGME execution, account isolation, resource-limited workers, cancellation and redacted errors | Real library operations with disposable keys; locked agent/missing library/timeouts fail closed; no direct handler gpg fallback; distinct mailbox and Shopkeeper keys |
| S05-04 | Native OpenBSD build/confinement/dependency qualification in authorized isolated environment | Helper privilege/socket/descriptor isolation, crash/core/log policies and restart behavior; dependency inventory and rollback evidence; no capability enabled just because compile passes |

Do not write custom cryptographic primitives or enable a permissive fallback.

## S06 — Inbound PGP/MIME and protected reading

Goal: actual signature verification and decryption while retaining hostile-content controls.
Likely boundaries: MIME parser, runtime crypto client, rendering, attachment/source routes.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S06-01 | Bounded PGP/MIME classification and exact signed-byte canonicalization | Valid supported fixtures plus malformed/truncated/unsupported multipart cases; part/depth/size limits and unambiguous content selection; preserve original source bytes |
| S06-02 | Real signature verification and separate signer binding/key-validity states | Good/bad/unknown/expired/revoked and multiple-signature policy; tampered bytes fail; no green “verified” from metadata alone or implied content safety |
| S06-03 | Real decryption through isolated helper into bounded transient content transport | Correct/missing/wrong/locked keys, malformed ciphertext, cancel/timeouts; no plaintext persistence; account isolation and actual execution-location labeling |
| S06-04 | Reparse and sanitize decrypted MIME; render state strip, downloads, source and failures | Hostile decrypted HTML cannot bypass sanitizer/CSP; attachment access bound to account/message; source ciphertext versus decrypted source clearly specified; no decrypted-body cache or unsafe retry |

## S07 — Outbound OpenPGP and protected delivery

Goal: cryptographic controls govern actual delivered bytes, not just a preview.
Likely boundaries: outbound preflight, recipient policies, MIME builder,
crypto helper, local submission and Sent storage.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S07-01 | Runtime-bound sign/encrypt/self settings and page 04 defaults Unsigned/Not encrypted/self Off; separate recipient readiness; green/orange/blocked preflight | Required/optional/disabled matrix; missing/ambiguous/revoked keys; revalidate at submission; mandatory failure blocks without downgrade; permitted reduced protection is orange |
| S07-02 | PGP/MIME signing and independent verification of emitted message | Real disposable-key signatures, attachments and line endings; signature failure means no successful signed-send claim; no unintended cleartext copy |
| S07-03 | Encryption and sign-then-encrypt, encrypt-to-self and privacy-aware Bcc envelope handling | Every intended recipient and sender can decrypt as required; outsiders cannot; no Bcc header/key identity leakage beyond approved protocol limits; no downgrade on key failure |
| S07-04 | Wire compose/send/Sent/reply/forward with transaction and failure reconciliation | Deliver to controlled local sink, independently decrypt/verify bytes; stale policy, interrupted helper/submission and Sent-store failure handled; no automatic duplicate send or plaintext fallback |

Sending to real external recipients is a live side effect requiring separate
bounded authority, not implied by “run integration tests.”

## S08 — Remaining pictured capabilities

Goal: complete ancillary mockup controls with finite semantics from D05.
Likely boundaries: narrow account-private stores/services, mail operations and UI.
No general command runner, arbitrary filesystem browser or groupware platform.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S08-01 | Approved Documents upload/list/folders/search/sort/views/download/bin/restore; shared authoritative mailbox/storage quota and retention | Joint quota reservations and concurrent mail/document writes cannot bypass account limit; unavailable authority refuses writes; MIME/filename limits, isolation, CSRF and interruption cleanup |
| S08-02 | Labels/tags/finite menus plus page 16 mailbox subfolder create/rename/move/delete and hierarchy | Protected/system restrictions, cycles, stale identities, cross-account denial, non-empty disposition and confirmation; bounded concurrency; all menu actions have tests |
| S08-03 | Scheduled send and snooze with bounded persisted jobs and restart/cancel/edit behavior | Timezone/DST, clock changes, worker ownership, duplicate dispatch suppression, ambiguous-send manual reconciliation; revalidate keys/identity/policy at send time; no unauthenticated scheduler control |
| S08-04 | Notification inbox/badge/read state and all page 17 preferences, including explicitly consented desktop delivery | Actual per-account events and bounded retention; opt-in permissions and factual delivery status; no fake score, private-content leak or unsolicited external notice |

## S09 — Integrated visual, interaction and accessibility completion

Goal: match approved references and D01 amendments with all real backends wired.
Likely boundaries: UI/CSS/components plus synthetic browser regression fixtures.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S09-01 | Whole-site theme/responsiveness and persisted preference audit including every new page | Light/dark/system screenshot matrix at 360/768/1440 widths, 200% zoom, long data, keyboard and visible focus; no light-only popup/form/source/error surface |
| S09-02 | Final pages 01–09/27 comparison and security/error-state matrix | Every approved control plus compatible I/C/F mapped; selection, toolbars and crypto failures; screenshots backed by actual route tests |
| S09-03 | Final pages 10–24, contacts/notices, retained Login/TOTP 25/26 | Every approved Settings/key/account/document control functional; real facts; authorized workflows; no auth redesign or unapproved visual substitutions |
| S09-04 | Independent human usability/accessibility acceptance and deviation reconciliation | Keyboard-only journeys, screen-reader labels/status and contrast review; no placeholder accepted as complete; approved deviations linked without quietly weakening requirements |

## S10 — Assurance and release candidate

Goal: independent behavioral security assurance before live qualification.
Likely boundaries: tests/gates, WSTG mappings, evidence/release documents.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S10-01 | Full user-journey integration with actual helpers and disposable accounts/keys | Normal/key-enabled/key-disabled accounts; receive/read/reply/forward/send/Sent/drafts, settings and recovery; all UX IDs covered |
| S10-02 | Security review of authorization, key isolation, rendering, parser/resource bounds and state races | Reviewer independent of implementation where available; local synthetic tests only; findings must be fixed/retested or block acceptance, not recast as passes |
| S10-03 | Dependency, performance, concurrency, storage and fault/restart qualification | Concrete S00 budgets enforced; no unbounded queue/key/document growth; evidence of cleanup and no sensitive output; native target results |
| S10-04 | Assemble commit-pinned release candidate and upgrade/rollback package | Developer/acceptance/version gates plus fresh strict-release evidence; every warning/skip explained; no old V13/V15 or TOTP evidence passed off as current crypto qualification |

## S11 — Authorized qualification, deployment and closeout

Goal: bounded live proof, reversible rollout and accepted final state.
Likely boundaries: deployment SOPs/scripts, migration and release evidence.
Requires fresh D06 authority for exact host/account/action/window.

| Slice | Deliverable and source boundary | Required proof / exit |
| --- | --- | --- |
| S11-01 | Preflight exact target, old/new source/binary hashes, dependency/state backup and rollback rehearsal | Host key/name/IP match, recoverable OSMAP baseline, narrow approved accounts; no assumed Roundcube fallback or Vultr permission |
| S11-02 | Controlled OpenBSD functional qualification of mail, crypto, themes and account workflows | Human private-terminal key/recovery actions as required; actual independently verified delivered crypto; no production secrets in evidence; reconcile each mutation |
| S11-03 | Approved staged deployment with monitoring and rollback triggers | Source sync distinguished from binary installation; health and workflow checks; migration failures rollback safely; external mail/key/account changes stay within approved bounds |
| S11-04 | Verified temporary-state cleanup, operator acceptance and signed final evidence | Restored account/credential/session/job state or explicit retained-state disposition; all 48 slices ACCEPTED and UX IDs proven; approved sync SHA equality; target-specific completion/non-claims |

## Common acceptance pack for every slice

The slice work order must name:
1. Parent source SHA, approved plan digest, dependencies and decision references.
2. Exact file/operation allowlist, data ownership and bounded mutation authority.
3. Applicable positive, negative, malformed-input, concurrency and interruption tests.
4. Fixture setup/cleanup, concrete budgets, expected outputs and failure dispositions.
5. Source-only, native, live and release claims separately.
6. The common gates from the execution contract, with raw sanitized exit/status evidence.
7. Migration and rollback, or explicit “documentation-only/no migration.”
8. Signed commit, signature proof, review checkpoint, and any separately approved sync.

No “remaining slices” estimate may omit blocked or partially implemented rows.
