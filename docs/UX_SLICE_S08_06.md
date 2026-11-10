# S08-06 — Presentation style

## Approved outcome — 2026-11-10

The owner approved the nine-page desktop/touch mockup pack, then clarified:
“within settings appearance the user can select the presentation style icon,
or text labels”. Settings → Appearance therefore offers **Presentation style**:
**Icons** or **Text labels**. Text labels is the default. This is design approval,
not completed-product acceptance. Original S08 and S08-05 remain accepted;
S08-07 Junk and removed Documents work are outside this slice.

The per-account choice survives navigation, refresh and sign-in. Icons mode
covers existing primary and secondary actions and navigation throughout the
authenticated app, including the sidebar. Desktop controls have meaningful
accessible names and visible hover/focus names. Touch-capable phones, tablets
and hybrid computers retain visible action labels and usable spaced targets;
mouse/trackpad capability alone must not hide labels on a touch-capable device.
Unknown input capability retains labels. Device fallback does not change the
saved account choice. Text labels shows readable action names.

The approved visual reference is `docs/design/s08-06-approved-20261110/`.
It covers Compose, Inbox, Drafts, Outbox, Sent, Contacts, Archive, Bin and Mailbox
with separate touch versions. Other authenticated pages use the same rules.
The original retained mockup archive SHA256 is
`746b71ee94b05253c492ad3c284a9b7a86e8b3a56b057a17cf7fcf2e8ff3fbf3`.
All reference content is synthetic. Mockups illustrate presentation; they do not
add actions or replace existing route semantics with a new mail application.

## Preserved boundaries and implementation

Keep the accepted logo, field labels/values, message content, folder names,
identity/security facts, errors, help and confirmation wording readable.
Keep native form values and status-bearing summaries. Keep existing pre-send,
Send, destructive confirmation, disabled-state and Outbox reconciliation rules.
No unknown submission is retried; no new mail/account/key operation is added.
Pre-sign-in Login/TOTP/recovery retains labelled presentation.

Reuse Rust Appearance persistence, its account-hashed atomic sidecar/lock,
Runtime gateway, existing authenticated request context, source-owned templates,
local inert icons and CSS. Old/missing fields default to Text labels. Invalid
forms preserve all settings. Theme-only saves retain presentation style.
Account identity comes from the validated session, never a prior account cookie.
Unavailable settings use finite labelled defaults without writing a replacement.
No new dependency, icon CDN, service, database, Python tool or general UI/test
framework. Reader hostile-markup and CSP protections remain intact.

Root owns integration, implementation, documentation, Git and the single native
queue; `/root/s08_scrum` coordinates and `/root/s08_delivery_review` independently
reviews delivery/security/QA. Bounded developers receive disjoint file ownership.
The active ledger contains the actual assignments, allowance, results and next
action. The frozen plan is unchanged; S08-06 is an additive Appearance extension
mapped mechanically to S01-01, without claiming parent completion.

## S05 delivery method and T01–T09

Each boundary follows expected observation → execution → diagnosis → smallest
supported correction → original-case/essential-negative retest. Retain failures,
unknown observations and measured/unknown cumulative cost. Two failures at one
functional boundary stop retries for combined independent reassessment. Reuse
matching passes; run normal broad gates at delivery. No blanket repeated suite,
renamed allowance or new test machinery replaces a working journey.

| Task | Minimum result required before product closure |
| --- | --- |
| T01 Definition | Approved references and exact setting labels; inspect actual store, gateway, HTTP, shared template and responsive contracts before edits. |
| T02 Rendering | Actual controls preserve actions/content/states; Text labels and Icons produce the approved presentation; finite icon mappings have no misleading fallback. |
| T03 Persistence | Real save/load/Runtime/HTTP, refresh/re-login, old records, theme-only updates and two accounts preserve the correct independent style. |
| T04 Integration | Actual routes across mail/reader, compose/drafts/outbox, contacts/folders/labels, notifications and Settings/security/key pages retain reachable actions. |
| T05 Negatives | Invalid/duplicate/foreign/CSRF/Origin/stale requests refuse without changing settings or action authority; disabled/destructive states retain meaning. |
| T06 Browser | Desktop pointer/keyboard, touch/hybrid emulation, narrow/wide, themes, density and zoom; visible labels/focus, spacing/scrolling and no hidden account actions. Physical-device observations remain separately identified. |
| T07 Recovery | Missing/legacy/corrupt/unavailable store and interrupted save preserve choices and unsent work; confirmed-save claims require matching persistence readback. |
| T08 Delivery | Independent source/results audit, normal gates and signed publication, matching OpenBSD Web/installed proof and recoverable Web-only delivery. No public mail/configuration or owner credential/key/message mutation. |
| T09 Owner | Only after required engineering/installed checks pass: short owner check of saved style, desktop primary/sidebar actions and labelled touch fallback; explicit acceptance separate from design approval. |

All product tests begin NOT_RUN. Existing static mockup checks are design-only.
Known prior aggregate V14 failures (two obsolete reader/OpenPGP scaffold text
assertions) remain recorded; no aggregate or release PASS is inferred.

## Concrete presentation boundaries

The finite source-owned icon families cover save/send/schedule, composition and
formatting, read/unread/star, selection/movement/archive/bin, folders/drafts,
contacts, search/filter application, navigation/details, settings/session/key
actions and notifications. Unknown mappings retain escaped visible text.
Existing source-owned DOM widgets keep their captions through recipient/file
updates, auto-save retargeting and password visibility/reset events. No rendered
mail or arbitrary HTML is scanned to choose an icon.

Native field values, folder/message links, security/policy summaries and explicit
consent/status information retain text. In particular, public-key capability,
account-key details and protection-policy summaries remain readable. Unavailable
controls may retain their existing readable disabled presentation. These are
readability boundaries, not permission to drop actions.

## Persistence migration and recovery

Appearance records are backward-readable and forward-written: the new code
reads versions 1/2/3, defaults legacy records to Text labels and writes version 3
on every confirmed Appearance or theme-only save. Reads do not migrate files.
The presentation cookie remains version 1 and carries no style authority.

Selecting Text labels reverses the feature in the compatible new binary; it
does not downgrade storage. The prior binary only reads versions 1/2. With a
version-3 record it uses display defaults/load warnings and refuses preference
writes without replacing the unsupported bytes. Login/authentication remains a
separate working boundary. Source inspection and disposable native tests must
retain these facts rather than claim old-version Appearance editing works.

Retain both the original executable and the assessed version-3-capable candidate.
Executable/service rollback preserves all current preference bytes, including
concurrent saves. Report that outcome as executable/service restoration with
preference schema retained; it is not full Appearance restoration. Restore full
editing through a compatible candidate or forward correction. Do not silently
restore stale preference backups or delete/downgrade current account choices.
No owner preference write is necessary to qualify the disposable native store.

## Retained verification history

Initial Appearance compilation refused a misplaced navigation mapping in the
native option helper; options were restored to escaped plain text and the mapping
moved into navigation. The changed focused run passed 32 tests (one explicitly
ignored child helper; its parent lock test passed). The first renderer run had
54 passes/8 label-adjacency failures; semantic form/action/disabled assertions
were preserved and strengthened, and the changed run passed 62 tests. Compose
formatting 9 and enhancement 2 focused tests passed. Actual source/CSP consumers
pass 12 composer and 3 password negative controls with exact script hashes.

Browser01 retained a fixture Sent-shortcut unavailable result after four desktop
checks. Direct Sent/Trash routes were then bound to the actual fixture contract.
Browser02's desktop checks remain scoped observations; its full-height touch
captures are NOT_QUALIFIED. An isolated before/during/after media diagnostic
proved those captures switched touch emulation into fine/hover input. Reviewed
viewport-only captures preserve input state. Browser03 retains 13 phone pages
and the raw exact-count refusal (36 to 40 visible captions, with no hidden
captions or input change). Exact caption count is not a product prerequisite.
Browser04 verifies remaining navigation/account actions, real recipient/file
handlers and a real 30-second auto-save/readback with zero Send requests. Visual
review found a wide-touch clock overlap; it remains unqualified until the scoped
normal-flow correction and matching layout check pass. Raw failures and scoped
passes remain distinct in the sprint-root evidence.

Browser05 supersedes the wide-touch layout finding: the normal-flow clock and
recipient tools pass the matching overlap check. Nine scoped observations cover
saved light/dark/system themes, compact/large density, account focus names,
phone-large layout, empty password Show/Hide labels and 720-CSS-pixel/DPR-2
layout equivalent to 200% scaling. This is not a native browser-UI zoom result.
Physical mixed-input hardware remains unobserved; the CSS explicitly retains
labels whenever any coarse pointer is present.

The first normal acceptance gate stopped in Rust tests with 2,333 passes,
23 failures and 90 explicit ignores. Independent review traced those failures
to old direct-inner-text assertions and link extractors; action, owner, GUID,
CSRF, Origin, revision and disabled-state assertions remain required. Scoped
semantic test-consumer corrections also strengthen negative control checks.
The exact affected-case run passed 27 cases and found one later old Identity
link-caption assertion after the earlier corruption/refusal checks passed.
The reviewed Identity correction passed its original-case retest; the other
27 passes are retained. The next aggregate recorded all 2,356 library cases
passing, then refused a missing index entry for the approved design README.
The index was corrected and the actual documentation-governance check passed.

A subsequent aggregate found one failure in the unchanged immediate-child
admission test after its EOF/owned-cleanup assertions passed. Its fixed result
was Unavailable; the underlying cause is UNKNOWN because the retained result
does not distinguish the possible admission/cleanup paths. The original case
passed in isolation with unchanged deadlines. Independent reassessment approved
one normal run with two test threads and no concurrent gate workflow; all 2,356
library cases passed. That run then stopped on stale generated V10 test/fixture
counts and inventory hashes. Refresh only the existing derived registers and
their linked claims, with no scanner, classification or security-gate change.
Raw failures and their scoped resolutions remain in the sprint root.

Normal delivery gates, final independent review, matching native/installed
observations and separate product owner acceptance remain pending at this entry.
