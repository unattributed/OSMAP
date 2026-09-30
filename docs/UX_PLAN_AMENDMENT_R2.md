# UX plan revision 2: final approved reference reconciliation

Date: 2026-09-30 UTC. Source checkpoint:
`bf20f08a77cec24420e7dedcd982260368f26a78`.
Prior signed plan anchor: `74522e5f99024720a3c47a3744207ff453de5731`.

## Authority and reason

The operator explicitly corrected the reference baseline in this task:

> these mockup images are the approved UX design in /osmap-ux-final-approved-20260919/images/

This instruction, followed by "alright continue working", approves adoption of
the final bundle and continued engineering under the existing one-day mandate.
It does not approve substituted designs, fabricated runtime state, GitHub
synchronization, or a claim of visual acceptance for earlier work.

Revision 1 named four annotated images from `osmap/final-image/`. S00 through
S03-01A used those inputs. The final approved bundle was not used for those
deliveries. Their tests remain evidence of the tested behaviour, resource
bounds and accessibility checks; their screenshots do not prove conformity to
the final approved designs. S01/S02 visual reconciliation is reopened. Existing
signed history and evidence are retained unchanged.

## Exact replacement reference

Authoritative repository copy:
`docs/design/osmap-ux-final-approved-20260919/`.
All 25 PNGs under its `images/`, the original `README.md` and
`APPROVAL_LOCK_FINAL.md` are retained byte for byte. The nested `SHA256SUMS`
covers all 27 files; the plan manifest additionally pins the entire bundle.
The four old images remain supplementary functional evidence only where they
are compatible with the final bundle. The old V14 archive is not a substitute.

Original archive:
`/media/veracrypt1/TMP_BACKUPS/tmp_osmap/AAA - Pictures/osmap-ux-final-approved-20260919.tar.gz`.
Archive SHA-256:
`072bb9545b1ccd3be1370ee75003d5b97d297061c09eb4482e7faaf07160bdce`.
Both the outer sidecar and every inner manifest entry were verified. Retained
verification report under S00 `approved-reference-reconciliation/verification.json`:
`76e168b2b4bcab0cc143ac3a3472181e5258c915438b0b01c10f8d304b269eda`.
All 25 images were individually inspected. Do not regenerate or edit them.

## Changed requirements and precedence

1. The desktop shell has the approved labelled sidebar, top search, protection
   disclosure, notification/account controls and appearance controls. A narrow
   icon-only desktop rail is not the final design. Preserve the approved page
   hierarchy, proportions, field placement and spacing; responsive and dark
   variants must retain that hierarchy and pass separate comparison.
2. All 27 named pages are in scope. Pages 25 Login and 26 TOTP retain the current
   repository implementation without redesign and intentionally have no PNG.
   At this checkpoint both inputs are in `render_login_page`; do not invent a
   separate TOTP screen. Pin that implementation and compare it after shell CSS
   changes. Existing appearance support must not become an authentication redesign.
3. Page 10 is **Settings > Security**. The bundle's explicit functional rule
   retires the standalone top-level destination even though shared sidebar art
   still contains a Security item. Security links and breadcrumbs resolve into
   Settings. Page 18 **Settings > Privacy & Security** remains distinct.
4. Settings pages 10–20 have their own selected section and controls. The settings
   header's search searches settings; it is not the old global mail search.
   General, Appearance, Identity, Reading & Mailbox, Composition, Copies &
   Folders, Notifications, Privacy & Security, OpenPGP, Authentication & Recovery,
   and Security must not be collapsed into one generic account form.
5. Page 07 Documents shares the authenticated account's authoritative mailbox/
   storage quota. The earlier 100 MiB document bound may remain an additional
   application cap, never a separate quota allowance. Mail plus documents plus
   in-flight reservations must respect the account limit, including concurrency
   with mail delivery; unavailable quota authority blocks writes. Add the shown
   folder, search, sort and view controls with account isolation.
6. Page 16 includes mailbox subfolder create, rename, move and delete, visible
   hierarchy and selected-folder facts. Protected/system folders cannot be
   renamed, moved or deleted. Non-empty deletion requires explicit disposition
   and confirmation; cycles, stale identity and cross-account access refuse.
7. Page 22 has independent accessible Show/Hide controls for all three password
   fields. Showing one field must not expose another, submit the form, change
   validation or write values to logs, storage, history or retained evidence.
8. Page 04 starts Unsigned, Not encrypted and Encrypt-to-self Off. Saved account
   policy and mandatory requirements must be explicit; example enabled settings
   in other images do not change these initial defaults. Recipient-key status
   is availability, not a protection toggle. GREEN requires all selected
   protections and required checks satisfied; permitted reduced/attention states
   are ORANGE. Mandatory policy failures block Send without silent downgrade.
9. Page 08 includes a separately confirmed permanent-delete action only where
   retention policy permits it; ordinary Bin remains reversible. Missing policy
   authority keeps permanent deletion unavailable and incomplete, never permits
   implicit expunge. Page 09 includes Messages, Documents and People categories;
   mail-only search is an intermediate state, not completion of that page.
10. Counts, quota, clocks/timezone, locations, timestamps, fingerprints, security
    events and capability badges are examples in the art. Render actual
    authorized data or the approved unknown/unavailable state. Never reproduce
    example facts, inferred locations, shortened fingerprints as trust, or
    fabricated operational status to obtain a matching screenshot.

## Interaction and security impact

The approved controls include Show/Hide, clipboard, keyboard shortcuts,
automatic draft saving and desktop notifications that the revision-1 script-free
implementation does not provide. These remain explicit open controls. The new
visual approval does not make a non-working button complete or authorize a
blanket permissive CSP. D01 remains the runtime boundary until a bounded
implementation work order defines the exact first-party enhancement, narrowly
scoped CSP, mail-content isolation, no-script fallback and negative tests.
That engineering decision may be made under the autonomous mandate; record it
before code changes. No framework, third-party script, inline handler, eval,
remote-content allowance or untrusted-mail scripting is implied by this plan.
Password controls must remain wholly local; browser notification permission
must be an explicit user action. No new browser script is introduced here.

All existing authentication, CSRF, account isolation, parser bounds, no-plaintext
persistence, key custody and truthful submission invariants remain mandatory.
Actual operational limits may be stricter than an example counter in the art.
A stricter bound must be visible and cannot justify dropping a pictured control.

## Ownership, ordering and tests

The 48 existing slice IDs remain stable; no existing gap or negative test is
deleted. `maint/ux/approved_pages.json` enumerates every page and its pictured
controls with owning slices and pending statuses. `maint/ux/acceptance.json`
retains historical functional results with an explicit revision-2 visual
review requirement. The following sequence supersedes the default ordering:

- Complete this separate signed planning checkpoint with exact reference bytes.
- Restore the preserved S03-01B contact implementation and finish its bounded
  behaviour, then reconcile shared shell/S01 and list/reader/S02 against pages
  01–03/05/08/09 before further page visual acceptance. Native/backend tests
  already passed are retained; changed behaviour gets fresh tests.
- Continue S03 compose/drafts against pages 04/06; carry independent Settings
  sections into S04-01, appearance into S01/S09, composition into S03/S07,
  subfolders into S08-02, quota/documents into S08-01 and notifications into S08-04.
- S09 verifies every final page and all state-matrix rows, not just A/C/I/F.
  S10/S11 require the expanded acceptance coverage before release/deployment.

Visual evidence includes the original 1536×1024 welcome reference and
1600×1100 page references, plus 360/768/1440 responsive, light/dark/system,
keyboard, forced colours and 200% reflow. Compare layout and interaction to
the actual PNG for that page. Retain comparison notes identifying differences;
zero overflow or a screenshot hash alone cannot prove visual conformity.
Unknown/unavailable fixtures are tested alongside populated capability states.
Login/TOTP regression checks compare the retained implementation, not a new image.

Before acceptance require controls to have real backend outcomes. New negative
coverage includes joint quota reservations, protected/non-empty/cyclic folder
operations, password-field independence/no exfiltration, all three compose
defaults and preflight colours, category search isolation and retained auth UI.

## Rollback and checkpoint discipline

This is a documentation/reference-only change, with no state migration,
deployment, host mutation or Git synchronization. The previous signed plan is
preserved in Git; rolling back code does not make its old visuals approved.
Reverting this reference correction requires new explicit operator direction.

Unfinished agent-authored S03-01B work was preserved with per-file hashes under
S03 `worktree-preservation-before-reference-r2/` and removed from the worktree
only for this planning commit. Restore it after signing without overwriting new
ledger entries. The signing commit is the revision-2 trust anchor; record its
SHA in the next append-only execution entry. The autonomous mandate permits
continued work after signature verification; Git synchronization remains pending.
