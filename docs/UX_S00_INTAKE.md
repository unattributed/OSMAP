# UX S00 intake and baseline

Runtime source assessed: `2a6993fe7df42a57f0cbb5fe3e33e331b400fef9`.
Plan anchor: `74522e5f99024720a3c47a3744207ff453de5731`, verified Shopkeeper
signature and unchanged manifest. Intake date: 2026-09-29. This is source and
synthetic browser evidence, not live-host or cryptographic qualification.

## Reference provenance

All four originals were available, hashed and visually inspected at the exact
path in the frozen epic. Their SHA-256 values match that epic:

| Ref | File | SHA-256 |
| --- | --- | --- |
| A | account-settings-annotated.png | ec018ece38ca113192426ecdd6f6de7d3c1e888ddef7d484decf22d0a0ce9a6b |
| C | compose-page-annotated.png | 0844a2efec4baea3ab56c1e854f8ff0ad53a980f8dedb27d01c280d23bb9ee0f |
| I | Inbox + reader -- mapped-regions-controls-opengpg_states-secure_reading_functions.png | 86c6da4ffd63f51563e06f54ba8bdfb427caaf0905ededbc5019c0914578bc22 |
| F | osmap-inbox-secure-reader-functional-specification.png | d1a212a1eb1f2202ab4e7bb87356371afe86b6bb63aaaa79f287cc0aa05ba920 |

The old V14 archive is not substituted. Reference names, fingerprints, dates,
verified badges and security claims are illustrative, not runtime facts.
Roundcube removal remains an operator-reported fact; no host inventory was
performed in S00-01. Existing TOTP evidence cannot establish new-epic recovery.

## Individual reference-control inventory

`UI` means `src/http_ui.rs`; `routes` means `src/http/routes_*.rs`.
Existing behavior is source-inspected and backed by the named tests below;
it is not blanket acceptance of a pictured control. Repeated controls retain
their reference IDs. The S00-04 matrix expands these into executable cases.

| Reference/control | UX parent | Current source behavior and missing work | Owning slice |
| --- | --- | --- | --- |
| A1/C1/I1 Compose | UX01 | `app_header`: working link; no icon rail | S01-02 |
| A1/C1/I1 Inbox | UX01 | Mailboxes link; no direct rail Inbox | S01-02 |
| A1/C1/I1 Sent | UX01 | Folder list only, no primary Sent shortcut | S01-02 |
| A1/C1/I1 Documents | UX14 | No store, routes or navigation | S08-01 |
| A1/C1/I1 Archive | UX04 | Folder and configured archive route; no rail shortcut | S01-02, S02-03 |
| A1/C1/I1 Bin | UX04 | Trash move on reader; no dedicated rail entry/restore affordance | S02-03 |
| A1/C1/I1 Security | UX09 | Settings and Sessions exist, no separate security navigation | S04-01 |
| A2/C1/I1 Settings selection | UX01 | Current-page text link; reference gear rail missing | S01-02 |
| A1/C1/I1 rail collapse | UX01 | Absent | S01-02 |
| A3/C2/I3 OSMAP identity | UX01 | Text/OS monogram in topbar; local shield alignment needed | S01-02 |
| A3/C2/I3 notifications | UX01 | Absent; no event inbox | S08-04 |
| A3/C2/I3 user menu | UX01 | Identity chip and Log Out form, no bounded menu | S01-02 |
| A4 settings heading | UX09 | `render_settings_page`, heading and account present | S04-01 |
| A4 absence of global search | UX09 | Settings currently has no search | S01-03 |
| A5 OpenPGP capability card | UX09 | Explicit unavailable status, no runtime capability | S05-02 |
| A6 Manage Keys | UX09 | Absent; no public-key route/store | S05-02 |
| A7 full fingerprint | UX09 | Absent; binding model is separate scaffold | S05-02 |
| A7 copy/select | UX09 | No configured fingerprint; selectable text decision needed | S09-03 |
| A8 signing policy | UX10 | Disabled control; no persisted runtime policy | S07-01 |
| A9 encryption policy | UX10 | Disabled control; no actual encrypted send | S07-01 |
| A10 encrypt to self | UX10 | Absent from settings; no runtime sender-recipient integration | S07-01 |
| A11 password status | UX11 | Card absent; authoritative status unknown | S04-01 |
| A11 last changed | UX11 | No authoritative timestamp adapter | S04-02 |
| A12 Change password | UX11 | Absent; authoritative helper absent | S04-02 |
| A13 recovery contact/status | UX12 | Card absent; no proof lifecycle/store | S04-03 |
| A14 Manage contact | UX12 | Absent | S04-03 |
| A15 principles strip | UX13 | Absent; never copy reference zero-knowledge claim | S01-03 |
| C2/I2 search | UX03 | `/search`, scoped/all-mailbox search; no topbar search | S02-01 |
| C2/I2 command field/shortcut | UX03 | Absent; finite navigation menu under D01/D05 needed | S02-01 |
| C2/I3 protection status/dropdown | UX01 | Session chip and reader trust strip; shared compact details needed | S01-03 |
| C3 close | UX06 | Navigation links; no save-and-close action | S03-02 |
| C3 minimize | UX06 | Absent | S03-02 |
| C3 expand | UX06 | Absent | S03-02 |
| C3 more | UX06 | No approved menu; define finite actions | S03-02 |
| C4 From identity | UX06 | Canonical username determines From; no impersonation selector | S03-01 |
| C4 To | UX06 | Existing validated recipient text field | S03-01 |
| C4 add Cc | UX06 | Existing labelled Cc field, always visible | S03-01 |
| C4 add Bcc | UX06 | Existing labelled Bcc field, always visible | S03-01 |
| C4 recipient remove | UX06 | Edit text, no token/chip editor | S03-01 |
| C4 contacts | UX06 | No address book or explicit contact selector | S03-01 |
| C4 OpenPGP enabled state | UX08 | Unavailable; never infer from reference | S07-01 |
| C5 subject/security icon | UX06 | Subject field exists; crypto metadata unavailable | S03-01, S07-01 |
| C6 Sign | UX08 | Disabled | S07-01 |
| C6 Encrypt | UX08 | Disabled | S07-01 |
| C6 Encrypt to self | UX08 | Absent; disabled compose options are sign/encrypt/require recipient keys | S07-01 |
| C6 recipient key ready | UX08 | No actual recipient binding/capability evidence | S07-01 |
| C7 message body | UX07 | Plain text textarea and server-side bounds | S03-03 |
| C8 bold | UX07 | Absent | S03-03 |
| C8 italic | UX07 | Absent | S03-03 |
| C8 underline | UX07 | Absent | S03-03 |
| C8 ordered list | UX07 | Absent | S03-03 |
| C8 unordered list | UX07 | Absent | S03-03 |
| C8 link | UX07 | Plain text only; constrained authoring needed | S03-03 |
| C8 image | UX07 | Attachment upload exists; no inline/remote image authoring | S03-03 |
| C8 attachment button | UX07 | Multipart file input exists | S03-04 |
| C8 emoji | UX07 | Unicode text allowed, no insertion affordance | S03-03 |
| C8 more/preview | UX07 | No approved toolbar menu or preview route | S03-03 |
| C9 attachment name/size | UX07 | Source attachment metadata and retained-draft count | S03-04 |
| C9 add more | UX07 | Multiple file input; server save/send bounds | S03-04 |
| C9 remove | UX07 | Source selection checkboxes; no retained-upload removal UI | S03-04 |
| C10 delete/cancel | UX08 | Draft delete route exists; compose discard confirmation absent | S03-02 |
| C10 security check | UX08 | No actual runtime preflight | S07-01 |
| C10 schedule | UX08 | No job store/worker/timezone model | S08-03 |
| C10 more | UX08 | No finite menu | S08-02 |
| C11 primary send | UX08 | Ordinary send + Sent reconciliation exists; no protected-send claim | S03-04, S07-04 |
| C11 send dropdown | UX08 | Absent; finite modes under D05 | S07-01, S08-03 |
| I4 list select | UX03 | Per-message bulk checkbox exists | S02-01 |
| I4 select menu | UX03 | No select-all/none server affordance | S02-01 |
| I4 unread filter | UX03 | Flags displayed but filter absent | S02-01 |
| I4 sort | UX03 | Allowlisted server sort links exist | S02-01 |
| I5 avatar | UX03 | Sender text only; safe initials needed | S02-01 |
| I5 sender/subject/time | UX03 | Existing table fields; compact row needed | S02-01 |
| I5 preview | UX03 | Metadata only; no bounded preview body | S02-01 |
| I6 selected row | UX03 | Reader page separately fetched; selected list not coordinated | S02-02 |
| I7 archive | UX04 | CSRF-bound move to configured archive exists | S02-03 |
| I7 delete | UX04 | CSRF-bound move to Trash exists | S02-03 |
| I7 mark read/unread | UX04 | Flags read, no flag mutation helper/route | S02-01 |
| I7 snooze | UX04 | Absent | S08-03 |
| I7 label | UX04 | Absent | S08-02 |
| I7 security/more/back | UX04 | Basic mailbox link; finite controls and context needed | S02-02, S08-02 |
| I8 subject/sender/recipient/time | UX05 | Existing reader metadata | S02-04 |
| I8 star | UX03 | No flag mutation | S02-01 |
| I8 OpenPGP indicator | UX15 | Foundation state only; no verification/decryption | S06-02 |
| I9 encrypted | UX15 | No runtime PGP/MIME classifier | S06-01 |
| I9 decrypted locally | UX15 | No runtime decryption; host-location conflict D02 | S06-03 |
| I9 signature verified | UX15 | No runtime verification | S06-02 |
| I9 remote blocked | UX05 | Rendering policy metadata exists | S02-04 |
| I9 View Source | UX05 | Absent despite source-escaped badge; no source route or details control | S02-04 |
| I10 sanitized after decryption | UX15 | No decryption; ordinary sanitizer already active | S06-04 |
| I11 body | UX05 | `RenderedMessageView`, escaped/plain or sanitized HTML | S02-04 |
| I12 attachment list/download | UX05 | Authenticated part route, forced download and bounds | S02-04 |
| I13 Reply | UX04 | Existing prefill route | S03-01 |
| I13 Reply all | UX04 | Absent; parser only accepts reply/forward | S03-01 |
| I13 Forward | UX04 | Existing prefill and selected source attachments | S03-01 |
| I14 OpenPGP footer/settings | UX09 | Explicit unavailable copy and settings link | S09-02 |
| I15 attachment icon | UX03 | List metadata does not include attachment presence | S02-01 |
| I15 protected icon | UX03 | Must distinguish renderer policy from cryptographic result | S01-03 |
| I15 star/read state | UX03 | Flags are displayed; interactive change missing | S02-01 |
| F empty mailbox | UX16 | UI empty state exists; add fixture and useful compose CTA | S02-04 |
| F failed load/retry | UX16 | 503 safe error exists; contextual read-only retry missing | S02-04 |
| F attachment unavailable | UX16 | Safe denied route; explicit return/retry affordance missing | S02-04 |
| F OpenPGP unavailable | UX16 | Honest scaffold-only state exists | S06-04 |
| F missing key | UX16 | Runtime state unavailable | S06-04 |
| F unverified signature | UX16 | Runtime state unavailable; no positive badge permitted | S06-04 |
| F remote blocked | UX16 | Existing rendering state | S02-04 |
| F empty search/reset | UX16 | Empty results renderer; add fixture and clear action | S02-04 |
| F pane-only/no reload | UX17 | Conflicts with script-free boundary; D01 required | S00-02 |
| F browser/VM-only plaintext | UX17 | Conflicts with helper design; D02 required | S00-02 |
| F keyboard/focus | UX17 | Visible focus and labels exist; browser audit required | S01-04, S09-04 |
| All light/dark/system | UX02 | Light-only CSS; persistence absent | S01-01, S01-04 |

## Route and response inventory

Authoritative dispatcher: `src/http_runtime.rs::handle_request`.
Every HTML response uses `html_response` except redirects, which have their own
small HTML body. Both need theme coverage. Parser, host, budget and runtime
failure responses also use the shared HTML response boundary.

| Method | Routes | Pages / important failure states |
| --- | --- | --- |
| GET | `/healthz` | Plain text health; no HTML theme |
| GET | `/login`, `/` | Login and 303 redirect; root validates session |
| POST | `/login`, `/logout` | 303 on success; sign-in error, malformed content, throttle, CSRF |
| GET | `/mailboxes`, `/mailbox` | Folders, list, empty list; auth redirect, missing/invalid folder, unavailable |
| GET | `/search` | Scoped/all search and empty results; missing query, invalid field, unavailable, budget 503 |
| GET | `/message` | Reader; malformed UID, denied/stale message, budget 503; source control absent |
| GET | `/attachment` | Forced binary download; malformed part, missing part, unavailable, budget 503 |
| GET | `/compose` | Empty/reply/forward form; invalid source, unavailable source; reply-all absent |
| GET | `/drafts`, `/draft` | Empty/populated drafts, resumed compose; stale/missing draft |
| POST | `/drafts/save`, `/drafts/delete` | Redirect or preserved compose on invalid/stale input; CSRF and ownership |
| POST | `/send` | 303 or preserved compose; invalid recipients/upload, throttle, submission/Sent failure |
| POST | `/message/move`, `/messages/move`, `/messages/archive` | Redirect or partial-failure error; CSRF, invalid/stale UID, bad destination, bounded selection |
| GET | `/sessions` | Current/other sessions, safe unavailable state |
| POST | `/sessions/revoke` | Current/other/all revocation; malformed target, stale session, CSRF |
| GET/POST | `/settings` | Preferences/account cards; invalid values, unavailable, CSRF, archive validation |
| Any unmatched | any | 404; unaccepted/missing Host 421; invalid context/request 400 |

No source-only route or details control exists: `view=source` is currently
ignored. The fixture named `source` captures that request returning the ordinary
reader; it is evidence of the missing control, not working source viewing.
Binary downloads never enter the HTML theme transformation.

## Source and existing behavioral tests

| Boundary | Implementation | Existing discriminating tests |
| --- | --- | --- |
| Mail/search | `http_gateway_mail.rs`, `mailbox.rs`, `http/routes_mail.rs` | `mailbox_message_list_sorts_by_*`, `search_page_applies_whitelisted_field_refinements`, `search_page_caps_excessive_all_mailbox_results` |
| Reader/content | `rendering.rs`, `rendering_html.rs`, `mime.rs`, `http_ui.rs` | `message_view_renders_safe_body_and_attachments`, `message_view_route_maps_oversized_mime_body_to_safe_failure`, `tests/v4_hostile_assurance.rs` |
| Moves | `http/routes_mail.rs`, mailbox helper | `bulk_move_reports_partial_success_when_later_uid_is_stale`, `message_move_rejects_mismatched_mailbox_uid_tuple` |
| Compose/drafts | `http/routes_compose.rs`, `http/routes_draft.rs`, `draft.rs`, `send.rs` | `draft_save_resume_and_list_are_authenticated_and_redacted`, `send_failure_preserves_draft`, `send_route_refetches_selected_original_attachment` |
| Settings | `settings.rs`, `http_gateway_settings.rs`, `http/routes_settings.rs` | `settings_page_renders_for_valid_session`, invalid preference/archive and CSRF tests |
| Session/auth | `session.rs`, `http/routes_auth.rs` | Same-origin, CSRF, current/all/other session and authentication budget tests |
| Crypto | `openpgp_helper_client.rs`, V12 models/gates | Foundation-only policy/protocol tests; no cryptographic behavior proof |

## Synthetic baseline reproducibility

`src/http/ux_fixtures.rs` is included only in the existing test module. It
calls the real router/renderers with the existing in-memory gateway; no socket,
runtime gateway, mail account or host connection is constructed. Fifteen HTML
states cover login, redirects, folders, list, search, reader, ignored source request,
compose, reply, empty drafts, settings, sessions and three errors. Tokens in
retained HTML are replaced with a non-authorizing marker.

```sh
OSMAP_UX_FIXTURE_DIR=/home/foo/Downloads/osmap-ux-s00/run-20260929/baseline \
  cargo test --lib ux_synthetic_route_baselines
/tmp/osmap-ux-browser-venv/bin/python maint/ux/capture_pages.py \
  /home/foo/Downloads/osmap-ux-s00/run-20260929/baseline \
  /home/foo/Downloads/osmap-ux-s00/run-20260929/baseline/screenshots
```

External test tooling: Python Playwright 1.58.0 in a disposable `/tmp` virtual
environment, existing Microsoft Edge executable, disposable browser context.
No runtime frontend dependency or tracked package manifest is introduced.
Only the loopback fixture origin is allowed; external page requests fail.
The capture records browser version, HTML/screenshot hashes, headings, control
count and document width at 360/768/1440 CSS pixels. Screenshots are baseline
observations, not proof that missing interactions work.

## Intake findings to carry forward

- The current topbar and table list do not match the compact icon rail and
  coordinated reader layout. Existing V14 status is not visual parity.
- View Source and Reply All are missing despite historical language suggesting
  broader workflow completion. A badge saying source is escaped is not proof
  of a working source control. The reader's five direct grid children also
  place its body in a narrow second row; fix the structure in S02.
- Theme colours are spread across shared CSS; login, native form controls,
  notices, source, errors and redirects require coverage.
- Server settings currently replace the full two-field record. Adding a theme
  requires a compatible parser and serialized partial updates to avoid losing
  unrelated preferences during concurrent writes.
- Generic browser error pages need spacing, headings and safe contextual
  navigation; error text alone does not satisfy the reference.
- Baseline Edge 154.0.4258.37 captured 45 screenshots. The empty drafts page
  overflows at 360 pixels (document width 534); this remains an S01-04 defect.
- Account status must remain honest while later helpers are incomplete. The
  reference's password-strength, zero-knowledge and device-decryption language
  cannot be copied into the current product.

## S00-01 revalidation — 2026-10-03, accepted revision 2

Everything above is the retained **2026-09-29 historical intake**, assessed
against its stated source and revision-1 references. Its missing-control and
source statements are not current implementation claims. This append reconciles
that history with the current revision-2 inventory; it does not erase valid
historical observations or establish application UAT acceptance.

The current source/evidence-pointer inventory assesses Git source
`6706f4f024f5575c4f86afaf9ad8d9b8e8e42e8b`. The accepted revision-2 anchor is
`6b3ce8fff27ca3dabf87039d54098bd9967a2e42`: Good Shopkeeper signature; current
plan and nested approved-reference checksum checks passed. The approved inventory
has **27 page IDs and 403 unique control IDs**. Its older status labels and
evidence are preserved as historical candidates, never promoted to current
functionality from file or route presence.

Retained owner-only artifacts:

- `/home/foo/Downloads/osmap-ux-s00/revalidation-20261003/control-map.json`:
  every approved ID, historical status/evidence, current open classification,
  actual page-route/handler context, frontend/backend/test candidates and error
  anchors. Its source index contains 161 existing file hashes, actual function
  and test names/lines, and 54 dispatcher routes including plaintext health.
- `control-map.md`: readable 27-page context table and all 403 control rows.
- `generate-control-map.py` and `control-map.sha256`: deterministic reproduction
  and portable basename checksums. The generator reads Git blobs at the assessed
  SHA, rather than mixing other agents' in-progress source edits into the map.
- `fixtures-light/routes.json` and `fixtures-light/approved-page-baselines.json`:
  the separate current synthetic-route baseline and all 27 page mappings. The
  fixture source hash is
  `dd9f1b5ab2c6db3040abdc3869af5d8c91578180433e88e85c37865963c3624b`.
  These contain actual route observations and explicit missing/partial states;
  they neither exercise Send nor contact mail hosts.

Reproduce the mapping without application or host mutation:

```sh
python3 /home/foo/Downloads/osmap-ux-s00/revalidation-20261003/generate-control-map.py \
  --repo /home/foo/Workspace/OSMAP \
  --base 6706f4f024f5575c4f86afaf9ad8d9b8e8e42e8b \
  --out /home/foo/Downloads/osmap-ux-s00/revalidation-20261003
```

The generator validated exact page/control set sizes, uniqueness, actual route
contexts and source/test candidate existence. Repeated generation produced
identical map bytes. Individual named tests were **not run by this inventory**;
fixture/browser results have their own recorded scope. Literal error anchors
are source locations, not a complete executed refusal/recovery matrix.

### Concrete current-source corrections to the old intake

These are inspected source facts, **not claims that the operator can complete
the corresponding journey**. The JSON's 17 direct control mappings retain their
literal anchors and named test candidates where located; remaining unlocated
control-specific mappings stay explicitly open.

| Historical statement | Current source fact | Verification still required |
| --- | --- | --- |
| Compose Minimize/Expand absent | `src/http_ui.rs:2100` renders Minimize as `/drafts/save` with `compose_action=minimize`, and presentation Expand/Restore through `compose-expanded`. `src/http/routes_draft.rs:923` routes a successfully saved Minimize to Drafts. | Current browser preservation/interaction; no direct behavioural pass inferred from these anchors. |
| Compose Sign/Encrypt/Self disabled or absent | `src/http_ui.rs:1968` renders direct `pgp_sign`, `pgp_encrypt`, `pgp_self` checkboxes when runtime capability is configured. `src/http/compose_protection.rs::intent_from_form` parses the choices; `src/http_gateway_mail.rs::prepare_outbound_request` enforces current bindings/policy before submission. `compose_live_protection_controls_are_direct_and_preserve_selection` exists in key-management route tests. | Actual selected-mode Send through the correct deployed configuration. Visible checkboxes and public eligibility do not prove this. |
| General/Composition signing and encryption defaults unavailable | Current General/Composition renderers project typed saved defaults. `src/http/routes_composition_preferences.rs::handle_composition_preferences_update` handles the finite triple; existing `openpgp_defaults_save_reload_isolate_accounts_and_apply_only_to_fresh_composers` and invalid/partial-form regression tests locate the source contract. | Current intended defaults, saved-draft preservation and actual policy-permitted Send remain separate results. Defaults do not override Required recipient policy. |
| Key-management mutation controls absent | `src/key_inventory_ui.rs::render_key_management_panel` contains account/recipient/public-import forms and public-certificate removal. `src/http/routes_keys.rs::handle_key_management_change` and `src/http_gateway_keys.rs::change_keys_impl` provide typed mutation and fresh password/TOTP paths. Forms are conditional on binding/inventory/admin readiness. | Human fresh-auth import/bind/change/remove persistence and error recovery under the actual account. The read-only fallback still has disabled controls. |
| Dedicated Documents, password-change and recovery-contact pages | Documents has no dispatcher route and disabled navigation; its synthetic request is a 404. Password/contact requirements have no dedicated browser form/route; the existing Authentication overview renders disabled Change/Manage controls. | These pages remain missing/open; an overview or error screenshot cannot substitute for their required functionality. |
| Scheduling and permanent deletion/retention | Compose Schedule remains disabled in source. Archive/Bin explicitly states archive dates and permanent-delete/retention management are unavailable. | Required backend workflows and UI actions remain incomplete. No missing feature is removed from the epic. |
| Separate TOTP Challenge page | The approved inventory retains the existing combined password/TOTP login implementation. The source map links it to `/login`, without inventing a new challenge page. | Retained layout/theme and actual auth/security regression evidence retain separate scope. |

Mapping classifications are **197 recorded candidate-pointer controls**, **139
page-family-only controls**, **43 controls on missing dedicated pages**, **17
direct source-present controls not currently exercised**, and **7 explicitly
source-unavailable controls**. All 403 remain `NOT_REVALIDATED` for current
control functionality and `UNACCEPTED` for human UAT in this inventory. These are
intake coverage states, not another sprint state machine or a claim that all
existing source is nonfunctional.

### Failed Send remains the essential unresolved journey

The user's reported failures across Send operations remain open. In particular,
the matched ordinary Proton `/send` 503 at **2026-10-03 06:18:00 UTC** occurred
after the assessed deployment and supersedes earlier “no postdeployment Send”
notes. At that audit's revision 5, Proton encryption was Required while the
reported message selected all protections Off; policy provenance is unknown.
That dated diagnosis does not establish current configuration, repair every
failure or make the intended success a passed refusal test.

The inventory and capture work changes no application workflow, policy, keys,
private-agent lifetime, services or live mail. A separately reviewed prerequisite
repair in `src/private_account_file.rs` releases the account lock explicitly
when its guard is dropped. A duplicated descriptor otherwise prolonged the lock;
the deterministic regression fails before the repair and passes afterward on
Linux and OpenBSD. This source correction is not installed application evidence
and does not establish the cause or repair of the reported Send failures.
Synthetic pages, screenshots, source pointers and test
names cannot close ordinary delivery, authoritative Sent, protected Proton
receipt/signature, encrypted return or fresh-auth key lifecycle. The next
authorized work order must preserve those outcomes and reconcile the exact
frontend/backend/configuration path before any UAT-ready claim.
