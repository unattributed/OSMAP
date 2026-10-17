# S04-01 — Settings and sessions: single delivery checklist

Status: **IN PROGRESS; no parent-slice closure claimed.** Source baseline:
`0c5dac8fec6466c0834af2a229a57325c5ea38f7`, branch
`feat/ux-completion-20260929`. Accepted R2 anchor:
`6b3ce8fff27ca3dabf87039d54098bd9967a2e42`; signed R3 introducing anchor:
`f2a117c17dbd93b634f9914c5608473dc682d8e0`.

The operator's 2026-10-17 instruction authorizes retaining the working
implementation, finishing demonstrated S04-01 gaps and making one closure
decision against this checklist. S04-02 and other slices remain stopped. This
execution document preserves the frozen plan and all **57 mapped controls**
(3 legacy and 54 approved controls); it neither waives requirements nor changes
ownership to manufacture closure. The active owner, time bound and next action
remain in the existing execution ledger, not a second tracking system.

## Functional exit and design boundary

The signed source and installed application must provide the defined account
settings, section navigation/search and truthful session controls. Each editable
preference must persist for its account and affect its named owning workflow;
unavailable facts remain visibly unavailable. Keep existing stores, native forms,
CSRF/session authorization, bounded account isolation and precise uncertain-save
responses. No general account-admin replacement or speculative storage redesign.

A disabled control or honest Unknown can satisfy an unavailable-state negative;
it cannot satisfy a required positive workflow. Controls requiring unfinished
password, recovery or shared-quota capabilities remain explicit dependencies.
They are not silently removed from this slice and do not authorize restarting
those stopped slices. Engineering completion, matching installed verification,
independent audit and reserved human judgment are recorded separately.

## Reusable evidence, with its original limits

These retained results were read during reconciliation. Historical matching
source evidence is credited for the behavior it actually executed; it is not
represented as a new execution against the current installed binary. Changes
since those source snapshots must be reviewed at the affected boundary before
current qualification. No unchanged full browser/native suite is required merely
to populate the acceptance register.

- **E1 Sessions:** `/home/foo/Downloads/osmap-ux-s04/run-20260930/sessions-edge/workflows.json`
  and `sessions-firefox/workflows.json`: PASS; synthetic authentication with real
  SessionService/store; selected/other/all revocation denies affected contexts,
  preserves current/unselected scope and Bob; Unknown location, native keyboard,
  no scripts/external requests. Ledger's signed checkpoint `a96db6313f0247c65aeaed947f2ba7ad3a021382`.
  The report does not independently enumerate every metadata/expiry/activity case.
- **E2 Appearance:** same root `appearance-{edge,firefox}/workflows.json`:
  PASS; real preference store, actual row/font/avatar/snippet/reader changes,
  restart/fresh login, account isolation and invalid/duplicate/no-CSRF refusal.
  Source checkpoint `f5fa3debaa420adc9ec5e06f755c48848f0360fc`; no current install claim.
- **E3 General:** same root `general-final-{edge,firefox}/workflows.json`:
  PASS; real account stores, save/reload/restart, settings search, profile/layout,
  independent appearance/archive/composition preservation and invalid-save refusal.
  The report explicitly tests disabled unavailable controls, not their positives.
- **E4 Reading:** same root `reading-{edge,firefox}/workflows.json`:
  PASS; real stores, stored login destination, sorting, source/file-detail display,
  content/archive independence, corruption refusal and Bob isolation. Synthetic mail.
- **E5 Composition/footer:** same root `composition-{edge,firefox}/workflows.json`
  and `signature-integrated-{edge,firefox}/report.json`: PASS; real preference
  persistence/quote placement; ledger records footer insertion once for newly
  opened composers, exact saved-draft preservation and owner/stale/restart controls.
  No provider submission or OpenPGP signing follows from ordinary footer tests.
- **E6 Copies/privacy:** same root `copies-{edge,firefox}/report.json` and
  `privacy-final-{edge,firefox}/report.json`: PASS; stale forms preserve other
  preferences, actual renderer plain/protected choice, stripped remote image,
  unavailable folder refusal, account isolation and zero external/script/send.
  Does not by itself prove every CSP/source-isolation requirement.
- **E7 Security navigation/status:** same root
  `security-integrated-{edge,firefox}/report.json`: PASS; two real session stores,
  account isolation and zero POST/external/script. Relevant source is
  `src/settings_security_ui.rs`, `src/http/routes_settings.rs` and
  `src/http/security_settings_tests.rs`. Exact per-control metadata/event positive
  criteria still require reconciliation; broad PASS is not every row's PASS.
- **E8 Mark-read:** `/home/foo/Downloads/osmap-ux-s02/revalidation-20261003/mark-read/`;
  ledger records controlled real Dovecot/signed-helper/BrowserApp native PASS plus
  8 no-script browser checks, Manual/OnOpen setting, actual Seen change, read-only
  GET/Back/reload and foreign/stale refusal. Signed source `364381ea5ccf70e0e206bafb39935b8f9b37c397`,
  helper-first deployment and installed GET-only form check; human mutation NOT RUN.
- **E9 Bin/delete:** `/home/foo/Downloads/osmap-ux-s02/revalidation-20261003/bin-folder/`
  and `permanent-delete/`; ledger records real helper/Dovecot configured Bin/Restore,
  preserved message identity/attachments and account isolation; native explicit
  permanent-delete confirmation/cancel/policy-revision tests. Existing chosen Bin
  is implemented; user-selectable Delete action is not proved by those commands.
- **E10 Sent/Draft destinations:** `/home/foo/Downloads/osmap-ux-s03/revalidation-20261003/sent-location/`
  and sibling `draft-location/` evidence referenced by ledger lines 6331–6586: actual generated
  choices, captured destinations, controlled Dovecot copy, private draft placement,
  reload/replay/isolation and exact input parity. Signed products `6f549911e66a40fabb964317e0efe8e8d80cd623`
  and `d341da94714c2062f96a66c8e3122ed06b54a449`, helper-first installation recorded.
  Drafts are private server-owned OSMAP locations, not an IMAP mirror; user UAT
  remains separately recorded. Current baseline source keeps these forms.
- **E11 Digest:** `/home/foo/Downloads/osmap-ux-s04/revalidation-20261004/notifications-preferences/independent-delivery-review.json`
  actually PASS; source `6390a40dbaccdc205de0e58531af90aaee7dfe7d`, 34-marker actual
  Serve proof, CAS/reload/original event rows/read badge/kinds/account isolation,
  matching installation. Individual/Daily UTC groups existing in-app session
  events only; no scheduled/provider/email digest. Human Digest UAT NOT RUN.
  No approved PAGE17 control is mapped to S04-01 in the current register; retain
  this delivered implementation without silently adding/removing mapped scope.

- **E12 Baseline executed source controls:**
  `/home/foo/Downloads/osmap-ux-s04/revalidation-20261004/password-change/repository-sync-stop-20261017/documentation-commit-attempt2.log`:
  actual mandatory gate passes named source CSP/isolation, security count/unknown,
  Sessions render and last-seen persistence/concurrency tests. Artifact SHA-256
  `f785a73b6fd0d8af1b67c1333cec684364b9b56a0f7ae0fc8d7b6deb7b74cd8a`. These are existing baseline source tests,
  including synthetic gateway fixtures; they do not establish current installed
  full-workflow or human acceptance. E9 additionally has actual native permanent
  delete result `native-retention-http-attempt1-result.json` SHA-256
  `b14f56b2e4ad57070cf6bdcab11b3b645dc7c77948a0f95412e33314606f970f`; same-UID disposable scope and
  issued-session limits remain explicit.

## Outcome / action / expected result / actual evidence

Legend: **REUSE** = relevant executed evidence exists within its stated scope;
**PARTIAL** = only part of this exact requirement is evidenced;
**GAP** = concrete baseline source omits required behavior;
**DEPENDENCY** = positive needs an explicitly stopped/outstanding backend workflow.
These are reconciliation states, not new acceptance enums or whole-control PASS.

- **UX09-001 — A1/C1/I1 Security [REUSE]**
  Action: Open Settings and select Security/Privacy.
  Expected: Security is discoverable inside Settings; Privacy remains distinct.
  Actual evidence: E3/E7: distinct Settings/navigation and heading; current installed parity not requalified.
- **UX09-002 — A4 settings heading [REUSE]**
  Action: Open Settings as the authenticated account.
  Expected: The Settings heading and owned account context are accurate.
  Actual evidence: E3/E7: distinct Settings/navigation and heading; current installed parity not requalified.
- **UX11-001 — A11 password status [PARTIAL]**
  Action: Inspect own password status without modifying credentials.
  Expected: Only authoritative status is shown; unavailable dates/state remain Unknown.
  Actual evidence: E7/current UI: sign-in facts or Unknown; no invented authoritative last-change date.
- **R2-01-014 — Account security status [PARTIAL]**
  Action: Load known and unavailable authentication status
  Expected: Account security status reports measured factors or Unknown rather than a fabricated score.
  Actual evidence: Baseline documentation-commit-attempt2.log passes owned-count/literal-event and unknown-invalid-data tests; factual existing status source retained. PARTIAL source coverage, not current installed feed/parent closure.
- **R2-01-026 — Storage totals and category breakdown [DEPENDENCY]**
  Action: Load measured mail/document usage
  Expected: Totals and category breakdown reconcile with authoritative shared account usage and identify unknown measurements.
  Actual evidence: Current General/Copies say quota unavailable; shared mail/document authority and concurrent reservations remain outstanding.
- **R2-01-027 — Manage Storage [DEPENDENCY]**
  Action: Activate Manage Storage
  Expected: Owned quota/retention controls open with actual available authority and usage.
  Actual evidence: Current General/Copies say quota unavailable; shared mail/document authority and concurrent reservations remain outstanding.
- **R2-01-028 — System service status and View details [GAP]**
  Action: Load measured service statuses then View details
  Expected: Status and details agree with real service measurements and do not infer readiness from uptime alone.
  Actual evidence: Current Welcome/General expose Unknown; no measured service/detail, backup record or version-feed positive evidenced.
- **R2-01-029 — Backup status [GAP]**
  Action: Load a known backup record
  Expected: Backup timestamp/outcome matches retained backup metadata and states the scope of that backup.
  Actual evidence: Current Welcome/General expose Unknown; no measured service/detail, backup record or version-feed positive evidenced.
- **R2-01-030 — Update status [GAP]**
  Action: Load installed and available version metadata
  Expected: Update status distinguishes measured versions and unavailable update information.
  Actual evidence: Current Welcome/General expose Unknown; no measured service/detail, backup record or version-feed positive evidenced.
- **R2-10-001 — Settings section selection [REUSE]**
  Action: Choose Privacy then Security in Settings navigation
  Expected: Selected section and heading match the route; Security and Privacy remain distinct.
  Actual evidence: E1/E7 routes to distinct Security/Privacy and actual owned browser sessions.
- **R2-10-002 — Security page role [REUSE]**
  Action: Read the Security page role
  Expected: Explanation accurately identifies account protection/authentication controls and links separate privacy settings.
  Actual evidence: E1/E7 routes to distinct Security/Privacy and actual owned browser sessions.
- **R2-10-011 — Manage active sessions [REUSE]**
  Action: Choose Manage active sessions
  Expected: Actual browser-session list opens for the current account.
  Actual evidence: E1/E7 routes to distinct Security/Privacy and actual owned browser sessions.
- **R2-10-012 — Recent security events [PARTIAL]**
  Action: Create sign-in/revocation events then inspect recent events
  Expected: Bounded events match retained actual records and do not include private bodies/secrets.
  Actual evidence: E11 retains actual SessionIssued/SessionRevoked events; full recent-event metadata criteria not reconciled.
- **R2-11-004 — Timezone [PARTIAL]**
  Action: Save a timezone then open a fixed-time message
  Expected: Stored preference reloads and actual time conversion uses that timezone.
  Actual evidence: E12: implemented account-private CAS fixed UTC offsets and typed mail display; six changed source tests and one keyboard browser save/reload/conversion pass. Matching installed qualification remains open; no DST claim.
- **R2-11-005 — Language [GAP]**
  Action: Select a supported language and reload
  Expected: Selected supported language persists and affected user-visible labels follow its implemented scope.
  Actual evidence: src/settings_general_ui.rs fixes English and disables language; no saved supported-language workflow.
- **R2-11-007 — Density [REUSE]**
  Action: Choose density and reload Inbox
  Expected: Stored density affects actual row spacing and preserves accessible targets.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-11-008 — Reader layout [REUSE]**
  Action: Choose reader layout then open a message
  Expected: Stored layout changes the documented reader/list arrangement while content/context remain intact.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-11-009 — Configure Appearance [REUSE]**
  Action: Activate Configure Appearance
  Expected: Appearance section opens with the current account's saved preferences.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-11-010 — Default start page [REUSE]**
  Action: Choose a supported start page then sign in again
  Expected: Post-login navigation opens that owned destination without open redirect.
  Actual evidence: E4: real stored bounded login destination; forged cookie cannot retarget; restart/Bob controls.
- **R2-11-011 — Archive folder [PARTIAL]**
  Action: Select an owned archive folder then archive a controlled message
  Expected: Preference persists and the backend move targets that exact folder.
  Actual evidence: E3/E6 prove saved owned Archive choice; exact authoritative move destination proof must be linked from existing message-move evidence.
- **R2-11-012 — Delete behaviour [GAP]**
  Action: Choose approved delete behaviour then delete a controlled message
  Expected: Actual action follows the saved behaviour with permanent deletion still separately confirmed/policy-permitted.
  Actual evidence: General disables Delete behaviour; Copies labels explicit message controls, with no saved Delete-action selector. E9 commands do not prove a preference.
- **R2-11-013 — Mark-read policy [REUSE]**
  Action: Choose mark-read policy then open an unread message
  Expected: Actual Seen transition follows the saved policy and reload agrees.
  Actual evidence: E8: actual Manual/OnOpen persistence and Seen transitions; GET/Back/reload remain read-only.
- **R2-11-019 — Remote-content enforced state [REUSE]**
  Action: Inspect enforced remote-content state then open hostile HTML
  Expected: Display agrees with blocked external requests and actual sanitized content.
  Actual evidence: E6: real sanitized protected rendering, stripped remote image and zero external requests; current security policy unchanged review required.
- **R2-11-020 — Sanitization enforced state [REUSE]**
  Action: Inspect enforced sanitization state then open hostile HTML
  Expected: Display agrees with applied sanitizer and does not offer an unsafe cosmetic bypass.
  Actual evidence: E6: real sanitized protected rendering, stripped remote image and zero external requests; current security policy unchanged review required.
- **R2-11-021 — CSP enforced state [PARTIAL]**
  Action: Inspect CSP state on Settings/Reader/Compose
  Expected: Display matches actual response policy including the authorized hash-pinned Compose exception.
  Actual evidence: Baseline gate passes composer_hash_allowance_never_reaches_reader_auth_or_other_pages and source response CSP assertions; exact default/pinned Compose policy covered. Current installed wire/browser proof separate.
- **R2-11-022 — Source isolation state [PARTIAL]**
  Action: Inspect Source isolation state then open source
  Expected: Display agrees with escaped/no-store source and inert rendering.
  Actual evidence: Baseline gate passes authenticated/escaped/bounded source test with no-store/exact CSP and denied wrong identity. StubGateway content; no new installed operator-message execution.
- **R2-11-024 — Manage password [DEPENDENCY]**
  Action: Activate Manage password
  Expected: Actual own-account password change workflow opens with effects and step-up stated.
  Actual evidence: Actual own-password form/workflow is unqualified and S04-02 remains stopped; a navigation card is not its required positive.
- **R2-11-025 — Manage TOTP [PARTIAL]**
  Action: Activate Manage TOTP
  Expected: Current factor lifecycle workflow opens with actual state and documented safeguards.
  Actual evidence: Operator TOTP_ROTATION=PASS is retained; exact current account-state/manage-route evidence must be linked, not generalized to recovery.
- **R2-11-026 — Manage recovery [DEPENDENCY]**
  Action: Activate Manage recovery
  Expected: Current contact/coordinator workflow opens with actual proof status and no MFA bypass.
  Actual evidence: Recovery-contact proof lifecycle remains outstanding/stopped S04-03/04; Unknown/unavailable is negative-only.
- **R2-11-030 — Save changes [PARTIAL]**
  Action: Change permitted General fields then Save changes
  Expected: Confirmed owned persistence survives reload and each preference affects its specified workflow.
  Actual evidence: E2–E6/E8/E10 show individual working saves; timezone/language/Delete and dependent positives prevent every pictured preference closure.
- **R2-11-031 — Reset section [PARTIAL]**
  Action: Modify unsaved General fields then Reset section
  Expected: Current saved values are restored for that section without changing another section's preferences.
  Actual evidence: E12: General now reloads saved section through authenticated GET; keyboard browser changes five independent controls then Reset restores all, with no POST or saved-store byte change. Matching installation remains open.
- **R2-12-005 — Density [REUSE]**
  Action: Save compact versus comfortable density
  Expected: Actual row/control spacing changes while bounded content and focus remain accessible.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-12-006 — Font size [REUSE]**
  Action: Save a supported font size
  Expected: Actual text size follows the preference without overflow at narrow widths/200 percent zoom.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-12-007 — Reader layout [REUSE]**
  Action: Save a supported reader layout
  Expected: Reader/list arrangement changes as documented and remains operable by keyboard.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-12-008 — Show avatars [REUSE]**
  Action: Toggle Show avatars
  Expected: Visible owned sender/avatar presentation changes without fetching external resources.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-12-009 — Message preview [REUSE]**
  Action: Toggle Message preview
  Expected: List snippets appear/disappear according to stored setting without leaking extra message bodies.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-12-010 — Actual selected-state preview [PARTIAL]**
  Action: Change unsaved appearance options
  Expected: Preview reflects the actual selected settings and distinguishes saved from unsaved values.
  Actual evidence: E2 selected settings/rendered preview exists; exact unsaved-versus-saved preview criterion needs source/evidence reconciliation.
- **R2-12-011 — Save changes [REUSE]**
  Action: Save all permitted appearance fields then reload as A and B
  Expected: A's persisted options survive; B retains its independent settings.
  Actual evidence: E2/E3: actual saved presentation effects, persistence/account isolation and invalid-save refusal.
- **R2-14-001 — Default start page [REUSE]**
  Action: Save a supported default start page then sign in
  Expected: Post-login destination matches the owned saved page without arbitrary redirect.
  Actual evidence: E4: real stored bounded login destination; forged cookie cannot retarget; restart/Bob controls.
- **R2-14-011 — Sent folder [REUSE]**
  Action: Choose an owned Sent folder then send to controlled sink
  Expected: One accepted submission has its copy stored/reconciled at the configured authoritative folder.
  Actual evidence: E10: owned Sent captured copy destination and private Drafts/Working storage with preserved existing IDs; current source retains forms.
- **R2-14-012 — Drafts folder [REUSE]**
  Action: Choose an approved draft location then save/resume
  Expected: Actual owned draft storage and UI location agree; no arbitrary filesystem path is accepted.
  Actual evidence: E10: owned Sent captured copy destination and private Drafts/Working storage with preserved existing IDs; current source retains forms.
- **R2-15-002 — Reply placement [REUSE]**
  Action: Save above/below reply placement then Reply
  Expected: Authoring position relative to quoted text matches persisted choice without altering quote/threading.
  Actual evidence: E5: stored quote placement and ordinary footer insertion once; existing drafts untouched, distinct from OpenPGP signature.
- **R2-15-003 — Include signature [REUSE]**
  Action: Save include-signature preference then open new mail/reply
  Expected: Actual saved signature text is inserted according to preference, separate from OpenPGP signing.
  Actual evidence: E5: stored quote placement and ordinary footer insertion once; existing drafts untouched, distinct from OpenPGP signature.
- **R2-16-005 — Archive folder [PARTIAL]**
  Action: Choose an owned archive folder then archive
  Expected: Only selected tuple moves to configured archive and no alias for Junk is silently assumed.
  Actual evidence: E3/E6 prove saved owned Archive choice; exact authoritative move destination proof must be linked from existing message-move evidence.
- **R2-16-006 — Bin folder [REUSE]**
  Action: Choose an owned Bin folder then bin
  Expected: Only selected tuple moves to configured Bin without implicit permanent deletion.
  Actual evidence: E9: saved private Bin selector and actual reversible selected-tuple move/Restore; no implicit expunge.
- **R2-16-007 — Delete action [GAP]**
  Action: Save permitted delete action then invoke it
  Expected: Actual backend action follows saved choice with separate permanent-delete policy/confirmation.
  Actual evidence: General disables Delete behaviour; Copies labels explicit message controls, with no saved Delete-action selector. E9 commands do not prove a preference.
- **R2-16-008 — Permanent-delete confirmation policy [PARTIAL]**
  Action: Inspect permanent-delete confirmation then cancel/confirm in controlled account
  Expected: Cancel preserves message; confirmation permits only policy-authorized deletion of intended tuples.
  Actual evidence: E9 native-retention-http-attempt1-result.json PASS25 scoped cases including actual disposable single/bulk helper/Dovecot deletion. Required inspect/Cancel/confirm is implemented; no user-configurable confirmation bypass is required. Current installed scope remains separate.
- **R2-20-005 — Active session count [PARTIAL]**
  Action: Create two browser sessions then inspect count
  Expected: Count matches actual retained active owned sessions including stated current-session scope.
  Actual evidence: Baseline gate passes security_summary_owner_failure_count_and_literal_events (7 retained records,1 revoked,6 active) and excess/duplicate Unknown test. Current installed/complete expiry scope remains separate.
- **R2-20-006 — Manage sessions [REUSE]**
  Action: Activate Manage sessions
  Expected: Actual owned session list and revoke controls open; browser scope is distinct from IMAP/SMTP.
  Actual evidence: E1/E7 routes to distinct Security/Privacy and actual owned browser sessions.
- **R2-24-001 — Sign out all other sessions [REUSE]**
  Action: Sign out all other owned browser sessions
  Expected: Other sessions are actually revoked; current session remains according to the documented policy.
  Actual evidence: E1: actual target/other/all browser revocation and preserved Bob/current scope; UI distinguishes browser from independent mail sessions.
- **R2-24-002 — Actual device metadata [PARTIAL]**
  Action: Inspect known/unknown device metadata
  Expected: Display reflects actual retained client metadata and Unknown remains explicit.
  Actual evidence: Baseline gate passes sessions_page_renders_for_valid_session plus escaped device/foreign metadata tests; existing device/Unknown source retained. Full missing/long/expired matrix not established.
- **R2-24-003 — Actual browser metadata [PARTIAL]**
  Action: Inspect browser metadata for a controlled session
  Expected: Safe parsed browser label matches recorded metadata and is not claimed as attested identity.
  Actual evidence: Baseline sessions_page_renders_for_valid_session actually asserts Firefox for controlled recorded data; existing bounded reported_browser parser retained. Full malformed/missing matrix/current installed proof separate.
- **R2-24-004 — Known location or unknown [PARTIAL]**
  Action: Inspect known/unknown session location
  Expected: Only real available location evidence is displayed; guessed/geolocated facts are not invented.
  Actual evidence: E1 proves Unknown location/current context and actual denial after revoke; exact parsed/long/expired metadata negatives require focused existing evidence linkage.
- **R2-24-005 — Last activity [PARTIAL]**
  Action: Perform an authenticated action at fixed clock then inspect last activity
  Expected: Actual retained activity time changes within its documented update scope.
  Actual evidence: Baseline gate passes validate_session_updates_last_seen and concurrent update test with stored last_seen_at200; Sessions source renders actual retained value. Installed browser producer-to-render check not newly executed.
- **R2-24-006 — Current/active state [PARTIAL]**
  Action: Inspect current/active session state
  Expected: Current session is correctly marked and expired/revoked sessions are not labelled active.
  Actual evidence: E1 proves Unknown location/current context and actual denial after revoke; exact parsed/long/expired metadata negatives require focused existing evidence linkage.
- **R2-24-007 — Revoke selected session [REUSE]**
  Action: Revoke one selected other session
  Expected: That session's next authenticated request fails while unselected/current sessions remain as specified.
  Actual evidence: E1: actual target/other/all browser revocation and preserved Bob/current scope; UI distinguishes browser from independent mail sessions.
- **R2-24-008 — Browser versus IMAP/SMTP revocation scope [REUSE]**
  Action: Revoke a browser session then check documented mail scope
  Expected: Display/behaviour distinguish browser-token revocation from independent IMAP/SMTP credentials/connections.
  Actual evidence: E1: actual target/other/all browser revocation and preserved Bob/current scope; UI distinguishes browser from independent mail sessions.

## Bounded repair and essential verification order

1. Retain working stores/forms/session authority and credit E1–E11 only for their
   actual executed outcomes. Resolve PARTIAL rows by reading existing exact tests,
   logs and current changed source, before considering another execution.
2. First concrete repairs: restore the General Reset action as a read-only
   reload of that section’s current saved values (no write or cross-section
   reset), and timezone persistence using a finite validated explicit
   UTC-offset selector and actual account-owned message-time conversion. Keep UTC
   as absent-record default; no named-zone/DST claims. A malformed/duplicate/stale
   or unauthorized save must preserve prior/unrelated/account-B state. Show the
   selected offset explicitly, never silently relabel UTC as local time.
3. Other demonstrated gaps receive a bounded owning-workflow implementation
   decision after reconciliation: supported language, reset-to-current-saved
   section values, saved Delete behavior and measured status integrations. Do not
   begin a new backend diagnostic programme to make an unavailable badge green.
   Dependencies remain explicitly blocked rather than waived or called complete.
4. For each actual change, define the exact action and expected result before
   editing. Execute one discriminating positive across persistence/reload and its
   owning consumer, plus relevant unauthorized/invalid/account-isolation and
   preservation negatives. Reuse existing harnesses and matching passing cases;
   no new QA framework, full-mail fixture replay or unchanged Rust rebuild merely
   for assurance. Mandatory repository hooks still run normally.
5. Perform matching installed functional verification only for changed paths and
   any existing path whose source/runtime mismatch is demonstrated. Root owns the
   sole host/native queue and exact bounded cleanup. Existing operator data,
   credentials, factors, keys, mail and unrelated settings remain preserved.
6. Independent review checks the actual producer, persistence and consumer result,
   relevant security boundaries and honest remaining dependencies. Update the
   existing acceptance register with exact evidence scope, not broad inferred PASS.

## Closure decision and human boundary

Close S04-01 only when its mapped positive/negative outcomes have appropriate
matching evidence or an explicit operator-approved amendment changes a
requirement. A blocked dependency keeps the original parent slice open; this
checklist supplies no such amendment. No whole-sprint/epic completion follows.

Only after agent-owned changed behavior, matching installed functional QA and
independent review PASS for the exact submitted scope may the operator receive
one short combined usability/remaining reserved-observation check. Reuse actual
TOTP/Folders/protected-mail observations in their original scope. Do not ask the
operator to debug unfinished code, resend provider mail, disclose secrets or
repeat already supplied outcomes. Human results are recorded separately and
must never be invented from a build, page, badge or primitive fixture.

## E12 — changed source results, 2026-10-17

Evidence root: `/home/foo/Downloads/osmap-ux-s04/revalidation-20261017/settings-sessions/`.
`timezone-candidate-readiness.json` pins16 source paths; final selected test log
`timezone-selected-attempt4.log` passes6/0fail/0skip in5.219s. Real Runtime
generated form proves private save/reload/restart/Bob; separate StubGateway
mail consumers exercise mailbox/search/readers/Archive without changing canonical
metadata. `changed-browser-attempt3-result.json` and its report pass in2.070s
with existing synthetic authentication/mail and real private stores: keyboard
timezone save, exact conversion and five-field GET Reset, unchanged settings
bytes/unrelated Reading choice/Bob, zero scripts/external requests/Send. Browser,
testserver and owned test dependency environment are cleaned. These are scoped
source/browser results, not installed/backend acceptance.

Earlier selected-test assumptions and missing Python dependency launcher failures
are retained; no application action ran during the two import failures. The
reviewed private test-only dependency remedy reused installed Edge and was
removed afterward. First OpenBSD compile failed allocation before tests under
the default build environment;455 source pins match before/after and the Cargo
leader is reaped. Private build staging remains retained. No service, account,
mail, key or production setting changed. No parent closure follows.

## E13 — matching OpenBSD source qualification

`native-attempt2/native-execution-result.json` passes six changed cases, zero
failures/skips,455 input hashes before/after and a fresh application build.
Native action94.231s; full upload/execute/result-retention action97.199s.
The application is
`ce34bc302c60bca94fce7dc52717c2aa549fc63df94d98a1aad6fca60c8a5362`.
The successful action reuses the existing release opt0/debug0 build cache,
bounded child-only4GiB data/core0 profile and unchanged120s phase limits.
It does not establish the unique cause of the earlier allocator failure or
alter any application/service limit. Both Cargo leaders are reaped; complete
group absence is not claimed. Private build stages remain retained, with no
service/configuration/account/mail/key action. This is source/native evidence,
not installation or parent acceptance. Independent source-delivery review is
CLEAR at `independent-source-delivery-review.json`; no further changed-boundary
QA is recommended beyond required repository hooks.

## Mandatory source admission disposition

Normal signed commit attempt1 passed1770 library tests/0fail/48 explicit native
ignores, then refused two8-argument function signatures under Clippy. No commit
was created. Retained `settings-sessions/commit-attempt1.log` SHA-256
`a63a42f05d57c52ed278be97b114a9fd23e136ddf82a395deaaea3bc4a757df7`; full-action elapsed was not measured. The correction groups existing
values into tuples and immediately destructures them; no behavior/security/guard
change. Independent `independent-arity-correction-review.json` CLEAR SHA-256
`b044ae01a8ffc13f63f8885927fbaffa23fdcf80a18a434482649838a2ba97de` permits reuse of prior behavior evidence plus normal mandatory hooks.
The native binaryce34bc30 remains pinned to its original source; the three
mechanical correction paths were not rebuilt natively or installed. Parent
S04-01 remains open; no extra browser/native assurance campaign is required.
