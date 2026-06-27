# Known Limitations

## Current Documentation Limitations

- Phase 1 is evidence-based but still intentionally public-safe, so some local
  implementation details and private notes are summarized rather than published
- A repo-owned pilot workflow inventory baseline now exists, and the final
  Version 2 trial cohort has been confirmed against that bounded workflow set
- The exact Postfix configuration has not yet been exhaustively summarized in
  public docs, though service bindings and usage are already clear

## Current Program Limitations

- The implementation is deployed for the bounded known-host use case, but it
  remains prototype-grade for broader adoption and is not a general-purpose
  production webmail claim
- Direct public browser exposure remains limited and evidence-gated. The
  current Version 2 evidence supports the approved limited direct-public
  browser posture, not a broad production launch.
- The implementation now has a bounded browser slice with login, mailbox read,
  message view, compose, send, CSRF handling, and attachment download, and it
  now uses bounded concurrent request handling with an explicit connection cap
  plus route-class worker budgets for message search, message view, send, and
  login, plus route-deadline propagation for helper-backed search/message view,
  sendmail-backed submission, and external-auth login, but it still does not
  provide a mature worker pool, async runtime, route-deadline propagation for
  every expensive route, or a complete denial-of-service mitigation story
- The current HTTP runtime now has clearer connection-pressure, write-failure,
  and accept-failure observability, but it still depends on adjacent controls
  and does not yet provide a complete request-resource exhaustion strategy
- Runtime auth, mailbox, and sendmail command execution now has a shared
  timeout-enforced executor with a bounded environment and explicit stdout and
  stderr byte caps. It still depends on the synchronous request model, so very
  slow but under-limit backend commands remain bounded by timeout and the first
  search/message-view route budgets rather than a full worker-pool budget.
- The implementation now has a bounded message-view fetch path, plus
  MIME-aware classification and attachment metadata surfacing, but it does not
  yet provide preview-oriented attachment behavior
- The implementation now has a first outbound send path with reply and forward
  draft generation, bounded new attachment upload/submission behavior, and
  explicit source-attachment selection for reply/forward sends. Accepted
  submissions are filed into the sender's `Sent` mailbox through the local
  mailbox helper. It still does not automatically reattach original-message
  attachments. Explicit source attachment references persist across draft
  resume, but source bytes do not, and source deletion or mutation fails closed.
- The implementation now has a conservative rendering layer with both
  plain-text and sanitized-HTML modes, but it still does not provide
  inline image rendering, full rich-header coverage, or any external-resource
  loading. The fixture corpus now covers hostile HTML, remote-resource
  stripping, `cid:` metadata, malformed multipart boundaries, encoded headers,
  and suspicious attachment names, but it is not yet a broad real-world corpus.
- The implementation now provides a bounded, backend-authoritative browser
  search path across one mailbox or all visible mailboxes, but it does not yet
  provide a broad query language, saved searches, or faceted search behavior.
  The Version 3 browser surface now provides bounded result sorting controls
  for UID, subject, from, received date, flags, and size plus whitelisted
  all-text, subject-only, and from-only field refinement while continuing to
  fail deterministically for invalid inputs. The browser route caps rendered
  search rows, but broader advanced search still needs product-level refinement
  decisions.
- The implementation now provides a first one-message move path between
  existing mailboxes plus settings-backed archive shortcuts, including bounded
  selected-message archive from mailbox-list pages, but it does not yet provide
  general bulk move to arbitrary destinations or archive mailbox discovery. The
  current Version 2 move/archive surface validates configured archive targets
  against the authenticated user's mailbox list and re-resolves the source
  mailbox plus UID before reporting move success.
- The implementation now provides a first browser-visible session list,
  self-service revocation for one session, other sessions, or all sessions, and
  automatic revocation for expired or inactive sessions. Version 3 now makes
  concurrent sessions the explicit policy and surfaces normalized device labels,
  and V6 adds a store-local advisory lock for cross-process operations sharing
  one session directory, but it does not provide cross-host locking or
  anomaly-oriented session analysis
- The implementation now provides a first bounded end-user settings surface,
  but it currently exposes only HTML display and archive-mailbox preferences
  rather than a broad settings platform
- The Rust backend now implements a bounded dual-bucket file-backed login
  throttle for browser authentication plus a bounded dual-bucket submission
  throttle for the browser send path plus a bounded dual-bucket message-move
  throttle for the first folder-organization path. Store-local advisory locks
  now serialize each complete two-bucket state transaction across cooperating
  processes on one host. Broader request-abuse controls, distributed
  coordination, and richer anomaly handling still depend on adjacent defenses
  such as nginx, PF, and operator monitoring
- Operator-facing migration, rollback, pilot, workflow-inventory, and
  acceptance-gate guidance now exists, and the final Version 2 trial cohort
  has completed the bounded pilot workflows
- The selected-message archive route reuses the current message-move throttle
  once per selected UID. The remaining lower-volume authenticated POST routes
  in the current browser surface (`/settings`, `/sessions/revoke`, and
  `/logout`) are now both CSRF-bound and same-origin-bound and remain much
  lower abuse value than login, send, or message move, so the next hardening win
  is unlikely to be another narrow per-route throttle
- A formal migration baseline now exists, and the bounded Version 2 end-user
  pilot is complete, but broader Roundcube migration rehearsal remains future
  rollout work
- The existing host is multi-purpose, which constrains how aggressively the
  replacement can diverge from current operational patterns
- Required user workflows are defined at product level, but detailed field-level
  UX and edge-case behavior are still unspecified
- The identity model intentionally stops short of phishing-resistant MFA,
  native-client coexistence refinement, recovery design, and broader browser
  session-management UX
- The architecture now defines a clear system shape, and the current repo now
  materially proves login, read, search, move, send, session, and confinement
  behavior on the validated host. Version 1 closeout remains anchored to the
  frozen release gate and the successful April 14, 2026 current-pushed-snapshot
  host rerun.
- The OpenBSD runtime now has an enforced confinement mode, and the current
  helper-side plus serve-side dependency view is narrowed to explicit auth,
  sendmail, loader, library, config, and socket paths on the validated host,
  but the policy still keeps conservative library fallbacks when exact
  versioned shared-library files are unavailable
- `mail.blackbagsecurity.com` now has a dedicated least-privilege Dovecot auth
  listener for `_osmap`, and positive browser login plus TOTP-backed session
  issuance are now validated there under `enforce`
- `mail.blackbagsecurity.com` now also has a dedicated Dovecot userdb listener
  for the `vmail` mailbox-helper path, and helper-backed mailbox listing,
  message-list retrieval, message view, and attachment download are now proven
  there under `enforce`
- the current direct `doveadm` mailbox-read path remains a prototype bridge;
  production `serve` mode now freezes the least-privilege deployment posture
  around `OSMAP_MAILBOX_HELPER_SOCKET_PATH`, while direct mailbox backends
  remain only as development and test seams rather than an acceptable
  production shape
- the helper/OpenBSD confinement plan should now be treated as the deliberate
  Version 1 stopping point, but the current split-runtime operator model is
  still repo-owned scaffolding rather than finished packaging or ports
  integration
- the OpenBSD confinement plan now keeps the top-level state root read-only and
  only the explicit child directories writable, and both the helper and the
  browser runtime now prefer exact `doveadm`, mailwrapper/sendmail, loader,
  library, config, and socket paths on the validated host, but the current
  plan still keeps conservative directory fallbacks when a host does not expose
  the expected exact versioned shared-library filenames
- the new repo-owned real login-plus-send proof depends on an operator-supplied
  validation password for the dedicated validation mailbox; that keeps the
  proof reproducible without teaching the repository to store mailbox secrets,
  but it also means the host harness is not completely self-contained
- sanitized HTML rendering and the first settings-driven plain-text fallback
  are now proven on `mail.blackbagsecurity.com`, and the first live mutation
  proof for one-message move plus bounded send now exists there too, and the
  bounded move-throttle plus send-throttle behaviors are both now proven there,
  and the bounded `cid:` inline-image metadata path is now proven there too,
  but broader mutation coverage is still incomplete
- The SDLC and release rules are implemented, but strict release validation
  remains dependent on current host, credential, TLS, WSTG, and sanitized
  evidence inputs
- The project now has an implementation plan, work breakdown, Version 1
  closeout gate, Version 2 readiness gate, and Version 2 pilot closeout record.
  Future progress should continue through scoped gates rather than by widening
  the completed Version 2 surface.
- Version 3 daily-driver functionality and assurance work are implemented and
  carried forward by later gates. The broader product limitations in this
  document remain unchanged.

## Version 3 Daily-Driver Adoption Boundary

Version 3 implemented the pilot-proven gaps that blocked ordinary daily use:

- MIME and HTML correctness
- draft save and resume
- reply and forward attachment handling
- richer search
- bounded bulk folder actions
- session and device policy
- TLS CBC cleanup or a documented exception
- WSTG regression evidence

The authoritative Version 3 scope is now recorded in:

- `docs/V3_DEFINITION.md`
- `docs/V3_ACCEPTANCE_CRITERIA.md`
- `docs/V3_ROADMAP.md`
- `docs/V3_SECURITY_GATES.md`

The following remain out of scope for Version 3:

- contacts, calendar, groupware, plugins, mobile app, and broad admin console
- remote external content loading
- OpenPGP implementation, except design-only investigation
- broad runtime rewrite
- general Roundcube parity

The April 2026 WSTG backlog maps into Version 3 as follows:

- TLS 1.2 CBC suites have been removed from the reviewed nginx public-edge
  artifact and live edge evidence is archived at
  `maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt`.
- Concurrent sessions are explicit policy, device labels are normalized, and
  session state changes are protected by local concurrency tests plus a
  cross-process store lock. Cross-host coordination and anomaly scoring remain
  out of scope.
- Richer search ergonomics are partially supported through bounded result
  sorting and whitelisted all-text/subject/from refinement. Advanced search,
  bounded bulk folder actions, and folder ergonomics remain Version 3 workflow
  refinements only to the extent required by the daily-driver adoption
  boundary.

## Version 6 Controlled Retirement Readiness Boundary

V6 production readiness passed on June 18, 2026. The original V6 closeout
record kept selected-cohort retirement incomplete until no-fallback,
observability, resource-resilience, and final archive evidence passed against
one assessed deployment.

V9 Slice 6 later accepted the V6 selected-cohort/no-Roundcube closeout criteria
for the bounded V9 release-candidate decision. That reconciliation is scoped to
the selected-cohort V9 evidence chain and does not turn V6 into a general
Roundcube-replacement or broad webmail parity claim.

The primary V6 gaps at the definition baseline are:

- file-backed session mutations now have a restrictive store-local advisory
  lock for processes sharing one host directory; distributed locking remains
  out of scope
- explicit source-attachment selections now persist across draft resume as
  bounded source references only; source-message deletion or mutation remains
  a visible fail-closed condition and no source bytes are persisted
- production readiness passed with a sanitized host report, deployed commit,
  binary SHA256, service state, rollback unit, and browser-facing GET proof
- the V9 selected-cohort decision accepted the required no-fallback,
  observability, and resource evidence for the bounded release-candidate scope
- the bounded resource model has a fail-closed validator and is carried forward
  by the V9 evidence chain for selected-cohort operation
- Roundcube retirement remains bounded to the selected cohort and keeps
  operator rollback expectations in force
- the original V6 archive tooling remains useful for standalone V6 evidence
  refreshes, but V9 now controls the current selected-cohort release-candidate
  decision

V6 does not close or relax the broader limitations around general webmail
parity, remote content, attachment preview, groupware, broad administration,
OpenPGP, ManageSieve UI, or a complete denial-of-service strategy.

## Version 9 Production Convergence Boundary

V9 Slice 1 reconciled source and production identity after PR #19. The final
V9 gate then accepted `a8915c0993b96a9d53de083dc84cb7520aef0097` as a bounded
selected-cohort release candidate while production runtime code remained
`49c9f230d7865f01deadbc6a5a0f6e876c63e89b` and live binary SHA256 remained
`411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`.

The V9 release-candidate decision resolved the specific V4 carry-forward, V6
selected-cohort, V7 production availability, hold-period, healthy-service, and
rollback-reference blockers listed in `docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`.
The remaining limitations are scope limits, not unresolved V9 gate blockers:

- the release-candidate claim is selected-cohort only;
- complete Roundcube feature parity is not claimed;
- general hostile email safety is not claimed;
- unbounded mailbox parsing safety is not claimed;
- production runtime code still remains the PR #19 deployed binary, with
  documentation-only source drift recorded by the V9 gate.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:START -->

## V7 production availability limitation update

The previous V7 production-availability reopening is closed by V9 Slice 5 evidence. The closeout is bounded. It proves the tested selected-user production path, not complete Roundcube parity and not a final release-candidate state.

Remaining limitations after this closeout and the later V9 Slice 7 gate:

- This is a selected-cohort release-candidate decision, not a general release
  claim.
- This does not claim complete Roundcube replacement.
- Production was not rebuilt for Slice 2 documentation-only changes, and no rebuild is required for that documentation merge.
- V6 selected-cohort/no-Roundcube closure and the final V9 release-candidate
  gate are reconciled by `docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:END -->

## V12 OpenPGP bounded implementation track

Earlier documents correctly treated OpenPGP as out of scope for prior releases. V12 changes that status only within the boundary defined in `docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md`.

Until later V12 slices provide implementation evidence, OSMAP must not claim working OpenPGP decryption, verification, signing, encryption, key discovery, account binding, or UI integration. The current claim is limited to a documented requirement and claims boundary.

<!-- OSMAP:V12-SLICE2-DIAGNOSTICS:START -->

### V12 Slice 2 diagnostics limitation

V12 Slice 2 provides OpenPGP public key inventory and toolchain diagnostics only. OSMAP still must not claim implemented OpenPGP decryption, signature verification, signing, encryption, account binding, key discovery for delivery, or UI integration.

<!-- OSMAP:V12-SLICE2-DIAGNOSTICS:END -->

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:START -->

### V12 Slice 3 account binding limitation

V12 Slice 3 validates account-to-fingerprint configuration only. OSMAP still must not claim implemented OpenPGP decryption, signature verification, signing, encryption, PGP/MIME handling, passphrase handling, helper cryptographic operations, or browser UI integration.

<!-- OSMAP:V12-SLICE3-ACCOUNT-BINDING:END -->
