# Known Limitations

## Current Documentation Limitations

- Phase 1 is evidence-based but still intentionally public-safe, so some local
  implementation details and private notes are summarized rather than published
- A repo-owned pilot workflow inventory baseline now exists, and the final
  Version 2 trial cohort has been confirmed against that bounded workflow set
- The exact Postfix configuration has not yet been exhaustively summarized in
  public docs, though service bindings and usage are already clear

## Current Program Limitations

- The implementation now has runtime, auth, TOTP, and session foundations, but
  it is still a prototype-grade browser mail product rather than a production
  service
- Direct public browser exposure remains limited and evidence-gated. The
  current Version 2 evidence supports the approved limited direct-public
  browser posture, not a broad production launch.
- The implementation now has a bounded browser slice with login, mailbox read,
  message view, compose, send, CSRF handling, and attachment download, and it
  now uses bounded concurrent request handling with an explicit connection cap,
  but it still does not provide a mature worker pool, async runtime, or a
  complete denial-of-service mitigation story
- The current HTTP runtime now has clearer connection-pressure, write-failure,
  and accept-failure observability, but it still depends on adjacent controls
  and does not yet provide a complete request-resource exhaustion strategy
- The implementation now has a bounded message-view fetch path, plus
  MIME-aware classification and attachment metadata surfacing, but it does not
  yet provide preview-oriented attachment behavior
- The implementation now has a first outbound send path with reply and forward
  draft generation plus bounded new attachment upload/submission behavior, but
  it does not yet support draft persistence or original-message attachment
  reattachment
- The implementation now has a conservative rendering layer with both
  plain-text and sanitized-HTML modes, but it still does not provide
  inline image rendering, full rich-header coverage, or any external-resource
  loading
- The implementation now provides a bounded, backend-authoritative browser
  search path across one mailbox or all visible mailboxes, but it does not yet
  provide advanced query ergonomics, sorting controls, or richer search
  refinement behavior. The Version 2 browser surface must keep that existing
  search route operational or fail deterministically for invalid inputs; it
  must not expose a visible search form that leads to a generic runtime 503 for
  ordinary authenticated search.
- The implementation now provides a first one-message move path between
  existing mailboxes plus settings-backed archive shortcuts, including bounded
  selected-message archive from mailbox-list pages, but it does not yet provide
  general bulk move to arbitrary destinations or archive mailbox discovery. The
  current Version 2 move/archive surface validates configured archive targets
  against the authenticated user's mailbox list and re-resolves the source
  mailbox plus UID before reporting move success.
- The implementation now provides a first browser-visible session list,
  self-service revocation for one session, other sessions, or all sessions, and
  automatic revocation for expired or inactive sessions, but it does not yet
  provide richer device labeling or anomaly-oriented session analysis
- The implementation now provides a first bounded end-user settings surface,
  but it currently exposes only one user-facing preference rather than a broad
  settings platform
- The Rust backend now implements a bounded dual-bucket file-backed login
  throttle for browser authentication plus a bounded dual-bucket submission
  throttle for the browser send path plus a bounded dual-bucket message-move
  throttle for the first folder-organization path, but broader request-abuse
  controls and richer anomaly handling still depend on adjacent defenses such
  as nginx, PF, and operator monitoring
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
- The SDLC and release rules are now defined, but they have not yet been proven
  against a full live implementation pipeline
- The project now has an implementation plan, work breakdown, Version 1
  closeout gate, Version 2 readiness gate, and Version 2 pilot closeout record.
  Future progress should continue through scoped gates rather than by widening
  the completed Version 2 surface.

## Version 3 Backlog From April 2026 WSTG

- TLS 1.2 CBC suite removal is real hardening work, but it belongs to Version 3
  because it is an edge and compatibility decision outside the bounded Version
  2 browser workflow fixes.
- Concurrent-session caps, device limits, and richer session anomaly handling
  remain Version 3 policy work. Version 2 keeps session visibility and
  self-service revocation, while the WSTG observation did not show a confirmed
  vulnerability in allowing more than one active session.
- The session revoke race observation remains Version 3 investigation because
  the reported evidence used a shared client cookie jar and was not a confirmed
  server-side flaw.
- Richer search ergonomics, archive mailbox discovery, general bulk move, and
  move-history UI remain Version 3 workflow refinement. Version 2 only needs
  the exposed search, archive, and one-message move workflows to be correct,
  bounded, and non-misleading.
- Additional pilot-requested functionality and Thunderbird-like UX polish
  remain Version 3 or later work.
