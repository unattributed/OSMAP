# Known Limitations

## Current Documentation Limitations

- Phase 1 is evidence-based but still intentionally public-safe, so some local
  implementation details and private notes are summarized rather than published
- Active user workflow inventory has not yet been confirmed with direct usage
  analysis
- The exact Postfix configuration has not yet been exhaustively summarized in
  public docs, though service bindings and usage are already clear

## Current Program Limitations

- The implementation now has runtime, auth, TOTP, and session foundations, but
  it is still a prototype-grade browser mail product rather than a production
  service
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
  encoded-header handling, inline image rendering, or any external-resource
  loading
- The implementation now provides a bounded, backend-authoritative browser
  search path across one mailbox or all visible mailboxes, but it does not yet
  provide advanced query ergonomics, sorting controls, or richer search
  refinement behavior
- The implementation now provides a first one-message move path between
  existing mailboxes plus a settings-backed archive shortcut, but it does not
  yet provide bulk move, mailbox-list selection actions, or archive mailbox
  discovery
- The implementation now provides a first browser-visible session list and
  self-service revocation path, but it does not yet provide richer device
  labeling or anomaly-oriented session analysis
- The implementation now provides a first bounded end-user settings surface,
  but it currently exposes only one user-facing preference rather than a broad
  settings platform
- The Rust backend now implements a bounded dual-bucket file-backed login
  throttle for browser authentication plus a bounded dual-bucket submission
  throttle for the browser send path plus a bounded dual-bucket message-move
  throttle for the first folder-organization path, but broader request-abuse
  controls and richer anomaly handling still depend on adjacent defenses such
  as nginx, PF, and operator monitoring
- The remaining authenticated POST routes in the current browser surface
  (`/settings`, `/sessions/revoke`, and `/logout`) are CSRF-bound and much
  lower abuse value than login, send, or message move, so the next hardening
  win is unlikely to be another narrow per-route throttle
- No formal migration plan has been completed
- The existing host is multi-purpose, which constrains how aggressively the
  replacement can diverge from current operational patterns
- Required user workflows are defined at product level, but detailed field-level
  UX and edge-case behavior are still unspecified
- The identity model intentionally stops short of phishing-resistant MFA,
  native-client coexistence refinement, recovery design, and broader browser
  session-management UX
- The architecture now defines a clear system shape, but mailbox, rendering,
  send-path, and confinement enforcement details still need proof through
  implementation
- The OpenBSD runtime now has an enforced confinement mode, but its helper
  compatibility view is still broader than the final target even after the
  first narrowing passes away from blanket `/etc` and `/var` visibility
- `mail.blackbagsecurity.com` now has a dedicated least-privilege Dovecot auth
  listener for `_osmap`, and positive browser login plus TOTP-backed session
  issuance are now validated there under `enforce`
- `mail.blackbagsecurity.com` now also has a dedicated Dovecot userdb listener
  for the `vmail` mailbox-helper path, and helper-backed mailbox listing,
  message-list retrieval, message view, and attachment download are now proven
  there under `enforce`
- the current direct `doveadm` mailbox-read path remains a prototype bridge;
  the selected least-privilege next step is a dedicated local mailbox-read
  helper boundary, and mailbox listing, message-list retrieval, plus
  message-view retrieval now use that helper when configured, while attachment
  download now reuses the helper-backed message-view path instead of making the
  web runtime fetch directly, but the broader read-path migration is not
  complete
- attachment download is now proven against a real attachment-bearing mailbox
  under enforced confinement, but a distinct helper-side attachment-byte
  operation still does not exist
- sanitized HTML rendering and the first settings-driven plain-text fallback
  are now proven on `mail.blackbagsecurity.com`, and the first live mutation
  proof for one-message move plus bounded send now exists there too, and the
  bounded move-throttle plus send-throttle behaviors are both now proven there,
  but broader mutation coverage is still incomplete
- The SDLC and release rules are now defined, but they have not yet been proven
  against a full live implementation pipeline
- The project now has an implementation plan and work breakdown, but there is
  not yet a fully proven browser proof of concept covering hardened deployment
  and successful live mutation workflows beyond the first bounded move/send
  coverage
