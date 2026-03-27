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
  it is not yet a usable browser mail product
- The implementation now has a bounded browser slice with login, mailbox read,
  message view, compose, send, and CSRF handling, but it does not yet include
  attachment download handlers or concurrent request handling
- The implementation now has a bounded message-view fetch path, plus
  MIME-aware classification and attachment metadata surfacing, but it does not
  yet provide attachment retrieval or download behavior
- The implementation now has a first outbound send path with reply and forward
  draft generation plus bounded new attachment upload/submission behavior, but
  it does not yet support draft persistence or original-message attachment
  reattachment
- The implementation now has a plain-text-first rendering layer, but it does
  not yet define HTML mail sanitization, encoded-header handling, or inline
  resource policy
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
  first narrowing pass away from a blanket `/var` unveil
- The current browser-driven invalid-login path on `mail.blackbagsecurity.com`
  produces the same `doveadm` backend error with confinement disabled and
  enabled, so that host-specific browser-auth path still needs refinement
- The SDLC and release rules are now defined, but they have not yet been proven
  against a full live implementation pipeline
- The project now has an implementation plan and work breakdown, but there is
  not yet a full browser proof of concept covering attachment download and
  hardened deployment end to end
