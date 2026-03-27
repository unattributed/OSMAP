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
  message view, compose, send, CSRF handling, and attachment download, but it
  still uses a sequential listener rather than concurrent request handling
- The implementation now has a bounded message-view fetch path, plus
  MIME-aware classification and attachment metadata surfacing, but it does not
  yet provide preview-oriented attachment behavior or successful live-host
  attachment reads under enforced confinement
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
- `mail.blackbagsecurity.com` now has a dedicated least-privilege Dovecot auth
  listener for `_osmap`, and positive browser login plus TOTP-backed session
  issuance are now validated there under `enforce`, but authenticated mailbox
  and message reads are still not proven for `_osmap`
- `mail.blackbagsecurity.com` now also has a dedicated Dovecot userdb listener
  for `_osmap`, and OSMAP supports `OSMAP_DOVEADM_USERDB_SOCKET_PATH`, but the
  host's current Dovecot virtual-user model still resolves mailbox access to
  `uid=2000(vmail)` and `gid=2000(vmail)`, which blocks least-privilege
  mailbox helpers from running successfully as `_osmap`
- the current direct `doveadm` mailbox-read path remains a prototype bridge;
  the selected least-privilege next step is a dedicated local mailbox-read
  helper boundary, and the first mailbox-list helper slice now exists, but the
  broader read-path migration is not complete
- the mailbox helper is not yet live-host validated under the target OpenBSD
  `vmail` boundary, and helper-specific OpenBSD confinement is not yet
  implemented
- The current synthetic session-gated attachment request under enforced mode on
  `mail.blackbagsecurity.com` now reaches the route, validates the session, and
  updates session state without the previous Dovecot stats-writer noise, but
  successful live attachment-bearing reads are still not proven there
- The SDLC and release rules are now defined, but they have not yet been proven
  against a full live implementation pipeline
- The project now has an implementation plan and work breakdown, but there is
  not yet a fully proven browser proof of concept covering hardened deployment
  and successful live attachment workflows end to end
