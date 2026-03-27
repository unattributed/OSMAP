# Known Limitations

## Current Documentation Limitations

- Phase 1 is evidence-based but still intentionally public-safe, so some local
  implementation details and private notes are summarized rather than published
- Active user workflow inventory has not yet been confirmed with direct usage
  analysis
- The exact Postfix configuration has not yet been exhaustively summarized in
  public docs, though service bindings and usage are already clear

## Current Program Limitations

- No implementation code exists yet for the replacement
- The Version 1 product definition is now documented, but architecture and
  threat-model choices are still pending
- No formal migration plan has been completed
- The security model is now defined at Phase 3 level, but control selection and
  implementation details are still pending
- The existing host is multi-purpose, which constrains how aggressively the
  replacement can diverge from current operational patterns
- Required user workflows are defined at product level, but detailed field-level
  UX and edge-case behavior are still unspecified
- The identity model intentionally stops short of a full implementation plan for
  native-client coexistence, phishing-resistant MFA, or recovery design
