# Version 4 Roadmap

## Purpose

This roadmap sequences Version 4 work so OSMAP can make a narrow, defensible
hostile-content safety claim without widening into rich webmail rendering or
Roundcube parity.

## Roadmap Rules

- keep application changes behind the gates in `V4_ACCEPTANCE_CRITERIA.md`
- preserve the Version 3 release, helper-boundary, session, CSRF, same-origin,
  WSTG, TLS, and supply-chain gates
- treat hostile-content evidence as a release requirement, not a later audit
  task
- land one payload class or containment behavior at a time with tests and
  evidence
- keep all evidence redacted enough to commit or archive safely
- reject work that requires Javascript rendering, automatic remote-content
  loading, attachment preview, malware-scanning claims, contacts, calendar,
  groupware, plugins, mobile app, or broad Roundcube parity

## Work Sequence

| Order | Slice | Deliverable | Exit gate |
| --- | --- | --- | --- |
| 0 | V4 boundary definition | document the Version 4 scope, acceptance criteria, security gates, roadmap, payload goals, and residual risk | V4 docs name in-scope work, out-of-scope work, completion criteria, and evidence requirements |
| 1 | Sanitizer fixture hardening | expand hostile HTML fixtures for obfuscated schemes, scriptable containers, forms, event handlers, CSS, media, SVG, MathML, frames, objects, embeds, templates, and remote fetch surfaces | sanitizer and rendering tests prove forbidden payloads do not survive |
| 2 | Link destination visibility | disclose preserved external link destinations in rendered message bodies | CSS and route evidence prove allowed links expose destinations visibly |
| 3 | Executable attachment containment | downgrade browser-executable attachment media types and force download with `nosniff` | attachment tests prove HTML, SVG, and script attachments are served as `application/octet-stream` |
| 4 | MIME ambiguity and metadata breadth | verify malformed, unsupported, nested, suspicious, or oversized MIME inputs fail closed or surface only bounded metadata | MIME and rendering fixtures prove withheld placeholders or safe metadata behavior |
| 5 | Live hostile-content proof | run the host-assisted V4 validator against the reviewed runtime | sanitized live report proves `/message`, `/attachment`, and evidence-redaction behavior |
| 6 | V4 closeout evidence | archive the local gate, live proof, residual-risk statement, and carry-forward evidence for the assessed commit or tag | V4 closeout record can honestly claim hostile-content safety inside the OSMAP browser boundary |

## Current Status

The first V4 implementation slice has started and is present on `main`.

Current completed local pieces include:

- `docs/V4_HOSTILE_CONTENT_SAFETY_GOALS.md`
- `docs/V4_HOSTILE_CONTENT_TEST_MATRIX.md`
- sanitizer fixture expansion in `src/rendering_html.rs`
- link destination disclosure CSS in `src/http_support.rs`
- executable attachment download hardening in `src/attachment.rs`
- local V4 safety guard in `maint/security/test-osmap-v4-hostile-content-safety.sh`
- live validator wrapper regression in
  `maint/security/test-osmap-live-validate-v4-hostile-content.sh`
- host-assisted live evidence lane in
  `maint/live/osmap-live-validate-v4-hostile-content.ksh`

The live V4 hostile-content proof has now passed on the reviewed OpenBSD host
for assessed commit `a3f6e98`. The sanitized report is archived at
`maint/live/latest-host-v4-hostile-content-report.txt`, and the evidence
summary is recorded in `docs/V4_CLOSEOUT_EVIDENCE.md`.

The remaining release-closeout work is to carry this proof forward to the final
V4 assessed release commit or tag, archive the full local and carry-forward
gate bundle, and finalize the residual-risk statement.

## First Next Step

Carry the passed live V4 hostile-content proof into the final V4 closeout
bundle for the assessed release commit or tag.

The proof must show:

- hostile HTML is sanitized before browser presentation
- unsafe URL schemes and relative navigation targets are removed
- preserved links disclose their destinations
- remote fetch surfaces do not survive rendering
- HTML, SVG, and script attachments are forced to download as
  `application/octet-stream`
- the report excludes private body markers, attachment body markers, session
  cookies, CSRF tokens, credentials, TOTP material, provider secrets, and host
  secrets
