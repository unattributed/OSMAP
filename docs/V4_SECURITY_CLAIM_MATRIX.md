# V4 Security Claim Matrix

## Purpose

This matrix converts the hostile-content containment claim into auditable,
continuously validated claims.

The scope is assurance only. It does not add end-user functionality, rich-mail
rendering, automatic remote content, attachment preview, malware detection, URL
reputation, or Roundcube feature parity.

## Matrix

| Claim | Implementation | Automated test | Validation evidence | Residual risk | Limitation | Non-goal |
| --- | --- | --- | --- | --- | --- | --- |
| Hostile HTML cannot execute in the message view | `src/rendering_html.rs` allowlist sanitizer plus the full message-view response builder | `tests/v4_hostile_assurance.rs` route-backed body-panel DOM negative assertions | `maint/live/osmap-v4-hostile-assurance-report.json` route-backed observations and archived corpus evidence | sanitizer bugs in dependencies may exist | OSMAP renders only a narrow subset of HTML | rich HTML feature parity |
| Remote content does not load automatically from rendered mail | sanitizer removes fetch-capable tags, CSS, meta refresh, CID URLs, data/blob/file URLs, and protocol-relative URLs before the message page is built | hostile corpus fixtures under `tests/testdata/hostile-mail-corpus/html/` plus route-backed auto-fetch surface observations | zero observed auto-fetch, beacon, WebSocket, and service-worker surfaces in the V4 assurance report | future browser features could add new fetch surfaces | current proof is for server-rendered OSMAP pages and route-backed fetch-surface scanning, not a full browser engine | remote image loading |
| MIME parser behavior is bounded under malformed input | `src/mime.rs` bounded header values, header counts, part counts, boundary length, and nesting depth | `tests/v4_hostile_assurance.rs` MIME robustness assertions plus product-code MIME tests | parser observations in the V4 assurance report | MIME is intentionally partial and conservative | unsupported or ambiguous content may be withheld | full MIME client compatibility |
| Attachment deception is contained as download-only behavior | `src/attachment.rs` filename normalization, content-type normalization, bounded decode, browser-executable media downgrade, and `src/http_support.rs` forced-download response headers | `tests/v4_hostile_assurance.rs` attachment deception assertions plus route-backed forced-download header assertions | attachment route observations in the V4 assurance report | downloaded files may still be malicious after the user opens them | OSMAP does not inspect archives or documents for malware | attachment preview safety |
| Browser isolation headers preserve the mail/browser boundary | `src/http_support.rs` CSP, `X-Frame-Options`, `nosniff`, CORP, no-referrer, and forced download headers | `tests/v4_hostile_assurance.rs` source invariant assertions, response header assertions, and route-backed browser-boundary observations | browser isolation observations in the V4 assurance report | browser or proxy misconfiguration can weaken protection outside the Rust response path | route-backed scanning complements live-host route proof but is not a complete browser-engine conformance suite | service workers, WebSockets, client-side app runtime |
| V4 assurance evidence is release-gated, tuple-checked, and archived | `maint/security/osmap-v4-hostile-assurance-gate.sh`, `maint/security/osmap-v4-release-tuple-gate.sh`, and `maint/security/osmap-release-check.sh` | release gate invokes the V4 assurance gate, validates report/archive presence, and reconciles the frozen V4.0.0 release tuple against current hostile-assurance evidence | `maint/live/osmap-v4-hostile-assurance-report.json`, `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`, `maint/live/latest-host-v4-hostile-content-report.txt`, and `maint/live/osmap-v3-release-evidence-summary.json` | release evidence must be refreshed after code changes; historical release evidence remains tied to its assessed commit | developer mode may run only local reproducible checks; post-release assurance reports can assess a later commit than the frozen `v4.0.0` tuple | unreviewed skipped release evidence or silent tuple drift |

## Release Rule

V4 cannot inherit the hostile-content containment claim unless
`maint/security/osmap-v4-hostile-assurance-gate.sh` passes for the assessed
commit and produces both:

- `maint/live/osmap-v4-hostile-assurance-report.json`
- `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`

The strict `make release-check` path records these artifacts in the machine
readable release summary and includes them in the sanitized release archive.

`maint/security/osmap-v4-release-tuple-gate.sh` reconciles two distinct
evidence lanes:

- the frozen V4.0.0 release tuple: tag `v4.0.0`, evidence bundle commit
  `59da020`, assessed code commit `09a95b7`, the live-host V4 report, and the
  V3 release carry-forward summary
- current hostile-content assurance evidence: the latest
  `maint/live/osmap-v4-hostile-assurance-report.json` and archive for the
  assessed commit under test

The current assurance report may name a later commit than the frozen release
tuple, but it must be a passed report, must include evidence metadata, must
archive the matching machine-readable report, and must not be silently confused
with the historical `v4.0.0` release tuple.
