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
| Hostile HTML cannot execute in the message view | `src/rendering_html.rs` allowlist sanitizer with clean-content tags, denied relative URLs, and allowed URL schemes only | `tests/v4_hostile_assurance.rs` browser-rendered negative assertions | `maint/live/osmap-v4-hostile-assurance-report.json` and archived corpus evidence | sanitizer bugs in dependencies may exist | OSMAP renders only a narrow subset of HTML | rich HTML feature parity |
| Remote content does not load automatically from rendered mail | sanitizer removes fetch-capable tags, CSS, meta refresh, CID URLs, data/blob/file URLs, and protocol-relative URLs | hostile corpus fixtures under `tests/testdata/hostile-mail-corpus/html/` | zero-fetch assertions in the V4 assurance report | future browser features could add new fetch surfaces | current proof is for server-rendered OSMAP pages | remote image loading |
| MIME parser behavior is bounded under malformed input | `src/mime.rs` bounded header values, header counts, part counts, boundary length, and nesting depth | `tests/v4_hostile_assurance.rs` MIME robustness assertions plus product-code MIME tests | parser observations in the V4 assurance report | MIME is intentionally partial and conservative | unsupported or ambiguous content may be withheld | full MIME client compatibility |
| Attachment deception is contained as download-only behavior | `src/attachment.rs` filename normalization, content-type normalization, bounded decode, and browser-executable media downgrade | `tests/v4_hostile_assurance.rs` attachment deception assertions | attachment observations in the V4 assurance report | downloaded files may still be malicious after the user opens them | OSMAP does not inspect archives or documents for malware | attachment preview safety |
| Browser isolation headers preserve the mail/browser boundary | `src/http_support.rs` CSP, `X-Frame-Options`, `nosniff`, CORP, no-referrer, and forced download headers | `tests/v4_hostile_assurance.rs` source invariant assertions | browser isolation observations in the V4 assurance report | browser or proxy misconfiguration can weaken protection outside the Rust response path | static source assertions complement live route proof | service workers, WebSockets, client-side app runtime |
| V4 assurance evidence is release-gated and archived | `maint/security/osmap-v4-hostile-assurance-gate.sh` and `maint/security/osmap-release-check.sh` | release gate invokes the V4 assurance gate and validates report/archive presence | `maint/live/osmap-v4-hostile-assurance-report.json` and `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz` | release evidence must be refreshed after code changes | developer mode may run only local reproducible checks | unreviewed skipped release evidence |

## Release Rule

V4 cannot inherit the hostile-content containment claim unless
`maint/security/osmap-v4-hostile-assurance-gate.sh` passes for the assessed
commit and produces both:

- `maint/live/osmap-v4-hostile-assurance-report.json`
- `maint/live/osmap-v4-hostile-assurance-evidence.tar.gz`

The strict `make release-check` path records these artifacts in the machine
readable release summary and includes them in the sanitized release archive.
