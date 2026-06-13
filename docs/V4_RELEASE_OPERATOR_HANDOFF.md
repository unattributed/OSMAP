# Version 4 Release Operator Handoff

## Purpose

This document is the operator-facing handoff for the GitHub release to publish
from tag `v4.0.0`.

It packages the already-reviewed V4 closeout evidence into a short release-note
and operator checklist. It does not add a broader safety claim beyond
`docs/V4_DEFINITION.md` and `docs/V4_CLOSEOUT_EVIDENCE.md`.

OSMAP V4 does not claim rich-mail safety, malware prevention, attachment preview safety, URL reputation, document sanitization, archive inspection, or safety for files opened outside OSMAP.

## Release Identity

| Field | Value |
| --- | --- |
| GitHub release tag | `v4.0.0` |
| Evidence bundle commit | `59da020` |
| Assessed V4 code commit | `09a95b7` |
| Assessed host | `mail.blackbagsecurity.com` |
| Host checkout | `~/OSMAP` |
| Live validator | `maint/live/osmap-live-validate-v4-hostile-content.ksh` |
| Live report | `maint/live/latest-host-v4-hostile-content-report.txt` |
| Live result marker | `result=v4_hostile_content_live_proof_passed` |

The tag `v4.0.0` resolves to evidence bundle commit `59da020`.
The code behavior assessed for the V4 claim is `09a95b7`.

## GitHub Release Draft

Title:

```text
OSMAP v4.0.0 - hostile-content safety release
```

Body:

```markdown
OSMAP v4.0.0 is a hostile-content safety release for the OSMAP browser-mail
boundary.

Assessed V4 code commit: `09a95b7`
Evidence bundle commit: `59da020`
Reviewed host: `mail.blackbagsecurity.com`

This release hardens hostile message-content handling for:

- sanitizer-backed HTML message rendering
- visible disclosure of preserved external link destinations
- browser-executable attachment download containment
- malformed, nested, suspicious, unsupported, and oversized MIME inputs
- sanitized, commit-safe release evidence

Scope boundary:

V4 contains hostile message content inside the OSMAP browser boundary. It does
not claim rich-mail safety, malware prevention, attachment preview safety, URL
reputation, document sanitization, archive inspection, or safety for files
after they are opened outside OSMAP.

Primary evidence:

- `docs/V4_DEFINITION.md`
- `docs/V4_ACCEPTANCE_CRITERIA.md`
- `docs/V4_SECURITY_GATES.md`
- `docs/V4_MIME_AMBIGUITY_EVIDENCE.md`
- `docs/V4_CLOSEOUT_EVIDENCE.md`
- `maint/live/latest-host-v4-hostile-content-report.txt`
- `maint/live/osmap-v4-frozen-v3-release-evidence-summary.json`
- `maint/live/osmap-v3-release-evidence-summary.md`
- `maint/live/osmap-v3-release-evidence.tar.gz`
- `maint/security/test-osmap-v4-closeout-evidence.sh`

Validation summary:

- host V4 hostile-content live proof passed for `09a95b7`
- host V3 release carry-forward `make release-check` passed for `09a95b7`
- local `make security-check` passed with the V4 closeout evidence consistency
  guard
- V4 MIME ambiguity and metadata breadth are covered by product-code regression
  tests named in `docs/V4_MIME_AMBIGUITY_EVIDENCE.md`

Residual risks:

- preserved external links may still lead users to phishing, malware,
  credential capture, or misleading destinations outside OSMAP
- OSMAP visibly discloses preserved link destinations, but does not provide URL
  reputation, detonation, or destination safety scoring
- downloaded attachments are forced downloads with reviewed browser-safety
  headers and browser-executable media types are downgraded to
  `application/octet-stream`, but files may still be malicious after a user
  opens them in external applications
- unsupported rich-mail behavior may be withheld or reduced to bounded metadata
  instead of rendered with Roundcube-like fidelity
```

## Operator Checklist

Before treating `v4.0.0` as the current V4 release:

- verify the tag exists on origin:

```sh
git ls-remote --tags origin 'v4.0.0*'
```

- verify the tag dereferences to the evidence bundle commit:

```sh
git rev-parse v4.0.0^{}
```

Expected commit:

```text
59da020a6f7d04535515cf7d5c3b26b4f3496ec8
```

- verify the live report names the assessed V4 code commit and pass marker:

```sh
grep -E '^(commit|result)=' maint/live/latest-host-v4-hostile-content-report.txt
```

Expected values:

```text
commit=09a95b7
result=v4_hostile_content_live_proof_passed
```

- run the local evidence consistency guard:

```sh
sh maint/security/test-osmap-v4-closeout-evidence.sh
```

- run the standard local security gate before any new development inherits the
  V4 claim:

```sh
make security-check
```

## Operational Boundary

Operators may describe V4 as hostile-content containment for the browser-mail
boundary only when referencing tag `v4.0.0`, evidence bundle commit `59da020`,
and assessed V4 code commit `09a95b7`.

Any code change after `09a95b7` requires refreshed V4 evidence before it can
inherit the V4 hostile-content safety claim.

Any evidence-bundle change after `59da020` should be treated as post-tag
documentation unless a new tag or release note explicitly supersedes
`v4.0.0`.

## Residual-Risk Statement

OSMAP V4 contains hostile message content inside the browser boundary; it does
not make attacker-controlled email globally safe.

The remaining risk is user-driven and boundary-crossing:

- users can still choose to follow preserved external links
- external destinations can still be malicious or misleading
- downloaded files can still be malicious when opened outside OSMAP
- OSMAP does not scan, detonate, sanitize, or preview arbitrary attachment
  contents
- reduced rendering of unsupported rich-mail content is intentional and should
  not be treated as a fidelity defect inside the V4 safety claim
