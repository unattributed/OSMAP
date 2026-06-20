# V7 rendering regression close-out

## Status

V7 entered stabilization freeze because daily-driver message rendering regressed after testing discipline weakened. A production-visible multipart HTML message rendered only the historical placeholder instead of a sanitized HTML view when no safe plain-text body was available.

Feature development remains frozen until this gate passes.

## Closed regression class

The recovered behavior is protected by fixture-based Rust tests and a required V7 rendering regression gate. The protected rule is:

- when a safe plain-text part exists and the user prefers plain text, OSMAP renders plain text;
- when no safe plain-text part exists but a selected HTML body exists, OSMAP renders sanitized HTML;
- OSMAP never renders raw HTML;
- OSMAP does not load remote content;
- OSMAP does not allow active content.

## Bounded security claim

OSMAP renders sanitized HTML only through the current allowlist policy and blocks active or remote content. This is a bounded browser-mail rendering claim. It does not claim that arbitrary hostile HTML is safe outside that policy, outside the OSMAP rendering path, or outside the tested containment boundary.

## Gate coverage

The close-out gate is `maint/security/osmap-v7-rendering-regression-gate.sh` and is reachable through:

```sh
make v7-rendering-regression-check
make v7-check
make security-check
```

The gate runs Rust tests for:

- HTML-only singlepart sanitized rendering;
- HTML-only multipart sanitized rendering when no safe plain-text body exists;
- plain-text preference selecting plain text when available;
- sanitized-HTML preference selecting sanitized HTML when available;
- plain-text preference falling back to sanitized HTML when no safe plain body exists;
- Windows-1252 and RFC 2047 subject and body decoding;
- hostile HTML sanitization for scripts, handlers, forms, iframes, object/embed, remote image fetches, relative URLs, protocol-relative URLs, and unsafe schemes;
- malformed MIME fail-closed behavior without raw HTML rendering;
- truthful UI labels for body source, rendering mode, HTML presence, sanitized HTML notice, and remote-content blocking.

## Evidence recording

Run-specific evidence is written outside the repository by `RUN_ME.sh` under:

```text
$HOME/osmap-v7-rendering-regression-closeout-evidence/<timestamp>
```

The runner produces an evidence archive and matching SHA-256 file:

```text
osmap-v7-rendering-regression-closeout-evidence-<timestamp>.tar.gz
osmap-v7-rendering-regression-closeout-evidence-<timestamp>.tar.gz.sha256
```

The archive contains the exact command output, diffs, gate output, final repository state, commit identity when created, and the run-specific archive checksum.
