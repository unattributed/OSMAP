# V14 Slice 4 Modern Inbox and Message List

## Status

V14 Slice 4 improves the authenticated mailbox message-list page as a functional inbox-like surface. The slice remains bounded to server-rendered Rust HTML, local CSS, and existing mailbox list behavior.

## Functional acceptance

This slice provides:

- clearer message-list hierarchy for UID, subject, sender, received date, flags, size, and action cells
- scan-friendly subject links with a compact sender/date metadata line
- visible message-list status badges for remote-content blocking, sorting/search preservation, and CSRF-bound bulk actions
- a bounded empty-state row when no messages are rendered
- preserved sort links, mailbox search, bulk move, and archive controls

The page remains useful without JavaScript. The browser can still sort, search, archive, and move messages through existing server routes and forms.

## Security acceptance

- This slice makes no OpenPGP runtime capability change and does not expand V12 OpenPGP claims.

All mailbox names, message subjects, senders, dates, flags, and generated links remain escaped before rendering. State-changing controls remain POST based and CSRF-bound. This slice adds no runtime JavaScript, no frontend framework, no npm/node build chain, no external CDN, no remote image or font fetch, and no new dependency.

V4 hostile-message route compatibility remains required. The message-list modernization must not add runtime SVG, script, remote fetch surfaces, or route-backed browser primitives that weaken hostile-content assurance.

## Governance acceptance

This slice does not expand release claims, production deployment state, OpenPGP runtime capability, decrypt, verify, sign, encrypt, PGP/MIME parsing, key discovery, passphrase handling, private key access, or decrypted rendering.

The V14 gate is extended with `osmap-v14-message-list-gate.sh`. V10 generated inventory registers may be refreshed only to account for source drift and must pass `make v10-check` before PR review.

## Evidence expectations

Expected local validation:

- `git diff --check`
- `make v14-check`
- `make v10-check`
- `cargo check`
- `cargo test html_response_accepts_typed_template_output_and_escapes_title --lib`
- `cargo test --test v4_hostile_assurance -- v4_hostile_content_assurance_corpus_gate`

GitHub Actions remains the merge gate before this slice is merged to `origin/main`.
