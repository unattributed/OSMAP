# V14 Streamline WebUI and OpenPGP UX Integration

## Purpose

V14 is the authenticated WebUI modernization and OpenPGP UX integration sprint.
It is scoped to OSMAP's existing security model: server-rendered Rust HTML,
small trust boundary, low dependency footprint, restrictive browser policy, and
explicit evidence before capability claims.

This sprint starts after the V13 reviewed production and assurance closeout. V13
remains the current production deployment evidence reference until a later V14
closeout explicitly supersedes it.

## Current boundary

V14 does not begin by changing runtime cryptography, deployment posture, or live
host configuration. The sprint first establishes UI claims, design rules, local
assets, and documentation controls before changing authenticated routes.

V12 remains the OpenPGP foundation. V12 provides requirements, diagnostics,
account fingerprint binding, helper protocol and client scaffolding, GPGME
readiness gates, capability policy, outbound preflight, and inbound security
state models. V12 does not enable decrypt, verify, sign, encrypt, PGP/MIME
parsing, passphrase handling, private-key access, browser OpenPGP controls, key
discovery, or decrypted-content rendering.

## Goals

- Keep the current login page unchanged.
- Modernize authenticated application pages only.
- Preserve the existing routes and server-side behavior while improving layout,
  clarity, and account-level security surfaces.
- Match the approved reference images stored under
  `docs/design/v14-approved-ui-reference/`.
- Use a narrow icon rail, compact global top bar, center message list, large
  reader pane, compact trust strip, and concise icon-led controls.
- Add UI surfaces for account-level OpenPGP capability states without claiming
  cryptographic runtime behavior that is not implemented and evidenced.
- Keep secure mail rendering, source viewing, attachment handling, and account
  boundaries explicit to users and maintainers.

## Non-goals

- No JavaScript.
- No Node, npm, Vite, Webpack, React, Vue, Svelte, Alpine, htmx, or frontend
  framework.
- No external icon CDN, webfont CDN, remote stylesheet, remote image, or remote
  asset fetch.
- No CSP script allowance.
- No broad dependency expansion for visual presentation.
- No login page redesign in this sprint.
- No runtime OpenPGP cryptographic claim until later slices implement and
  evidence the required helper, policy, rendering, logging, and error handling
  paths.
- No claim that a verified signature makes message content safe.
- No bypass of protected rendering for decrypted content.

## Implementation rules

1. Authenticated UI remains server-rendered Rust HTML.
2. UI controls use links, forms, buttons, local CSS, and local inline SVG icons.
3. Any future dependency requires a written security and maintenance rationale.
4. The SBOM footprint stays small and reviewable.
5. Runtime responses must retain a restrictive Content Security Policy.
6. Script tags, inline event handlers, `javascript:` URLs, and frontend build
   artifacts are not part of the runtime UI.
7. Remote content blocking, link protection, sanitized HTML, attachment
   isolation, and explicit source view remain default behavior.
8. Source view remains explicit, escaped, authorized, and bounded.
9. Decrypted content, when later implemented, must still pass through protected
   rendering.
10. Passphrases, private key material, decrypted plaintext, full sensitive
    message bodies, and reusable credentials must not be logged.

## Product language

The user-facing label for OSMAP's secure rendering posture is
`Protected by Default`.

Use this language for trust strips, account security cards, documentation, and
future UI copy. Avoid language that implies an optional relaxed browsing mode or
that protection is only active after a user toggles a special state.

## Approved visual reference archive

The approved visual reference images are tracked as documentation assets:

- `docs/design/v14-approved-ui-reference/main-page-annotated.png`
- `docs/design/v14-approved-ui-reference/compose-page-annotated.png`
- `docs/design/v14-approved-ui-reference/secure-acct-admin-page-annotated.png`
- `docs/design/v14-approved-ui-reference/SHA256SUMS`

These files are reference material only. They must not be loaded by the runtime
browser UI. Later visual changes should compare against these files and update
the checksum record only when the project owner explicitly approves a new visual
reference.

## Authenticated app shell model

The authenticated app shell should converge on:

- a narrow left rail for primary navigation;
- a compact top bar for search, status, and account context;
- a center message list for mailbox scanning;
- a large reader pane for the selected message;
- a compact trust strip above message content;
- concise icon-led controls with accessible names;
- visible keyboard focus and predictable tab order.

The shell must not obscure security state. Navigation and visual density must
make `Protected by Default`, remote blocking, attachment isolation, rendering
mode, source view, and OpenPGP state easier to find.

## Icon inventory

The icon system should use local inline SVG helpers or repository-local SVG
assets only. Icons are decorative unless they communicate state, in which case
they require accessible text.

Primary navigation icons:

- Mailboxes
- Inbox or current folder
- Compose
- Drafts
- Sessions
- Settings
- Account security
- Log out

Message list icons:

- Unread
- Attachment present
- Protected rendering state
- Plain text
- Sanitized HTML
- Remote content blocked
- Attachment isolated
- OpenPGP encrypted
- OpenPGP decrypted locally
- Signature verified
- Unknown signer
- Cannot decrypt
- Missing key

Reader and compose icons:

- Reply
- Forward
- Archive
- Move
- Delete
- View Source
- Download attachment
- Sign
- Encrypt
- Encrypt to self
- Recipient key ready
- Missing recipient key
- Send Protected

## OpenPGP UX state model

OpenPGP controls appear only when account capability is configured. Accounts
without configured capability must not show controls that imply signing,
encryption, decryption, verification, key discovery, or key management support.

Reader states:

| State | Meaning | Claim boundary |
| --- | --- | --- |
| Encrypted | The message has OpenPGP-related metadata or policy state indicating encrypted content. | Does not imply decryptable content. |
| Decrypted locally | A later evidenced helper has produced plaintext for local rendering. | Plaintext must still pass protected rendering. |
| Signature verified | A later evidenced helper verified a signature against configured key material. | Verification does not make content safe. |
| Unknown signer | Signature metadata exists but signer trust or binding is unavailable. | Must not display as verified. |
| Cannot decrypt | Encrypted content cannot be decrypted for this account. | Do not expose sensitive helper details. |
| Missing key | A required account or sender key is not configured. | Do not attempt discovery unless separately scoped. |

Compose states:

| Control or state | Display condition | Claim boundary |
| --- | --- | --- |
| Sign | Account signing capability is configured. | Must fail closed when signing policy cannot be satisfied. |
| Encrypt | Account encryption capability is configured. | Must fail closed on missing recipient key when policy requires encryption. |
| Encrypt to self | Account policy requires or allows self-recipient encryption. | Must not silently drop self protection. |
| Recipient key ready | Recipient key binding is configured and policy accepts it. | Must not imply external trust beyond the configured binding. |
| Missing key | Recipient key is unavailable or policy cannot be satisfied. | Must stop protected send when encryption is required. |
| Send Protected | Final send action when configured policy requirements pass. | Must preserve existing send behavior and audit boundaries. |

## Account security page model

The account security page should expose account security posture without adding
unimplemented reset or key-management claims.

Required account security cards:

- OpenPGP account capability
- Full fingerprint when configured
- Signing policy
- Encryption policy
- Encrypt-to-self policy
- Manage Keys entry point, disabled or informational until implemented
- Password status or change entry point within existing account policy
- Recovery Contact surface as a management placeholder only, unless a later
  slice implements a full recovery flow
- Design-principles strip summarizing server-rendered, JavaScript-free,
  low-SBOM, Protected by Default behavior

## Accessibility requirements

- All icon-only controls require accessible names.
- State icons need visible or screen-reader text.
- Focus indicators must be visible against the approved color palette.
- Keyboard navigation must remain predictable without JavaScript.
- Forms must retain labels, error messages, CSRF fields, and safe value
  preservation on validation failure.
- Touch targets should remain practical on small screens.
- Responsive layout must preserve content order and security-state visibility.

## Slice acceptance rules

A V14 slice is complete only when evidence shows:

- exact files changed;
- no live-host assumption unless explicitly scoped;
- no runtime JavaScript addition;
- no frontend build chain addition;
- no external asset reference;
- no dependency growth without recorded justification;
- protected rendering remains the default security model;
- OpenPGP UI does not overclaim beyond implemented and evidenced capability;
- source view remains explicit, escaped, authorized, and bounded;
- generated evidence archive and checksum were produced under
  `~/Downloads/osmap-v14-streamline-webui-openpgp-evidence/`.

## Slice sequence

1. UI claims and design specification.
2. CSS and local icon foundation.
3. Authenticated app shell.
4. Modern inbox and message list.
5. Modern reader and `Protected by Default` trust strip.
6. OpenPGP reader states.
7. Compose page and OpenPGP controls.
8. Account security page.
9. No-JavaScript and low-SBOM gates.
10. Accessibility and responsive pass.
11. Final regression and evidence closeout.
