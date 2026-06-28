# V14 Approved UI Reference Images

This directory stores the approved visual references for the V14 Streamline WebUI and OpenPGP UX integration sprint.

These files are design references only. They are not loaded by the runtime browser UI, and they must not be treated as remote assets, templates, or executable content.

## Files

- `main-page-annotated.png`, approved authenticated mailbox and reader direction.
- `compose-page-annotated.png`, approved authenticated compose direction.
- `secure-acct-admin-page-annotated.png`, approved account security and account administration direction.
- `SHA256SUMS`, checksum record for drift detection.

## Design constraints carried forward

- Keep the existing login page unchanged.
- Modernize authenticated pages only.
- Use a narrow icon rail, compact top global bar, center message list, large reader pane, compact trust strip, and concise icon-led controls.
- Use local inline SVG icons or repository-local SVG assets only.
- Do not load remote images, icon sets, fonts, styles, or scripts.
- Keep the browser UI JavaScript-free and server-rendered.
- Keep the current restrictive CSP posture, including no script allowance.
- Use the product language `Protected by Default` for secure rendering and account protection states.
