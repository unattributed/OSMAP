# mail.blackbagsecurity.com Edge Artifacts

This directory carries the reviewed edge-cutover artifacts for the validated
`mail.blackbagsecurity.com` host shape.

These files are intentionally host-specific. They are not generic nginx or PF
examples. They are the repo-owned replacements and additions referenced by
`docs/EDGE_CUTOVER_PLAN.md` for the real Version 2 browser-edge move on the
validated host.

The current artifact set is:

- `nginx/sites-enabled/main-ssl.conf`
- `nginx/templates/osmap-root.tmpl`
- `pf.anchors/macros.pf`
- `pf.anchors/selfhost.pf`

Use them when the host is ready for the reviewed OSMAP edge cutover. They are
meant to replace hand-edited ad hoc changes during that move.
