# Decision Log

## 2026-03-27

### Keep planning artifacts public and non-sensitive

The repository will keep a public documentation map under `docs/`, including
placeholder documents for planned work. Those placeholders should contain
minimal public-safe text rather than private planning detail or empty file
stubs.

### Complete Phase 0 with public-safe formal outputs

The project now treats Phase 0 as complete enough to proceed because the
charter, constraints, assumptions, roadmap, and early acceptance criteria are
documented in reviewable form.

### Ground Phase 1 in live-system evidence

Phase 1 documentation will be based on read-only inspection of the existing mail
host rather than inferred architecture alone. This keeps the replacement effort
anchored to operational reality.

### Preserve the current VPN-first access model as the starting point

The current environment intentionally keeps webmail, IMAP, and authenticated
submission behind WireGuard and nginx allowlisting. OSMAP should treat that as
the baseline security posture and only relax it by explicit later-phase design
decision.

### Define Version 1 as a narrow mail-only replacement

Phase 2 defines Version 1 as a browser-based mail product with strong
authentication, core mailbox workflows, attachments, search, session management,
and audit visibility. Groupware, plugin ecosystems, mobile apps, and broad
administrative surfaces remain out of scope.

### Preserve native-client coexistence

The product definition explicitly keeps Thunderbird and other native clients as
supported access paths. OSMAP is not intended to replace them or centralize all
mail access in the browser.

### Keep the decision log current during phase execution

`docs/DECISION_LOG.md` should be updated as meaningful phase decisions are made.
It is a live project control document, not an after-action summary written only
at the end of a phase.
