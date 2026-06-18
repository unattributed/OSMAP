# V6 Roadmap

## Milestone

V6 is controlled Roundcube retirement readiness for a selected cohort. Work is
ordered so release claims cannot outrun evidence.

## Ordered Slices

1. Record the source, evidence, toolchain, and known-gap baseline.
2. Define V6 scope, acceptance criteria, roadmap, and security gates.
3. Add V5 carry-forward and V6 closeout gates.
4. Add a fail-closed production-readiness live validator.
5. Add a no-Roundcube-fallback retirement rehearsal recorder.
6. Turn observability and incident-response expectations into live evidence.
7. Close or strictly release-gate cross-process session-store mutation safety.
8. Preserve only explicit source-attachment references across draft resume.
9. Prove bounded resource behavior and recovery with live-safe methods.
10. Assemble sanitized closeout evidence, checksums, and operator handoff.

Each implementation slice has a trace under `docs/V6_TRACES/` and ends in a
reviewable commit. A later slice cannot turn an earlier failed or missing gate
into an implicit pass.

## Delivery Constraints

- Keep the code dependency-light and server rendered.
- Do not introduce a large framework, async runtime, telemetry stack,
  JavaScript-heavy UI, plugin system, or remote-content behavior.
- Keep live credentials and private evidence outside repository artifacts.
- Prefer operator-prompted or environment-provided secrets for authenticated
  validation.
- Keep Roundcube available as an explicit rollback unit until the selected
  cohort's retirement rehearsal passes; do not hide fallback inside OSMAP.

## Exit

The roadmap exits only through the V6 closeout gate. If live evidence is
missing, V6 remains an implemented but incomplete candidate.
