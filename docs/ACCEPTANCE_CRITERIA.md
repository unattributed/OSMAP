# Acceptance Criteria

## Phase 0 Acceptance Criteria

Phase 0 is acceptable when all of the following are true:

- The project purpose is explicitly documented
- Version 1 scope and non-goals are written down
- Environmental constraints and security principles are recorded
- A documented execution strategy exists for later phases
- Key risks and unknowns are identified rather than deferred implicitly
- The operator can approve progression to current-system analysis

## Phase 1 Acceptance Criteria

Phase 1 is acceptable when all of the following are true:

- The existing host layout and major services are documented from evidence
- The current mail stack components and their responsibilities are mapped
- Network exposure and access boundaries are documented
- Roundcube's current role, dependencies, and integration points are captured
- Trust boundaries and migration-sensitive dependencies are identified
- The analysis is detailed enough to support Product Definition and Security
  Model work without guessing

## Current Status On March 27, 2026

Phase 0:

- Charter, constraints, success criteria, and planning baseline are documented
- A formal Phase 0 exit baseline now exists in public-safe form

Phase 1:

- Read-only inspection has confirmed the current host, active services,
  listening sockets, network policy shape, nginx control-plane model, Dovecot
  bindings, and Roundcube integration points
- The resulting current-state documents in `docs/` should now be treated as the
  baseline for Phase 1 review and refinement
