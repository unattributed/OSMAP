## Summary

Describe the change in one or two short paragraphs.

## Why This Change

- What problem does this solve?
- Why is this the smallest coherent fix or improvement?

## Validation

- [ ] `make check`
- [ ] `make test`
- [ ] `make lint`
- [ ] `make fmt-check`

If any check was not run, explain why.

## Security and Operations Review

- [ ] This change preserves OSMAP's bounded scope.
- [ ] This change does not widen browser trust casually.
- [ ] This change does not add unnecessary dependencies.
- [ ] This change keeps authoritative mail services outside OSMAP where appropriate.
- [ ] I considered OpenBSD deployment, confinement, and maintenance impact.

## Documentation

- [ ] I updated documentation if behavior, scope, or status changed.
- [ ] I updated `docs/DECISION_LOG.md` for meaningful security, architecture, or governance decisions.

## Notes for Reviewers

Call out any areas where reviewers should pay particular attention, especially:

- auth and session behavior
- HTTP parsing or rendering behavior
- attachment or MIME handling
- helper execution and filesystem boundaries
- OpenBSD `pledge(2)` and `unveil(2)` impact
