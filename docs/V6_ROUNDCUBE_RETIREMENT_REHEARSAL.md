# V6 Roundcube Retirement Rehearsal

## Purpose

This is the operator procedure for proving that a selected cohort can perform
its required browser-mail work in OSMAP without normal Roundcube fallback.
It does not claim broad feature parity or require immediate deletion of the
operator rollback unit.

## Cohort Selection

Use sanitized labels such as `cohort_user_1`. Select only users whose required
workflows fit `PILOT_WORKFLOW_INVENTORY.md`. A user who requires an unresolved
Roundcube-only or out-of-scope workflow is not part of the retirement-ready
cohort.

## Rehearsal

For each selected user, exercise and record the disposition of:

- password plus TOTP login
- mailbox and message listing
- message view and safe HTML or plain-text behavior
- one-mailbox and, when required, all-visible-mailbox search
- attachment download
- compose, send, reply, and forward
- bounded uploaded-attachment send
- explicit source-attachment selection send, when required
- draft save and resume, when required
- move or archive, when required
- session listing and revocation
- settings update, when required
- logout

Every workflow must be marked `passed`, `not_required_for_selected_cohort`, or
`failed`. Any required failure or normal Roundcube fallback fails the
rehearsal.

## Recording

After the human walkthrough, set the corresponding `OSMAP_V6_WORKFLOW_*`
environment confirmations and run:

```sh
ksh ./maint/live/osmap-live-record-v6-retirement-rehearsal.ksh \
  --cohort-labels cohort_user_1,cohort_user_2
```

The recorder writes only sanitized dispositions to
`maint/live/latest-host-v6-retirement-rehearsal-report.txt`. It requires
explicit confirmation that Roundcube fallback was not used, native clients and
the underlying mail stack were unchanged, and secrets were redacted.
