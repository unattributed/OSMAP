# V6 Release Operator Handoff

## Current State

V6 source Slices 00 through 09 are assembled on
`feature/v6-controlled-retirement-readiness`. V6 commit
`18d853643e2eca054cb7d2ad1d4d5b275f8af4f3` is now deployed on
`mail.blackbagsecurity.com`, and the production-readiness report has passed.
V6 closeout remains incomplete until the no-fallback rehearsal, observability,
and resource-resilience reports also pass.

## Before Deployment

1. Select the exact V6 candidate commit and record its full hash.
2. Run `cargo test`, clippy, the supply-chain gate, V4, V5, and
   `make security-check` on that commit.
3. Follow `MAIL_HOST_BINARY_DEPLOYMENT_SOP.md` and preserve both the current
   binary and `/etc/osmap/osmap-serve.env` as one rollback unit.
4. Confirm `osmap_serve` and `osmap_mailbox_helper` are healthy after restart.

## Host-Side Evidence Commands

From the deployed candidate checkout on `mail.blackbagsecurity.com`:

```sh
cd ~/OSMAP
sh maint/live/osmap-live-validate-v6-production-readiness.ksh
```

Perform the human selected-cohort walkthrough in
`V6_ROUNDCUBE_RETIREMENT_REHEARSAL.md`, then run the recorder with every
workflow variable explicitly classified:

```sh
cd ~/OSMAP
env \
  OSMAP_V6_WORKFLOW_PASSWORD_TOTP_LOGIN=passed \
  OSMAP_V6_WORKFLOW_MAILBOX_LISTING=passed \
  OSMAP_V6_WORKFLOW_MESSAGE_LISTING=passed \
  OSMAP_V6_WORKFLOW_MESSAGE_VIEW=passed \
  OSMAP_V6_WORKFLOW_SAFE_HTML_OR_PLAIN_TEXT=passed \
  OSMAP_V6_WORKFLOW_SEARCH_ONE_MAILBOX=passed \
  OSMAP_V6_WORKFLOW_SEARCH_ALL_VISIBLE_MAILBOXES=not_required_for_selected_cohort \
  OSMAP_V6_WORKFLOW_ATTACHMENT_DOWNLOAD=passed \
  OSMAP_V6_WORKFLOW_COMPOSE_SEND=passed \
  OSMAP_V6_WORKFLOW_REPLY=passed \
  OSMAP_V6_WORKFLOW_FORWARD=passed \
  OSMAP_V6_WORKFLOW_BOUNDED_ATTACHMENT_UPLOAD_SEND=passed \
  OSMAP_V6_WORKFLOW_EXPLICIT_SOURCE_ATTACHMENT_SELECTION_SEND=passed \
  OSMAP_V6_WORKFLOW_DRAFT_SAVE_RESUME=passed \
  OSMAP_V6_WORKFLOW_MOVE_OR_ARCHIVE=passed \
  OSMAP_V6_WORKFLOW_SESSION_LISTING=passed \
  OSMAP_V6_WORKFLOW_SESSION_REVOCATION=passed \
  OSMAP_V6_WORKFLOW_SETTINGS_UPDATE=passed \
  OSMAP_V6_WORKFLOW_LOGOUT=passed \
  OSMAP_V6_ROUNDCUBE_FALLBACK_USED=no \
  OSMAP_V6_NATIVE_CLIENTS_UNCHANGED=yes \
  OSMAP_V6_UNDERLYING_MAIL_STACK_UNCHANGED=yes \
  OSMAP_V6_REHEARSAL_SECRETS_REDACTED=passed \
  sh maint/live/osmap-live-record-v6-retirement-rehearsal.ksh
```

Replace any workflow that is genuinely outside the selected cohort with
`not_required_for_selected_cohort`; never mark an untested workflow passed.

Then run:

```sh
cd ~/OSMAP
env \
  OSMAP_V6_CAPACITY_EVIDENCE=negative_live_safe_not_triggered \
  OSMAP_V6_OBSERVABILITY_OPERATOR_REVIEW=passed \
  sh maint/live/osmap-live-validate-v6-observability.ksh

sh maint/live/osmap-live-validate-v6-resource-resilience.ksh
```

## Final Closeout Commands

After copying the four sanitized reports into the candidate checkout:

```sh
cd ~/OSMAP
sh maint/security/osmap-v4-hostile-assurance-gate.sh
sh maint/security/osmap-v5-boundary-gate.sh
sh maint/security/osmap-v6-retirement-readiness-gate.sh
sh maint/security/osmap-v6-evidence-archive.sh
make v6-check
```

Verify the archive checksum and inspect the member list before publication.

## Failure And Rollback

If any command fails, V6 remains incomplete. Preserve the reports as diagnostic
evidence, do not rewrite them into passing form, restore the binary plus
environment rollback unit if production behavior regressed, and keep Roundcube
available as the explicit operator-controlled fallback.
