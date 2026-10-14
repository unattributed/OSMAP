# OSMAP functional baseline work order

Current authority, 2026-10-14: the operator explicitly resumed the OSMAP epic,
sprints and slices. Restore the failed development services and finish this
ordinary-mail baseline as the immediate dependency. Earlier pause statements
below describe the initial baseline mandate; they do not override this resumption.

The operator's instruction, “codify this all together then complete the
baseline for me”, authorizes this bounded work order. The wider UX epic remains
paused. This document consolidates the agreed preservation, reference,
inventory, verification, repair and closure requirements; it does not amend
the frozen revision-2 plan or remove any original sprint or slice requirement.

## Success and deliverables

1. Preserve all current Git references and unfinished work. Verify signatures,
   integrity and an isolated restoration from the preserved bundle. Preserve
   deployed application/configuration copies privately on their respective
   hosts, and rehearse restoration into isolated copies without replacing
   standard services or exporting configuration secrets.
2. Pin the earlier working application's documentary provenance, current
   source and both deployed binary hashes. Distinguish an actual retained
   binary from a historical report. Missing historical artifacts remain
   unknown and cannot be called qualified rollback images.
3. Inventory all 403 approved controls, their owning original slices, source
   and backend candidates, prerequisites and actual evidence. Distinguish
   ordinary core mail to preserve from later UX/OpenPGP/account work. A
   candidate source location is not an implementation or acceptance claim.
4. Supply repeatable core tests with prerequisites, precise browser steps,
   backend witnesses, expected positive and negative results, assessed
   source/image, evidence and cleanup. Use real installed application paths
   and two disposable authoritative-domain identities with genuine
   password/TOTP authentication. Keep disposable secrets outside Git and
   retained evidence.
5. Reconcile each result as PASS, FAIL, NOT RUN or INDETERMINATE. Preserve
   failed attempts, isolate the earliest measured boundary, repair only
   demonstrated ordinary core-mail defects, and retest the matching installed
   version. Existing component tests, HTML and service health cannot replace
   an installed user journey.
6. Independently review preservation, outcomes, required repairs and limits.
   BASELINE VERIFIED requires every core case below to satisfy its defined
   outcomes on matching signed source and deployed images. HUMAN ACCEPTED
   additionally requires recorded stakeholder UAT. Baseline verification does
   not close an original catalogue slice, sprint or the epic by implication.

## Controlled execution

The web target is obsd1.blackbagsecurity.com (192.168.1.44); the authoritative
mailbox backend is mail.blackbagsecurity.com (216.128.179.75). Verify host
identity before each host operation. Actual Send tests use uniquely marked
public synthetic messages between two fresh controlled accounts on the
authoritative domain, through the installed application's configured SMTP
backend. Independently verify recipient Inbox bytes and authoritative Sent
MIME. A synthetic sink, redirect or Sent row alone does not qualify delivery.

The operator controls external provider Sends. This work does not send to
Proton, repeat an ambiguous Send, alter Duncan's password, OpenPGP keys or
policy, inspect private correspondence, change quota or expand parked account,
quota or SDK implementation. Existing Required protection policies must
refuse unsafe ordinary Send; they are not downgraded for a passing test.
Controlled accounts, factors and mail are created and cleaned only through
exact fresh leases; uncertainty retains owned state for reconciliation.

## Core acceptance cases

- CORE-01: genuine installed password/TOTP login, authoritative account
  binding, Inbox navigation, logout and missing/expired/foreign-session
  refusal without another account's rows.
- CORE-02: Inbox/list/reader/headers/body/back using exact message identity,
  read state and bounded source/download; stale or foreign identity and
  unsafe content cannot expose another account or execute remote content.
- CORE-03: installed search/filter/sort/selection/originating-row return over
  controlled messages, including empty/multiple/stale results and bounded
  pagination/account isolation.
- CORE-04: create/save/reopen/edit/discard Draft; owner isolation, conflict,
  interrupted-save reconciliation and preservation without duplicate writes.
- CORE-05: one ordinary Compose submission through the installed configured
  SMTP path, accepted outcome, exact authoritative recipient Inbox and Sent;
  required protection refuses unsafe submission, uncertain Send is not retried.
- CORE-06: Reply, Reply-all and Forward with correct recipients, excluded
  self, threading and quoted context; actual recipient and Sent verification,
  injection/duplicate/foreign-recipient/stale-source refusal.
- CORE-07: bounded attachment upload/remove/Send/download with exact recipient
  and Sent MIME bytes; oversized/path/foreign-account/interrupted upload
  refusal without orphan or inline execution.
- CORE-08: read/unread/star/flag/Archive/Bin/restore using exact controlled
  identity and location, stale/replay/foreign identity and partial-bulk
  preservation. Permanent deletion requires actual retention authority and
  explicit confirmation; fixture cleanup is separately scoped.
- CORE-09: reload/restart around controlled draft/read/action, retained state,
  current session and service health; unavailable backend/uncertain mutation
  cannot silently duplicate Send, erase Draft or weaken account policy.

Every positive and negative retains its exact scope. Disposable fault fixtures
do not establish that standard services were subjected to that fault. The
initial FB-01–10 browser design covers overlapping cases, but is insufficient
until search/origin and restart/uncertainty obligations are also reconciled.

## Roles, limits and delivery

Root owns project management, integration, Git and host execution. Assigned
developers implement only concrete gaps; independent QA reproduces actual
workflows; the dedicated Scrum/security reviewer reconciles acceptance and
scope; technical writing maintains the existing ledger and decision log.
Agents work on isolated candidates, not simultaneous canonical or host writes.

The initial discovery/reproduction budget is two engineering hours, not a
completion estimate. After two failures at one boundary, reassess its source
contract and measured evidence before another attempt. Do not widen deadlines
or substitute variants without explaining the cause and changed hypothesis.

Minimal repairs require a focused regression, independent review, existing
applicable gates, a Shopkeeper-signed verified commit and prompt synchronization
under standing operator authorization. Deployment uses the exact reviewed
image, helper first where required, preserved configuration and bounded
rollback. No hook, assertion, authentication or isolation waiver is authorized.

## Initial assessed state

At work-order commencement, canonical source is
ee360329d2051a0ea93b36411dab523a54fd37bb on
feat/ux-completion-20260929. Both deployed applications have SHA-256
6394c41ae7a373faf155044dbf36dbaeaea5ad4331a3f94f4d2d98cafac1cbc2.
The accepted signed plan anchor is
6b3ce8fff27ca3dabf87039d54098bd9967a2e42; its manifest verifies unchanged.
These identities do not establish functional baseline completion.

The strongest located pre-V14 affirmative delivery record is V9 source
49c9f230d7865f01deadbc6a5a0f6e876c63e89b and binary
411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3
in V9_PRODUCTION_CONVERGENCE.md. V13's later recorded source
7009b15322c4e7795c797c1387b403e0f4935adb and binary
333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963
have narrower recorded authentication/security evidence, without a located
fresh Send/recipient result for that exact image. Historical archive bytes
have not been recovered in this baseline action; neither is assumed an
available qualified rollback. The current application's own preserved image
is the immediate recovery artifact.

Retained evidence root:
/home/foo/Downloads/osmap-ux-s00/functional-baseline-20261006/.
Current outcomes and superseding versions belong in UX_EXECUTION_LEDGER.md,
DECISION_LOG.md and the evidence results, not the frozen plan.
