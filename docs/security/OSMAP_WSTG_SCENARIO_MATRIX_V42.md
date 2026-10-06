# OSMAP WSTG v4.2 Scenario Matrix

This document summarizes `maint/wstg-testing-pack/wstg-scenario-matrix.v42.json`.

The matrix is a due-diligence control, not a test result. A scenario is not complete until it has either executed evidence or a documented not-applicable proof.

## Current coverage summary

| Category | WSTG v4.2 scenario entries | Mapped by current OSMAP pack | Needs applicability or evidence decision |
| --- | ---: | ---: | ---: |
| INFO | 10 | 10 | 0 |
| CONF | 11 | 11 | 0 |
| IDNT | 5 | 5 | 0 |
| ATHN | 10 | 10 | 0 |
| ATHZ | 4 | 4 | 0 |
| SESS | 9 | 9 | 0 |
| INPV | 19 | 19 | 0 |
| ERRH | 2 | 2 | 0 |
| CRYP | 4 | 4 | 0 |
| BUSL | 9 | 9 | 0 |
| CLNT | 13 | 13 | 0 |
| APIT | 1 | 1 | 0 |

## Interpretation

- `mapped_in_current_pack` means the current OSMAP mapping references the WSTG ID.
- `not_mapped_in_current_pack` means the current OSMAP mapping does not reference the WSTG ID.
- `not_applicable_candidate_but_requires_repo_or_live_proof` means the scenario may not apply to OSMAP, but release due diligence still needs evidence.
- `candidate_gap_for_v3_wstg_due_diligence_backlog` means the scenario should become a manual or automated due-diligence item.

## Supplemental mapping note

The current OSMAP mapping includes these WSTG identifiers that were not present in the retrieved OWASP v4.2 stable table of contents used for this matrix:

- `WSTG-v42-CONF-12`

For those identifiers, keep the OSMAP test if it is valuable, but add a source note that explains whether it comes from latest WSTG content, an OWASP mirror, or an OSMAP-specific supplemental control.

## UX S02-01 search-helper development delta

The authenticated all-folder search operation is a new helper protocol boundary.
Its bounded component evidence supplements the existing mappings; it does not
mark a full WSTG scenario or credential-backed release run complete.

| Existing mapping | Concrete component check |
| --- | --- |
| WSTG-v42-ATHZ-02 / ATHZ-04 | Canonical account and ordered scope grants; foreign/mismatched identities refused; owned native paired accounts and exact mailbox GUID scope |
| WSTG-v42-INPV-12 | Typed search field and literal argument vector; no client-selected program or shell command; pattern-shaped names resolved to exact GUIDs |
| WSTG-v42-BUSL-03 / BUSL-05 | Operation/account/count/order/query/field-bound HMAC, in-process replay refusal, byte/row/result bounds, absolute transport deadline and worker release |
| WSTG-v42-ERRH-01 | Whole-result refusal for malformed/out-of-scope/late replies; finite gateway error codes exclude private queries and native diagnostics |

Executed attempts, source pins and matching deployment outcomes belong in
`docs/UX_EXECUTION_LEDGER.md` and the S02 sprint root. Helper replay remains
in-memory; restart/clock-rollback protection, human password/TOTP, SMTP delivery,
OpenPGP and broad hostile-email or strict-release assurance are not established
by these Search tests.

## Git commit comment

The S02 Manual/On Open repair adds two finite authenticated native POST routes:
`/settings/mark-read` saves the account-owned CAS preference; `/message/open`
verifies the current owned GUID pair and reuses the established Seen action.
Local integrated cases exercise missing/wrong CSRF, foreign/stale identity,
unavailable preference/view, ambiguous flag outcome and worker admission.
GET, reload and Back never change flags; Unread reader retention does not waive
the other original filters or search membership. Existing ATHZ, SESS, BUSL and
INPV scenario mappings cover these component checks. Native and browser results
are recorded in the UX ledger; they do not close full WSTG scenarios, human UAT,
SMTP/OpenPGP or the strict release gate.

The S02 conversation-order component carries optional bounded public thread
headers through the existing authenticated message codec. ATHZ account/GUID
checks remain in the actual routes and reader; INPV/BUSL checks cover strict
typed metadata, bounded references/results/frames, ambiguous duplicate and cycle
refusal, current filtered membership and explicit-sort precedence. Unknown native
headers retain usable independent rows, while malformed helper metadata is
refused. This adds no helper command, body fetch, authorization or sender trust.
Actual model, disposable native and no-script browser outcomes belong in the
ledger and do not establish full WSTG or human Send acceptance.

```text
add wstg due diligence matrix
```

The S02 configurable Bin component adds authenticated `/settings/bin-folder`
with exact CSRF, revision, folder and return-section fields. Current account
LIST and a unique private selectable native namespace are checked before CAS;
stale/corrupt/foreign/unselectable states refuse without a Trash fallback.
Existing ATHZ/SESS/BUSL/INPV mappings cover these bounded checks. Reversible
Bin/Restore still uses the established message GUID-bound move path, one worker
and current owned folder facts. The disposable OpenBSD proof moves exactly one
synthetic record to Deleted and back, preserving GUID/flags, neighbours and a
second account; it performs no append, expunge, SMTP or cryptography. Actual
results and signed deployment pins belong in the UX ledger. This does not close
whole WSTG scenarios, human UAT, strict release or permanent-deletion authority.

The saved reader-presentation repair adds no route or download permission.
Existing account/session authority selects current persisted source/attachment
display preferences; stale cookie hints do not override them. ATHZ/SESS checks
cover account isolation and response-scope reset, while BUSL/INPV component
regressions preserve corrupt state, finite presentation defaults, identical
escaped source text and decoded attachment bytes. Native disposable mixed-value
saves/readers restore fixture state; installed validation is GET-only. Current
executed proof and deployed binary pins belong in the ledger. These component
checks do not close entire WSTG scenarios, strict release, human UAT or Send.

Native Source/Download component execution now follows actual renderer GUID
links through Runtime gateway, signed helper and disposable Dovecot. ATHZ/SESS
controls include foreign same-UID, stale GUID and unauthenticated refusals;
INPV/BUSL controls retain selector rejection before native reads, escaped stored
source, exact decoded bytes, forced-download isolation and reusable budgets.
This extends executable bounded evidence, not routes, permission or whole WSTG
scenario/release acceptance. Actual source/binary/outcomes remain in the ledger.


## UX S04-02 private mutation and SMTP-control development delta

The disabled account-mutation components add command and private-descriptor
boundaries. Existing ATHZ/SESS mappings cover canonical account scope, current
kernel peer admission and channel-generation isolation; BUSL/INPV cover the
source-derived cutoff, account lock prerequisite, finite frame grammar, one-use
cancellation, original absolute budget and uncertainty latch. CRYP component
checks exercise actual native ARGON2ID full-tail positive/negative verification;
CONF component checks cover closed client configuration and disposable kernel
write restrictions. These are bounded component results recorded in the UX
ledger, not completed WSTG scenarios or release evidence. Local UID admission
does not prove unique supervised-worker ownership, installed module custody,
all authentication ingress, native factory activation or human password/Send
acceptance. The password form and native qualification gates remain disabled.

The next disabled control composition adds distinct-purpose password-free MAC
delegation and a durable consumed-grant journal to ATHZ/SESS/BUSL/CRYP component
coverage. Original receive-time budget and current source listener custody are
rechecked; complete grant publication precedes terminal acknowledgement. Late
acknowledgement failure remains unconfirmed after possible cutoff consumption.
Native key/issuer custody, worker/flock continuity, production ingress and TCP
absence remain unqualified. This does not close a WSTG scenario or password UAT.
