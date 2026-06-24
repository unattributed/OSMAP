# V9 Production Convergence and Operational Closure

## Purpose

V9 exists to remove drift between source, production, evidence, and
documentation after V6, V7, V8, and the PR #19 forward/send production fix.

V9 is not a new-feature sprint and does not pursue Roundcube feature parity.
Its purpose is to decide whether the current OSMAP state can make a defensible
release-candidate claim.

## Assessed convergence point

| Item | Value |
|---|---|
| Assessed commit | `49c9f230d7865f01deadbc6a5a0f6e876c63e89b` |
| Short commit | `49c9f23` |
| Commit title | `bound forwarded compose body size` |
| Production source path | `/home/foo/OSMAP` |
| Production binary | `/usr/local/bin/osmap` |
| Live binary SHA256 | `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3` |
| Prior live binary SHA256 | `500cdd839be9c70297d33cbce6661815ebfb4740ba8b607f63a6cdf98ac7dca7` |
| Production deploy evidence archive | `osmap-forward-body-binary-deploy-20260622-133538Z.tar.gz` |
| Production deploy evidence SHA256 | `21a2d3b97808fe6bc971974ef46a42d27216f31f04cefe7cf4894c1f667a7800` |
| V9 Slice 1 intake evidence archive | `osmap-v9-slice-1-intake-20260622-142413Z.tar.gz` |
| V9 Slice 1 intake evidence SHA256 | `5de376e832ae79f8c29afd1e3b0243f8ac09a04d4bb0c71a7a771fd65403e331` |

## PR #19 production fix

PR #19 addressed a production-observed forward/send regression where forwarding
an HTML-heavy message produced a compose body above the previous 64 KiB send
validator cap.

The observed failure before the fix was:

```text
category=http action=compose_request_rejected
reason="body exceeded maximum length of 65536 bytes"
method="POST" path="/send" status_code="400"
```

After the PR #19 deployment, the post-deployment retest recorded:

```text
category=submission action=message_submitted
method="POST" path="/send" status_code="303"
```

Postfix/Brevo delivery evidence recorded queue `DDEA73CE8C4` with size `82299`,
`status=sent`, and queue removal. The Postfix line-folding entry
`breaking line > 998 bytes with <CR><LF>SPACE` is treated as transport line
folding, not a delivery failure, because the same queue entry completed with
`status=sent` and was removed.

## Slice 1 intake result

Slice 1 was read-only. It did not deploy, rebuild, restart services, edit files,
authenticate, or send mail.

The uploaded Slice 1 evidence proves:

- local `/home/foo/Workspace/OSMAP` was clean on `main` at `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`;
- `origin/main` resolved to `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`;
- production `/home/foo/OSMAP` was clean on `main` at `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`;
- production `origin/main` resolved to `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`;
- live `/usr/local/bin/osmap` had SHA256 `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`;
- `osmap_mailbox_helper` and `osmap_serve` reported `ok` through `rcctl check`;
- the PR #19 deployment archive existed on the host with SHA256
  `21a2d3b97808fe6bc971974ef46a42d27216f31f04cefe7cf4894c1f667a7800`;
- bounded OSMAP logs recorded real browser session validation, mailbox listing,
  message listing, sanitized HTML rendering, and successful send flow after the
  deployment;
- the bounded crash/restart scan did not show panic, segmentation fault, core
  dump, fatal, crash, restart, killed, out-of-memory, or OOM entries in the
  captured window.

## What V9 does not prove yet

V9 Slice 1 does not prove release readiness.

The remaining V9 proof items are:

1. repo documentation reconciliation;
2. production hold-period proof against the deployed binary;
3. V4 hostile-content carry-forward refresh on current `main`;
4. V7 production availability closeout using real-login, mailbox, and send
   evidence;
5. V6 selected-cohort/no-Roundcube closeout decision;
6. final release-candidate gate and rollback record.

## Bounded release language

Acceptable current claim:

```text
OSMAP source, production checkout, and live OpenBSD binary identity are
reconciled at commit 49c9f230d7865f01deadbc6a5a0f6e876c63e89b, and the PR #19 forward/send production fix has
post-deployment send and delivery evidence.
```

Unacceptable current claim:

```text
OSMAP is release ready.
```

Release-candidate status remains undecided until the final V9 gate records a
PASS, CONDITIONAL PASS, or FAIL decision.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:START -->

## Slice 5, V7 production availability closeout

V9 Slice 5 closes the V7 production availability reopening based on current evidence.

**Verdict:** `V7_PRODUCTION_AVAILABILITY_CAN_BE_CLOSED`

Evidence basis:

- V9 Slice 5 evidence archive: `osmap-v9-slice-5-v7-production-closeout-20260624-131645Z.tar.gz`
- V9 Slice 5 archive SHA256: `2a2514ca62028bb1d444802b2f614014e7dae92e52864517caebdfadd39b7076`
- V9 Slice 3 hold-period archive SHA256: `18c3710a109d8d5152e11d2cebafacae4c8047be9587a5d5ef691d462bba6b0d`
- V9 Slice 4 hostile-content carry-forward archive SHA256: `0a67c1e254a7277003253d26fc5b3d5700072fe53c453a6dc890374ae53c2ac1`
- Current documented main head: `fcf360587daeda57f2de515ef8f85fc69d016f4e`
- Production runtime source head remains the PR #19 source point: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- Production runtime binary SHA256 remains: `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

What is proven:

- V7 rendering regression gate passed against current `origin/main`.
- V7 rendering gate wrapper passed against current `origin/main`.
- V7 boundary hardening gate passed against current `origin/main`.
- V9 Slice 3 proved real browser login, mailbox listing, message view, sanitized HTML rendering, send submission, and Postfix/Brevo delivery during a production hold window.
- The production snapshot showed `osmap_mailbox_helper(ok)` and `osmap_serve(ok)` with no crash, panic, or restart markers in the bounded scan.
- V9 Slice 4 proved the V4 hostile-content containment gate still passes against current `origin/main`.

Limits of the claim:

- This closes the V7 production availability reopening only for the tested selected-user production path and the current rendering policy.
- This is not a general release-candidate decision.
- This does not claim complete Roundcube replacement.
- Production was not rebuilt for Slice 2 documentation-only changes, and no rebuild is required for that documentation merge.
- V6 selected-cohort/no-Roundcube retirement closeout and the final V9 release-candidate gate remain open.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:END -->

<!-- OSMAP:V9_RELEASE_CANDIDATE_DECISION:START -->

## V9 release candidate decision

Status: PASS.

Current main `a8915c0993b96a9d53de083dc84cb7520aef0097` is accepted as the V9 selected-cohort release candidate. Production runtime code remains `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`, production binary SHA256 remains `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`, and drift from production runtime source to current main is documentation-only.

The controlling closeout record is `docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md`.

This is not a claim of complete Roundcube feature parity, general hostile email safety, or unbounded release readiness.

<!-- OSMAP:V9_RELEASE_CANDIDATE_DECISION:END -->
