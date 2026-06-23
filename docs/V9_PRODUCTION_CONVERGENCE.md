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
