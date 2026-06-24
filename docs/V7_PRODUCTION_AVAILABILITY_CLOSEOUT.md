# V7 production availability closeout

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:START -->

## Status

**Verdict:** `V7_PRODUCTION_AVAILABILITY_CAN_BE_CLOSED`

This document records the V9 Slice 5 evidence-backed closeout of the V7 production availability reopening.

## Evidence basis

- V9 Slice 5 evidence archive: `osmap-v9-slice-5-v7-production-closeout-20260624-131645Z.tar.gz`
- V9 Slice 5 archive SHA256: `2a2514ca62028bb1d444802b2f614014e7dae92e52864517caebdfadd39b7076`
- V9 Slice 3 hold-period archive SHA256: `18c3710a109d8d5152e11d2cebafacae4c8047be9587a5d5ef691d462bba6b0d`
- V9 Slice 4 hostile-content carry-forward archive SHA256: `0a67c1e254a7277003253d26fc5b3d5700072fe53c453a6dc890374ae53c2ac1`
- Current documented main head: `fcf360587daeda57f2de515ef8f85fc69d016f4e`
- Production runtime source head remains the PR #19 source point: `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- Production runtime binary SHA256 remains: `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

## What is proven

- V7 rendering regression gate passed against current `origin/main`.
- V7 rendering gate wrapper passed against current `origin/main`.
- V7 boundary hardening gate passed against current `origin/main`.
- V9 Slice 3 proved real browser login, mailbox listing, message view, sanitized HTML rendering, send submission, and Postfix/Brevo delivery during a production hold window.
- The production snapshot showed `osmap_mailbox_helper(ok)` and `osmap_serve(ok)` with no crash, panic, or restart markers in the bounded scan.
- V9 Slice 4 proved the V4 hostile-content containment gate still passes against current `origin/main`.

## Claim boundaries

- This closes the V7 production availability reopening only for the tested selected-user production path and the current rendering policy.
- This is not a general release-candidate decision.
- This does not claim complete Roundcube replacement.
- Production was not rebuilt for Slice 2 documentation-only changes, and no rebuild is required for that documentation merge.
- V6 selected-cohort/no-Roundcube retirement closeout and the final V9 release-candidate gate remain open.

## Release impact

This closeout improves the V9 release-readiness story, but it does not by itself make OSMAP a release candidate. V6 selected-cohort/no-Roundcube retirement closeout and the final V9 release-candidate gate remain open.

<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:END -->
