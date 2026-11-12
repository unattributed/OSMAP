# S05-01 — Existing Rust crypto-helper transport

Started 2026-10-31 (America/Toronto) from accepted S04-04
`35719f01b36b67d11a567c8cebed09a209773102` at the operator's direction.

## Observable outcome and simplest route

An authenticated application operation reaches the existing Rust crypto client,
authenticated Unix socket, account-mapped Rust helper and fixed GPGME worker.
The client returns only a validated result bound to the original request.
Unauthorized, malformed, expired, replayed or excessive work is refused within
the existing bounds. Reuse this route; no new service, protocol, cryptographic
primitive, dependency or general test framework is required.

The existing GPGME C worker and its GnuPG engine shim remain isolated behind the
Rust boundary. This slice does not replace them or claim an all-Rust crypto
engine. Key-management presentation and encryption-off-by-default UX belong to
S05-02; existing selections and policies are preserved. S04-04 remains accepted.

## Design

- Journey: existing Runtime operation -> typed Rust request -> Unix helper ->
  authorized worker -> authenticated result -> normal application consumer.
- Frontend: reuse the current application gateway; no new page or browser script.
- Backend: `openpgp_crypto{,_protocol,_runtime,_process}.rs`, existing GPGME worker
  and native Rust integration tests. Account and key-home authority comes from
  operator mapping and the validated session, never caller-selected paths.
- Interfaces: current versioned metadata and length-delimited binary payload,
  HMAC, account/operation/nonce binding, expiry and shared replay verifier.
- Persistence: no new store or migration; operation content remains transient.
- Security: preserve peer UID checks, exact fingerprint authorization, strict
  error metadata and existing 16 MiB content/64 KiB header/50 recipient bounds,
  ten-second crypto deadlines, one worker per account and two globally.
- Failure/recovery: preserve the earliest failure separately from cleanup;
  bounded typed errors, no handler fallback or automatic ambiguous-operation
  retry, disposable native fixtures only, no real credentials, external email or
  public-MTA submission; T05 uses a synthetic loopback SMTP sink.

## T01–T09 contract

| Test | Expected result and evidence level |
| --- | --- |
| T01 existing contract | Reconcile source and historical audit findings; distinguish current executable evidence from unavailable historical raw logs. Source. |
| T02 build | Locked Rust builds and relevant format/lint checks; current native executable identified. Source/native. |
| T03 wire | Exact binary-content/signature round trips for all four operation types; malformed/unknown results, frame limits and error content refuse. Source/native. |
| T04 authority | Wrong accounts/fingerprints, MAC/peer, expiry and replay refuse before execution. Reuse separate-principal evidence explicitly; do not claim a fresh peer test unless run. Source/native. |
| T05 Runtime | Existing production gateway -> actual Rust service/client -> worker -> independently checked output using disposable fixture. Native isolated application composition. |
| T06 bounds | Existing deadline, duplex, output limit, concurrency and descendant tests; no invented performance target. Source/native. |
| T07 failures | Unavailable/locked/missing-key/malformed results cannot become success or expose error content; cleanup disposition explicit. Source/native. |
| T08 native | Fresh obsd1 disposable-key authenticated round trip and gateway test; preserve running OSMAP/mail roles and owner state, no public service mutation. Native. |
| T09 delivery | Independent review, normal gates, Shopkeeper signature and ordinary GitHub synchronization, then owner acceptance of this infrastructure scope. Delivery/human acceptance separate. |

## Current work and evidence

Existing protocol/runtime/worker implementations and tests are present. A source
review identified request issuance cloning operation content before validating
the caller's operation. A focused regression checks invalid local decryption
selections before issuance; server-owned decryption authority remains unchanged.
At that initial source checkpoint, build/native outcomes were pending. Actual
qualification is recorded below.

Native verification uses fresh private `/tmp/osmap-crypto-fixture-*` homes,
disposable Ed25519/CV25519 keys, the existing Rust libtest and fixed C workers.
It does not restart or reconfigure live services, use owner private keys, send
external email, change account policy or deploy candidate binaries. The same-UID
fixture does not repeat the historical separate-principal qualification.
The fixed fixture has a 240-second outer deadline and at most 15 seconds for
termination/reaping after timeout. Success checks exact disposable agent-socket
disappearance before removing owned scratch; failure retains it for diagnosis.

Private sanitized logs belong under
`/home/foo/Downloads/osmap-ux-s05/s05-01-20261031/`; raw fixture material never
enters Git. Failed attempts remain history. Two failures at the same boundary
require causal reassessment, not another unchanged workflow retry.

Engineering closes against the required current source/native observations and
independent review. Owner acceptance remains separate; no new browser workflow
or manual crypto ceremony is invented for this infrastructure slice. Production
release and the final integrated Daybreak Blue review remain separate.

## Actual implementation and qualification — 2026-10-31

The existing Rust/helper/GPGME route was retained. The product correction is five
Rust lines validating `Operation` before cloning content into a request, preserving
`Limit` versus `Invalid` errors. Invalid empty/malformed local decryption
selections previously reached issuance; the new regression reproduced that RED
and then passed after correction. Helper-side decryption authority remains
operator-owned. Four new tests cover that refusal, limit compatibility, binary
round trips for all operations and authenticated invalid error responses.

The source work is signed at `8577e12a2be6fa98db0eb115b70935960974483d`.
The simplified native runner is signed at
`cebd67291f800bb9304a189a12995a75d980ca0c`. All Rust/C/Cargo build inputs are
identical between these revisions. The native test executable SHA256 is
`0646aad797bbb727094d1050d22bc74aac629c372652bc0cd8c92595acd4fc3b`.

| Test | Actual observations |
| --- | --- |
| T01 | Current Rust protocol, dispatcher, gateway, GPGME worker and earlier security findings reconciled. October 1 source-review records retained; original local raw-log directory unavailable. No engine replacement required. |
| T02 | Locked local bin check, formatting and strict all-target Clippy PASS. Native libtest, Web and crypto-helper build PASS, 164.677 seconds with the demonstrated S04 compiler profile. |
| T03 | Current crypto group 19 PASS locally and natively. New exact binary-content/signature and authenticated unknown-error/error-content cases PASS; invalid local decrypt selection RED/GREEN preserved. |
| T04 | Current account/fingerprint, MAC, expiry/replay and request-bound error tests PASS. Existing October 1 separate-principal evidence is explicitly reused; the fresh fixture uses one disposable OS principal. |
| T05 | Existing native production gateway test explicitly executed: actual `Service::serve` children, Rust gateway, crypto worker, ephemeral loopback SMTP sink and controlled Sent save PASS. Submitted protected bytes independently checked by its existing assertions. No public SMTP/Dovecot/provider delivery claimed. |
| T06 | Current native duplex/deadline/output/descendant, concurrency and shared-profile controls PASS. Non-strict worker cleanup was retained; no new universal process-group absence claim. |
| T07 | Current unavailable/locked/malformed and error-content refusal controls PASS. Fixture cleanup checks agent-socket disappearance; readback independently confirms scratch absent. |
| T08 | Existing authenticated native Rust service/client test explicitly executed: actual signing, verification, encryption/decryption and protected-reader checks PASS. Native focused and functional execution took 16.396 seconds. Eight checked live services remain healthy and public HTTPS login returns 200. |
| T09 | Technical review and normal signed delivery precede separate owner acceptance. No new key-management UI, full S05/S06/S07 acceptance or production release inferred. |

The normal `make acceptance-check` completed successfully: 2,080 Rust library
tests passed, zero failed and 74 special/native tests were explicitly ignored
in that local run. Its V10/V12/V13 and security gates passed. The two named native
tests above were separately selected and executed on obsd1; they are not counted
as passes merely because they appear in the ignored local set.

## Preserved failures and smallest corrections

1. The new invalid-local-decryption-selection regression failed against the old
   implementation. Validation before allocation corrected the demonstrated
   boundary; no transport replacement or new dependency was introduced.
2. The actual S05-01 catalogue maps no page-control rows. The existing work-order
   validator incorrectly required nonempty row IDs even for that infrastructure
   slice. It now permits empty IDs only when the actual mapping is empty, while
   retaining mandatory functional outcomes, tests, stages and all mapped
   obligations. Its 56 regressions pass. The initial normal acceptance run then
   refused the stale coupled validator source pin before Cargo; the exact pin
   was refreshed and its affected tests passed. The failed aggregate is retained.
3. Native build01 stopped with a Rust compiler allocation refusal/SIGABRT under
   the inherited 1.5 GiB data soft limit. No native functional test ran. Build02
   reused the successful S04 profile: compiler-only 4 GiB soft data limit within
   its existing hard limit, one Cargo job and private build temporary space on
   `/home`. Stack and system/service policy were unchanged. The original log
   remains retained; successful build02 does not relabel build01.

Private actual-result SHA256:
`99c1362bdd887a54ef42aa91bcc3dcafcd3ac29cb895ef035aea513c14b4e037`.
Native functional log SHA256:
`c3fa0d54a597e1b3e395b0a5467d10f235e8631476758c1aa1b3eb90b3f11b48`.
Build02 receipt SHA256:
`cfd97d8c018c72c2210d5052beac9ada828a41b994fdab0d94cf6c904e432a39`.

## Installation and acceptance boundary

No live executable or environment was replaced. Before/after Web, crypto-helper,
worker and engine hashes are unchanged. The fresh isolated candidate establishes
the S05-01 transport/application composition; public installed UX integration
continues with S05-02. No owner key, password, factor, binding or policy was
modified. Disposable private material was removed after exact-home agent stop
and socket readback; compiler/public-source artifacts remain private evidence.

Owner acceptance consists of accepting this reviewed infrastructure result.
The practical email/key/policy list, encryption-off-by-default presentation and
its browser acceptance remain S05-02 requirements, not additional manual tests
invented for this slice.
