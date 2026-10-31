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
Build and native outcomes are not yet qualified by this specification.

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
