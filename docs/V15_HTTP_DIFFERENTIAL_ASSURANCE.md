# V15 HTTP Edge/Origin Differential Assurance

## Purpose

OSMAP accepts browser traffic through nginx and then parses the forwarded
HTTP/1.1 request itself. The security boundary is therefore the combined
interpretation of the edge and origin, not either parser in isolation.

The V15 differential harness preserves the exact request bytes and records:

- source-parser acceptance or rejection through a Rust parser oracle
- raw edge response status, headers, connection closure, and response count
- raw direct-origin response over the OpenBSD loopback listener
- nginx and OSMAP log lines containing the per-case run token
- the required strict origin policy and edge policy for every corpus case
- token-correlated edge interpretation and origin forwarding count
- the application response separately from parser and forwarding decisions

## Repository Components

- `examples/osmap-http-parser-oracle.rs`
- `maint/security/osmap-v15-http-differential.py`
- `maint/security/test-osmap-v15-http-differential.py`
- `maint/security/v15-http-differential-corpus.json`

These components add no runtime dependency and do not alter the server-rendered,
JavaScript-free browser surface.

## Two-Stage Use

### Offline inventory

The offline mode runs all 37 byte cases through the source parser oracle. It
records required-policy findings without failing the harness process when
`--enforcement inventory` is selected.

This mode is used when admitting or reviewing the harness itself. A finding
is evidence that parser remediation is required, not evidence that the
harness malfunctioned.

### Live required-policy campaign

The live mode sends the same rendered bytes to:

1. `mail.blackbagsecurity.com:443` using validated TLS and SNI
2. the active OSMAP loopback listener at `127.0.0.1:8080` through the
   authorised SSH connection to `mail`
3. the local source parser oracle

The live campaign also captures matching nginx and OSMAP log evidence using
a unique non-secret query token. It does not use credentials, session
cookies, CSRF tokens, or state-changing payloads.

Live execution must use `--enforcement required-policy`. Any required-policy
disagreement returns non-zero and blocks acceptance until reviewed.

## Corpus Classes

The corpus covers:

- canonical controls
- request-line whitespace
- CRLF, bare-LF, and mixed line termination
- obsolete folding and invalid field names
- Host authority requirements
- duplicate, conflicting, comma-list, and malformed Content-Length
- Transfer-Encoding and CL/TE combinations
- truncated, excess, and pipelined bytes
- GET/POST body rules
- request-target normalization
- request-line, field, and header-block limits

Every case now has an enforceable policy. `REJECT_BEFORE_ORIGIN` requires zero
origin requests and a rejecting edge outcome. `REJECT_OR_FORWARD_ONCE` permits
the edge either to reject directly or to forward one unchanged semantic shape
to the strict origin for rejection. `FORWARD_EXACTLY_ONE` requires one response
and one origin request with the same method, complete target, and authority.
`CANONICALIZE_EXACTLY_ONE` permits only syntax canonicalization or discarding
unused bytes or fields while preserving that same semantic shape.

The six former observation-only cases are closed as follows:

| Case | Origin | Edge |
|---|---|---|
| `valid_post_content_length_zero` | accept | forward exactly one; record the route status separately |
| `underscore_field_name` | reject under OSMAP's narrow field-name allowlist | discard the unused field and canonicalize exactly one equivalent request |
| `dot_in_field_name` | reject under OSMAP's narrow field-name allowlist | discard the unused field and canonicalize exactly one equivalent request |
| `comma_content_length_same` | reject strict framing | reject before origin |
| `malformed_content_length_plus` | reject non-digit Content-Length | reject before origin |
| `oversized_header_field` | reject above the 8 KiB value limit | reject before origin |

The three previously accepted request-syntax normalizations use
`CANONICALIZE_EXACTLY_ONE`. The pipelining case uses
`FORWARD_EXACTLY_ONE`: nginx must close the client connection after the first
response, preventing queued bytes from becoming another origin request.
Unambiguous chunked framing and non-message trailing bytes may likewise be
canonicalized only into one equivalent origin request; every other hostile
case must be rejected at the edge or by one strict origin request.

## Evidence Handling

Reports contain base64-encoded raw request bytes and bounded response bodies.
They contain no credentials or session material. The live bundle must keep
the host log capture and JSON result together with the SHA-256 evidence
manifest.

Normal public access logs continue to omit query strings. A separate
conditional log records the complete target and upstream outcome only when the
request contains a bounded `OSMAPS04-*` differential token. This makes live
forwarding cardinality deterministic without exposing normal browser queries.

## Acceptance Boundary

Acceptance requires the complete offline and live campaigns to report:

```text
case_count=37
required_policy_failures=0
measured_unique_cases=0
origin_request_cardinality_violations=0
```

Parser conformance is accepted only after the live campaign runs the complete
corpus with required-policy enforcement. The isolated nginx regression test
also proves that a pipelined second request is not forwarded while a new client
connection remains usable.

<!-- slice-03e-closeout:start -->
# OSMAP V15 request-line parser assurance closeout

## Controlling decision

OSMAP V15 Slice 03D is complete. Slice 03E records the accepted implementation, fresh read-only production verification, local governance evidence, and protected-integration state. This closeout does not redeploy the accepted binary and does not modify nginx, the mailbox helper, PF, or OpenBSD policy.

## Accepted source and production identity

| Item | Accepted value |
|---|---|
| Parser-remediation commit | `315534ff915f4ae3e5ba8a5778060891ccefec07` |
| Commit signature fingerprint | `F55E404E91A0753701F91B01A7228D3FB5084B34` |
| Previous production binary SHA-256 | `c9edd0ff7b80e15ef6c0a953e296480a0b40935a510ad69776790a8337cd1787` |
| Deployed production binary SHA-256 | `4dc1005f1e3f11ecf463fa4724a432622b7952bd378831f4c135ef3544f0f5bf` |
| Installed path | `/usr/local/bin/osmap` |
| Ownership and mode | `root:wheel:755` |
| Rollback | Not required |

## Authoritative evidence index

| Stage | Archive | SHA-256 | Internal verification |
|---|---|---|---|
| Slice 03C parser remediation and V10 reconciliation | `osmap-v15-slice-03c-v10-full-chain-reconciliation-resume-evidence-20260729T194823Z.tar.gz` | `ee488721a77ca8b38ba2459628d245ecf6ee959aa7bd1fbf61616a43de9156eb` | 33 internal entries verified |
| Slice 03D.2 corrected edge-policy reconciliation | `osmap-v15-slice-03d2-log-field-parser-correction-resume-20260730T010854Z-evidence-20260730T055959Z.tar.gz` | `e3528f42419f6bf7876e590ebbe3191214ef1e280183ef21c1998a10580fd080` | 20 internal entries verified |
| Slice 03D.3 authoritative production deployment | `osmap-v15-slice-03d3-final-bounded-redeployment-evidence-20260730T061621Z.tar.gz` | `69df4a801842bcffdb991808f03b3b223d6cbd83957e73e073474fea717776e0` | 128 internal entries verified |
| Slice 03E nginx hash-contract provenance | `osmap-v15-slice-03e-nginx-state-provenance-diagnostic-evidence-20260730T102808Z.tar.gz` | `86f311f83ddace1bad6536176e2ef74ecf3daeeed8ff01df6a822d0b8eac622c` | 40 internal entries verified |

The evidence archives remain outside Git. This repository records their filenames, cryptographic digests, acceptance conclusions, and workstation retrieval location under `/home/foo/Downloads`.

## Slice acceptance chain

* **Slice 03C**, the request-line parser remediation and complete V10 raw, refined, and claims-register reconciliation passed. The signed source rejects ambiguous request-line separators and mixed line termination at the direct origin.
* **Slice 03D.2**, the edge-policy reconciliation corrected the earlier assumption that every malformed client byte sequence must remain malformed after nginx. The accepted policy requires either rejection before origin or one safe, semantically equivalent canonical request at origin.
* **Slice 03D.3**, the exact signed source was built natively on OpenBSD, deployed as `/usr/local/bin/osmap`, and accepted without rollback.

## Direct-origin acceptance

| Request form | Required and observed result |
|---|---|
| Valid `/healthz` control | HTTP 200 |
| Double-space request line | HTTP 400 |
| Leading request-line whitespace | HTTP 400 |
| Tab request-line separators | HTTP 400 |
| Mixed CRLF and LF | HTTP 400 |

The origin contract remains strict. OSMAP rejects all four ambiguous forms before application routing.

## TLS-edge acceptance

The accepted edge target is TCP `192.168.1.44:443`, TLS SNI `mail.blackbagsecurity.com`, and HTTP Host `mail.blackbagsecurity.com`.

| Request form | Accepted edge result |
|---|---|
| Valid `/healthz` control | One canonical request forwarded, HTTP 200 |
| Double-space request line | Canonicalised into exactly one safe request, HTTP 200 |
| Leading request-line whitespace | Rejected before origin, HTTP 400 |
| Tab request-line separators | Rejected before origin, HTTP 400 |
| Mixed CRLF and LF | Canonicalised into exactly one safe request, HTTP 200 |

Safe reverse-proxy canonicalisation is not equivalent to permissive origin parsing. Acceptance requires exactly one semantically equivalent method, target, and Host interpretation, with one unambiguous message boundary. Multiple requests, changed methods or targets, inconsistent Host handling, pipelining, or frontend and backend disagreement fail closed.

## Fresh read-only production verification

| Control | Result |
|---|---|
| Binary digest | `4dc1005f1e3f11ecf463fa4724a432622b7952bd378831f4c135ef3544f0f5bf` |
| Ownership and mode | `root:wheel:755` |
| `osmap_serve` | healthy, exactly one process |
| `osmap_mailbox_helper` | healthy, exactly one process |
| Origin listener | exactly one, loopback-only on `127.0.0.1:8080` |
| nginx | healthy, configuration test passed |
| Direct `/healthz` with required Host | HTTP 200 |
| Effective nginx configuration state | unchanged under the accepted direct merged-stream hash contract, `00b93403e0570195fbdd721a8e48fb0e63aa305dee9ae4958f46a616a8fbde1f` |
| PF-relevant state | unchanged, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Verification timestamp | `2026-07-30T16:52:52Z` |

No service restart, reload, redeployment, configuration change, or policy change occurred during this verification.

## Repository reconciliation

| Item | Recorded state |
|---|---|
| Canonical repository | `/home/foo/Workspace/OSMAP` |
| Integration worktree | `/home/foo/Workspace/OSMAP-v15-integration` |
| `main` | `890666a8e1dfd82db451b668cd8bfac9023b62fa` |
| `origin/main` | `890666a8e1dfd82db451b668cd8bfac9023b62fa` |
| Accepted commit reachable from local `main` | `no` |
| Accepted commit reachable from `origin/main` | `no` |
| Closeout branch | `v15/slice-03e-closeout` |
| Relevant open PR before Slice 03E | `none` |

## Local CI and governance

Status: **PASS**

* Rust tests passed: `570`
* Rust tests failed: `0`
* Rust tests ignored: `4`
* Required command set: cargo-fmt-check, cargo-check-all-targets, cargo-build-all-targets, cargo-test-all-targets, cargo-clippy-deny-warnings, make-v10-check, make-v14-check, make-security-check, make-acceptance-check, parser-request-line-regression, parser-crlf-regression, hostile-assurance-regression, v15-parser-oracle-build, v15-differential-harness, v15-differential-result-validation
* GitHub Actions were not used.

## Adjacent-control and cleanup boundary

Effective nginx configuration, mailbox-helper state, OSMAP listener exposure, and PF-relevant state remained unchanged. The nginx digest is defined by the exact direct stream `doas -n nginx -T 2>&1 | sha256 -q`, avoiding command-substitution serialization changes. The retained deployment session cleanup state is: **pending after protected-integration evidence**. Cleanup is permitted only after the accepted archives, remote evidence inventory, production verification, exact-tree CI, signed closeout commit, and pull-request evidence pass.

## Final status

Slice 03D status: **COMPLETE**. Slice 03E is a nonfunctional closeout and protected-integration slice. It introduces no JavaScript, Node.js, npm, frontend framework, external CDN, production Rust behaviour, or new dependency.
<!-- slice-03e-closeout:end -->

<!-- slice-04-closeout:start -->
## V15 Slice 04 policy closure

Slice 04 is complete for the fixed 37-case HTTP edge/origin corpus.

| Item | Accepted value |
|---|---|
| Implementation commit | `158f61d3735712faac019cae97f7ef3e26787973` |
| Assessed policy and harness commit | `6e28ae4ed8b83584ba5df1e522e17b358e5e8ebd` |
| Signing fingerprint | `F55E404E91A0753701F91B01A7228D3FB5084B34` |
| Deployed release binary SHA-256 | `d7426c8b51bed05f535da7195246a04365c3c5f39967a0170e64f350761cc85e` |
| Evidence archive | `osmap-v15-slice04-evidence-6e28ae4.tar.gz` |
| Evidence archive SHA-256 | `de1a823e21c7a5014ec840c132d9e77b5759b03186727947f51cd5947d16fb6d` |
| Previous binary rollback SHA-256 | `4dc1005f1e3f11ecf463fa4724a432622b7952bd378831f4c135ef3544f0f5bf` |

The archive's internal manifest verified every file. It preserves exact
base64-encoded corpus requests, raw edge and direct-origin responses, response
and connection observations, token-correlated forwarding logs, application
outcomes, signed commit identities, deployment diffs, and service state.

Both the offline and live required-policy campaigns passed:

```text
case_count=37
required_policy_failures=0
measured_unique_cases=0
origin_request_cardinality_violations=0
```

The parser now rejects non-ASCII-decimal `Content-Length` values and enforces
an 8 KiB generic header-value limit. nginx closes OSMAP client connections
after one response, so the pipelined second request no longer reaches the
origin. The conditional test log does not record normal browser query strings.

The deployed services remained healthy after the bounded binary installation,
nginx configuration validation, OSMAP restart, and nginx reload. Rollback
copies and an executable restore procedure remain under the host-side Slice 04
deployment sessions.

The historical Slice 03 evidence and conclusions above remain unchanged.
Slice 04 does not claim universal HTTP parser equivalence beyond the fixed
corpus and accepted edge configuration.
<!-- slice-04-closeout:end -->
