# Current Project Status

## Purpose

This document is the current public-safe status record for OSMAP. It exists so
README.md, docs/README.md, historical version files, and later sprint records do
not leave maintainers guessing which statements are current and which are
provenance.

Historical version documents remain valid as evidence records for the slices
that produced them. When a historical document conflicts with this file, the
current README, or the latest version closeout record, treat the historical
statement as provenance rather than current release posture.

## Current source posture

The repository now contains completed governance, hardening, OpenPGP foundation,
and WSTG assurance work through V13. Earlier README language that described the
project as only post-V9 is stale.

The current authoritative status chain is:

1. V9 selected-cohort release-candidate closeout.
2. V10 governance, claims-boundary, acceptance, documentation, and fail-closed
   assumption triage.
3. V11 runtime fail-closed closure for the refined high-relevance assumption
   queue.
4. V12 non-cryptographic OpenPGP secure foundation through Slice 14 closeout
   readiness.
5. V13 WSTG assurance integrity, adversarial validation, and production
   deployment closeout.

## Version status summary

| Version | Current status | Current claim boundary |
| --- | --- | --- |
| V4 | Historical hostile-content safety release evidence remains the formal tagged release baseline. | Bounded hostile-content containment only, not broad malware or hostile-mail safety. |
| V5 | Boundary hardening evidence and production deployment records exist. | Identity, Host, origin, response, and trusted HTML boundary hardening only. |
| V6 | Production readiness passed and was later reconciled by V9 for selected-cohort no-Roundcube operation. | Selected-cohort readiness only, not broad Roundcube retirement. |
| V7 | Production availability reopening is closed for the tested selected-user path. | Tested path and current rendering policy only. |
| V8 | Regression matrices and mandatory CI enforcement are complete. | Source stabilization and regression protection, not a new production deployment by itself. |
| V9 | Selected-cohort release-candidate gate passed at `a8915c0993b96a9d53de083dc84cb7520aef0097`. | Selected-cohort release candidate under documented limitations. |
| V10 | Governance, acceptance, documentation status, and fail-closed assumption triage are gate-visible. | Governance and claims-boundary control, not runtime feature expansion. |
| V11 | Refined high-relevance runtime fail-closed closure is documented and gated. | Runtime hardening for selected assumption paths, not broad public release readiness. |
| V12 | OpenPGP foundation completed through Slice 14 closeout readiness. | Non-cryptographic foundation only. No decrypt, verify, sign, encrypt, PGP/MIME parsing, passphrase handling, private-key access, browser controls, or decrypted rendering. |
| V13 | WSTG assurance integrity and adversarial validation are completed and deployed. | WSTG assurance upgrade, live validation, and deployment evidence under the explicit residual limits in the V13 closeout. |

## Current production and deployment records

V9 recorded the selected-cohort release-candidate decision while production was
still running the PR #19 binary:

- V9 selected-cohort release-candidate commit:
  `a8915c0993b96a9d53de083dc84cb7520aef0097`
- V9 production runtime source:
  `49c9f230d7865f01deadbc6a5a0f6e876c63e89b`
- V9 production binary SHA256:
  `411c976cccb0687f1a6e840470584fd8921eb5469e68905e457cf3edfe0cdea3`

V13 later records a reviewed production deployment:

- V13 final reviewed commit:
  `7009b15322c4e7795c797c1387b403e0f4935adb`
- V13 live and staged binary SHA256:
  `333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963`
- V13 release run:
  `osmap-wstg-20260627-204207`
- V13 credentialed release outcome:
  `42 pass`, `0 fail`, `0 warning`, `0 skip`, and `4 justified not-applicable`

The V13 closeout remains the current production deployment evidence reference.
Source sync alone must still not be described as deployment.

## Active gates

Developer and acceptance gates now include:

```sh
make security-check
make acceptance-check
make v10-check
make v11-check
make v12-check
make v13-check
```

Strict release validation remains separate:

```sh
OSMAP_SECURITY_PROFILE=release make release-check
```

The strict release path remains evidence-dependent and may fail safely when live
host, credentialed WSTG, TLS, supply-chain, or sanitized evidence inputs are
missing or stale.

## OpenPGP status

OpenPGP is no longer merely a design-only investigation. V12 created a bounded,
non-cryptographic implementation foundation:

- requirement and claims boundary;
- public key inventory and dependency diagnostics;
- explicit account-to-full-fingerprint binding model;
- helper protocol scaffold;
- GPGME readiness and availability gates;
- compile and link scaffold;
- protocol-only helper invocation scaffold;
- typed Rust helper-client planning boundary;
- helper-client integration gate;
- capability policy, outbound preflight, and inbound security-state models;
- Slice 14 closeout readiness audit.

V12 does not enable runtime cryptography. OSMAP must not claim working OpenPGP
decryption, signature verification, signing, encryption, PGP/MIME handling,
passphrase handling, private-key access, browser OpenPGP controls, key
discovery, WKD, keyserver lookup, or decrypted-content rendering until later
slices implement and evidence those functions.

## Current residual limitations

The current project still does not claim:

- complete Roundcube replacement for all users;
- general hostile-email safety;
- malware prevention beyond the explicitly tested mail-stack boundary;
- attachment preview safety;
- broad URL reputation or phishing protection;
- unbounded MIME, mailbox, archive-recursion, or document-sanitization safety;
- full ASVS verification;
- universal production readiness outside the documented deployed scope;
- OpenPGP runtime cryptographic operations.

## Documentation maintenance rule

Any future slice that changes current release posture, production deployment,
OpenPGP capability, WSTG assurance, or selected-cohort scope must update this
file, the root README, docs/README.md, KNOWN_LIMITATIONS.md, and the relevant
version closeout document in the same change stream.
