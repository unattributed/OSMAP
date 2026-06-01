# OSMAP V3 Release Evidence Summary

- Assessed ref: `78cad661717ae1f17f3a8df5a5125a2322ae99d2`
- Generated UTC: `2026-06-01T14:23:35Z`
- Host target: `mail.blackbagsecurity.com`
- Command: `make release-check`
- Cargo build: `passed`
- Cargo test: `passed`
- Cargo clippy: `passed`
- Cargo fmt-check: `passed`
- Supply-chain: `passed`
- Dependency inventory: `passed` at `/home/foo/OSMAP/maint/live/osmap-v3-dependency-inventory.txt`
- WSTG summary: `passed` at `/home/foo/OSMAP/maint/live/osmap-wstg-release-summary.json`
- Authenticated WSTG: `passed`
- TLS CBC cleanup: `passed`
- TLS standard validation: `passed`
- Resource and timeout hardening: `passed`
- Helper boundary evidence: `passed`
- V3 live MIME and HTML proof: `passed`
- V3 pilot rehearsal: `passed`
- Sanitized evidence archive: `passed` at `/home/foo/OSMAP/maint/live/osmap-v3-release-evidence.tar.gz`
- Skipped checks: ``

## V2 Carry-Forward Evidence

- `maint/live/latest-host-v2-readiness-report.txt`
- `maint/live/latest-host-v2-readiness-service-guard-report.txt`
- `docs/V2_PILOT_STATUS.md`
- `docs/V2_PILOT_CLOSEOUT.md`

## Host-Readiness Evidence

- `maint/live/latest-host-v2-readiness-report.txt`
- `maint/live/latest-host-edge-cutover-report.txt`
- `maint/live/latest-host-internet-exposure-report.txt`
- `maint/live/latest-host-service-enablement-report.txt`

## TLS Edge Evidence

- `maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt`

## TLS Standard Evidence

- `maint/live/latest-host-tls-standard-report.json`

## Resource And Timeout Evidence

- `maint/live/osmap-v3-resource-timeout-evidence-2026-05-02.txt`
- `maint/live/latest-host-v3-resource-controls-report.txt`

## Helper Boundary Evidence

- `/home/foo/OSMAP/maint/live/latest-host-helper-boundary-report.txt`
- `maint/live/osmap-live-validate-helper-peer-auth.ksh`

## V3 Live MIME And HTML Proof Evidence

- `maint/live/osmap-live-validate-v3-mime-html-proof.ksh`
- `/home/foo/OSMAP/maint/live/latest-host-v3-mime-html-proof-report.txt`

## V3 Pilot Rehearsal Evidence

- `/home/foo/OSMAP/maint/live/latest-host-v3-pilot-rehearsal-report.txt`
- `docs/PILOT_WORKFLOW_INVENTORY.md`
