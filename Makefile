# Keep developer entrypoints obvious and conservative so operators and
# collaborating developers do not have to memorize cargo subcommands.

.PHONY: build check test lint fmt-check supply-chain-check security-check release-check v6-check v7-check v7-rendering-regression-check v8-check v8-mail-workflow-check v8-attachment-safety-check v8-mailbox-operation-check v8-session-integrity-check v8-resource-robustness-check v8-final-regression-check install-hooks run v10-check v11-check acceptance-check v12-check

build:
	cargo build

check:
	cargo check

test:
	cargo test

lint:
	cargo check
	@if cargo clippy --version >/dev/null 2>&1; then \
		cargo clippy --all-targets -- -D warnings; \
	else \
		printf '%s\n' 'note: cargo-clippy is not installed in this environment; ran cargo check only'; \
	fi

fmt-check:
	@if cargo fmt --version >/dev/null 2>&1; then \
		cargo fmt --check; \
	else \
		printf '%s\n' 'note: rustfmt is not installed in this environment; formatting check skipped'; \
	fi

supply-chain-check:
	sh maint/security/osmap-supply-chain-check.sh

security-check:
	OSMAP_SECURITY_PROFILE=developer sh maint/security/osmap-security-check.sh

release-check:
	OSMAP_SECURITY_PROFILE=release sh maint/security/osmap-release-check.sh

v6-check:
	sh maint/security/osmap-v5-boundary-gate.sh
	sh maint/security/osmap-v6-retirement-readiness-gate.sh

v7-check:
	sh maint/security/osmap-v7-boundary-hardening-gate.sh
	sh maint/security/osmap-v7-rendering-regression-gate.sh

v7-rendering-regression-check:
	sh maint/security/osmap-v7-rendering-regression-gate.sh

v8-check:
	sh maint/security/osmap-v8-stabilization-gate.sh
	sh maint/security/osmap-v8-mail-workflow-gate.sh
	sh maint/security/osmap-v8-attachment-safety-gate.sh
	sh maint/security/osmap-v8-mailbox-operation-gate.sh
	sh maint/security/osmap-v8-session-integrity-gate.sh
	sh maint/security/osmap-v8-resource-robustness-gate.sh
	sh maint/security/osmap-v8-final-regression-gate.sh

v8-mail-workflow-check:
	sh maint/security/osmap-v8-mail-workflow-gate.sh

v8-attachment-safety-check:
	sh maint/security/osmap-v8-attachment-safety-gate.sh

v8-mailbox-operation-check:
	sh maint/security/osmap-v8-mailbox-operation-gate.sh

v8-session-integrity-check:
	sh maint/security/osmap-v8-session-integrity-gate.sh

v8-resource-robustness-check:
	sh maint/security/osmap-v8-resource-robustness-gate.sh

v8-final-regression-check:
	sh maint/security/osmap-v8-final-regression-gate.sh

install-hooks:
	chmod +x .githooks/pre-commit .githooks/pre-push maint/security/osmap-security-check.sh maint/security/osmap-supply-chain-check.sh maint/security/osmap-release-check.sh maint/security/osmap-v4-hostile-assurance-gate.sh maint/security/osmap-v4-release-tuple-gate.sh maint/security/osmap-v4-security-claim-matrix-gate.sh maint/security/osmap-v5-boundary-gate.sh maint/security/osmap-v6-retirement-readiness-gate.sh maint/security/osmap-v7-boundary-hardening-gate.sh maint/security/osmap-v7-rendering-regression-gate.sh maint/security/test-osmap-v7-rendering-regression-gate.sh maint/security/osmap-v6-evidence-archive.sh maint/security/osmap-evidence-metadata.sh maint/security/osmap-cwe-top25-guard.sh maint/security/osmap-cwe-top25-guard.py
	git config core.hooksPath .githooks

run:
	cargo run

v10-check:
	sh maint/security/osmap-v10-governance-gate.sh

v11-check:
	sh maint/security/osmap-v11-runtime-fail-closed-gate.sh

acceptance-check:
	$(MAKE) security-check
	$(MAKE) v10-check
	$(MAKE) v11-check

v10-fail-closed-remediation-check:
	python3 -B maint/security/osmap-v10-fail-closed-remediation.py --check maint/security/v10-fail-closed-remediation.json

v12-check:
	sh maint/security/osmap-v12-openpgp-claims-gate.sh
	sh maint/security/test-osmap-v12-openpgp-claims-gate.sh
	sh maint/security/osmap-v12-openpgp-diagnostics-gate.sh
	sh maint/security/test-osmap-v12-openpgp-diagnostics-gate.sh
	sh maint/security/osmap-v12-openpgp-account-binding-gate.sh
	sh maint/security/test-osmap-v12-openpgp-account-binding-gate.sh
	sh maint/security/osmap-v12-openpgp-helper-protocol-gate.sh
	sh maint/security/test-osmap-v12-openpgp-helper-protocol-gate.sh
	sh maint/security/osmap-v12-openpgp-gpgme-readiness-gate.sh
	sh maint/security/test-osmap-v12-openpgp-gpgme-readiness-gate.sh
