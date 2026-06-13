# Keep developer entrypoints obvious and conservative so operators and
# collaborating developers do not have to memorize cargo subcommands.

.PHONY: build check test lint fmt-check supply-chain-check security-check release-check install-hooks run

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

install-hooks:
	chmod +x .githooks/pre-commit .githooks/pre-push maint/security/osmap-security-check.sh maint/security/osmap-supply-chain-check.sh maint/security/osmap-release-check.sh maint/security/osmap-v4-hostile-assurance-gate.sh maint/security/osmap-v4-release-tuple-gate.sh maint/security/osmap-evidence-metadata.sh
	git config core.hooksPath .githooks

run:
	cargo run
