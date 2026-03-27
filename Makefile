# Keep developer entrypoints obvious and conservative so operators and
# collaborating developers do not have to memorize cargo subcommands.

.PHONY: build check test lint fmt-check run

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

run:
	cargo run
