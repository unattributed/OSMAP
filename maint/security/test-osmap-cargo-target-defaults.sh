#!/bin/sh
# Execute the real initialization blocks without running nested full gates.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-cargo-defaults.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

for checkout in 'checkout one' 'checkout two'; do
    fixture_root="$test_root/$checkout"
    mkdir -p "$fixture_root/maint/security"
    for gate in osmap-security-check.sh osmap-release-check.sh osmap-v4-hostile-assurance-gate.sh; do
        source_gate="$repo_root/maint/security/$gate"
        fixture_gate="$fixture_root/maint/security/$gate"
        # Fail if the tested initialization boundary is changed or removed.
        [ "$(grep -c '^export TMPDIR CARGO_HOME CARGO_TARGET_DIR$' "$source_gate")" -eq 1 ]
        sed -n '1,/^export TMPDIR CARGO_HOME CARGO_TARGET_DIR$/p' "$source_gate" > "$fixture_gate"
        cat >> "$fixture_gate" <<'PROBE'
printf '%s\n' "$CARGO_TARGET_DIR"
PROBE
        for mode in unset empty explicit; do
            expected="$fixture_root/target"
            if [ "$mode" = explicit ]; then
                expected="$test_root/explicit build cache"
            fi
            actual=$(
                unset CARGO_TARGET_DIR
                TMPDIR="$test_root/shared-tmp"
                CARGO_HOME="$test_root/cargo-home"
                OSMAP_RELEASE_EVIDENCE_DIR="$test_root/evidence"
                OSMAP_SECURITY_PROFILE=release
                export TMPDIR CARGO_HOME OSMAP_RELEASE_EVIDENCE_DIR OSMAP_SECURITY_PROFILE
                case "$mode" in
                    empty) CARGO_TARGET_DIR=; export CARGO_TARGET_DIR ;;
                    explicit) CARGO_TARGET_DIR="$expected"; export CARGO_TARGET_DIR ;;
                esac
                # Invocation from outside the fixture checkout must still work.
                cd "$test_root"
                sh "$fixture_gate"
            )
            if [ "$actual" != "$expected" ]; then
                printf 'Cargo target default failed: %s / %s / %s\n' "$checkout" "$gate" "$mode" >&2
                printf 'expected=%s\nactual=%s\n' "$expected" "$actual" >&2
                exit 1
            fi
            [ -d "$expected" ]
        done
    done
done

printf '%s\n' 'checkout-local Cargo target regression checks passed (18 cases)'
