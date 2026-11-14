#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
guard="$repo_root/maint/security/osmap-cwe-top25-guard.sh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-cwe-guard-test.XXXXXX")
cleanup() {
	rm -rf "$tmp_root"
}
trap cleanup EXIT INT TERM

# Exercise the real downstream scans as well as their source-aware guard.
legacy_scan="$tmp_root/legacy-scan.sh"
printf '%s\n' 'set -eu' > "$legacy_scan"
awk -v begin='echo "==> scanning for disallowed unsafe outside src/openbsd.rs"' \
    -v end='echo "==> validating closeout ssh wrapper command assembly"' '
    $0 == end { ended = 1; exit }
    $0 == begin { found = 1 }
    found { print }
    END { if (!found || !ended) exit 1 }
' "$repo_root/maint/security/osmap-security-check.sh" >> "$legacy_scan"
combined_scan() (
    cd "$1"
    OSMAP_CWE_SCAN_ROOT="$1" sh "$guard" && sh "$legacy_scan"
)

make_repo() {
	label=$1
	root="$tmp_root/$label"
	mkdir -p "$root/src"
	cat > "$root/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
libc = "0.2"
EOF
	cat > "$root/src/lib.rs" <<'EOF'
pub fn render_safe_text(input: &str) -> String {
    input.replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    #[test]
    fn hostile_strings_in_tests_are_not_production_code() {
        let _fixture = "<script>eval('x'); document.write('x'); new WebSocket('wss://example.invalid')";
        assert!(true);
    }
}
EOF
	cat > "$root/src/auth.rs" <<'EOF'
use std::process::Command;

pub fn reviewed_command_boundary(program: &str) {
    let _ = Command::new(program);
}
EOF
	cat > "$root/src/openbsd.rs" <<'EOF'
pub fn reviewed_ffi_boundary() {
    let _ = unsafe { libc::geteuid() };
}
EOF
	printf '%s\n' "$root"
}

assert_passes() {
	root=$1
	output="$tmp_root/pass.out"
	if ! OSMAP_CWE_SCAN_ROOT="$root" sh "$guard" >"$output" 2>&1; then
		cat "$output"
		echo "expected guard to pass for $root" >&2
		exit 1
	fi
	grep -q "CWE Top 25 guard passed" "$output"
}

assert_fails_with() {
	root=$1
	expected=$2
	output="$tmp_root/fail.out"
	if OSMAP_CWE_SCAN_ROOT="$root" sh "$guard" >"$output" 2>&1; then
		cat "$output"
		echo "expected guard to fail for $root" >&2
		exit 1
	fi
	if ! grep -q "$expected" "$output"; then
		cat "$output"
		echo "expected guard output to contain $expected" >&2
		exit 1
	fi
}

clean_repo=$(make_repo clean)
assert_passes "$clean_repo"

unsafe_repo=$(make_repo unsafe)
cat >> "$unsafe_repo/src/lib.rs" <<'EOF'
pub fn new_unsafe_boundary() {
    let _ = unsafe { 1 };
}
EOF
assert_fails_with "$unsafe_repo" "CWE-787"

command_repo=$(make_repo command)
cat > "$command_repo/src/mailbox.rs" <<'EOF'
use std::process::Command;

pub fn new_unreviewed_command() {
    let _ = Command::new("/usr/bin/id");
}
EOF
assert_fails_with "$command_repo" "CWE-78"

shell_repo=$(make_repo shell)
cat > "$shell_repo/src/mailbox.rs" <<'EOF'
pub fn shell_command_shape() -> &'static str {
    "/bin/sh -c whoami"
}
EOF
assert_fails_with "$shell_repo" "shell-based command execution"

sql_repo=$(make_repo sql)
cat >> "$sql_repo/Cargo.toml" <<'EOF'
rusqlite = "0.99"
EOF
assert_fails_with "$sql_repo" "CWE-89"

browser_repo=$(make_repo browser)
cat > "$browser_repo/src/rendering.rs" <<'EOF'
pub fn unsafe_browser_sink() -> &'static str {
    "element.innerHTML = payload; serviceWorker.register('/sw.js')"
}
EOF
assert_fails_with "$browser_repo" "CWE-94"

deser_repo=$(make_repo deserialization)
cat > "$deser_repo/src/session.rs" <<'EOF'
pub fn unsafe_decode(input: &[u8]) {
    let _ = bincode::deserialize::<String>(input);
}
EOF
assert_fails_with "$deser_repo" "CWE-502"

http_repo=$(make_repo outbound_http)
cat >> "$http_repo/Cargo.toml" <<'EOF'
reqwest = "0.12"
EOF
assert_fails_with "$http_repo" "CWE-918"


# Only the exact reviewed password adapter receives CWE-89 admission. A changed
# SQL statement and an unrelated production SQL path still fail closed.
reviewed_sql_repo=$(make_repo reviewed_password_sql)
cp "$repo_root/src/account_password_backend.rs" "$reviewed_sql_repo/src/account_password_backend.rs"
assert_passes "$reviewed_sql_repo"
python3 - "$reviewed_sql_repo/src/account_password_backend.rs" <<'PYCODE'
from pathlib import Path
import sys
path = Path(sys.argv[1])
source = path.read_text()
assert "LIMIT 2;" in source
path.write_text(source.replace("LIMIT 2;", "LIMIT 3;", 1))
PYCODE
assert_fails_with "$reviewed_sql_repo" "reviewed SQL boundary changed"

reviewed_admin_repo=$(make_repo reviewed_admin_sql)
cp "$repo_root/src/admin_postfixadmin.rs" "$reviewed_admin_repo/src/admin_postfixadmin.rs"
assert_passes "$reviewed_admin_repo"
printf '\n' >> "$reviewed_admin_repo/src/admin_postfixadmin.rs"
assert_fails_with "$reviewed_admin_repo" "reviewed SQL boundary changed"

unknown_sql_repo=$(make_repo unknown_production_sql)
cat > "$unknown_sql_repo/src/mailbox.rs" <<'EOF'
pub fn unreviewed_query() -> &'static str { "SELECT password FROM mailbox" }
EOF
assert_fails_with "$unknown_sql_repo" "CWE-89"

# Each external fixture exclusion depends on its real cfg(test) parent marker.
# Losing the marker must expose the child to normal production scanning.
for parent in account_password_backend.rs account_password_native.rs account_password_policy_endpoint.rs account_password_process.rs account_access_service.rs openpgp_public_admin_runtime.rs openpgp_crypto_personal.rs; do
    registered_repo=$(make_repo "registered_${parent%.rs}")
    fixture="${parent%.rs}_tests.rs"
    cp "$repo_root/src/$parent" "$registered_repo/src/$parent"
    cat > "$registered_repo/src/$fixture" <<'EOF'
pub fn hostile_scanner_fixture() {
    let _ = "/bin/sh";
    let _ = "SELECT password FROM mailbox";
    let _ = unsafe { 1 };
}
EOF
    assert_passes "$registered_repo"
    python3 - "$registered_repo/src/$parent" "$fixture" <<'PYCODE'
from pathlib import Path
import sys
path = Path(sys.argv[1])
source = path.read_text()
marker = '#[cfg(test)]\n#[path = "' + sys.argv[2] + '"]\nmod tests;'
assert source.count(marker) == 1
path.write_text(source.replace(marker, marker.replace('#[cfg(test)]\n', ''), 1))
PYCODE
    assert_fails_with "$registered_repo" "$fixture"
done

# Native scheduler fixtures are excluded only while their exact test-only
# registration chain is intact. Removing any link exposes the hostile fixture.
for boundary in runtime_cfg runtime_path scheduled_cfg scheduled_parent scheduled_include; do
    registered_repo=$(make_repo "$boundary")
    mkdir -p "$registered_repo/src/http"
    cp "$repo_root/src/http_runtime.rs" "$registered_repo/src/http_runtime.rs"
    cp "$repo_root/src/http_gateway_mail.rs" "$registered_repo/src/http_gateway_mail.rs"
    cp "$repo_root/src/http/protected_send_gateway_native_tests.rs" "$registered_repo/src/http/protected_send_gateway_native_tests.rs"
    case "$boundary" in
        runtime_*)
            fixture=http_runtime_scheduled_positive_native_tests.rs
            printf '%s\n' 'pub fn hostile_scanner_fixture() { let _ = "/bin/sh"; }' > "$registered_repo/src/$fixture"
            ;;
        scheduled_*)
            fixture=http/protected_send_gateway_scheduled_native_tests.rs
            printf '%s\n' 'pub fn hostile_scanner_fixture() { let _ = std::process::Command::new("/usr/bin/id"); }' > "$registered_repo/src/$fixture"
            ;;
    esac
    assert_passes "$registered_repo"
    if ! combined_scan "$registered_repo" > "$tmp_root/combined.out" 2>&1; then
        cat "$tmp_root/combined.out"
        echo "registered native fixture failed downstream scans" >&2
        exit 1
    fi
    python3 - "$registered_repo" "$boundary" <<'PYCODE'
from pathlib import Path
import sys
root = Path(sys.argv[1])
boundaries = {
    "runtime_cfg": ("src/http_runtime.rs", '#[cfg(all(test, target_os = "openbsd"))]\n#[path = "http_runtime_scheduled_positive_native_tests.rs"]', '#[path = "http_runtime_scheduled_positive_native_tests.rs"]'),
    "runtime_path": ("src/http_runtime.rs", '#[path = "http_runtime_scheduled_positive_native_tests.rs"]', ''),
    "scheduled_cfg": ("src/http_gateway_mail.rs", '#[cfg(test)]\nmod tests {', 'mod tests {'),
    "scheduled_parent": ("src/http_gateway_mail.rs", 'include!("http/protected_send_gateway_native_tests.rs");', ''),
    "scheduled_include": ("src/http/protected_send_gateway_native_tests.rs", 'include!("protected_send_gateway_scheduled_native_tests.rs");', ''),
}
relative, marker, replacement = boundaries[sys.argv[2]]
path = root / relative
source = path.read_text()
if source.count(marker) != 1:
    raise SystemExit("exact native registration marker required")
path.write_text(source.replace(marker, replacement, 1))
PYCODE
    assert_fails_with "$registered_repo" "$fixture"
    if combined_scan "$registered_repo" > "$tmp_root/combined.out" 2>&1; then
        echo "broken native registration passed combined scans" >&2
        exit 1
    fi
    grep -q "$fixture" "$tmp_root/combined.out"
done

for production_repo in "$command_repo" "$shell_repo"; do
    if combined_scan "$production_repo" > "$tmp_root/combined.out" 2>&1; then
        echo "production command/shell sink passed combined scans" >&2
        exit 1
    fi
    grep -q 'CWE-78' "$tmp_root/combined.out"
done
combined_scan "$repo_root" > "$tmp_root/combined.out" 2>&1 || {
    cat "$tmp_root/combined.out"
    exit 1
}

echo "CWE Top 25 guard regression checks passed"
