#!/usr/bin/env python3
"""Isolated lifecycle state-machine tests; no SSH, accounts, or real secrets."""
import hashlib
import os
import grp
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "maint/live/osmap-rotate-totp-over-ssh.sh"
OLD = hashlib.sha256(b"synthetic previous factor").hexdigest()

# Bash functions stand in for host/TTY boundaries. The coordinator, candidate
# construction, digest comparisons and transition decisions run unchanged.
HARNESS = r'''
source "$ROTATION_SCRIPT"
require_command() { return 0; }
rotation_host_check() { [[ "$CASE" != wrong_host ]]; }
rotation_preflight() {
    printf '%s\n' 'mailbox_exists=true' 'totp_exists=true' 'totp_metadata_safe=true'
    [[ "$CASE" != missing_mailbox ]] || return 4
    if [[ -f "$CASE_ROOT/installed" ]]; then
        printf 'active_factor_sha256=%s\n' "$(cat "$CASE_ROOT/installed")"
    elif [[ "$CASE" == stale && -f "$CASE_ROOT/enrolled" ]]; then
        printf 'active_factor_sha256=%064d\n' 0
    else
        printf 'active_factor_sha256=%s\n' "$OLD_DIGEST"
    fi
    [[ "$CASE" != malformed ]] || printf 'active_factor_sha256=duplicate\n'
    printf '%s\n' 'TOTP_REVOCATION_DRY_RUN=PASS'
}
prepare_enrollment_material() {
    WORK_ROOT="$CASE_ROOT/enrollment"
    mkdir "$WORK_ROOT" || return 1
    SECRET_FILE="$WORK_ROOT/secret"
    generate_secret > "$SECRET_FILE"
}
show_and_verify_enrollment() {
    printf '%s\n' enroll >> "$CASE_ROOT/events"
    [[ "$CASE" != enrollment_failed ]] || return 1
    touch "$CASE_ROOT/enrolled"
}
rotation_authorize() {
    printf '%s\n' authorize >> "$CASE_ROOT/events"
    [[ "$CASE" != authorization_failed ]]
}
rotation_revoke() {
    printf '%s\n' revoke >> "$CASE_ROOT/events"
    [[ "$3" == "$OLD_DIGEST" ]] || return 6
    [[ "$CASE" != revoke_failed ]] || return 6
    [[ "$CASE" != revoke_lost_response ]] || return 255
    [[ "$CASE" != revoke_bad_output ]] || return 0
    printf '%s\n' 'TOTP_REVOCATION=PASS' 'active_factor_absent=true' \
        'revoked_factor_preserved=true' "revoked_factor_sha256=$3"
}
remote_provision() {
    printf '%s\n' provision >> "$CASE_ROOT/events"
    [[ "$CASE" != install_failed ]] || return 10
    printf '%s\n' "$4" > "$CASE_ROOT/installed"
    [[ "$CASE" != install_lost_response ]] || return 255
    [[ "$CASE" != install_bad_output ]] || return 0
    [[ "$CASE" != final_mismatch ]] || printf '%064d\n' 0 > "$CASE_ROOT/installed"
    printf '%s\n' 'TOTP_PROVISIONING=PASS'
}
run_rotation alice@example.com 192.0.2.1 test.example.com "$MUTATION"
'''


class RotationTests(unittest.TestCase):
    def run_case(self, case="success", mutation=True):
        with tempfile.TemporaryDirectory(prefix="osmap-rotation-test-") as root:
            env = dict(os.environ, ROTATION_SCRIPT=str(SCRIPT), CASE=case,
                       CASE_ROOT=root, OLD_DIGEST=OLD,
                       MUTATION=str(mutation).lower())
            result = subprocess.run(["bash", "-c", HARNESS], env=env,
                                    capture_output=True, text=True, timeout=15)
            events = Path(root, "events")
            transitions = events.read_text().splitlines() if events.exists() else []
            self.assertFalse(Path(root, "enrollment").exists(), "secret scratch leaked")
            return result, transitions

    def test_success_requires_verified_enrollment_before_mutations(self):
        result, events = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ["enroll", "authorize", "revoke", "provision"])
        self.assertIn("TOTP_ROTATION=PASS", result.stdout)
        self.assertNotIn("secret=", result.stdout + result.stderr)

    def test_dry_run_has_no_enrollment_or_mutation(self):
        result, events = self.run_case(mutation=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])
        self.assertIn("TOTP_ROTATION_DRY_RUN=PASS", result.stdout)

    def test_preconditions_and_human_gates_preserve_old_factor(self):
        for case in ("wrong_host", "missing_mailbox", "malformed", "stale",
                     "enrollment_failed", "authorization_failed"):
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("revoke", events)
                self.assertNotIn("provision", events)

    def test_failed_or_ambiguous_revocation_never_installs_or_retries(self):
        for case in ("revoke_failed", "revoke_lost_response", "revoke_bad_output"):
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertEqual(result.returncode, 24, result.stderr)
                self.assertEqual(events.count("revoke"), 1)
                self.assertNotIn("provision", events)
                self.assertIn("manual_review_required=true", result.stderr)

    def test_failed_or_unverified_install_never_retries_or_claims_success(self):
        for case in ("install_failed", "install_lost_response", "install_bad_output",
                     "final_mismatch"):
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertEqual(result.returncode, 24, result.stderr)
                self.assertEqual(events.count("provision"), 1)
                self.assertNotIn("TOTP_ROTATION=PASS", result.stdout)
                self.assertIn("old_factor_restore_performed=false", result.stderr)

    def test_invalid_cli_and_environment_never_contact_ssh(self):
        cases = [
            (["--rotate", "alice@example.com"], {}),
            (["--dry-run", "Alice@example.com", "--host", "192.0.2.1",
              "--expected-hostname", "test.example.com"], {}),
            (["--dry-run", "alice@example.com", "--host", "-proxy",
              "--expected-hostname", "test.example.com"], {}),
            (["--dry-run", "alice@example.com", "--host", "192.0.2.1",
              "--expected-hostname", "test.example.com"],
             {"OSMAP_TOTP_SECRET_DIR": "/tmp/unsafe;command"}),
        ]
        for args, overrides in cases:
            with self.subTest(args=args, overrides=overrides):
                result = subprocess.run(["bash", str(SCRIPT), *args],
                                        env=dict(os.environ, **overrides),
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("ssh:", result.stderr)

    def test_sourcing_legacy_tools_does_not_dispatch(self):
        for name in ("provision", "revoke"):
            path = ROOT / f"maint/live/osmap-{name}-totp-over-ssh.sh"
            result = subprocess.run(["bash", "-c", 'source "$1"; printf loaded',
                                     "test", str(path)], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "loaded")

    def test_shared_helpers_keep_seed_and_code_out_of_subprocess_arguments(self):
        result = subprocess.run(["bash", "-c", r'''
source "$1"
test_secret=$(generate_secret)
test_code=''
python3() {
    local arg
    for arg in "$@"; do
        [[ "$arg" != "$test_secret" && ( -z "$test_code" || "$arg" != "$test_code" ) ]] || return 96
    done
    command python3 "$@"
}
test_code=$(totp_code "$test_secret" 1234567890 6)
verify_totp_code "$test_secret" "$test_code" 1234567890
test_uri=$(build_otpauth_uri alice@example.com "$test_secret")
[[ "$test_uri" == otpauth://totp/* ]]
''', "test", str(ROOT / "maint/live/osmap-provision-totp-over-ssh.sh")],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


class RemotePrimitiveTests(unittest.TestCase):
    """Run the actual remote shell programs against a synthetic local store.

    SSH, doas and OpenBSD utility syntax are adapters only. File type, modes,
    links, stale digests, archive preservation and candidate installation use
    real filesystem operations. This is not a native OpenBSD qualification.
    """

    def setUp(self):
        # Private scratch below the operator home avoids /tmp and a shared
        # worktree's writable ancestry, which the real guard must reject.
        self.temp = tempfile.TemporaryDirectory(prefix="osmap-rotation-test-", dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.store = self.root / "active"
        self.store.mkdir(mode=0o700)
        self.archive = self.root / "archive"
        self.factor = self.store / ("alice@example.com".encode().hex() + ".totp")
        self.old_bytes = b"synthetic prior factor, never usable for authentication\n"
        self.factor.write_bytes(self.old_bytes)
        self.factor.chmod(0o600)
        adapters = {
            "ssh": r'''#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in -T) shift ;; -o) shift 2 ;; *) shift; break ;; esac
done
if [ "$1" = hostname ]; then printf '%s\n' test.example.com; exit 0; fi
[ "$1" = sh ] || exit 99
exec "$@"
''',
            "doas": r'''#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in -n) shift ;; -u) shift 2 ;; *) break ;; esac
done
if [ "$1" = /usr/local/bin/doveadm ]; then
    [ "${NO_MAILBOX:-0}" = 0 ] || exit 1
    printf '%s\n' INBOX
    exit 0
fi
exec "$@"
''',
            "stat": r'''#!/bin/sh
set -eu
if [ "$1" = -f ]; then
    case "$2" in '%Su') field=%U ;; '%Sg') field=%G ;; '%Lp') field=%a ;; '%i') field=%i ;; *) exit 99 ;; esac
    exec /usr/bin/stat -c "$field" "$3"
fi
exec /usr/bin/stat "$@"
''',
            "sha256": r'''#!/bin/sh
set -eu
[ "$1" = -q ] || exit 99
sha256sum "$2" | awk '{print $1}'
''',
            "qrencode": "#!/bin/sh\nexit 99\n",  # Enrollment is explicitly mocked.
        }
        for name, script in adapters.items():
            path = self.bin / name
            path.write_text(script)
            path.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        ROTATION_SCRIPT=str(SCRIPT),
                        OSMAP_TOTP_SECRET_DIR=str(self.store),
                        OSMAP_TOTP_REVOKED_DIR=str(self.archive),
                        OSMAP_TOTP_OWNER=pwd.getpwuid(os.getuid()).pw_name,
                        OSMAP_TOTP_GROUP=grp.getgrgid(os.getgid()).gr_name)

    def run_program(self, body):
        return subprocess.run(["bash", "-c", 'source "$ROTATION_SCRIPT"\n' + body],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def test_real_primitives_preserve_old_factor_and_install_verified_candidate(self):
        result = self.run_program(r'''
show_and_verify_enrollment() { return 0; }
rotation_authorize() { return 0; }
run_rotation alice@example.com 192.0.2.1 test.example.com true
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TOTP_ROTATION=PASS", result.stdout)
        archived = list(self.archive.glob("*.revoked.totp"))
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].read_bytes(), self.old_bytes)
        candidate = self.factor.read_text()
        self.assertTrue(candidate.startswith("# alice@example.com\nsecret="))
        self.assertEqual(self.factor.stat().st_mode & 0o777, 0o600)
        self.assertEqual(archived[0].stat().st_mode & 0o777, 0o600)
        self.assertNotIn(candidate.split("secret=")[1].strip(), result.stdout + result.stderr)

    def test_real_dry_run_does_not_create_archive(self):
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.factor.read_bytes(), self.old_bytes)

    def test_real_host_mismatch_is_refused(self):
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 other.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remote hostname does not match", result.stderr)
        self.assertFalse(self.archive.exists())

    def test_missing_mailbox_is_refused(self):
        self.env["NO_MAILBOX"] = "1"
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.factor.read_bytes(), self.old_bytes)

    def test_missing_active_factor_is_refused(self):
        self.factor.unlink()
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.archive.exists())

    def test_concurrent_install_is_not_overwritten_or_rolled_back(self):
        adapter = self.bin / "ln"
        adapter.write_text(r'''#!/bin/sh
set -eu
case "$1" in
    */.osmap-totp-stage.*)
        # A competing writer wins between absence check and no-overwrite link.
        printf '%s\n' 'synthetic concurrent factor' > "$2"
        chmod 600 "$2"
        ;;
esac
exec /bin/ln "$@"
''')
        adapter.chmod(0o700)
        result = self.run_program(r'''
show_and_verify_enrollment() { return 0; }
rotation_authorize() { return 0; }
run_rotation alice@example.com 192.0.2.1 test.example.com true
''')
        self.assertEqual(result.returncode, 24, result.stderr)
        self.assertNotIn("TOTP_ROTATION=PASS", result.stdout)
        self.assertEqual(self.factor.read_text(), "synthetic concurrent factor\n")
        archived = list(self.archive.glob("*.revoked.totp"))
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].read_bytes(), self.old_bytes)

    def test_unsafe_factor_modes_fail_before_enrollment(self):
        self.factor.chmod(0o644)
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.factor.read_bytes(), self.old_bytes)

    def test_symlinked_store_is_refused(self):
        link = self.root / "linked"
        link.symlink_to(self.store, target_is_directory=True)
        self.env["OSMAP_TOTP_SECRET_DIR"] = str(link)
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.archive.exists())

    def test_unsafe_parent_is_refused(self):
        self.store.chmod(0o777)
        result = self.run_program("run_rotation alice@example.com 192.0.2.1 test.example.com false")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.archive.exists())

    def test_legacy_revoke_rejects_stale_digest_without_removing_factor(self):
        result = self.run_program('rotation_revoke alice@example.com 192.0.2.1 ' +
                                  '0' * 64 + ' 20260914T120000Z')
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertEqual(self.factor.read_bytes(), self.old_bytes)
        self.assertFalse(self.archive.exists())

    def test_legacy_install_refuses_an_existing_factor(self):
        candidate = self.root / "candidate"
        candidate.write_text("synthetic replacement\n")
        candidate.chmod(0o600)
        self.env["CANDIDATE"] = str(candidate)
        self.env["CANDIDATE_DIGEST"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        result = self.run_program('remote_provision alice@example.com 192.0.2.1 "$CANDIDATE" "$CANDIDATE_DIGEST"')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(self.factor.read_bytes(), self.old_bytes)


if __name__ == "__main__":
    unittest.main()
