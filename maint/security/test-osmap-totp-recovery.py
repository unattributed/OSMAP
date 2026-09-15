#!/usr/bin/env python3
"""Recovery approval and transition tests; synthetic keys and accounts only."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "maint/live/osmap-totp-recovery-approval.py"
SCRIPT = ROOT / "maint/live/osmap-recover-totp-over-ssh.sh"


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


approval = module_at("recovery_approval", VERIFIER)
guard = module_at("rehearsal_guard", ROOT / "maint/live/osmap-totp-rehearsal-check.py")
rotation = module_at("rotation_tests", ROOT / "maint/security/test-osmap-totp-rotation.py")
OLD = rotation.OLD


def valid_payload():
    now = int(time.time())
    return {"schema": approval.SCHEMA, "account": "alice@example.com",
            "ssh_host": "192.0.2.1", "expected_hostname": "test.example.com",
            "previous_factor_sha256": OLD, "request_id": "synthetic-case-1",
            "issued_at": now, "expires_at": now + 900, "identity_method": "in_person",
            "identity_case": "identity-1", "session_case": "sessions-1",
            "containment_case": "containment-1", "sessions_revoked": True,
            "access_contained": True}


def validate(payload):
    return approval.validate_payload(json.dumps(payload).encode(), "alice@example.com",
                                     "192.0.2.1", "test.example.com", OLD, int(time.time()))


class ApprovalPolicyTests(unittest.TestCase):
    def rehearsal_payload(self):
        payload = valid_payload()
        account, host, hostname = approval.REHEARSAL_TARGET
        payload.update(schema=approval.REHEARSAL_SCHEMA, account=account, ssh_host=host,
                       expected_hostname=hostname, identity_method="controlled_test_custody")
        payload["no_valid_sessions"] = payload.pop("sessions_revoked")
        return payload

    def validate_rehearsal(self, payload, target=None, rehearsal=True):
        return approval.validate_payload(json.dumps(payload).encode(),
                                         *(target or approval.REHEARSAL_TARGET),
                                         OLD, int(time.time()), rehearsal=rehearsal)

    def test_rehearsal_and_production_approvals_are_not_interchangeable(self):
        payload = self.rehearsal_payload()
        self.validate_rehearsal(payload)
        with self.assertRaises(approval.ApprovalError):
            self.validate_rehearsal(payload, rehearsal=False)
        production = dict(payload, schema=approval.SCHEMA, identity_method="in_person")
        production["sessions_revoked"] = production.pop("no_valid_sessions")
        self.validate_rehearsal(production, rehearsal=False)
        with self.assertRaises(approval.ApprovalError):
            self.validate_rehearsal(production)

    def test_rehearsal_cannot_select_another_account_host_or_hostname(self):
        for index, field in enumerate(("account", "ssh_host", "expected_hostname")):
            payload = self.rehearsal_payload()
            target = list(approval.REHEARSAL_TARGET)
            target[index] = payload[field] = "other.example.com"
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):
                self.validate_rehearsal(payload, target)

    def test_rehearsal_keeps_freshness_exact_fields_and_truthful_controls(self):
        changes = {"no_valid_sessions": False, "access_contained": False,
                   "identity_method": "in_person", "identity_case": "",
                   "expires_at": 0, "issued_at": True, "previous_factor_sha256": "0" * 64}
        for field, value in changes.items():
            payload = self.rehearsal_payload()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):
                self.validate_rehearsal(payload)
        for value in ("true", 1, None):
            with self.assertRaises(approval.ApprovalError):
                self.validate_rehearsal(dict(self.rehearsal_payload(), no_valid_sessions=value))
        with self.assertRaises(approval.ApprovalError):
            self.validate_rehearsal(dict(self.rehearsal_payload(), sessions_revoked=True))

    def test_valid_policy(self):
        self.assertEqual(validate(valid_payload())["request_id"], "synthetic-case-1")

    def test_identity_sessions_containment_and_exact_target_are_required(self):
        changes = {
            "schema": "unknown", "account": "bob@example.com", "ssh_host": "192.0.2.2",
            "expected_hostname": "other.example.com", "previous_factor_sha256": "0" * 64,
            "identity_method": "email_only", "identity_case": "", "session_case": "",
            "containment_case": "", "request_id": "case\nforged=true",
            "sessions_revoked": False, "access_contained": False,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                payload = valid_payload()
                payload[field] = value
                with self.assertRaises(approval.ApprovalError):
                    validate(payload)

    def test_boolean_attestations_cannot_be_strings_or_numbers(self):
        for field in ("sessions_revoked", "access_contained"):
            for value in ("true", 1, None, [], {}):
                payload = valid_payload()
                payload[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(approval.ApprovalError):
                    validate(payload)

    def test_time_window_is_bounded_and_current(self):
        now = int(time.time())
        for issued, expires in ((now - 20, now), (now + 20, now + 40),
                                (now, now + 901), (now, now), (True, now + 1),
                                (str(now), now + 30), (now, float(now + 30))):
            payload = valid_payload()
            payload.update(issued_at=issued, expires_at=expires)
            with self.subTest(issued=issued, expires=expires), self.assertRaises(approval.ApprovalError):
                validate(payload)

    def test_unknown_missing_duplicate_and_nonobject_fields_fail(self):
        original = valid_payload()
        for field in original:
            payload = copy.deepcopy(original)
            del payload[field]
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):
                validate(payload)
        payload = dict(original, arbitrary="unexpected")
        with self.assertRaises(approval.ApprovalError):
            validate(payload)
        for data in (b'[]', b'{"schema":"one","schema":"two"}', b'\xff', b'{'):
            with self.assertRaises(approval.ApprovalError):
                approval.validate_payload(data, "alice@example.com", "192.0.2.1",
                                          "test.example.com", OLD, int(time.time()))

    def test_private_file_checks_reject_symlinks_permissive_and_large_files(self):
        with tempfile.TemporaryDirectory(prefix="osmap-recovery-files-") as root:
            path = Path(root, "approval")
            path.write_bytes(b"synthetic")
            path.chmod(0o600)
            self.assertEqual(approval.read_private_file(path), b"synthetic")
            with mock.patch.object(approval.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(approval.ApprovalError):
                approval.read_private_file(path)
            path.chmod(0o644)
            with self.assertRaises(approval.ApprovalError):
                approval.read_private_file(path)
            path.chmod(0o600)
            alias = Path(root, "alias")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                approval.read_private_file(alias)
            path.write_bytes(b"x" * (approval.MAX_BYTES + 1))
            with self.assertRaises(approval.ApprovalError):
                approval.read_private_file(path)
            pipe = Path(root, "pipe")
            os.mkfifo(pipe, 0o600)
            with self.assertRaises(approval.ApprovalError):
                approval.read_private_file(pipe)

    def test_template_cannot_authorize_recovery(self):
        result = subprocess.run(["python3", str(VERIFIER), "--template", "--account",
                                 "alice@example.com", "--host", "192.0.2.1",
                                 "--expected-hostname", "test.example.com", "--digest", OLD],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(approval.ApprovalError):
            validate(json.loads(result.stdout))

    def test_revocation_expiry_and_verifier_failure_statuses_fail_closed(self):
        valid = f"[GNUPG:] VALIDSIG {approval.SHOPKEEPER} 2026-09-14 1 0 4 0 22 8 00 {approval.SHOPKEEPER}\n"
        for status in ("REVKEYSIG", "EXPSIG", "EXPKEYSIG", "KEYEXPIRED", "SIGEXPIRED", "FAILURE"):
            output = (valid + f"[GNUPG:] {status} fixture\n").encode()
            with mock.patch.object(approval.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output)), self.assertRaises(approval.ApprovalError):
                approval.verify_signature(b"synthetic", b"synthetic")

    def test_signature_timeout_fails_closed(self):
        with mock.patch.object(approval.subprocess, "run", side_effect=subprocess.TimeoutExpired("gpg", 15)), self.assertRaises(subprocess.TimeoutExpired):
            approval.verify_signature(b"synthetic", b"synthetic")


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing verifier is a test failure, not silently skipped assurance.
        if not shutil.which("gpg") or not shutil.which("gpgconf"):
            raise RuntimeError("recovery signature tests require gpg and gpgconf")
        cls.directory = tempfile.TemporaryDirectory(prefix="osmap-recovery-gpg-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.env = dict(os.environ, GNUPGHOME=str(cls.root))
        cls.addClassCleanup(lambda: subprocess.run(
            ["gpgconf", "--homedir", str(cls.root), "--kill", "gpg-agent"],
            capture_output=True, check=False, timeout=10))
        # This unprotected, disposable test key is never used for a real account
        # or commit. It exists only under the temporary test GNUPGHOME.
        subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                        "--quick-generate-key", "OSMAP synthetic recovery test", "ed25519", "sign", "0"],
                       env=cls.env, capture_output=True, check=True, timeout=20)
        keys = subprocess.run(["gpg", "--batch", "--with-colons", "--list-keys"],
                              env=cls.env, capture_output=True, text=True, check=True, timeout=5)
        cls.fingerprint = next(line.split(":")[9] for line in keys.stdout.splitlines()
                               if line.startswith("fpr:"))
        cls.data = json.dumps(valid_payload()).encode()
        cls.path = cls.root / "approval.json"
        cls.path.write_bytes(cls.data)
        cls.path.chmod(0o600)
        cls.sig_path = cls.root / "approval.sig"
        subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                        "--detach-sign", "--output", str(cls.sig_path), str(cls.path)],
                       env=cls.env, capture_output=True, check=True, timeout=5)
        cls.sig_path.chmod(0o600)
        cls.signature = cls.sig_path.read_bytes()

    def test_actual_detached_signature_and_fingerprint_verification(self):
        with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)):
            approval.verify_signature(self.data, self.signature, expected_signer=self.fingerprint)

    def test_modified_data_invalid_or_multiple_signatures_fail(self):
        for data, signature in ((self.data + b" ", self.signature),
                                (self.data, b"invalid"),
                                (self.data, self.signature + self.signature)):
            with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)), self.assertRaises(approval.ApprovalError):
                approval.verify_signature(data, signature, expected_signer=self.fingerprint)

    def test_production_pin_rejects_other_valid_signers(self):
        with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)), self.assertRaises(approval.ApprovalError):
            approval.verify_signature(self.data, self.signature)
        result = subprocess.run(["python3", str(VERIFIER), "--approval", str(self.path),
                                 "--signature", str(self.sig_path), "--account", "alice@example.com",
                                 "--host", "192.0.2.1", "--expected-hostname", "test.example.com",
                                 "--digest", OLD], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "RECOVERY_APPROVAL=REFUSED\n")
        self.assertNotIn("synthetic-case-1", result.stdout + result.stderr)


RECOVERY_HARNESS = rotation.HARNESS.replace('source "$ROTATION_SCRIPT"', 'source "$RECOVERY_SCRIPT"')
RECOVERY_HARNESS = RECOVERY_HARNESS.replace(
    'run_rotation alice@example.com 192.0.2.1 test.example.com "$MUTATION"', r'''
python3() {
    if [[ "${1:-}" == */osmap-totp-recovery-approval.py && "${2:-}" == --approval ]]; then
        printf '%s\n' approval >> "$CASE_ROOT/approvals"
        [[ "$CASE" != unsigned ]] || return 1
        [[ "$CASE" != expired_after_enrollment || ! -f "$CASE_ROOT/enrolled" ]] || return 1
        printf '%s\n' 'RECOVERY_APPROVAL=PASS' 'approval_request_id=synthetic-case-1'
        if [[ "$CASE" == changed_approval && -f "$CASE_ROOT/enrolled" ]]; then
            printf 'approval_sha256=%064d\n' 1
        else
            printf 'approval_sha256=%064d\n' 0
        fi
        return 0
    fi
    command python3 "$@"
}
if [[ "$CASE" != no_tty ]]; then
    recovery_authorize() { rotation_authorize "$@"; }
fi
operation=--dry-run
[[ "$MUTATION" != true ]] || operation=--recover
recovery_main "$operation" alice@example.com --host 192.0.2.1 \
    --expected-hostname test.example.com --approval synthetic.json --signature synthetic.sig
''')


class RecoveryTransitionTests(unittest.TestCase):
    def run_case(self, case="success", mutation=True, rehearsal=False):
        with tempfile.TemporaryDirectory(prefix="osmap-recovery-test-") as root:
            env = dict(os.environ, RECOVERY_SCRIPT=str(SCRIPT), CASE=case, CASE_ROOT=root,
                       OLD_DIGEST=OLD, MUTATION=str(mutation).lower())
            harness = RECOVERY_HARNESS
            if rehearsal:
                harness = harness.replace("'RECOVERY_APPROVAL=PASS'", "'REHEARSAL_APPROVAL=PASS'")
                harness = harness.replace('recovery_main "$operation" alice@example.com --host 192.0.2.1',
                    '''rehearsal_check() {
    printf '%s\\n' guard >> "$CASE_ROOT/approvals"
    [[ "$CASE" != containment_failed ]] || return 1
    [[ "$CASE" != containment_lost || ! -f "$CASE_ROOT/enrolled" ]]
}
recovery_main --controlled-rehearsal "$operation" osmap-helper-validation@blackbagsecurity.com --host 192.168.1.44''')
                harness = harness.replace("--expected-hostname test.example.com --approval",
                                          "--expected-hostname obsd1.blackbagsecurity.com --approval")
            result = subprocess.run(["bash", "-c", harness], env=env,
                                    capture_output=True, text=True, timeout=15, start_new_session=True)
            events_path = Path(root, "events")
            events = events_path.read_text().splitlines() if events_path.exists() else []
            approvals_path = Path(root, "approvals")
            checks = approvals_path.read_text().splitlines() if approvals_path.exists() else []
            self.assertFalse(Path(root, "enrollment").exists(), "secret scratch leaked")
            return result, events, checks

    def test_rehearsal_checks_containment_twice_and_labels_result_distinctly(self):
        result, events, checks = self.run_case(rehearsal=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(checks, ["guard", "approval", "guard", "approval"])
        self.assertEqual(events, ["enroll", "authorize", "revoke", "provision"])
        self.assertIn("TOTP_RECOVERY_REHEARSAL=PASS", result.stdout)
        self.assertNotIn("TOTP_RECOVERY=PASS", result.stdout)

    def test_rehearsal_containment_loss_and_approval_failure_never_mutate(self):
        for case in ("containment_failed", "containment_lost", "unsigned",
                     "expired_after_enrollment", "changed_approval", "no_tty"):
            result, events, _ = self.run_case(case, rehearsal=True)
            self.assertNotEqual(result.returncode, 0, case)
            self.assertNotIn("revoke", events)
            self.assertNotIn("provision", events)

    def test_rehearsal_dry_run_and_partial_results_are_not_real_recovery(self):
        result, events, checks = self.run_case(mutation=False, rehearsal=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])
        self.assertEqual(checks, ["guard", "approval"])
        self.assertIn("TOTP_RECOVERY_REHEARSAL_DRY_RUN=PASS", result.stdout)
        result, _, _ = self.run_case("install_failed", rehearsal=True)
        self.assertEqual(result.returncode, 24)
        self.assertIn("TOTP_RECOVERY_REHEARSAL=INCOMPLETE", result.stderr)

    def test_rehearsal_wrong_target_refused_before_any_ssh(self):
        result = subprocess.run(["bash", str(SCRIPT), "--controlled-rehearsal", "--request",
                                 "alice@example.com", "--host", "192.168.1.44",
                                 "--expected-hostname", "obsd1.blackbagsecurity.com"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("ssh:", result.stderr)
        for key, value in (("OSMAP_TOTP_SECRET_DIR", "/tmp/elsewhere"),
                           ("OSMAP_TOTP_REVOKED_DIR", "/tmp/elsewhere"),
                           ("OSMAP_TOTP_OWNER", "root"), ("OSMAP_TOTP_GROUP", "wheel")):
            result = subprocess.run(["bash", str(SCRIPT), "--controlled-rehearsal", "--request",
                                     approval.REHEARSAL_TARGET[0], "--host", "192.168.1.44",
                                     "--expected-hostname", "obsd1.blackbagsecurity.com"],
                                    env=dict(os.environ, **{key: value}), capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 2, key)
            self.assertNotIn("ssh:", result.stderr)

    def test_recovery_verifies_approval_before_enrollment_and_again_before_mutation(self):
        result, events, checks = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(checks, ["approval", "approval"])
        self.assertEqual(events, ["enroll", "authorize", "revoke", "provision"])
        self.assertIn("TOTP_RECOVERY=PASS", result.stdout)
        self.assertNotIn("TOTP_ROTATION=PASS", result.stdout)

    def test_dry_run_verifies_approval_without_enrollment_or_mutation(self):
        result, events, checks = self.run_case(mutation=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])
        self.assertEqual(checks, ["approval"])
        self.assertIn("TOTP_RECOVERY_DRY_RUN=PASS", result.stdout)

    def test_invalid_or_changed_approval_authorization_and_identity_stop_mutation(self):
        for case in ("unsigned", "expired_after_enrollment", "changed_approval", "stale",
                     "authorization_failed", "enrollment_failed", "wrong_host", "missing_mailbox", "no_tty"):
            with self.subTest(case=case):
                result, events, _ = self.run_case(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("revoke", events)
                self.assertNotIn("provision", events)
                if case == "unsigned":
                    self.assertEqual(events, [])

    def test_ambiguous_outcomes_never_retry_or_claim_recovery(self):
        for case in ("revoke_failed", "revoke_lost_response", "revoke_bad_output",
                     "install_failed", "install_lost_response", "install_bad_output", "final_mismatch"):
            with self.subTest(case=case):
                result, events, _ = self.run_case(case)
                self.assertEqual(result.returncode, 24, result.stderr)
                self.assertEqual(events.count("revoke"), 1)
                self.assertLessEqual(events.count("provision"), 1)
                if case.startswith("revoke"):
                    self.assertNotIn("provision", events)
                self.assertIn("TOTP_RECOVERY=INCOMPLETE", result.stderr)
                self.assertNotIn("TOTP_RECOVERY=PASS", result.stdout)

    def test_missing_approval_or_bad_target_is_refused_before_ssh(self):
        for args in (["--recover", "alice@example.com", "--host", "192.0.2.1",
                      "--expected-hostname", "test.example.com"],
                     ["--recover", "Alice@example.com", "--host", "192.0.2.1",
                      "--expected-hostname", "test.example.com", "--approval", "x", "--signature", "y"]):
            result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True,
                                    text=True, timeout=5, start_new_session=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("ssh:", result.stderr)


class RehearsalGuardTests(unittest.TestCase):
    def record(self, **changes):
        fields = dict(session_id="a" * 64, csrf_token="b" * 64,
                      canonical_username=guard.ACCOUNT, issued_at="100", expires_at="10000",
                      last_seen_at="200", revoked_at="", remote_addr="127.0.0.1",
                      user_agent="synthetic", factor="totp")
        fields.update(changes)
        return "".join(f"{key}={value}\n" for key, value in fields.items())

    def check_fixture(self, content, now=500, symlink=False):
        with tempfile.TemporaryDirectory(prefix="osmap-rehearsal-session-") as root:
            directory = Path(root)
            path = directory / ("a" * 64 + ".session")
            path.write_text(content)
            path.chmod(0o600)
            if symlink:
                path.rename(directory / "original")
                path.symlink_to(directory / "original")
            return guard.check_records(directory, os.getuid(), now)

    def test_usable_session_refused_but_revoked_or_expired_are_distinguished(self):
        with self.assertRaises(guard.Refused):
            self.check_fixture(self.record())
        self.assertEqual(self.check_fixture(self.record(revoked_at="300")), (1, 1, 0))
        self.assertEqual(self.check_fixture(self.record(expires_at="400")), (1, 0, 1))
        self.assertEqual(self.check_fixture(self.record(), now=2000), (1, 0, 1))
        self.assertEqual(self.check_fixture(self.record(canonical_username="other@example.com")), (0, 0, 0))

    def test_malformed_duplicate_future_and_symlink_records_refused(self):
        for content in (self.record() + "revoked_at=1\n", self.record(revoked_at="later"),
                        self.record(revoked_at="900"), self.record(csrf_token="invalid"),
                        self.record() + "extra=1\n", self.record(user_agent="unsafe\rvalue")):
            with self.subTest(content_type="synthetic"), self.assertRaises(guard.Refused):
                self.check_fixture(content)
        with self.assertRaises((guard.Refused, OSError)):
            self.check_fixture(self.record(revoked_at="300"), symlink=True)

    def test_config_must_bind_exact_listener_directory_and_timeouts(self):
        valid = ("OSMAP_SESSION_DIR=/var/lib/osmap/sessions\nOSMAP_LISTEN_ADDR=127.0.0.1:8080\n"
                 "OSMAP_SESSION_LIFETIME_SECS=43200\nOSMAP_SESSION_IDLE_TIMEOUT_SECS=1800\n")
        guard.check_config(valid)
        for text in (valid.replace("8080", "8081"), valid.replace("1800", "9999"),
                     valid + "OSMAP_SESSION_DIR=/tmp/elsewhere\n", "",
                     valid + "export OSMAP_SESSION_DIR=/tmp/elsewhere\n",
                     valid + "OTHER=value; OSMAP_SESSION_DIR=/tmp/elsewhere\n",
                     valid + "OTHER=$(command)\n"):
            with self.assertRaises(guard.Refused):
                guard.check_config(text)

    def test_unsafe_file_metadata_and_directory_ancestry_refused(self):
        with tempfile.TemporaryDirectory(prefix="osmap-rehearsal-metadata-") as root:
            path = Path(root, "record")
            path.write_text("synthetic")
            path.chmod(0o644)
            with self.assertRaises(guard.Refused):
                guard.read_regular(path, os.getuid())
            path.chmod(0o600)
            with self.assertRaises(guard.Refused):
                guard.read_regular(path, os.getuid() + 1)
            os.link(path, Path(root, "second"))
            with self.assertRaises(guard.Refused):
                guard.read_regular(path, os.getuid())
            directory_link = Path(root, "directory-link")
            directory_link.symlink_to(root)
            with self.assertRaises(guard.Refused):
                guard.safe_ancestry(directory_link, os.getuid())

    def test_running_or_uncertain_service_is_refused(self):
        for code in (0, 2, 255):
            with mock.patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], code)), \
                    self.assertRaises(guard.Refused):
                guard.service_stopped()
        with mock.patch.object(guard.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
                mock.patch.object(guard.socket, "socket") as probe:
            probe.return_value.__enter__.return_value.connect_ex.return_value = 0
            with self.assertRaises(guard.Refused):
                guard.service_stopped()
            probe.return_value.__enter__.return_value.connect_ex.return_value = guard.errno.ECONNREFUSED
            guard.service_stopped()

    def test_other_platform_never_runs_host_commands(self):
        with mock.patch.object(guard.platform, "system", return_value="Linux"), \
                mock.patch.object(guard.subprocess, "run") as run, mock.patch("builtins.print") as output:
            self.assertEqual(guard.main(), 1)
            run.assert_not_called()
            output.assert_called_once_with("REHEARSAL_CONTAINMENT=REFUSED")


if __name__ == "__main__":
    unittest.main()
