#!/usr/bin/env python3
"""Focused coordinator identity, one-shot workflow and real codec boundaries.

All accounts, signing keys and enrollment material are disposable synthetic
fixtures. No host is contacted and no production identity decision is created.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "maint/live/osmap-coordinate-recovery-over-ssh.sh"
VERIFIER = ROOT / "maint/live/osmap-totp-recovery-approval.py"
STATUS_FIXTURES = None
ACCOUNT = "alice@recovery.invalid"
HOST = "192.0.2.1"
HOSTNAME = "recovery.invalid"
OLD = "a" * 64


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


approval = module_at("coordinator_approval", VERIFIER)
legacy = module_at("coordinator_signature_helpers", ROOT / "maint/security/test-osmap-totp-recovery.py")


def payload():
    now = int(time.time())
    return {"schema": approval.COORDINATOR_SCHEMA, "account": ACCOUNT,
            "ssh_host": HOST, "expected_hostname": HOSTNAME,
            "previous_factor_sha256": OLD, "expected_epoch": 3,
            "request_id": "synthetic-case-1", "issued_at": now,
            "expires_at": now + 900, "identity_method": "in_person",
            "identity_case": "synthetic-identity-1"}


def validate(value, rehearsal=False, target=None):
    account, host, hostname = target or (ACCOUNT, HOST, HOSTNAME)
    data = json.dumps(value).encode()
    return approval.validate_coordinator_payload(data, account, host, hostname,
                                                  OLD, 3, int(time.time()), rehearsal)


class IdentityAdmissionTests(unittest.TestCase):
    def test_identity_only_schema_has_no_fabricated_effect_attestations(self):
        self.assertEqual(validate(payload())["request_id"], "synthetic-case-1")
        for extra in ("sessions_revoked", "access_contained", "no_valid_sessions"):
            with self.subTest(extra=extra), self.assertRaises(approval.ApprovalError):
                validate(dict(payload(), **{extra: True}))

    def test_exact_binding_and_independent_identity_are_required(self):
        changes = {"schema": "wrong", "account": "bob@recovery.invalid",
                   "ssh_host": "192.0.2.2", "expected_hostname": "other.invalid",
                   "previous_factor_sha256": "b" * 64, "expected_epoch": 4,
                   "identity_method": "email_only", "identity_case": "",
                   "request_id": "case\nforged=true"}
        for name, value in changes.items():
            with self.subTest(name=name), self.assertRaises(approval.ApprovalError):
                validate(dict(payload(), **{name: value}))

    def test_exact_fields_duplicate_keys_types_and_time_refuse(self):
        original = payload()
        for name in original:
            value = dict(original)
            del value[name]
            with self.subTest(missing=name), self.assertRaises(approval.ApprovalError):
                validate(value)
        for change in ({"expected_epoch": True}, {"expected_epoch": "3"},
                       {"issued_at": True}, {"expires_at": original["issued_at"]},
                       {"issued_at": original["issued_at"] + 60},
                       {"expires_at": original["issued_at"] + 901}):
            with self.subTest(change=change), self.assertRaises(approval.ApprovalError):
                validate(dict(original, **change))
        for data in (b'[]', b'{"schema":"a","schema":"b"}', b'\xff', b'{'):
            with self.subTest(data=data), self.assertRaises(approval.ApprovalError):
                approval.validate_coordinator_payload(data, ACCOUNT, HOST, HOSTNAME,
                                                       OLD, 3, int(time.time()))

    def test_controlled_custody_is_reserved_and_not_real_identity(self):
        account, host, hostname = approval.REHEARSAL_TARGET
        value = dict(payload(), account=account, ssh_host=host,
                     expected_hostname=hostname, identity_method="controlled_test_custody")
        validate(value, rehearsal=True, target=approval.REHEARSAL_TARGET)
        for rehearsal, target in ((False, approval.REHEARSAL_TARGET),
                                  (True, (ACCOUNT, HOST, HOSTNAME))):
            with self.subTest(rehearsal=rehearsal), self.assertRaises(approval.ApprovalError):
                validate(value, rehearsal, target)
        with self.assertRaises(approval.ApprovalError):
            validate(dict(value, identity_method="in_person"), True, approval.REHEARSAL_TARGET)


class CoordinatorSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the existing disposable-key setup; never use the real signer.
        legacy.SignatureTests.setUpClass.__func__(cls)
        cls.coordinator_path = cls.root / "coordinator.json"
        cls.coordinator_signature = cls.root / "coordinator.sig"
        cls.coordinator_bytes = json.dumps(payload()).encode()
        cls.coordinator_path.write_bytes(cls.coordinator_bytes)
        cls.coordinator_path.chmod(0o600)
        subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                        "--detach-sign", "--output", str(cls.coordinator_signature),
                        str(cls.coordinator_path)], env=cls.env, capture_output=True,
                       check=True, timeout=5)
        cls.coordinator_signature.chmod(0o600)

    def verify(self):
        return approval.verify_coordinator_approval(self.coordinator_path,
            self.coordinator_signature, ACCOUNT, HOST, HOSTNAME, OLD, 3)

    def test_real_signature_runs_through_coordinator_native_projection(self):
        actual_verifier = approval.verify_signature
        with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)), mock.patch.object(
                approval, "verify_signature", side_effect=lambda data, sig:
                actual_verifier(data, sig, expected_signer=self.fingerprint)):
            native = self.verify()
        self.assertEqual(native["schema"], "osmap-account-recovery-v1")
        self.assertEqual(native["account"], ACCOUNT)
        self.assertEqual(native["case_id"], "synthetic-case-1")
        self.assertEqual(native["approval_sha256"], hashlib.sha256(self.coordinator_bytes).hexdigest())
        self.assertNotIn("sessions_revoked", native)
        self.assertNotIn("access_contained", native)

    def test_real_valid_unpinned_signer_and_modified_decision_refuse(self):
        with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)), self.assertRaises(approval.ApprovalError):
            self.verify()
        actual_verifier = approval.verify_signature
        self.coordinator_path.write_bytes(self.coordinator_bytes + b" ")
        try:
            with mock.patch.dict(os.environ, GNUPGHOME=str(self.root)), mock.patch.object(
                    approval, "verify_signature", side_effect=lambda data, sig:
                    actual_verifier(data, sig, expected_signer=self.fingerprint)), self.assertRaises(approval.ApprovalError):
                self.verify()
        finally:
            self.coordinator_path.write_bytes(self.coordinator_bytes)

    def test_freshness_is_sampled_after_signature_verification(self):
        value = json.loads(self.coordinator_bytes)
        with mock.patch.object(approval, "verify_signature"), mock.patch.object(
                approval.time, "time", return_value=value["expires_at"]), self.assertRaises(approval.ApprovalError):
            self.verify()


# Run the real source workflow, substituting only external/native/TTY effect
# boundaries. Event files survive command-substitution subshells. No SSH runs.
WORKFLOW = r'''
source "$COORDINATOR_SCRIPT"
event() { printf '%s\n' "$1" >> "$CASE_ROOT/events"; }
ssh() { event forbidden_ssh; return 97; }
require_command() { return 0; }
coordinator_status() { event status; printf '%s\n' "$STATUS"; }
coordinator_identity() {
    event identity
    [[ "$CASE" != unsigned ]] || return 1
    [[ "$CASE" != expired_after_enrollment || ! -f "$CASE_ROOT/enrolled" ]] || return 1
    if [[ "$CASE" == changed_approval && -f "$CASE_ROOT/enrolled" ]]; then
        command python3 -c 'import json,os;v=json.loads(os.environ["NATIVE"]);v["approval_sha256"]="b"*64;print(json.dumps(v))'
    else printf '%s\n' "$NATIVE"; fi
}
prepare_enrollment_material() {
    event enroll
    WORK_ROOT="$CASE_ROOT/enrollment"; mkdir "$WORK_ROOT"
    SECRET_FILE="$WORK_ROOT/secret"; printf '%s\n' 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' > "$SECRET_FILE"
}
show_and_verify_enrollment() { event verify_enrollment; touch "$CASE_ROOT/enrolled"; [[ "$CASE" != enrollment_failed ]]; }
coordinator_authorize() { event authorize; [[ "$CASE" != authorization_failed ]]; }
coordinator_release_authorize() { event release_authorize; [[ "$CASE" != release_denied ]]; }
rotation_snapshot() {
    event snapshot
    [[ "$CASE" != snapshot_failed ]] || { printf '%s\n' 'synthetic-private-native-detail' >&2; return 7; }
    if [[ -f "$CASE_ROOT/installed_digest" ]]; then
        [[ "$CASE" != final_mismatch ]] || { printf '%064d\n' 0; return 0; }
        cat "$CASE_ROOT/installed_digest"
    else
        [[ "$CASE" != stale_prebegin ]] || { printf '%064d\n' 0; return 0; }
        printf '%s\n' "$OLD_DIGEST"
    fi
}
coordinator_native() {
    local verb="$2" payload="$3"
    event "native:$verb"
    [[ "$CASE" != "${verb}_failed" ]] || return 255
    printf '%s' "$payload" | command python3 -c 'import json,os,sys
r=json.load(sys.stdin);verb=sys.argv[1];v=json.loads(os.environ["STATUS"])
v.update(case_id=r["case_id"],case_state={"begin":"sessions_revoked","prepare-factor":"factor_replacement","reconcile":"reconciled"}[verb],state="active" if verb=="reconcile" else "pending",epoch=r["expected_epoch"]+(1 if verb=="reconcile" else 0),existing_factor_sha256=r.get("replacement_factor_sha256") if verb=="reconcile" else r["previous_factor_sha256"])
if os.environ["CASE"]==verb+"_wrong_response":v["epoch"]+=1
print(json.dumps(v))' "$verb"
}
rotation_revoke() {
    event revoke
    [[ "$CASE" != revoke_failed && "$CASE" != revoke_lost_response ]] || return 255
    [[ "$CASE" != revoke_bad_output ]] || { printf '%s\n' 'TOTP_REVOCATION=PASS'; return 0; }
    printf '%s\n' 'TOTP_REVOCATION=PASS' 'active_factor_absent=true' 'revoked_factor_preserved=true' "revoked_factor_sha256=$OLD_DIGEST"
}
remote_provision() {
    event provision
    [[ "$CASE" != install_failed ]] || return 1
    printf '%s\n' "$4" > "$CASE_ROOT/installed_digest"
    [[ "$CASE" != install_lost_response ]] || return 255
    [[ "$CASE" != install_bad_output ]] || { printf '%s\n' 'unexpected'; return 0; }
    printf '%s\n' 'TOTP_PROVISIONING=PASS'
}
coordinator_run "$ACCOUNT" "$HOST" "$HOSTNAME" "$MUTATION"
'''


class CoordinatorWorkflowTests(unittest.TestCase):
    def run_case(self, case="success", mutation=True, rehearsal=False):
        with tempfile.TemporaryDirectory(prefix="osmap-coordinator-workflow-") as root:
            account = approval.REHEARSAL_TARGET[0] if rehearsal else ACCOUNT
            now = int(time.time())
            native = {"schema": "osmap-account-recovery-v1", "account": account,
                      "case_id": "synthetic-case-1", "expected_epoch": 3,
                      "previous_factor_sha256": OLD, "approval_sha256": "c" * 64,
                      "identity_method": "controlled_test_custody" if rehearsal else "in_person",
                      "identity_case": "synthetic-identity-1", "issued_at": now,
                      "expires_at": now + 900}
            status = {"schema": "osmap-account-recovery-v1", "account": account,
                      "state": "active", "epoch": 3, "existing_factor_sha256": OLD,
                      "case_id": None, "case_state": None, "failure": None, "session_failure": None,
                      "runtime_paths": {"factor_directory": "/var/lib/custom/state/secrets/totp",
                                        "revoked_directory": "/var/lib/custom/state/secrets/totp-revoked"}}
            env = dict(os.environ, COORDINATOR_SCRIPT=str(SCRIPT), CASE_ROOT=root,
                       CASE=case, ACCOUNT=account, HOST=HOST, HOSTNAME=HOSTNAME,
                       STATUS=json.dumps(status), NATIVE=json.dumps(native), OLD_DIGEST=OLD,
                       COORDINATOR_REHEARSAL=str(rehearsal).lower(), MUTATION=str(mutation).lower())
            result = subprocess.run(["bash", "-c", WORKFLOW], env=env,
                                    capture_output=True, text=True, timeout=10, start_new_session=True)
            events_path = Path(root, "events")
            events = events_path.read_text().splitlines() if events_path.exists() else []
            self.assertFalse(Path(root, "enrollment").exists(), "disposable enrollment scratch leaked")
            self.assertNotIn("forbidden_ssh", events)
            self.assertNotIn("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", result.stdout + result.stderr)
            return result, events

    def test_real_workflow_orders_identity_containment_effects_and_final_decision(self):
        result, events = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ["status", "identity", "enroll", "verify_enrollment", "authorize",
                                  "snapshot", "identity", "native:begin", "native:prepare-factor",
                                  "revoke", "provision", "snapshot", "release_authorize", "native:reconcile"])
        self.assertIn("ACCOUNT_RECOVERY=PASS", result.stdout)
        self.assertIn("password_reset_performed=false", result.stdout)
        self.assertIn("mail_connection_termination_qualified=false", result.stdout)

    def test_unsigned_stale_changed_or_denied_identity_never_contains_or_mutates(self):
        for case in ("unsigned", "expired_after_enrollment", "changed_approval",
                     "authorization_failed", "enrollment_failed", "stale_prebegin"):
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(event.startswith("native:") for event in events))
                self.assertNotIn("revoke", events)
                self.assertNotIn("provision", events)

    def test_uncertainty_stops_at_first_effect_boundary_without_retry_or_release(self):
        stops = {"begin_failed": "native:begin", "begin_wrong_response": "native:begin",
                 "prepare-factor_failed": "native:prepare-factor", "prepare-factor_wrong_response": "native:prepare-factor",
                 "revoke_failed": "revoke", "revoke_lost_response": "revoke", "revoke_bad_output": "revoke",
                 "install_failed": "provision", "install_lost_response": "provision", "install_bad_output": "provision",
                 "final_mismatch": "snapshot", "release_denied": "release_authorize",
                 "reconcile_failed": "native:reconcile", "reconcile_wrong_response": "native:reconcile"}
        for case, last in stops.items():
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertEqual(result.returncode, 24, result.stderr)
                self.assertEqual(events[-1], last)
                for event in ("native:begin", "native:prepare-factor", "revoke", "provision", "native:reconcile"):
                    self.assertLessEqual(events.count(event), 1, (case, events))
                self.assertIn("ACCOUNT_RECOVERY=INCOMPLETE", result.stdout)
                self.assertIn("containment_release=UNKNOWN", result.stdout)
                self.assertNotIn("ACCOUNT_RECOVERY=PASS", result.stdout)

    def test_prebegin_snapshot_refusal_retains_fixed_cause_without_private_text(self):
        result, events = self.run_case("snapshot_failed")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(events[-1], "snapshot")
        self.assertFalse(any(event.startswith("native:") for event in events))
        self.assertNotIn("synthetic-private-native-detail", result.stdout + result.stderr)
        diagnostic = json.loads(result.stderr)
        self.assertEqual(diagnostic["schema"], "osmap-account-recovery-prebegin-refusal-v1")
        self.assertEqual(diagnostic["phase"], "factor_snapshot")
        self.assertEqual(diagnostic["cause"], "FACTOR_SNAPSHOT_REFUSED")
        self.assertEqual(diagnostic["exit"], 7)
        self.assertFalse(diagnostic["native_begin_dispatched"])
        self.assertFalse(diagnostic["automatic_mutation_retry"])
        self.assertEqual(diagnostic["observation_bytes"], len(b"synthetic-private-native-detail"))
        self.assertEqual(diagnostic["observation_sha256"],
                         hashlib.sha256(b"synthetic-private-native-detail").hexdigest())

    def test_dry_run_has_no_enrollment_tty_or_native_effect(self):
        result, events = self.run_case(mutation=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ["status", "identity"])
        self.assertIn("COORDINATOR_DRY_RUN=PASS", result.stdout)
        self.assertIn("containment_and_sessions_not_yet_performed=true", result.stdout)

    def test_controlled_rehearsal_does_not_claim_real_user_recovery(self):
        result, _ = self.run_case(rehearsal=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ACCOUNT_RECOVERY_REHEARSAL=PASS", result.stdout)
        self.assertIn("real_user_identity_verification=false", result.stdout)
        self.assertNotIn("ACCOUNT_RECOVERY=PASS", result.stdout)

    def test_both_actual_terminal_decisions_refuse_without_a_private_terminal(self):
        for function in ("coordinator_authorize", "coordinator_release_authorize"):
            env = dict(os.environ, COORDINATOR_SCRIPT=str(SCRIPT), FUNCTION=function,
                       COORDINATOR_REHEARSAL="false")
            result = subprocess.run(["bash", "-c", 'source "$COORDINATOR_SCRIPT"\n"$FUNCTION" alice@recovery.invalid recovery.invalid synthetic-case-1'],
                                    env=env, capture_output=True, text=True, timeout=5, start_new_session=True)
            self.assertNotEqual(result.returncode, 0, function)


class SerializedProducerConsumerTests(unittest.TestCase):
    def test_actual_native_status_output_through_real_shell_consumer_and_mutations(self):
        if STATUS_FIXTURES is None:
            self.skipTest("actual Rust output requires --status-fixtures LOG; ordinary workflow tests remain synthetic")
        rows = [json.loads(line.split("=", 1)[1]) for line in Path(STATUS_FIXTURES).read_text().splitlines()
                if line.startswith("RECOVERY_STATUS_FIXTURE=")]
        self.assertEqual(len(rows), 4)
        for row, verb in zip(rows[1:], ("begin", "prepare-factor", "reconcile")):
            env = dict(os.environ, COORDINATOR_SCRIPT=str(SCRIPT), VERB=verb,
                       ACCOUNT=row["account"], CASE_ID=row["case_id"], EPOCH=str(rows[0]["epoch"]),
                       DIGEST=row["existing_factor_sha256"])
            code = 'source "$COORDINATOR_SCRIPT"\ncoordinator_result "$VERB" "$ACCOUNT" "$CASE_ID" "$EPOCH" "$DIGEST"'
            good = subprocess.run(["bash", "-c", code], env=env, input=json.dumps(row),
                                  capture_output=True, text=True, timeout=5, start_new_session=True)
            self.assertEqual(good.returncode, 0, (verb, good.stderr))
            changes = {"schema": "wrong", "account": "bob@recovery.invalid",
                       "case_id": "other-case", "epoch": row["epoch"] + 1,
                       "existing_factor_sha256": "0" * 64,
                       "state": "unknown", "failure": "sessions_incomplete",
                       "session_failure": {"stage": "write", "completed_writes": 1, "attempted_writes": 2}}
            for field, value in changes.items():
                changed = copy.deepcopy(row)
                changed[field] = value
                with self.subTest(verb=verb, field=field):
                    refused = subprocess.run(["bash", "-c", code], env=env, input=json.dumps(changed),
                                             capture_output=True, text=True, timeout=5, start_new_session=True)
                    self.assertNotEqual(refused.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--status-fixtures")
    args, remaining = parser.parse_known_args()
    STATUS_FIXTURES = args.status_fixtures
    unittest.main(argv=[__file__, *remaining])
