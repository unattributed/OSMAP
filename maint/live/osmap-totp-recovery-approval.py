#!/usr/bin/env python3
"""Verify a bounded operator attestation; never create or sign an authorization."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

SHOPKEEPER = "F55E404E91A0753701F91B01A7228D3FB5084B34"
SCHEMA = "osmap-totp-recovery-approval-v1"
MAX_BYTES = 16384
FIELDS = {
    "schema", "account", "ssh_host", "expected_hostname", "previous_factor_sha256",
    "request_id", "issued_at", "expires_at", "identity_method", "identity_case",
    "session_case", "containment_case", "sessions_revoked", "access_contained",
}


class ApprovalError(ValueError):
    pass


def read_private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or metadata.st_size > MAX_BYTES):
            raise ApprovalError("approval/signature must be bounded owner-only regular files")
        data = source.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise ApprovalError("empty or oversized approval/signature")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalError("duplicate approval field")
        result[key] = value
    return result


def validate_payload(data, account, host, hostname, digest, now):
    try:
        approval = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ApprovalError("invalid approval JSON") from error
    if not isinstance(approval, dict) or set(approval) != FIELDS:
        raise ApprovalError("unexpected approval schema fields")
    expected = {"schema": SCHEMA, "account": account, "ssh_host": host,
                "expected_hostname": hostname, "previous_factor_sha256": digest}
    if any(approval[key] != value for key, value in expected.items()):
        raise ApprovalError("approval does not match the exact account, host and factor state")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ApprovalError("invalid factor digest")
    for field in ("request_id", "identity_case", "session_case", "containment_case"):
        value = approval[field]
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
            raise ApprovalError("missing or invalid opaque approval reference")
    if approval["identity_method"] not in ("in_person", "established_out_of_band"):
        raise ApprovalError("independent identity verification must be attested")
    if approval["sessions_revoked"] is not True or approval["access_contained"] is not True:
        raise ApprovalError("session revocation and access containment must be attested")
    issued, expires = approval["issued_at"], approval["expires_at"]
    if (type(issued) is not int or type(expires) is not int
            or not 0 <= issued <= now < expires or not 0 < expires - issued <= 900):
        raise ApprovalError("approval expired, future-dated, or exceeds the 15-minute lifetime")
    return approval


def verify_signature(data, signature, expected_signer=SHOPKEEPER):
    # Verify private snapshots, not paths that can change between parsing and
    # signature checking. No automatic key discovery or import is allowed.
    with tempfile.TemporaryDirectory(prefix="osmap-recovery-verify-") as directory:
        paths = [Path(directory, "approval"), Path(directory, "signature")]
        for path, payload in zip(paths, (data, signature)):
            with path.open("xb") as destination:
                os.chmod(path, 0o600)
                destination.write(payload)
        result = subprocess.run(
            ["gpg", "--no-options", "--batch", "--no-auto-key-retrieve",
             "--no-auto-key-import", "--status-fd=1", "--verify", str(paths[1]), str(paths[0])],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False,
        )
    statuses = [line.split() for line in result.stdout.decode("ascii", errors="replace").splitlines()
                if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY",
                "FAILURE", "NODATA", "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED"}
    if any(len(fields) < 2 or fields[1] in rejected for fields in statuses):
        raise ApprovalError("expired, revoked, or invalid approval signature")
    signatures = [fields for fields in statuses if fields[1] == "VALIDSIG"]
    if result.returncode or len(signatures) != 1 or len(signatures[0]) != 12:
        raise ApprovalError("approval signature could not be verified")
    if signatures[0][-1] != expected_signer:
        raise ApprovalError("approval is not signed by the pinned Shopkeeper identity")


def verify_approval(path, signature_path, account, host, hostname, digest):
    data, signature = read_private_file(path), read_private_file(signature_path)
    verify_signature(data, signature)
    # Timestamp is sampled after signature checking so a slow verifier cannot
    # make an already expired approval valid at the end of verification.
    approval = validate_payload(data, account, host, hostname, digest, int(time.time()))
    return approval, hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", action="store_true")
    parser.add_argument("--approval")
    parser.add_argument("--signature")
    parser.add_argument("--account", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    if args.template:
        if args.approval or args.signature:
            parser.error("template mode cannot verify an approval")
        now = int(time.time())
        print(json.dumps({
            "schema": SCHEMA, "account": args.account, "ssh_host": args.host,
            "expected_hostname": args.expected_hostname, "previous_factor_sha256": args.digest,
            "request_id": "", "issued_at": now, "expires_at": now + 900,
            "identity_method": "REQUIRES_OPERATOR_VERIFICATION", "identity_case": "",
            "session_case": "", "containment_case": "",
            "sessions_revoked": False, "access_contained": False,
        }, indent=2))
        return 0
    if not args.approval or not args.signature:
        parser.error("verification requires --approval and --signature")
    try:
        approval, digest = verify_approval(args.approval, args.signature, args.account,
                                          args.host, args.expected_hostname, args.digest)
    except (ApprovalError, OSError, subprocess.SubprocessError):
        # Neither an untrusted approval nor gpg's diagnostic text is reflected.
        print("RECOVERY_APPROVAL=REFUSED")
        return 1
    print("RECOVERY_APPROVAL=PASS")
    print(f"approval_sha256={digest}")
    print(f"approval_request_id={approval['request_id']}")
    print("identity_verification_attested=true")
    print("session_revocation_attested=true")
    print("access_containment_attested=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
