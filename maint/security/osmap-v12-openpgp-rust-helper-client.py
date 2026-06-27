#!/usr/bin/env python3
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "openpgp_helper_client.rs"
CFG = ROOT / "maint" / "security" / "v12-openpgp-rust-helper-client.example.json"
LIB = ROOT / "src" / "lib.rs"


def fail(msg):
    print(msg, file=sys.stderr)
    return 1


def main():
    if "--self-test" in sys.argv:
        for path in (SRC, CFG, LIB):
            if not path.exists():
                return fail(f"missing {path}")
        source = SRC.read_text()
        forbidden_runtime_source = [
            "Command::new",
            "std::process::Command",
            "sh -c",
            "/bin/sh",
            "gpg --",
            "gpgme_op_",
        ]
        found = [token for token in forbidden_runtime_source if token in source]
        if found:
            return fail("forbidden token in Rust helper client source: " + ", ".join(found))
        if "#[test]" in source:
            return fail("Slice 9 keeps Rust behavior checks in the V12 gate to avoid V10 inventory drift")
        required_snippets = [
            "OPENPGP_HELPER_PROTOCOL_ARG",
            "MAX_HELPER_REQUEST_BYTES",
            "MAX_HELPER_STDOUT_BYTES",
            "MAX_HELPER_STDERR_BYTES",
            "DEFAULT_HELPER_TIMEOUT",
            "OpenPgpHelperInvocationPlan",
            "validate_helper_path",
            "is_safe_helper_path_byte",
            "classify_helper_result",
            "HelperExitNonZero",
            "MalformedHelperJson",
            "OversizedStdout",
            "OversizedStderr",
            "byte.is_ascii_alphanumeric()",
            "matches!(byte, b'/' | b'.' | b'_' | b'-')",
        ]
        missing = [snippet for snippet in required_snippets if snippet not in source]
        if missing:
            return fail("missing required Rust boundary snippet: " + ", ".join(missing))
        if not re.search(r"pub\s+mod\s+openpgp_helper_client\s*;", LIB.read_text()):
            return fail("src/lib.rs does not expose openpgp_helper_client module")
        lib_text = LIB.read_text()
        if lib_text.startswith("pub mod openpgp_helper_client;"):
            return fail("openpgp_helper_client module was inserted before crate docs")
        data = json.loads(CFG.read_text())
        invariants = data.get("safety_invariants", {})
        required_false = [
            "browser_ui_integrated",
            "direct_gpg_runtime_crypto_allowed",
            "helper_process_spawned_by_slice",
            "message_decryption_attempted",
            "message_encryption_attempted",
            "message_signature_verification_attempted",
            "message_signing_attempted",
            "passphrases_prompted_or_stored",
            "pgp_mime_parsing_attempted",
            "private_key_access_attempted",
            "secret_key_listing_attempted",
            "shell_invocation_allowed",
        ]
        bad = [key for key in required_false if invariants.get(key) is not False]
        if bad:
            return fail("bad safety invariant: " + ", ".join(bad))
        print("V12 OpenPGP Rust helper client boundary self-test passed")
        return 0
    report = {
        "schema": "osmap-v12-openpgp-rust-helper-client-boundary-report-v1",
        "rust_helper_client_status": "available",
        "source_path": "src/openpgp_helper_client.rs",
        "test_location": "maint/security/osmap-v12-openpgp-rust-helper-client.py, make v12-check, and cargo test",
        "allowed_operations": ["capability_status", "diagnostic_ping", "policy_check"],
        "limits": {
            "max_request_bytes": 4096,
            "max_stdout_bytes": 8192,
            "max_stderr_bytes": 2048,
            "timeout_seconds": 5,
        },
        "safety_invariants": json.loads(CFG.read_text())["safety_invariants"],
        "valid": True,
        "warnings": [],
        "errors": [],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
