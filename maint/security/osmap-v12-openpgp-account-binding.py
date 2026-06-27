#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "osmap-v12-openpgp-account-bindings-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-account-binding-report-v1"
FULL_FINGERPRINT_RE = re.compile(r"^[A-F0-9]{40}$|^[A-F0-9]{64}$")
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,189}$")
FORBIDDEN_FIELDS = {
    "email_match",
    "email_key_match",
    "match_by_email",
    "match_by_uid",
    "uid_match",
    "user_id",
    "user_id_match",
    "uid",
    "key_id",
    "short_key_id",
    "recipient_lookup",
    "auto_discover",
    "autodiscover",
    "keyserver_lookup",
    "wkd_lookup",
    "trust_uid_text",
}
REQUIRED_POLICY = {
    "require_explicit_fingerprint": True,
    "reject_email_only_key_match": True,
    "reject_short_key_ids": True,
    "ambiguous_match_fails_closed": True,
}


@dataclass
class ValidationState:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    normalized_accounts: list[dict[str, Any]] = field(default_factory=list)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)


class ValidationError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc


def normalize_fingerprint(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\s:]", "", value).upper()


def looks_like_full_fingerprint(value: str) -> bool:
    return bool(FULL_FINGERPRINT_RE.fullmatch(value))


def contains_control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def walk_forbidden_fields(obj: Any, state: ValidationState, prefix: str = "$") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in FORBIDDEN_FIELDS:
                state.error(f"forbidden email-only or user-ID matching field at {prefix}.{key}")
            walk_forbidden_fields(value, state, f"{prefix}.{key}")
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            walk_forbidden_fields(value, state, f"{prefix}[{idx}]")


def inventory_fingerprints(inventory_report: Any | None) -> set[str] | None:
    if inventory_report is None:
        return None
    try:
        keys = inventory_report["public_key_inventory"]["keys"]
    except (TypeError, KeyError):
        raise ValidationError("inventory report does not look like osmap-v12-openpgp-diagnostics output")
    result: set[str] = set()
    for item in keys:
        if not isinstance(item, dict):
            continue
        fp = normalize_fingerprint(item.get("primary_fingerprint", ""))
        if looks_like_full_fingerprint(fp):
            result.add(fp)
    return result


def validate_account(entry: Any, state: ValidationState, seen_accounts: set[str], inventory: set[str] | None) -> None:
    if not isinstance(entry, dict):
        state.error("account entry is not an object")
        return

    account = entry.get("account", "")
    if not isinstance(account, str) or not account:
        state.error("account entry is missing account")
        return
    canonical_account = account.lower()
    if contains_control(account) or not ACCOUNT_RE.fullmatch(account):
        state.error(f"account has unsupported identity shape: {account!r}")
    if canonical_account in seen_accounts:
        state.error(f"duplicate account binding: {canonical_account}")
    seen_accounts.add(canonical_account)

    enabled = entry.get("openpgp_enabled", False)
    if not isinstance(enabled, bool):
        state.error(f"openpgp_enabled must be boolean for {canonical_account}")
        enabled = False

    policy = entry.get("policy", {})
    if not isinstance(policy, dict):
        state.error(f"policy must be object for {canonical_account}")
        policy = {}
    for name, required_value in REQUIRED_POLICY.items():
        if policy.get(name) is not required_value:
            state.error(f"policy.{name} must be {required_value} for {canonical_account}")

    primary = normalize_fingerprint(entry.get("primary_fingerprint", ""))
    allowed_raw = entry.get("allowed_fingerprints", [])
    if not isinstance(allowed_raw, list):
        state.error(f"allowed_fingerprints must be a list for {canonical_account}")
        allowed_raw = []
    allowed = [normalize_fingerprint(value) for value in allowed_raw]

    if enabled:
        if not primary:
            state.error(f"enabled account missing primary_fingerprint: {canonical_account}")
        if primary and not looks_like_full_fingerprint(primary):
            state.error(f"enabled account uses non-full fingerprint: {canonical_account}")
        if not allowed:
            state.error(f"enabled account missing allowed_fingerprints: {canonical_account}")
        for fp in allowed:
            if not looks_like_full_fingerprint(fp):
                state.error(f"allowed fingerprint is not a full fingerprint for {canonical_account}: {fp!r}")
        if primary and primary not in allowed:
            state.error(f"primary fingerprint is not explicitly allowed for {canonical_account}")
        if len(allowed) != len(set(allowed)):
            state.error(f"duplicate allowed fingerprint for {canonical_account}")
        if inventory is not None:
            for fp in allowed:
                if looks_like_full_fingerprint(fp) and fp not in inventory:
                    state.error(f"configured fingerprint absent from diagnostics inventory for {canonical_account}: {fp}")
    else:
        if primary or allowed:
            state.error(f"disabled account must not carry OpenPGP fingerprints: {canonical_account}")

    state.normalized_accounts.append(
        {
            "account": canonical_account,
            "openpgp_enabled": enabled,
            "primary_fingerprint": primary if enabled else "",
            "allowed_fingerprint_count": len(allowed) if enabled else 0,
            "policy_requires_explicit_fingerprint": policy.get("require_explicit_fingerprint") is True,
            "policy_rejects_email_only_key_match": policy.get("reject_email_only_key_match") is True,
            "policy_rejects_short_key_ids": policy.get("reject_short_key_ids") is True,
            "policy_ambiguous_match_fails_closed": policy.get("ambiguous_match_fails_closed") is True,
        }
    )


def validate_config(config: Any, inventory_report: Any | None = None) -> ValidationState:
    state = ValidationState()
    if not isinstance(config, dict):
        state.error("top-level binding config is not an object")
        return state
    if config.get("schema") != SCHEMA:
        state.error(f"schema must be {SCHEMA}")
    walk_forbidden_fields(config, state)
    accounts = config.get("accounts")
    if not isinstance(accounts, list):
        state.error("accounts must be a list")
        return state
    if not accounts:
        state.error("accounts must not be empty")
        return state

    inventory = inventory_fingerprints(inventory_report)
    seen_accounts: set[str] = set()
    for entry in accounts:
        validate_account(entry, state, seen_accounts, inventory)
    if not any(item.get("openpgp_enabled") for item in state.normalized_accounts):
        state.warning("no OpenPGP-enabled accounts are configured")
    return state


def build_report(config_path: Path, state: ValidationState) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": utc_now(),
        "config_path": str(config_path),
        "valid": not state.errors,
        "errors": state.errors,
        "warnings": state.warnings,
        "account_bindings": state.normalized_accounts,
        "purpose": "Validate explicit account-to-OpenPGP-fingerprint binding before any cryptographic operation is integrated.",
        "safety_invariants": {
            "email_only_key_matching_allowed": False,
            "short_key_ids_allowed": False,
            "uid_text_authorization_allowed": False,
            "ambiguous_key_match_fails_closed": True,
            "message_decryption_attempted": False,
            "message_signature_verification_attempted": False,
            "message_signing_attempted": False,
            "message_encryption_attempted": False,
            "passphrases_prompted_or_stored": False,
            "private_key_material_collected": False,
            "browser_request_handler_touched_keys": False,
        },
        "next_required_boundary": "OpenPGP helper integration must consume only validated explicit account fingerprints and must preserve fail-closed behavior.",
    }


def write_outputs(out_dir: Path, report: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "openpgp-account-binding-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# OSMAP V12 OpenPGP account fingerprint binding report",
        "",
        f"Generated UTC: `{report['generated_at_utc']}`",
        f"Valid: `{str(report['valid']).lower()}`",
        "",
        "## Safety invariants",
        "",
    ]
    for key, value in report["safety_invariants"].items():
        lines.append(f"- `{key}`: `{str(value).lower()}`")
    lines.extend(["", "## Accounts", ""])
    for account in report["account_bindings"]:
        lines.append(
            f"- `{account['account']}`: enabled=`{str(account['openpgp_enabled']).lower()}`, allowed_fingerprint_count=`{account['allowed_fingerprint_count']}`"
        )
    if report["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {item}" for item in report["errors"])
    (out_dir / "openpgp-account-binding-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def valid_example_config() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "accounts": [
            {
                "account": "alice@example.invalid",
                "openpgp_enabled": True,
                "primary_fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
                "allowed_fingerprints": ["0123456789ABCDEF0123456789ABCDEF01234567"],
                "policy": dict(REQUIRED_POLICY),
            },
            {
                "account": "bob@example.invalid",
                "openpgp_enabled": False,
                "primary_fingerprint": "",
                "allowed_fingerprints": [],
                "policy": dict(REQUIRED_POLICY),
            },
        ],
    }


def assert_invalid(name: str, config: dict[str, Any], inventory: dict[str, Any] | None = None) -> None:
    state = validate_config(config, inventory)
    if not state.errors:
        raise AssertionError(f"expected invalid config for {name}")


def self_test() -> None:
    good = valid_example_config()
    state = validate_config(good)
    if state.errors:
        raise AssertionError(f"valid example failed: {state.errors}")

    duplicate = valid_example_config()
    duplicate["accounts"].append(dict(duplicate["accounts"][0]))
    assert_invalid("duplicate account", duplicate)

    short_key = valid_example_config()
    short_key["accounts"][0]["primary_fingerprint"] = "D039F691"
    short_key["accounts"][0]["allowed_fingerprints"] = ["D039F691"]
    assert_invalid("short key id", short_key)

    email_only = valid_example_config()
    email_only["accounts"][0]["match_by_email"] = True
    assert_invalid("email-only matching", email_only)

    uid_match = valid_example_config()
    uid_match["accounts"][0]["user_id_match"] = "Alice Example <alice@example.invalid>"
    assert_invalid("user id matching", uid_match)

    primary_missing = valid_example_config()
    primary_missing["accounts"][0]["allowed_fingerprints"] = ["FEDCBA9876543210FEDCBA9876543210FEDCBA98"]
    assert_invalid("primary not in allowed list", primary_missing)

    missing_inventory = valid_example_config()
    inventory = {
        "schema": "osmap-v12-openpgp-diagnostics-v1",
        "public_key_inventory": {"keys": [{"primary_fingerprint": "FEDCBA9876543210FEDCBA9876543210FEDCBA98"}]},
    }
    assert_invalid("missing inventory fingerprint", missing_inventory, inventory)

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "bindings.json"
        cfg.write_text(json.dumps(good), encoding="utf-8")
        report = build_report(cfg, validate_config(load_json(cfg)))
        write_outputs(Path(tmp) / "out", report)
        assert (Path(tmp) / "out" / "openpgp-account-binding-report.json").exists()

    print("V12 OpenPGP account binding self-test passed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate OSMAP V12 OpenPGP account fingerprint binding config")
    parser.add_argument("--check", type=Path, help="account binding JSON file to validate")
    parser.add_argument("--inventory", type=Path, help="optional Slice 2 diagnostics JSON inventory")
    parser.add_argument("--output", type=Path, help="directory for validation report")
    parser.add_argument("--self-test", action="store_true", help="run regression self-test")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if not args.check:
        parser.error("--check is required unless --self-test is used")
    config = load_json(args.check)
    inventory = load_json(args.inventory) if args.inventory else None
    state = validate_config(config, inventory)
    report = build_report(args.check, state)
    if args.output:
        write_outputs(args.output, report)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not state.errors else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
