"""Keep native OpenPGP authority out of browser route handlers.

V12's original scaffold had no runtime OpenPGP route, so its historical gate
rejected every mention of OpenPGP. The approved UX epic now has browser routes
for settings and protected mail. Those routes may parse finite choices and call
the authenticated gateway; they must not invoke helper clients, processes or
native crypto directly. This check retains that boundary without treating a
working UI label or high-level request type as a violation.
"""

import re


FORBIDDEN_DIRECT_AUTHORITY = re.compile(
    r"(?:"
    r"\b(?:std::process::)?Command::new\s*\("
    r"|\bstd::process\b"
    r"|\bprocess\b"
    r"|\bSystemCommandExecutor\b"
    r"|\brun_with_stdin_timeout\s*\("
    r"|\b(?:gpgme|libloading)\b"
    r"|\bopenpgp_(?:helper_client|inventory_runtime|inventory_process|crypto_runtime|crypto_process|crypto)\b"
    r"|\b(?:replace_operator|write_operator|import_public|remove_public)\s*\("
    r")"
)


def unexpected_reference(_name, source):
    return FORBIDDEN_DIRECT_AUTHORITY.search(source) is not None


def http_openpgp_references(http_dir, root):
    if not http_dir.exists():
        return []
    return [
        str(path.relative_to(root))
        for path in sorted(http_dir.rglob("*.rs"))
        if not path.name.endswith("_tests.rs")
        if unexpected_reference(
            path.relative_to(http_dir).as_posix(),
            path.read_text(encoding="utf-8"),
        )
    ]


def self_test():
    for allowed in (
        '"openpgp"',
        'crate::openpgp_bindings::Requirement',
        'crate::openpgp_inventory::Inventory::parse',
        'self.gateway.change_keys(context, session, request)',
    ):
        assert not unexpected_reference("routes_keys.rs", allowed)
    for forbidden in (
        "crate::openpgp_helper_client::invoke()",
        "crate::openpgp_inventory_runtime::Client",
        "crate::openpgp_inventory_process::execute()",
        "crate::openpgp_crypto_runtime::Client",
        'std::process::Command::new("gpg")',
        'Command::new("gpg")',
        "gpgme::Context",
        "use crate::openpgp_crypto_runtime as crypto;",
        "use crate::{openpgp_crypto_runtime};",
        "use std::process::{Command as Process};",
        "use std::{process as child};",
        "SystemCommandExecutor.run_with_stdin_timeout(...)",
        "store.replace_operator(update)",
    ):
        assert unexpected_reference("routes_keys.rs", forbidden)


if __name__ == "__main__":
    self_test()
    print("OpenPGP HTTP authority boundary positive and negative controls passed")
