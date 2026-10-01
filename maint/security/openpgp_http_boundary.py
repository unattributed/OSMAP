"""Preserve V12 crypto-handler isolation while permitting reviewed inventory UI.

Only exact presentation literals/symbols and the synthetic metadata parser are
allowed below. Runtime clients, processes and historical crypto helpers remain
forbidden in every browser route. This is not runtime crypto qualification.
"""
import re

UI_REFERENCES = {
    "header_theme.rs": (
        '"openpgp"',
        '"/settings?section=openpgp"',
        '"/settings?section=openpgp&folder=INBOX"',
        '"https://invalid.test/settings?section=openpgp"',
        "openpgp_return_tests",
        "finite_openpgp_theme_return",
    ),
    "routes_settings.rs": (
        '"openpgp"',
        '"OpenPGP Settings"',
        '"OpenPGP Key Management"',
        '"<p>Open Key Management from OpenPGP Settings.</p>"',
        "crate::http_ui::render_openpgp_settings",
    ),
    "key_inventory_fixture.rs": ("crate::openpgp_inventory::Inventory::parse", '"openpgp"'),
}


def unexpected_reference(name, source):
    for allowed in UI_REFERENCES.get(name, ()):
        source = source.replace(allowed, "")
    return bool(re.search(r"openpgp", source, re.IGNORECASE))


def http_openpgp_references(http_dir, root):
    if not http_dir.exists():
        return []
    return [str(path.relative_to(root)) for path in sorted(http_dir.rglob("*.rs"))
            if unexpected_reference(path.relative_to(http_dir).as_posix(),
                                    path.read_text(encoding="utf-8"))]


def self_test():
    for name, allowed in UI_REFERENCES.items():
        assert not unexpected_reference(name, "\n".join(allowed))
        for forbidden in ("crate::openpgp_helper_client::invoke()",
                          "crate::openpgp_inventory_runtime::Client",
                          "crate::openpgp_inventory_process::execute()",
                          "crate::openpgp_inventory::Inventory::to_bytes()"):
            assert unexpected_reference(name, "\n".join(allowed) + forbidden)
        assert unexpected_reference("unreviewed.rs", "\n".join(allowed))
    assert unexpected_reference("nested/routes_settings.rs", '"openpgp"')


if __name__ == "__main__":
    self_test()
    print("OpenPGP HTTP boundary positive and negative controls passed")
