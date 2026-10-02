#!/usr/bin/env python3
"""Exercise actual key-management links/forms in synthetic no-JS browsers.

The fixture never imports/removes keys. POST refusal is the gateway's deliberate
Unavailable result, not fresh-auth qualification. No live account or host is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server

PRIMARY = "0123456789ABCDEF0123456789ABCDEF01234567"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    repo = Path(__file__).resolve().parents[2]
    sources = ["src/settings_openpgp_ui.rs", "src/key_inventory_ui.rs",
               "src/http/routes_keys.rs", "src/http.rs", "src/http/key_inventory_fixture.rs"]
    before = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in sources}
    checks, blocked = [], []
    with tempfile.TemporaryDirectory(prefix="osmap-key-interactions-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        context = browser.new_context(java_script_enabled=False,
            user_agent="KeyInventoryInteractive", viewport={"width": 1600, "height": 1100})

        def constrain(route):
            if route.request.url.startswith(origin + "/") and not route.request.url.endswith("/send"):
                route.continue_()
            else:
                blocked.append(route.request.resource_type)
                route.abort()

        context.route("**/*", constrain)
        page = context.new_page()

        def visit(path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response and response.status == 200, path
            assert response.headers["cache-control"] == "no-store"

        def follow(locator, suffix):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                locator.click()
            assert navigation.value.status == 200
            assert page.url == origin + suffix

        def opened(panel):
            expect(page.locator(panel)).to_have_attribute("open", "")
            expect(page.locator(panel + " form")).to_be_visible()

        def screenshot(name):
            page.screenshot(path=str(args.output / name), full_page=True)

        try:
            visit("/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

            visit("/settings?section=openpgp")
            follow(page.get_by_role("link", name="Choose account key", exact=True),
                   "/settings/keys?panel=account")
            opened("#account-binding")
            primary = page.locator('#account-binding select[name="primary_fingerprint"]')
            signing = page.locator('#account-binding select[name="signing_fingerprint"]')
            expect(primary).to_be_visible()
            expect(signing).to_be_visible()
            assert primary.locator(f'option[value="{PRIMARY}"]').count() == 1
            assert signing.locator(f'option[value="{PRIMARY}"]').count() == 1
            primary.select_option(PRIMARY)
            signing.select_option(PRIMARY)
            expect(primary).to_have_value(PRIMARY)
            expect(signing).to_have_value(PRIMARY)
            checks.append("PAGE19 account action opens actual PAGE21 form with selectable inventoried primary/signer")
            screenshot("account-key-select.png")

            for name in ["Edit signing policy", "Edit encryption policy"]:
                visit("/settings?section=openpgp")
                follow(page.get_by_role("link", name=name, exact=True), "/settings/keys?panel=policy")
                opened("#protection-policy")
                expect(page.locator('#protection-policy select[name="signing"]')).to_be_visible()
                expect(page.locator('#protection-policy select[name="encryption"]')).to_be_visible()
            checks.append("PAGE19 signing/encryption policy actions both open real policy form without JavaScript")
            screenshot("policy-open.png")

            visit("/settings/keys")
            follow(page.locator(".key-management-toolbar").get_by_role("link", name="Import public key", exact=True),
                   "/settings/keys?panel=import#public-import")
            opened("#public-import")
            expect(page.locator('#public-import textarea[name="certificate"]')).to_be_visible()
            expect(page.locator('#public-import input[name="expected_primary_fingerprint"]')).to_be_visible()
            expect(page.locator("#public-import").get_by_role("button", name="Import public certificate", exact=True)).to_be_enabled()
            checks.append("PAGE21 Import toolbar navigates to an open visible public-certificate form")
            screenshot("import-open.png")

            visit("/settings/keys")
            follow(page.locator(".key-management-toolbar").get_by_role("link", name="+ Add binding", exact=True),
                   "/settings/keys?panel=recipient#recipient-binding")
            opened("#recipient-binding")
            expect(page.locator('#recipient-binding input[name="address"]')).to_be_visible()
            expect(page.locator('#recipient-binding input[name="primary_fingerprint"]')).to_be_visible()
            checks.append("PAGE21 Add binding toolbar opens actual recipient fingerprint/address form")
            screenshot("recipient-open.png")

            visit("/settings/keys")
            page.locator("#public-inventory > summary").click()
            expect(page.locator("#public-inventory")).to_have_attribute("open", "")
            row = page.locator(".public-key-row").first
            row.locator(":scope > summary").click()
            expect(row.get_by_label("Full public fingerprint").first).to_have_value(PRIMARY)
            row.get_by_text("Remove public certificate", exact=True).first.click()
            remove = row.get_by_role("button", name="Remove public certificate", exact=True)
            expect(remove).to_be_visible()
            expect(remove).to_be_enabled()
            checks.append("Imported public key expands and exposes enabled removal action; no removal executed")
            screenshot("remove-action-open.png")

            visit("/settings/keys?panel=account")
            form = page.locator("#account-binding form")
            form.locator('select[name="primary_fingerprint"]').select_option(PRIMARY)
            form.locator('select[name="signing_fingerprint"]').select_option(PRIMARY)
            form.get_by_label("Current mailbox password").fill("synthetic-post-fixture")
            form.get_by_label("Fresh authenticator code").fill("123456")
            with page.expect_navigation(wait_until="networkidle") as navigation:
                form.get_by_role("button", name="Save account binding", exact=True).click()
            assert navigation.value.status == 503, "fixture must preserve its unavailable mutation backend"
            opened("#account-binding")
            expect(page.locator("#account-binding").get_by_label("Current mailbox password")).to_have_value("")
            expect(page.locator("#account-binding").get_by_label("Fresh authenticator code")).to_have_value("")
            expect(page.locator('[role="alert"]')).to_be_visible()
            checks.append("Deliberate gateway POST503 refusal retains action panel and clears fresh credential fields")
            screenshot("post-refusal-clean.png")

            assert not blocked, "outside requests must remain zero"
            after = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in sources}
            assert before == after, "source changed during interaction proof; rerun coherent source"
            report = {"passed": True, "synthetic_only": True, "engine": args.engine,
                "browser_version": browser.version, "javascript_enabled": False,
                "outside_requests": 0, "checks": checks, "source_sha256": after,
                "actual_key_import_executed": False, "actual_key_remove_executed": False,
                "fresh_authentication_qualified": False,
                "mutation_backend": "Unavailable fixture; browser POST503 refusal only"}
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            browser.close()
            if process.poll() is None:
                stop_server(process, root)
    print(json.dumps({"passed": True, "checks": len(checks), "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
