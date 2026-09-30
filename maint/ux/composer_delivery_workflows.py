#!/usr/bin/env python3
"""Synthetic native delivery menu, attachment shortcut and stale-preview proof."""
import argparse
import json
from pathlib import Path
import tempfile
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", default="chromium", choices=["chromium", "firefox"])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks, external = [], []
    report = {"result": "FAIL", "checks": checks, "synthetic_only": True, "engine": args.engine}
    with tempfile.TemporaryDirectory(prefix="osmap-delivery-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version
        page = None

        def context(scripts=True, ua=None):
            result = browser.new_context(java_script_enabled=scripts, user_agent=ua,
                                         viewport={"width": 1600, "height": 1100}, color_scheme="light")
            def constrain(route):
                if route.request.url.startswith(origin + "/"):
                    route.continue_()
                else:
                    external.append(route.request.resource_type)
                    route.abort()
            result.route("**/*", constrain)
            return result

        def visit(page, path):
            assert page.goto(origin + path, wait_until="networkidle").status == 200

        def submit(page, label, status=200):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.get_by_role("button", name=label, exact=True).click()
            assert navigation.value.status == status, (label, navigation.value.status)

        def login(page):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            submit(page, "Sign In")

        def menu(page, selector):
            summary = page.locator(selector + " > summary")
            summary.focus()
            if not page.locator(selector).evaluate("element => element.open"):
                page.keyboard.press("Enter")
            expect(page.locator(selector)).to_have_attribute("open", "")
            return summary

        def stored(page):
            ident = page.locator('[name="draft_id"]').input_value()
            paths = [p for p in (root / "drafts").rglob("metadata.draft") if p.parent.name == ident]
            assert len(paths) == 1
            data = dict(line.split("=", 1) for line in paths[0].read_text().splitlines())
            assert bytes.fromhex(data["body_hex"]).decode() == "Public delivery workflow 🦊"
            assert data["attachment_count"] == "2"
            assert [(paths[0].parent / data[f"attachment_{i}_body_file"]).read_bytes() for i in range(2)] == [b"first", b"second"]
            return ident

        try:
            normal = context()
            page = normal.new_page()
            login(page)
            visit(page, "/compose")
            page.get_by_role("textbox", name="Add recipients", exact=True).fill("reader@example.test")
            page.keyboard.press("Enter")
            page.locator("#compose-body").fill("Public delivery workflow 🦊")
            for name, payload in [("first.txt", b"first"), ("second.txt", b"second")]:
                with page.expect_file_chooser() as chooser:
                    page.get_by_role("link", name="Attach local files", exact=True).click()
                chooser.value.set_files({"name": name, "mimeType": "text/plain", "buffer": payload})
            assert page.locator("#compose-attachment").evaluate("field => [...field.files].map(file => file.name)") == ["first.txt", "second.txt"]
            menu(page, ".compose-send-options")
            page.keyboard.press("Tab")
            expect(page.get_by_role("button", name="Pre-send check", exact=True)).to_be_focused()
            submit(page, "Pre-send check")
            assert "preflight=1" in page.url
            expect(page.locator(".compose-preflight")).to_contain_text("pass composition checks")
            ident = stored(page)
            checks.append("Attach opens cumulative picker; keyboard Send options reaches Pre-send check; save-first valid check preserves exact Unicode body and both file byte sequences")
            for action in ["preflight", "preview"]:
                if action == "preview":
                    submit(page, "Preview")
                expect(page.locator(".compose-preview")).to_have_attribute("data-stale", "false")
                page.locator("#compose-body").fill("Changed public delivery text")
                expect(page.locator(".compose-preview")).to_have_attribute("data-stale", "true")
                expect(page.locator(".compose-stale-preview")).to_be_visible()
                page.locator("#compose-body").fill("Public delivery workflow 🦊")
                expect(page.locator(".compose-stale-preview")).to_be_hidden()
                expect(page.locator(".compose-preview")).to_have_attribute("data-stale", "false")
                assert page.locator(".compose-stale-preview").count() == 1
            page.get_by_role("button", name="Edit all recipients", exact=True).click()
            page.locator('[name="to"]').fill("unfinished@")
            page.get_by_role("button", name="Use recipient chips", exact=True).click()
            menu(page, ".compose-send-options")
            submit(page, "Pre-send check")
            expect(page.locator(".compose-preflight [role=alert]")).to_contain_text("Edit this draft before sending")
            assert page.locator('[name="to"]').input_value() == "unfinished@"
            stored(page)
            checks.append("both saved preview and check become visibly stale after edits and clear on exact undo; invalid recipient check saves unfinished text and preserves body/files without sending")
            for scheme, forced in [("light", "none"), ("dark", "none"), ("light", "active")]:
                page.emulate_media(color_scheme=scheme, forced_colors=forced)
                for width in [1600, 360]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    for selector, name in [(".compose-footer-more", "more"), (".compose-send-options", "send-options")]:
                        summary = menu(page, selector)
                        expect(summary).to_be_focused()
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                        mode = "forced-colors" if forced == "active" else scheme
                        page.screenshot(path=str(args.output / f"{name}-{mode}-{width}.png"), full_page=True)
            menu(page, ".compose-footer-more")
            page.keyboard.press("Tab")
            expect(page.get_by_role("button", name="Save and close", exact=True)).to_be_focused()
            submit(page, "Save and close")
            assert page.url == origin + "/drafts"
            visit(page, "/draft?id=" + ident)
            stored(page)
            checks.append("native More opens by keyboard; Save and close persists the draft and navigates to Drafts; focused open menus captured at desktop/narrow in light/dark/forced colours")
            native_context = context(False)
            native = native_context.new_page()
            login(native)
            visit(native, "/compose")
            link = native.get_by_role("link", name="Attach local files", exact=True)
            expect(link).to_have_attribute("href", "#compose-attachment")
            link.click()
            expect(native.locator("#compose-attachment")).to_be_visible()
            native.locator("#compose-attachment").set_input_files({"name": "native.txt", "mimeType": "text/plain", "buffer": b"native"})
            submit(native, "Save Draft")
            expect(native.get_by_label("Remove native.txt", exact=True)).to_be_visible()
            native_context.close()
            checks.append("without JavaScript Attach remains an anchor to the usable native file input; native save retains selected file")
            paused = context(ua="OSMAP/DraftSaveUnconfirmed")
            unsure = paused.new_page()
            login(unsure)
            visit(unsure, "/compose")
            unsure.locator("#compose-body").fill("Public unconfirmed delivery state")
            submit(unsure, "Save Draft", 503)
            expect(unsure.get_by_role("button", name="Send Message", exact=True)).to_be_disabled()
            menu(unsure, ".compose-footer-more")
            expect(unsure.get_by_role("button", name="Save and close", exact=True)).to_be_disabled()
            expect(unsure.locator(".compose-footer-more button[value=preview]")).to_be_disabled()
            menu(unsure, ".compose-send-options")
            expect(unsure.get_by_role("button", name="Pre-send check", exact=True)).to_be_disabled()
            expect(unsure.locator(".compose-send-options button[aria-describedby]")).to_be_disabled()
            assert unsure.get_by_role("link", name="Attach local files", exact=True).count() == 0
            paused.close()
            normal.close()
            checks.append("unconfirmed save pauses Send, More mutations, Pre-send check and Attach; Schedule remains explicitly unavailable")
            assert not external
            report["result"] = "PASS"
        except Exception as error:
            report["failure"] = str(error)[:1400]
            if page and page.locator("#compose-form").count():
                page.screenshot(path=str(args.output / "failure-compose.png"), full_page=True)
            raise
        finally:
            report["external_requests"] = len(external)
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps({"result": report["result"], "checks": len(checks), "report": str(args.output / "workflows.json")}))


if __name__ == "__main__":
    main()
