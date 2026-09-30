#!/usr/bin/env python3
"""Qualify local composer controls with synthetic mail and real private drafts.

No runtime mail host, external request, browser profile or private account is used.
Only synthetic text, screenshots and boolean outcomes survive the temporary state.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile

from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks, blocked = [], []
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="osmap-composer-local-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)

        def context(mode="normal", ua=None):
            result = browser.new_context(viewport={"width": 1600, "height": 1100},
                                         color_scheme="light", java_script_enabled=mode != "no-script",
                                         user_agent=ua)

            def constrain(route):
                if not route.request.url.startswith(origin + "/"):
                    blocked.append(route.request.resource_type)
                    route.abort()
                elif mode in {"tampered", "extra-script"} and route.request.resource_type == "document" and route.request.method == "GET":
                    response = route.fetch()
                    body = response.text()
                    if 'id="compose-form"' in body:
                        if mode == "tampered":
                            body = body.replace('// Compose-only enhancement.', '// Changed bytes. Compose-only enhancement.', 1)
                        else:
                            body = body.replace('</body>', '<script id="unapproved">document.documentElement.dataset.unapproved="yes";</script></body>')
                    route.fulfill(response=response, body=body)
                else:
                    route.continue_()
            result.route("**/*", constrain)
            if mode == "no-file-api":
                result.add_init_script("window.DataTransfer = undefined;")
            if mode == "no-request-submit":
                result.add_init_script("HTMLFormElement.prototype.requestSubmit = undefined;")
            return result

        def visit(page, path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response and response.status == 200
            assert response.headers["cache-control"] == "no-store"
            return response

        def submit(page, label="Save Draft", expected_status=200):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.get_by_role("button", name=label, exact=True).click()
            assert navigation.value.status == expected_status, (navigation.value.status, page.locator("main").inner_text()[:1400])

        def login(page):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            submit(page, "Sign In")

        def file(name, body):
            return {"name": name, "mimeType": "text/plain", "buffer": body}

        def add(page, files):
            with page.expect_file_chooser() as chooser:
                page.get_by_role("button", name="Add more attachments", exact=True).click()
            chooser.value.set_files(files)

        def names(page):
            return page.locator("#compose-attachment").evaluate("input => [...input.files].map(file => file.name)")

        try:
            owned = context()
            page = owned.new_page()
            login(page)
            response = visit(page, "/compose")
            digest = base64.b64encode(hashlib.sha256((repo / "src/http/compose_local.js").read_bytes()).digest()).decode()
            assert "script-src 'sha256-" + digest + "'" in response.headers["content-security-policy"]
            assert "connect-src" not in response.headers["content-security-policy"]
            expect(page.locator("#compose-form")).to_have_attribute("data-local-controls", "ready")
            expect(page.locator("#compose-save-status")).to_have_text("Not saved yet.")
            page.get_by_label("Body", exact=True).fill("Public synthetic composer notes")
            expect(page.locator("#compose-save-status")).to_contain_text("Unsaved changes")
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Control+s")
            assert "/draft?id=" in page.url
            expect(page.locator("#compose-save-status")).to_have_text("Saved draft.")
            checks.append("exact hash enables only composer controls; Ctrl+S saves through the real native form")

            saved_url = page.url
            page.get_by_label("Body", exact=True).fill("Changed public text kept when navigation is cancelled")
            dialogs = []

            def cancel(dialog):
                dialogs.append(dialog.type)
                dialog.dismiss()
            page.once("dialog", cancel)
            with page.expect_event("dialog"):
                page.locator('.rail-link[aria-label="Drafts"]').click(no_wait_after=True)
            expect(page.locator("#compose-body")).to_have_value("Changed public text kept when navigation is cancelled")
            assert page.url == saved_url and dialogs == ["beforeunload"]
            page.get_by_label("Body", exact=True).fill("Public synthetic composer notes")
            expect(page.locator("#compose-save-status")).to_have_text("Saved draft.")
            checks.append("cancelled navigation preserves edits; restoring the saved value clears the dirty state")

            add(page, file("remove-me.txt", b"not persisted"))
            for unsupported in ["Project & review.txt", "notes-é.txt", "x" * 129]:
                add(page, file(unsupported, b"not persisted"))
                expect(page.get_by_role("alert")).to_contain_text("Use filenames of up to 128 characters")
                assert names(page) == ["remove-me.txt"]
                expect(page.locator("#compose-body")).to_have_value("Public synthetic composer notes")
            checks.append("unsupported and overlong filenames are refused without changing the previous FileList or author text")
            add(page, file("Project + review (1).txt", b"first retained public file"))
            assert names(page) == ["remove-me.txt", "Project + review (1).txt"]
            page.get_by_role("button", name="Remove newly added remove-me.txt", exact=True).click()
            assert names(page) == ["Project + review (1).txt"]
            add(page, [file("second.txt", b"second retained public file"), file("third.txt", b"third retained public file")])
            expect(page.locator("#compose-attachments-heading")).to_have_text("Attachments (3)")
            add(page, file("fourth.txt", b"not persisted"))
            expect(page.get_by_role("alert")).to_contain_text("Up to 3 attachments")
            assert names(page) == ["Project + review (1).txt", "second.txt", "third.txt"]
            page.get_by_role("button", name="Remove newly added third.txt", exact=True).click()
            add(page, file("too-large.txt", b"x" * (10485760 + 1)))
            expect(page.get_by_role("alert")).to_contain_text("10 MiB or smaller")
            assert names(page) == ["Project + review (1).txt", "second.txt"]
            add(page, file("third.txt", b"third retained public file"))
            checks.append("Add more is cumulative; individual removal and count/size refusal retain the exact previous FileList")

            for scheme in ["light", "dark"]:
                page.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    page.screenshot(path=str(args.output / f"pending-files-{scheme}-{width}.png"), full_page=True)
            page.emulate_media(color_scheme="light", forced_colors="active")
            for width in [360, 1600]:
                page.set_viewport_size({"width": width, "height": 1100})
                page.get_by_role("button", name="Add more attachments", exact=True).focus()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                page.screenshot(path=str(args.output / f"pending-files-forced-colors-{width}.png"), full_page=True)
            page.emulate_media(forced_colors="none")
            submit(page)
            for name in ["Project + review (1).txt", "second.txt", "third.txt"]:
                assert page.get_by_label("Remove " + name, exact=True).is_visible()
            payloads = sorted(path.read_bytes() for path in (root / "drafts").rglob("attachment-*.body"))
            assert payloads == sorted([b"first retained public file", b"second retained public file", b"third retained public file"])
            checks.append("native multipart save persists exactly the three chosen byte sequences and names; removed/rejected files never persist")

            page.get_by_label("Remove second.txt", exact=True).check()
            expect(page.locator("#compose-attachments-heading")).to_have_text("Attachments (2)")
            expect(page.locator("#compose-save-status")).to_contain_text("Unsaved changes")
            page.get_by_label("Remove second.txt", exact=True).uncheck()
            expect(page.locator("#compose-save-status")).to_have_text("Saved draft.")
            page.get_by_label("Remove second.txt", exact=True).check()
            add(page, file("replacement.txt", b"replacement public file"))
            expect(page.locator("#compose-attachments-heading")).to_have_text("Attachments (3)")
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Meta+s")
            assert page.get_by_label("Remove replacement.txt", exact=True).is_visible()
            assert page.get_by_label("Remove second.txt", exact=True).count() == 0
            checks.append("saved-file removal supports undo, releases one slot and persists a replacement through Cmd+S")

            response = visit(page, "/message?mailbox=INBOX&uid=9")
            assert "script-src" not in response.headers["content-security-policy"]
            assert page.locator("script").count() == 0
            page.get_by_role("link", name="Forward", exact=True).click()
            page.wait_for_load_state("networkidle")
            page.locator('input[name^="include_original_attachment_"][value="1.2"]').check()
            add(page, [file("forward-one.txt", b"forward one"), file("forward-two.txt", b"forward two")])
            expect(page.locator("#compose-attachments-heading")).to_have_text("Attachments (3)")
            add(page, file("over-source-cap.txt", b"not persisted"))
            expect(page.get_by_role("alert")).to_contain_text("Up to 3 attachments")
            submit(page)
            checks.append("reader retains script-free CSP; selected source attachments share the same visible three-file limit")

            hostile = context("extra-script")
            isolated = hostile.new_page()
            login(isolated)
            visit(isolated, "/compose")
            expect(isolated.locator("#compose-form")).to_have_attribute("data-local-controls", "ready")
            assert isolated.evaluate("document.documentElement.dataset.unapproved === undefined")
            text = '</textarea><script id="quoted-marker">document.documentElement.dataset.quoted="yes"</script>'
            isolated.get_by_label("Body", exact=True).fill(text)
            add(isolated, file("literal-notes.txt", b"public literal filename"))
            add(isolated, file("<em>notes.txt", b"public literal filename"))
            expect(isolated.get_by_role("alert")).to_contain_text("Use filenames of up to 128 characters")
            assert names(isolated) == ["literal-notes.txt"]
            expect(isolated.locator("#compose-body")).to_have_value(text)
            assert isolated.locator(".pending-attachments em").count() == 0
            submit(isolated)
            assert isolated.get_by_label("Body", exact=True).input_value() == text
            assert isolated.locator("#quoted-marker").count() == 0
            assert isolated.evaluate("document.documentElement.dataset.quoted === undefined && document.documentElement.dataset.unapproved === undefined")
            checks.append("additional inline script is refused; quoted text stays inert across save/resume; markup filenames are refused without losing selected files or text")
            hostile.close()

            recipients = context()
            addressed = recipients.new_page()
            login(addressed)
            visit(addressed, "/compose")
            original = '"Doe, Jane" <jane@example.test>, dup@example.test, dup@example.test, unfinished'
            editor = addressed.get_by_role("textbox", name="Add recipients", exact=True)
            editor.focus()
            addressed.keyboard.insert_text(original)
            addressed.keyboard.press("Enter")
            expect(addressed.locator(".compose-recipient-chip")).to_have_count(3)
            assert addressed.locator('[name="to"]').input_value() == original
            expect(editor).to_have_value(" unfinished")
            duplicate = addressed.get_by_role("button", name="Remove recipient dup@example.test", exact=True)
            duplicate.nth(1).focus()
            addressed.keyboard.press("Enter")
            retained = '"Doe, Jane" <jane@example.test>, dup@example.test, unfinished'
            assert addressed.locator('[name="to"]').input_value() == retained
            expect(addressed.locator(".compose-recipient-chip")).to_have_count(2)
            expect(addressed.locator("#compose-save-status")).to_contain_text("Unsaved changes")
            addressed.get_by_label("Body", exact=True).fill("Public recipient chip workflow")
            submit(addressed)
            assert addressed.locator('[name="to"]').input_value() == retained
            expect(addressed.get_by_role("textbox", name="Add recipients", exact=True)).to_have_value(" unfinished")
            checks.append("multi-address insertion preserves quoted commas and unfinished text; keyboard removal deletes only the selected duplicate; native draft save preserves exact remaining text")

            for unsupported in ['"Unclosed, Name <name@example.test>', 'Team: name@example.test;',
                                'a..b@example.test', 'name@-example.test', 'name@[127.0.0.1]',
                                'Name <name@example.test> extra']:
                addressed.get_by_role("button", name="Edit all recipients", exact=True).click()
                addressed.locator('[name="to"]').fill(unsupported)
                addressed.get_by_role("button", name="Use recipient chips", exact=True).click()
                expect(addressed.locator(".compose-recipient-chip")).to_have_count(0)
                expect(addressed.get_by_role("textbox", name="Add recipients", exact=True)).to_have_value(unsupported)
                assert addressed.locator('[name="to"]').input_value() == unsupported
            exact = '"A \\"Quoted\\", Name" <one@example.test>, two@example.test'
            addressed.get_by_role("button", name="Edit all recipients", exact=True).click()
            addressed.locator('[name="to"]').fill(exact)
            addressed.get_by_role("button", name="Use recipient chips", exact=True).click()
            expect(addressed.locator(".compose-recipient-chip")).to_have_count(2)
            assert addressed.locator('[name="to"]').input_value() == exact
            editor = addressed.get_by_role("textbox", name="Add recipients", exact=True)
            editor.focus()
            addressed.keyboard.press("Backspace")
            expect(addressed.get_by_role("button", name="Remove recipient two@example.test", exact=True)).to_be_focused()
            addressed.keyboard.press("Space")
            assert addressed.locator('[name="to"]').input_value() == exact.split(", two@example.test")[0]
            editor.focus()
            addressed.keyboard.insert_text("new@example.test")
            addressed.keyboard.press("Enter")
            assert addressed.locator('[name="to"]').input_value().endswith(", new@example.test")
            for width in [360, 1600]:
                addressed.set_viewport_size({"width": width, "height": 1100})
                assert addressed.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                addressed.screenshot(path=str(args.output / f"recipient-chips-light-{width}.png"), full_page=True)
            checks.append("Edit all preserves raw text; unsupported/incomplete syntax stays editable; escaped quotes stay intact; Backspace focuses last chip and Space removes it; new address appends through the canonical native field")
            recipients.close()

            for mode in ["no-script", "tampered", "no-file-api"]:
                fallback = context(mode)
                native = fallback.new_page()
                login(native)
                visit(native, "/compose")
                assert native.get_by_label("Add attachments", exact=True).is_visible()
                assert native.get_by_role("button", name="Add more attachments", exact=True).count() == 0
                if mode in {"no-script", "tampered"}:
                    native.locator('[name="to"]').fill('"Native, Name" <native@example.test>')
                    assert native.locator('[name="to"]').is_visible()
                native.get_by_label("Body", exact=True).fill("Public native fallback " + mode)
                native.get_by_label("Add attachments", exact=True).set_input_files(file("fallback.txt", b"native public file"))
                if mode == "no-file-api":
                    native.get_by_label("Body", exact=True).fill("")
                    expect(native.locator("#compose-save-status")).to_contain_text("Unsaved changes")
                    native.get_by_label("Body", exact=True).fill("Public native fallback " + mode)
                submit(native)
                assert native.get_by_label("Body", exact=True).input_value() == "Public native fallback " + mode
                assert native.get_by_label("Remove fallback.txt", exact=True).is_visible()
                if mode in {"no-script", "tampered"}:
                    assert native.locator('[name="to"]').input_value() == '"Native, Name" <native@example.test>'
                checks.append(mode + ": ordinary upload and Save work without enhanced file controls")
                fallback.close()

            fallback = context("no-request-submit")
            native = fallback.new_page()
            login(native)
            visit(native, "/compose")
            native.get_by_label("Body", exact=True).fill("Public keyboard fallback")
            with native.expect_navigation(wait_until="networkidle"):
                native.keyboard.press("Control+s")
            assert "/draft?id=" in native.url
            expect(native.locator("#compose-body")).to_have_value("Public keyboard fallback")
            checks.append("missing requestSubmit API retains native keyboard Save through the real button")
            fallback.close()

            uncertain = context(ua="OSMAP/DraftSaveUnconfirmed")
            unsure = uncertain.new_page()
            login(unsure)
            visit(unsure, "/compose")
            unsure.get_by_label("Body", exact=True).fill("Public unconfirmed enhancement check")
            submit(unsure, expected_status=503)
            assert unsure.get_by_role("button", name="Save Draft", exact=True).is_disabled()
            assert unsure.get_by_role("button", name="Send Message", exact=True).is_disabled()
            revision = unsure.url
            unsure.keyboard.press("Control+s")
            assert unsure.url == revision
            expect(unsure.locator("#compose-save-status")).to_contain_text("Save not confirmed")
            checks.append("unknown save remains paused; Ctrl+S does not submit or re-enable Save/Send")
            uncertain.close()
            owned.close()
            assert not blocked, "external request attempted"
        finally:
            browser.close()
            stop_server(process, root)
    report = {"result": "PASS", "browser": args.browser, "engine": args.engine,
              "synthetic_only": True, "checks": checks, "external_requests": len(blocked)}
    (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "checks": len(checks), "report": str(args.output / "workflows.json")}))


if __name__ == "__main__":
    main()
