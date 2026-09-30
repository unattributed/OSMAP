#!/usr/bin/env python3
"""Bounded synthetic native composer formatting, persistence and discard proof."""
import argparse
import base64
import json
import re
from pathlib import Path
import tempfile
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks, external = [], []
    report = {"result": "FAIL", "synthetic_only": True, "engine": args.engine, "checks": checks}
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="osmap-format-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version
        page = None

        def context(scripts=True):
            result = browser.new_context(viewport={"width": 1600, "height": 1100},
                                         color_scheme="light", java_script_enabled=scripts)
            def route(request):
                if request.request.url.startswith(origin + "/"):
                    request.continue_()
                else:
                    external.append(request.request.resource_type)
                    request.abort()
            result.route("**/*", route)
            return result

        def visit(page, path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == 200
            assert response.headers["cache-control"] == "no-store"

        def submit(page, label, status=200):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.get_by_role("button", name=label, exact=True).click()
            assert navigation.value.status == status, f"{label}: expected {status}, got {navigation.value.status}"

        def login(page):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            submit(page, "Sign In")

        def metadata(page):
            draft_id = page.locator('input[name="draft_id"]').input_value()
            paths = [path for path in (root / "drafts").rglob("metadata.draft") if path.parent.name == draft_id]
            assert len(paths) == 1
            return paths[0], dict(line.split("=", 1) for line in paths[0].read_text().splitlines())

        def persisted(page, body, mode="formatted"):
            expect(page.locator("#compose-body")).to_have_value(body)
            expect(page.get_by_label("Message format", exact=True)).to_have_value(mode)
            _, data = metadata(page)
            assert data["version"] == "9" and data["body_format"] == mode
            assert bytes.fromhex(data["body_hex"]).decode() == body

        def select(page, text):
            page.locator("#compose-body").evaluate("(field, text) => { field.focus(); const start = field.value.indexOf(text); if (start < 0) throw Error('selection absent'); field.setSelectionRange(start, start + text.length); }", text)

        try:
            normal = context()
            page = normal.new_page()
            login(page)
            visit(page, "/compose")
            page.get_by_role("textbox", name="Add recipients", exact=True).fill("reader@example.test")
            page.keyboard.press("Enter")
            source = "Start 🦊\nMiddle café 🦊\nEnd"
            page.locator("#compose-body").fill(source)
            select(page, "café 🦊")
            submit(page, "Bold")
            persisted(page, "Start 🦊\nMiddle **café 🦊**\nEnd")
            assert "preview=1" in page.url
            expect(page.locator(".compose-preview-html strong")).to_have_text("café 🦊")
            checks.append("native selected Bold preserves multiline Unicode surrounding text and UTF-16 selection; exact formatted source persists and preview renders selection")

            for label, expected, selector in [("Italic", "*Public emphasis*", "em"),
                                               ("Underline", "__Public emphasis__", "u")]:
                page.locator("#compose-body").fill("Public emphasis")
                submit(page, label)
                persisted(page, expected)
                expect(page.locator(".compose-preview-html " + selector)).to_have_text("Public emphasis")
            for label, expected in [("Bulleted list", "- one\n- two\nrest"),
                                    ("Numbered list", "1. one\n2. two\nrest")]:
                page.locator("#compose-body").fill("one\ntwo\nrest")
                select(page, "one\ntwo\n")
                submit(page, label)
                persisted(page, expected)
                expect(page.locator(".compose-preview-html li")).to_have_count(2)
                expect(page.locator(".compose-preview-html")).to_contain_text("rest")
            checks.append("Italic, Underline and both two-item lists save and preview; selected trailing newline preserves the untouched next line")

            page.locator("#compose-body").fill("Public link")
            page.locator(".compose-format-options summary").click()
            page.get_by_label("Link address", exact=True).fill("https://example.test/public")
            submit(page, "Insert link")
            persisted(page, "[Public link](https://example.test/public)")
            expect(page.locator(".compose-preview-html a")).to_have_attribute("href", "https://example.test/public")
            submit(page, "Insert emoji")
            persisted(page, "[Public link](https://example.test/public)🙂")
            literal = '<img src="https://invalid.example/image" onerror="window.bad=true"> **safe**'
            page.locator("#compose-body").fill(literal)
            submit(page, "Preview")
            persisted(page, literal)
            expect(page.locator(".compose-preview-html")).to_contain_text('<img src="https://invalid.example/image"')
            assert page.locator(".compose-preview-html img, .compose-preview-html script").count() == 0
            assert page.evaluate("window.bad === undefined")
            checks.append("link and emoji persist; preview escapes literal HTML and performs no remote image request")

            page.locator("#compose-body").fill("Public text retained after invalid link")
            page.locator(".compose-format-options summary").click()
            page.get_by_label("Link address", exact=True).fill("javascript:alert(1)")
            submit(page, "Insert link", 400)
            expect(page.locator("#compose-body")).to_have_value("Public text retained after invalid link")
            expect(page.locator(".notice-error:visible")).to_contain_text(re.compile(r"HTTP.*HTTPS.*mailto"))
            malformed = "[Rejected source](javascript:alert)"
            page.locator("#compose-body").fill(malformed)
            page.get_by_label("Message format", exact=True).select_option("formatted")
            submit(page, "Save Draft")
            persisted(page, malformed)
            submit(page, "Preview")
            expect(page.locator('.compose-preview [role="alert"]')).to_contain_text("Preview and sending are blocked")
            path, before = metadata(page)
            submit(page, "Send Message", 400)
            expect(page.locator("#compose-body")).to_have_value(malformed)
            assert dict(line.split("=", 1) for line in path.read_text().splitlines()) == before
            page.get_by_label("Message format", exact=True).select_option("plain")
            submit(page, "Save Draft")
            persisted(page, malformed, "plain")
            checks.append("invalid link refuses with actionable error and text retained; malformed formatted source saves, Preview and Send refuse, stored draft remains intact; Plain switch persists")

            with page.expect_file_chooser() as chooser:
                page.get_by_role("button", name="Add more attachments", exact=True).click()
            chooser.value.set_files({"name": "notes.txt", "mimeType": "text/plain", "buffer": b"Public attachment bytes"})
            page.locator("#compose-body").fill("Attachment preservation")
            submit(page, "Save Draft")
            path, data = metadata(page)
            original_blob = data["attachment_0_body_file"]
            submit(page, "Bold")
            path, data = metadata(page)
            assert data["attachment_0_body_file"] == original_blob
            assert (path.parent / original_blob).read_bytes() == b"Public attachment bytes"
            expect(page.get_by_label("Remove notes.txt", exact=True)).to_be_visible()
            png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jN1sAAAAASUVORK5CYII=")
            page.get_by_label("Attach local image", exact=True).click()
            page.get_by_label("Local image", exact=True).set_input_files({"name": "pixel.png", "mimeType": "image/png", "buffer": png})
            submit(page, "Save image attachment")
            expect(page.get_by_label("Remove pixel.png", exact=True)).to_be_visible()
            path, data = metadata(page)
            assert data["attachment_1_content_type_hex"] == b"image/png".hex()
            assert (path.parent / data["attachment_1_body_file"]).read_bytes() == png
            checks.append("saved attachment blob survives formatting; signature-valid local PNG persists as exact image/png attachment bytes")
            image_source = page.locator("#compose-body").input_value()
            page.get_by_label("Attach local image", exact=True).click()
            page.get_by_label("Local image", exact=True).set_input_files({"name": "unsupported.svg", "mimeType": "image/svg+xml", "buffer": b"<svg>synthetic</svg>"})
            submit(page, "Save image attachment", 400)
            expect(page.locator("#compose-body")).to_have_value(image_source)
            assert path.read_text().splitlines() == [key + "=" + value for key, value in data.items()]
            submit(page, "Save Draft")
            expect(page.get_by_label("Remove pixel.png", exact=True)).to_be_visible()
            expect(page.get_by_label("Remove notes.txt", exact=True)).to_be_visible()
            checks.append("unsupported image refuses without losing source or changing stored draft; native Save recovery keeps existing attachments")

            submit(page, "Preview")
            for scheme, forced in [("light", "none"), ("dark", "none"), ("light", "active")]:
                page.emulate_media(color_scheme=scheme, forced_colors=forced)
                for width in [1600, 360]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    mode = "forced-colors" if forced == "active" else scheme
                    page.screenshot(path=str(args.output / f"formatted-compose-{mode}-{width}.png"), full_page=True)
            page.emulate_media(color_scheme="light", forced_colors="none")
            page.set_viewport_size({"width": 1600, "height": 1100})
            saved_url = page.url
            draft_id = page.locator('input[name="draft_id"]').input_value()
            path, data = metadata(page)
            page.locator(".compose-discard summary").click()
            submit(page, "Review discard")
            expect(page.get_by_role("heading", name="Discard selected drafts?", exact=True)).to_be_visible()
            page.get_by_role("link", name="Keep drafts", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert path.exists()
            visit(page, urlparse(saved_url).path + "?" + urlparse(saved_url).query)
            page.locator(".compose-discard summary").click()
            submit(page, "Review discard")
            assert page.locator(f'input[name="selected_{draft_id}"]').input_value() == data["revision"]
            submit(page, "Discard 1 drafts")
            assert not path.exists()
            visit(page, "/compose")
            page.locator("#compose-body").fill("Public unsaved message to discard")
            page.locator(".compose-discard summary").click()
            expect(page.locator("#compose-body")).to_have_value("Public unsaved message to discard")
            with page.expect_navigation(wait_until="networkidle"):
                page.get_by_role("link", name="Discard unsaved message", exact=True).click()
            assert urlparse(page.url).path == "/drafts"
            checks.append("native saved-draft Review discard and Keep preserve data; revision-bound confirmation removes it; new-message Discard requires explicit confirmation")

            native_context = context(False)
            native = native_context.new_page()
            login(native)
            visit(native, "/compose")
            native.locator("#compose-body").fill("Public first\n\nPublic second café 🦊\n")
            submit(native, "Bold")
            persisted(native, "**Public first**\n\n**Public second café 🦊**\n")
            expect(native.locator(".compose-preview-html strong")).to_have_text(["Public first", "Public second café 🦊"])
            checks.append("JavaScript-disabled multiline full-body Bold saves exact per-line source, blank line and trailing newline; preview renders both strong spans")
            native_context.close()
            normal.close()
            assert not external, "external request attempted"
            report["result"] = "PASS"
        except Exception as error:
            report["failure"] = str(error)[:1600]
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
