#!/usr/bin/env python3
"""Synthetic submission-result browser proof; no mail transport is started."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    previous = list(args.output.glob("*.json")) + list(args.output.glob("*.log")) + list(args.output.glob("*.png"))
    if previous:
        archive = args.output / "prior-attempts" / str(time.time_ns())
        archive.mkdir(parents=True, mode=0o700)
        for path in previous: shutil.copy2(path, archive / path.name)
    checks, external = [], []
    report = dict(result="FAIL", synthetic_only=True, engine=args.engine, checks=checks)
    original = "Original saved body: public fixture 🦊"
    attempted = "Changed attempted body </textarea><script>never active</script> & 🦊\nSecond line"
    with tempfile.TemporaryDirectory(prefix="osmap-send-result-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version

        def visit(page, path):
            assert page.goto(origin + path, wait_until="networkidle").status == 200

        def submit(page, label, expected=200):
            with page.expect_navigation(wait_until="networkidle") as nav:
                page.get_by_role("button", name=label, exact=True).click()
            assert nav.value.status == expected, (label, nav.value.status)

        try:
            for marker, status in [("SendUnconfirmed", 503), ("SentCopyUnconfirmed", 200), ("Normal", 200)]:
                prefix = {"SendUnconfirmed":0,"SentCopyUnconfirmed":1,"Normal":2}[marker]
                original = "\n"*prefix + "Original saved body: public fixture 🦊"
                attempted = "\n"*prefix + "Changed attempted body </textarea><script>never active</script> & 🦊\r\nSecond line"
                normalized = attempted.replace("\r\n", "\n")
                sends = []
                context = browser.new_context(java_script_enabled=False, user_agent="OSMAP/" + marker,
                    viewport=dict(width=1600, height=1100), color_scheme="light")
                def route(r):
                    if r.request.method == "POST" and r.request.url == origin + "/send": sends.append(True)
                    if r.request.url.startswith(origin + "/"): r.continue_()
                    else: external.append(True); r.abort()
                context.route("**/*", route)
                page = context.new_page()
                visit(page, "/login")
                page.get_by_label("Username or Email").fill("alice@example.com")
                page.get_by_label("Password", exact=True).fill("correct horse battery staple")
                page.get_by_label("TOTP Code").fill("123456")
                submit(page, "Sign In")
                visit(page, "/compose")
                page.get_by_label("To", exact=True).fill("recipient@example.test")
                page.locator(".compose-bcc > summary").click()
                page.get_by_label("Bcc", exact=True).fill("hidden@example.test")
                page.get_by_label("Subject", exact=True).fill("Public synthetic submission " + marker)
                page.get_by_label("Body", exact=True).fill(original)
                page.locator("#compose-attachment").set_input_files(dict(name="saved.txt", mimeType="text/plain", buffer=b"first"))
                submit(page, "Save Draft")
                expect(page.get_by_label("Body", exact=True)).to_have_value(original)
                draft_url = page.url.removeprefix(origin)
                ident = page.locator('[name="draft_id"]').input_value()
                metadata = next(p for p in (root / "drafts").rglob("metadata.draft") if p.parent.name == ident)
                before = {p.name:p.read_bytes() for p in metadata.parent.iterdir() if p.is_file()}
                page.get_by_label("Body", exact=True).fill(attempted)
                page.locator("#compose-attachment").set_input_files(dict(name="attempt.txt", mimeType="text/plain", buffer=b"second-new"))
                submit(page, "Send Message", status)
                assert len(sends) == 1
                if marker == "Normal":
                    assert page.url.startswith(origin + "/compose?receipt=")
                    expect(page.locator("main")).to_contain_text("Submission acceptance is known. Delivery is not confirmed. A copy was stored in Sent.")
                    assert not metadata.exists()
                    checks.append("normal accepted submission redirects once to truthful success and removes original saved draft")
                else:
                    expect(page.get_by_role("heading", name="Submission could not be confirmed" if marker == "SendUnconfirmed" else "Message accepted for submission", exact=True)).to_be_visible()
                    expect(page.get_by_label("Message source", exact=True)).to_have_value(normalized)
                    assert page.locator("main textarea").count() == 5
                    assert page.locator("main textarea:not([readonly]), form[action='/send'], script").count() == 0
                    expect(page.get_by_text("saved.txt (5 bytes)", exact=True)).to_be_visible()
                    expect(page.get_by_text("attempt.txt (10 bytes)", exact=True)).to_be_visible()
                    assert "may differ from the text or attachments used in this attempt" in page.locator("main").inner_text()
                    assert "New uploads are not saved by this result page" in page.locator("main").inner_text()
                    assert "Nothing was sent" not in page.locator("main").inner_text()
                    if marker == "SentCopyUnconfirmed":
                        assert "Sent-copy storage could not be confirmed" in page.locator("main").inner_text()
                        assert "does not confirm delivery" in page.locator("main").inner_text()
                    else:
                        assert "may have accepted" in page.locator("main").inner_text()
                        assert "An empty Sent folder does not prove" in page.locator("main").inner_text()
                    assert {p.name:p.read_bytes() for p in metadata.parent.iterdir() if p.is_file()} == before
                    for width, forced in [(1600, "none"), (360, "none"), (360, "active")]:
                        page.set_viewport_size(dict(width=width, height=1100))
                        page.emulate_media(forced_colors=forced)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.screenshot(path=str(args.output / f"{marker}-{width}-{forced}.png"), full_page=True)
                    with page.expect_popup() as popup:
                        page.get_by_role("link", name="Compare the saved draft (opens in a new tab)", exact=True).click()
                    saved = popup.value
                    saved.wait_for_load_state("networkidle")
                    assert saved.url == origin + draft_url
                    expect(saved.get_by_label("Body", exact=True)).to_have_value(original)
                    with saved.expect_popup() as recovered_popup:
                        saved.get_by_role("link", name="View this attempt’s receipt and retained source (opens in a new tab)", exact=True).click()
                    recovered = recovered_popup.value
                    recovered.wait_for_load_state("networkidle")
                    expect(recovered.get_by_label("Attempt body source", exact=True)).to_have_value(normalized)
                    expect(recovered.locator("[data-attempt-attachment]")).to_have_count(2)
                    assert recovered.locator("main form, input[name=send_intent], script").count() == 0
                    assert len(sends) == 1
                    recovered.close()

                    expect(saved.locator("[data-saved-attachment]")).to_have_text(["saved.txt (5 bytes)"])
                    assert "attempt.txt" not in saved.locator("main").inner_text()
                    assert saved.locator("main textarea:not([readonly]), main form, form[action='/send']").count() == 0
                    assert saved.locator("button[data-header-theme]:not([disabled])").count() == 0
                    for width, forced in [(1600, "none"), (360, "none"), (360, "active")]:
                        saved.set_viewport_size(dict(width=width, height=1100))
                        saved.emulate_media(forced_colors=forced)
                        assert saved.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        saved.screenshot(path=str(args.output / f"saved-{marker}-{width}-{forced}.png"), full_page=True)
                    assert len(sends) == 1
                    checks.append(marker + ": exact escaped attempted source and two-file metadata; no send form/script; truthful uncertain state and recovery distinction; comparison opens original one-file draft as read-only metadata and exact source without another send")
                if marker == "Normal":
                    receipt = page
                else:
                    with page.expect_popup() as popup:
                        page.get_by_role("link", name="Check this attempt’s receipt (opens in a new tab)", exact=True).click()
                    receipt = popup.value
                    receipt.wait_for_load_state("networkidle")
                expect(receipt.get_by_label("Attempt body source", exact=True)).to_have_value(normalized)
                with receipt.expect_download() as body_download:
                    receipt.get_by_role("link", name="Download body source", exact=True).click()
                assert body_download.value.suggested_filename == "attempt-body.txt"
                assert Path(body_download.value.path()).read_bytes() == normalized.replace("\n", "\r\n").encode("utf-8")
                expect(receipt.get_by_label("Attempt Bcc", exact=True)).to_have_value("hidden@example.test")
                expect(receipt.locator("[data-attempt-attachment]")).to_have_count(2)
                assert "does not prove that submission was invoked, accepted, or delivered" in receipt.locator("main").inner_text()
                assert "UTC" in receipt.locator("main").inner_text()
                assert receipt.locator("main textarea:not([readonly]), main form, input[name=send_intent]").count() == 0
                for name, content in [("saved.txt", b"first"), ("attempt.txt", b"second-new")]:
                    with receipt.expect_download() as download:
                        receipt.get_by_role("link", name="Download " + name, exact=True).click()
                    downloaded = download.value
                    assert downloaded.suggested_filename == name
                    assert Path(downloaded.path()).read_bytes() == content
                for width, forced in [(1600, "none"), (360, "none"), (360, "active")]:
                    receipt.set_viewport_size(dict(width=width, height=1100))
                    receipt.emulate_media(forced_colors=forced)
                    assert receipt.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    receipt.screenshot(path=str(args.output / f"attempt-{marker}-{width}-{forced}.png"), full_page=True)
                assert len(sends) == 1
                checks.append(marker + ": exact durable attempted Unicode source and Bcc, two native downloads match bytes; receipt/download GETs never dispatch")
                context.close()
            assert not external
            report["result"] = "PASS"
        except Exception as error:
            report["failure_type"] = type(error).__name__
            raise
        finally:
            report["external_requests"] = len(external)
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps(dict(result=report["result"], checks=len(checks), report=str(args.output / "workflows.json"))))


if __name__ == "__main__":
    main()
