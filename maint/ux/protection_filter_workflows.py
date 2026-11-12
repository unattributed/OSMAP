#!/usr/bin/env python3
"""Exercise real MIME-filter controls against public synthetic metadata.

Native mailbox/helper proof is separate. No message, key or policy writes;
no storage, filled forms, tokens or request bodies are retained.
"""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = dict(result="FAIL", checks=[], captures=[], outside=0, writes=0,
                  sends=0, scripts=0, synthetic=True)
    with tempfile.TemporaryDirectory(prefix="osmap-protection-filter-") as tmp, \
            (args.output / "server.log").open("w") as log, sync_playwright() as pw:
        root = Path(tmp)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = pw.chromium.launch(executable_path=args.browser, headless=True)
        context = browser.new_context(java_script_enabled=False,
                                      user_agent="OSMAP/ManyMessages;ProtectionFilter;AttachmentNames",
                                      viewport=dict(width=1440, height=1000))

        def guard(route):
            req = route.request
            path = urlsplit(req.url).path
            if path == "/send":
                report["sends"] += 1
            if req.resource_type == "script":
                report["scripts"] += 1
            if not req.url.startswith(origin + "/"):
                report["outside"] += 1
                route.abort()
            elif req.method != "GET" and path != "/login":
                report["writes"] += 1
                route.abort()
            else:
                route.continue_()

        context.route("**/*", guard)
        page = context.new_page()

        def visit(path, status=200):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response and response.status == status
            assert response.headers["cache-control"] == "no-store"
            assert page.locator("script").count() == 0

        try:
            visit("/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")
            visit("/mailbox?name=INBOX&sort=subject&dir=asc&page=2")
            page.locator(".protection-filter > summary").press("Enter")
            page.get_by_role("link", name="Encrypted MIME", exact=True).press("Enter")
            query = parse_qs(urlsplit(page.url).query)
            assert query["pgp"] == ["encrypted"] and "page" not in query
            assert query["sort"] == ["subject"] and query["dir"] == ["asc"]
            expect(page.locator(".message-card")).to_have_count(31)
            assert all(text == "Encrypted MIME" for text in
                       page.locator(".message-card .message-security").all_text_contents())
            expect(page.locator(".message-body-preview").first).to_have_text("No preview available")
            page.locator(".mail-search-disclosure > summary").press("Enter")
            page.get_by_label("Search query", exact=True).fill("reader-fixture")
            page.locator("main").get_by_role("button", name="Search", exact=True).click()
            page.wait_for_load_state("networkidle")
            query = parse_qs(urlsplit(page.url).query)
            assert query["pgp"] == ["encrypted"] and query["mailbox"] == ["INBOX"]
            expect(page.locator(".search-result-row")).to_have_count(31)
            report["checks"].append("keyboard MIME filter resets paging, retains sort, selects real typed fixture metadata and survives Search form")
            visit("/search?q=reader-fixture&field=subject&scope=all&pgp=encrypted&page=2")
            expect(page.locator(".search-result-row")).to_have_count(12)
            page.get_by_role("link", name="Previous page", exact=True).press("Enter")
            assert parse_qs(urlsplit(page.url).query)["pgp"] == ["encrypted"]
            expect(page.locator(".search-result-row")).to_have_count(50)
            visit("/search?q=reader-fixture&field=subject&scope=all&pgp=encrypted&after=2099-01-01")
            page.get_by_role("link", name="Clear filters", exact=True).press("Enter")
            assert parse_qs(urlsplit(page.url).query) == dict(q=["reader-fixture"], field=["subject"], scope=["all"])
            expect(page.locator(".search-result-row")).to_have_count(50)
            report["checks"].append("all-folder typed filtering before pagination and empty-state Clear retain query, field and scope")
            visit("/search?q=reader-fixture&field=subject&scope=all&pgp=encrypted&sort=subject&dir=asc")
            page.locator(".sender-filter > summary").press("Enter")
            page.get_by_label("Sender address", exact=True).fill("sender@example.test")
            page.get_by_role("button", name="Apply sender", exact=True).click()
            page.wait_for_load_state("networkidle")
            query = parse_qs(urlsplit(page.url).query)
            assert query["from"] == ["sender@example.test"] and query["q"] == ["reader-fixture"]
            assert query["pgp"] == ["encrypted"] and query["field"] == ["subject"]
            expect(page.locator(".search-result-row")).to_have_count(50)
            page.locator(".search-result-more > summary").first.press("Enter")
            expect(page.locator(".public-attachment-details").first).to_be_visible()
            expect(page.locator(".public-attachment-details").first).to_contain_text("public-<b>.txt")
            expect(page.locator(".public-attachment-details").first).to_contain_text("129 encoded MIME bytes")
            assert page.locator(".public-attachment-details b").count() == 0
            current_url = page.url
            search_input = page.get_by_label("Search query", exact=True)
            search_input.fill("unsent query")
            search_input.press("Escape")
            expect(search_input).to_have_value("")
            assert page.url == current_url
            expect(page.locator(".search-result-row")).to_have_count(50)
            report["checks"].append("combined exact sender plus subject/protection query; keyboard public file details; native Escape clears only query without submission")
            visit("/mailbox?name=INBOX&pgp=verified", 400)
            report["checks"].append("unsupported assurance token is refused rather than displayed as a verified filter")
            for value, label, count in [("plain", "No outer OpenPGP MIME", 32),
                                        ("signed", "Signed MIME", 31),
                                        ("encrypted", "Encrypted MIME", 31),
                                        ("unknown", "OpenPGP MIME unknown", 31)]:
                for width in [360, 1440]:
                    for scheme in ["light", "dark"]:
                        page.set_viewport_size(dict(width=width, height=1000))
                        page.emulate_media(color_scheme=scheme)
                        visit("/mailbox?name=INBOX&pgp=" + value)
                        expect(page.locator(".message-card")).to_have_count(count)
                        assert set(page.locator(".message-card .message-security").all_text_contents()) == {label}
                        page.locator(".protection-filter > summary").press("Enter")
                        assert page.get_by_role("group", name="OpenPGP filter").is_visible()
                        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                        audit = page.evaluate(TEXT_AUDIT)
                        assert not audit["failures"] and not audit["ui_failures"]
                        name = f"{value}-{width}-{scheme}.png"
                        page.screenshot(path=str(args.output / name), full_page=True)
                        report["captures"].append(dict(file=name, width=width, scheme=scheme,
                                                       classification=value, contrast=audit))
            assert report["outside"] == report["writes"] == report["sends"] == report["scripts"] == 0
            report["result"] = "PASS"
        finally:
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps(dict(result=report["result"], checks=len(report["checks"]), captures=len(report["captures"]))))


if __name__ == "__main__":
    main()
