#!/usr/bin/env python3
"""Capture synthetic route HTML with an external, test-only Playwright install.

No mail host is contacted. The temporary server exposes only the supplied
fixture directory on loopback, and browser requests outside that server fail.
The browser runs in a disposable context without an operator profile.
"""

import argparse
import hashlib
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from playwright.sync_api import sync_playwright
from contrast_audit import TEXT_AUDIT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    parser.add_argument("--zoom", type=int, choices=[1, 2], default=1,
                        help="reflow simulation: divide CSS viewport and scale pixels; not native browser zoom")
    parser.add_argument("--forced-colors", choices=["none", "active"], default="none")
    parser.add_argument("--contrast", action="store_true", help="audit computed flat text and meaningful UI colours")
    parser.add_argument("--expand-details", action="store_true", help="audit disclosed main-content states")
    parser.add_argument("--schemes", nargs="+", choices=["light", "dark"], default=["light"])
    parser.add_argument("--widths", nargs="+", type=int, default=[360, 768, 1440])
    parser.add_argument("--names", nargs="+", help="capture only these manifest fixture names")
    parser.add_argument("--shell-checks", action="store_true", help="exercise native keyboard and shell disclosures")
    args = parser.parse_args()
    fixtures = args.fixtures.resolve(strict=True)
    routes = json.loads((fixtures / "routes.json").read_text())
    assert all(item["synthetic"] and item["tokens_redacted"] for item in routes)
    if args.names:
        assert set(args.names) <= {item["name"] for item in routes}
        routes = [item for item in routes if item["name"] in args.names]
    policies = {f"/{item['name']}.html": item["csp"] for item in routes}
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)

    class FixtureHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path not in policies:
                self.send_error(404)
                return
            super().do_GET()

        def end_headers(self):
            self.send_header("Content-Security-Policy", policies.get(self.path, "default-src 'none'"))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            super().end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(FixtureHandler, directory=str(fixtures)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    results = []
    shell_results = []
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)
            for scheme in args.schemes:
                for physical_width in args.widths:
                    width = physical_width // args.zoom
                    context = browser.new_context(viewport={"width": width, "height": 1000},
                                                  device_scale_factor=args.zoom,
                                                  color_scheme=scheme, reduced_motion="reduce",
                                                  forced_colors=args.forced_colors)
                    blocked_requests = []

                    def constrain_request(route):
                        if route.request.url.startswith(origin + "/"):
                            route.continue_()
                        else:
                            blocked_requests.append(route.request.resource_type)
                            route.abort()

                    context.route("**/*", constrain_request)
                    page = context.new_page()
                    for item in routes:
                        response = page.goto(f"{origin}/{item['name']}.html", wait_until="networkidle")
                        assert response and response.status == 200
                        if args.forced_colors == "active":
                            # Edge can retain the media-query value but lose its
                            # actual forced palette on a later navigation after
                            # a full-page capture. Reapply and verify the palette.
                            page.emulate_media(forced_colors="none")
                            page.emulate_media(forced_colors="active")
                        if args.shell_checks and item["name"] in {"settings", "settings-long-identity"}:
                            page.keyboard.press("Tab")
                            assert page.locator(":focus").get_attribute("class") == "skip-link"
                            page.keyboard.press("Enter")
                            assert page.locator(":focus").get_attribute("id") == "main-content"
                            page.evaluate("window.scrollTo(0, 0)")
                            toggle = page.locator(".rail-disclosure summary")
                            toggle.focus()
                            page.keyboard.press("Enter")
                            assert page.locator(".rail-disclosure").get_attribute("open") is not None
                            focus = toggle.evaluate("e => ({style:getComputedStyle(e).outlineStyle,width:parseFloat(getComputedStyle(e).outlineWidth)})")
                            assert focus["style"] != "none" and focus["width"] >= 2
                            assert page.locator(".rail-label").first.is_visible()
                            assert page.locator(".rail-links a[aria-current=page]").get_attribute("aria-label") == "Settings"
                            expanded = args.output / f"{item['name']}-expanded-{scheme}-{width}.png"
                            page.screenshot(path=str(expanded), full_page=True)
                            page.keyboard.press("Enter")
                            assert page.locator(".rail-disclosure").get_attribute("open") is None
                            if page.locator(".protection-menu").count():
                                page.locator(".protection-menu summary").focus()
                                page.keyboard.press("Enter")
                                assert page.locator(".protection-menu").get_attribute("open") is not None
                            menu = page.locator(".account-menu summary")
                            menu.focus()
                            page.keyboard.press("Enter")
                            if page.locator(".protection-menu").count():
                                assert page.locator(".protection-menu").get_attribute("open") is None
                            assert page.locator(".account-menu-panel .logout-button").is_visible()
                            assert page.locator(".account-menu-panel a[href='/sessions']").is_visible()
                            bounds = page.locator(".account-menu .account-menu-panel").bounding_box()
                            assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width + 1
                            account = args.output / f"{item['name']}-account-menu-{scheme}-{width}.png"
                            page.screenshot(path=str(account), full_page=True)
                            page.keyboard.press("Enter")
                            shell_results.append({"fixture": item["name"], "scheme": scheme, "width": width,
                                                  "skip_link": True, "keyboard_disclosures": True,
                                                  "visible_focus_outline": focus,
                                                  "account_menu_within_viewport": True,
                                                  "screenshots": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                                                  for p in [expanded, account]}})
                        if item["name"] == "source":
                            for summary in page.locator("summary").all():
                                if "source" in summary.inner_text().lower():
                                    summary.click()
                        if args.expand_details:
                            closed = page.locator("main details:not([open]) > summary")
                            for _ in range(closed.count()):
                                closed.first.click()
                        table_checks = []
                        for region in page.locator(".table-wrap").all():
                            assert region.get_attribute("tabindex") == "0"
                            assert region.get_attribute("aria-label")
                            region.focus()
                            overflow = region.evaluate("e => e.scrollWidth > e.clientWidth")
                            if overflow:
                                page.keyboard.press("ArrowRight")
                                page.wait_for_timeout(150)
                                assert region.evaluate("e => e.scrollLeft") > 0
                                region.evaluate("e => e.scrollLeft = 0")
                            table_checks.append({"keyboard_focus": True, "horizontal_scroll": overflow})
                        metrics = page.evaluate("""() => ({
                            viewport: window.innerWidth,
                            document_width: document.documentElement.scrollWidth,
                            background: getComputedStyle(document.body).backgroundColor,
                            foreground: getComputedStyle(document.body).color,
                            appearance: document.documentElement.dataset.appearance,
                            forced_colors_active: matchMedia('(forced-colors:active)').matches,
                            system_dark: matchMedia('(prefers-color-scheme:dark)').matches,
                            device_pixel_ratio: window.devicePixelRatio,
                            headings: Array.from(document.querySelectorAll('h1')).map(e => e.textContent),
                            main_landmarks: document.querySelectorAll('main').length,
                            controls: document.querySelectorAll('a,button,input,select,textarea,summary').length,
                            scripts: document.scripts.length
                        })""")
                        name = f"{item['name']}-{scheme}-{width}.png"
                        screenshot = args.output / name
                        page.screenshot(path=str(screenshot), full_page=True)
                        contrast = page.evaluate(TEXT_AUDIT) if args.contrast else None
                        results.append({"file": name, "route": item["route"], "scheme": scheme,
                                        "width": width, "physical_width": physical_width,
                                        "metrics": metrics, "contrast": contrast,
                                        "expected_appearance": item["appearance"], "table_checks": table_checks,
                                        "sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest()})
                    assert not blocked_requests, "synthetic pages attempted external requests"
                    context.close()
            failures = []
            for result in results:
                metrics = result["metrics"]
                reasons = []
                if metrics["document_width"] > result["width"]:
                    reasons.append("horizontal page overflow")
                if metrics["scripts"] or metrics["main_landmarks"] != 1 or len(metrics["headings"]) != 1:
                    reasons.append("script or landmark mismatch")
                if metrics["appearance"] != result["expected_appearance"]:
                    reasons.append("appearance preference mismatch")
                if metrics["forced_colors_active"] != (args.forced_colors == "active"):
                    reasons.append("forced-colour emulation mismatch")
                if args.forced_colors == "active" and metrics["background"] not in {"rgb(255, 255, 255)", "rgb(0, 0, 0)"}:
                    reasons.append("emulated forced palette was not applied")
                if metrics["system_dark"] != (result["scheme"] == "dark"):
                    reasons.append("system scheme emulation mismatch")
                effective = result["scheme"] if result["expected_appearance"] == "system" else result["expected_appearance"]
                expected_background = "rgb(13, 21, 38)" if effective == "dark" else "rgb(245, 247, 251)"
                if args.forced_colors == "none" and metrics["background"] != expected_background:
                    reasons.append("appearance colour mismatch")
                if result["contrast"] and (result["contrast"]["failures"] or result["contrast"]["ui_failures"]):
                    reasons.append("computed contrast below target")
                if reasons:
                    failures.append({"file": result["file"], "reasons": reasons})
            report = {"synthetic": True, "browser_version": browser.version,
                      "browser_executable": args.browser, "screenshots": results,
                      "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "outside_requests": 0,
                      "engine": args.engine, "reflow_simulation_scale": args.zoom,
                      "forced_colors": args.forced_colors,
                      "expanded_details": args.expand_details,
                      "passed": not failures, "failures": failures,
                      "shell_checks": shell_results}
            (args.output / "capture.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print(json.dumps({"screenshots": len(results),
                      "overflow_cases": sum(r["metrics"]["document_width"] > r["width"] for r in results),
                      "text_contrast_failures": sum(len((r["contrast"] or {}).get("failures", [])) for r in results),
                      "ui_contrast_failures": sum(len((r["contrast"] or {}).get("ui_failures", [])) for r in results),
                      "report": str(args.output / "capture.json")}))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
