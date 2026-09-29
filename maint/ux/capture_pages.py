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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--schemes", nargs="+", choices=["light", "dark"], default=["light"])
    parser.add_argument("--widths", nargs="+", type=int, default=[360, 768, 1440])
    parser.add_argument("--names", nargs="+", help="capture only these manifest fixture names")
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
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.browser, headless=True)
            for scheme in args.schemes:
                for width in args.widths:
                    context = browser.new_context(viewport={"width": width, "height": 1000},
                                                  color_scheme=scheme, reduced_motion="reduce")
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
                        if item["name"] == "source":
                            for summary in page.locator("summary").all():
                                if "source" in summary.inner_text().lower():
                                    summary.click()
                        metrics = page.evaluate("""() => ({
                            viewport: window.innerWidth,
                            document_width: document.documentElement.scrollWidth,
                            background: getComputedStyle(document.body).backgroundColor,
                            foreground: getComputedStyle(document.body).color,
                            appearance: document.documentElement.dataset.appearance,
                            headings: Array.from(document.querySelectorAll('h1')).map(e => e.textContent),
                            controls: document.querySelectorAll('a,button,input,select,textarea,summary').length,
                            scripts: document.scripts.length
                        })""")
                        name = f"{item['name']}-{scheme}-{width}.png"
                        screenshot = args.output / name
                        page.screenshot(path=str(screenshot), full_page=True)
                        results.append({"file": name, "route": item["route"], "scheme": scheme,
                                        "width": width, "metrics": metrics,
                                        "sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest()})
                    assert not blocked_requests, "synthetic pages attempted external requests"
                    context.close()
            report = {"synthetic": True, "browser_version": browser.version,
                      "browser_executable": args.browser, "screenshots": results}
            (args.output / "capture.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print(json.dumps({"screenshots": len(results),
                      "overflow_cases": sum(r["metrics"]["document_width"] > r["width"] for r in results),
                      "report": str(args.output / "capture.json")}))


if __name__ == "__main__":
    main()
