#!/usr/bin/env python3
"""Exercise the real router/forms/cookies with a bounded synthetic loopback gateway.

Authentication is a test fixture, not Dovecot/TOTP qualification. Appearance
uses the real file store. This starts no runtime gateway and sends no email.
No browser storage, session token, CSRF value or filled login form is retained.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from playwright.sync_api import sync_playwright

SERVER_STOP_SECONDS = 5


def require(condition, message='workflow_check_failed'):
    # Acceptance checks and their operations must remain active under python -O.
    # Evaluate optional diagnostics only on failure, as the original checks did.
    if not condition:
        raise AssertionError(message() if callable(message) else message)


def _reap_server(process, root):
    """Stop only the born private fixture group; never signal a reaped PID."""
    marker_error = None
    try:
        (root / "stop").touch()
    except OSError as error:
        marker_error = error
    graceful = marker_error is None
    code = process.returncode
    if graceful:
        try:
            code = process.wait(timeout=SERVER_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            graceful = False
    if not graceful and process.returncode is None:
        for number in (signal.SIGTERM, signal.SIGKILL):
            if process.returncode is None:
                try:
                    os.killpg(process.pid, number)
                except ProcessLookupError:
                    pass
            try:
                code = process.wait(timeout=SERVER_STOP_SECONDS)
                break
            except subprocess.TimeoutExpired:
                if number == signal.SIGKILL:
                    raise RuntimeError("synthetic server cleanup unconfirmed") from None
    # After direct reap the historical PID grants no further signal authority.
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        if marker_error is not None:
            raise marker_error
        return code, graceful
    raise RuntimeError("synthetic server group remains after direct reap")


def start_server(root, repo, log):
    for name in ["ready.json", "stop"]:
        (root / name).unlink(missing_ok=True)
    env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(root))
    deadline = time.monotonic() + 45
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    process = None
    try:
        process = subprocess.Popen(["cargo", "test", "--lib", "ux_synthetic_browser_server", "--", "--ignored", "--nocapture"],
                                   cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True,
                                   preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
        # Pending handled interruptions can run only after the child handle is
        # assigned and this cleanup-protected region owns its disposition.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        while time.monotonic() < deadline:
            if (root / "ready.json").exists():
                data = json.loads((root / "ready.json").read_text())
                origin = data.get("origin")
                match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", origin) if type(origin) is str else None
                require(data.get("synthetic") is True and match is not None
                        and 1 <= int(match[1]) <= 65535, "synthetic loopback origin refused")
                return process, origin
            if process.poll() is not None:
                raise RuntimeError("synthetic server exited before readiness; see fixture log")
            time.sleep(.05)
        raise RuntimeError("synthetic server readiness timed out")
    except BaseException:
        if process is not None:
            _reap_server(process, root)
        raise
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def stop_server(process, root):
    result, graceful = _reap_server(process, root)
    require(graceful, "synthetic server did not stop cleanly")
    require(result == 0, "synthetic server test failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-browser-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        browser = playwright.chromium.launch(executable_path=args.browser, headless=True)
        process, origin = start_server(root, repo, log)
        blocked = []
        context = browser.new_context(viewport={"width": 1280, "height": 900}, color_scheme="light")

        def constrain(route):
            if route.request.url.startswith(origin + "/"):
                route.continue_()
            else:
                blocked.append(route.request.resource_type)
                route.abort()

        context.route("**/*", constrain)
        page = context.new_page()

        # This exception is pinned to the accepted fixed Compose source. It
        # permits neither remote scripts nor scripts on any other visited page.
        trusted_script = (repo / "src/http/compose_local.js").read_bytes()
        trusted_hash = "sha256-" + base64.b64encode(hashlib.sha256(trusted_script).digest()).decode("ascii")
        require((trusted_hash == "sha256-kh8tYa8AQwqxy9l64g1sCx8epjT43a/Wj5pR91Smywc="), lambda: ("Compose source hash changed"))
        base_csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

        def visit(path):
            result = page.goto(origin + path, wait_until="networkidle")
            require((result and result.ok), lambda: (path))
            csp = result.all_headers().get("content-security-policy")
            if path == "/compose":
                require((page.locator("script").count() == 1), lambda: ("Compose requires exactly its fixed script"))
                script = page.locator("script#osmap-compose-local")
                require((script.count() == 1), lambda: ("Unexpected Compose script identity"))
                require((script.evaluate("element => [...element.attributes].map(attribute => [attribute.name, attribute.value])") == [["id", "osmap-compose-local"]]), lambda: ("Unexpected script attribute or external source"))
                require((script.text_content() == trusted_script.decode("utf-8")), lambda: ("Compose script source differs"))
                require((csp == base_csp + f"; connect-src 'self'; script-src '{trusted_hash}'; script-src-attr 'none'"), lambda: ("Unexpected Compose CSP allowance"))
            else:
                require((page.locator("script").count() == 0), lambda: ("Script outside Compose"))
                require((csp == base_csp), lambda: ("Non-Compose CSP changed"))

        def appearance(value):
            require((page.locator("html").get_attribute("data-appearance") == value), 'browser_workflows_check_101')

        def login(account, expected):
            visit("/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")
            appearance(expected)

        def logout():
            page.locator(".account-menu summary").click()
            page.get_by_role("button", name="Log Out", exact=True).click()
            page.wait_for_url(origin + "/login")

        try:
            login("alice", "system")
            visit("/settings?section=appearance")
            page.locator("label.settings-theme-dark").click()
            require((page.get_by_label("Dark", exact=True).is_checked()), 'browser_workflows_check_121')
            page.get_by_role("button", name="Save changes", exact=True).click()
            page.wait_for_url(origin + "/settings?section=appearance&appearance_updated=1")
            appearance("dark")
            for path in ["/compose", "/drafts", "/sessions", "/settings?section=appearance"]:
                visit(path)
                appearance("dark")
            page.reload(wait_until="networkidle")
            appearance("dark")
            require((page.get_by_label("Dark", exact=True).is_checked()), 'browser_workflows_check_130')
            checks.append("account preference persists through native form, redirect, navigation and reload")
            logout()
            appearance("dark")
            checks.append("logout retains presentation preference")
            context.add_cookies([{"name": "osmap_appearance", "value": "light", "url": origin}])
            login("alice", "dark")
            checks.append("login restores saved account choice over stale browser preference")
            logout()
            login("bob", "system")
            visit("/settings?section=appearance")
            page.emulate_media(color_scheme="dark")
            require((page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(13, 21, 38)"), 'browser_workflows_check_142')
            page.emulate_media(color_scheme="light")
            require((page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(245, 248, 254)"), 'browser_workflows_check_144')
            checks.append("system appearance follows OS change without a reload")
            light = page.get_by_label("Light", exact=True)
            light.focus()
            light.press("Space")
            require((light.is_checked()), 'browser_workflows_check_149')
            page.get_by_role("button", name="Save changes", exact=True).click()
            page.wait_for_url(origin + "/settings?section=appearance&appearance_updated=1")
            appearance("light")
            page.emulate_media(color_scheme="dark")
            require((page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(245, 248, 254)"), 'browser_workflows_check_154')
            logout()
            login("alice", "dark")
            checks.append("two synthetic accounts retain independent preferences")
            context.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            context.route("**/*", constrain)
            page = context.new_page()
            login("alice", "dark")
            logout()
            login("bob", "light")
            checks.append("new server process restores both saved account preferences")
            require((not blocked), lambda: ("synthetic application attempted outside requests"))
            report = {"synthetic": True, "authentication": "test fixture; not live Dovecot/TOTP",
                      "appearance_storage": "real AppearanceStore", "browser_version": browser.version,
                      "checks": checks, "outside_requests": 0, "passed": True}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            if process.poll() is None:
                stop_server(process, root)
            browser.close()
    print(json.dumps({"passed": True, "checks": len(checks), "report": str(args.output / "workflows.json")}))


if __name__ == "__main__":
    main()
