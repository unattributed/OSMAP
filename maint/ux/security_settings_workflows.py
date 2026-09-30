#!/usr/bin/env python3
"""Synthetic native Security/Authentication navigation; no security mutations."""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--engine', default='chromium')
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = dict(result='FAIL', captures=[], external_requests=0, post_requests=0, script_requests=0)
    with tempfile.TemporaryDirectory(prefix='osmap-security-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
        root = Path(temp)
        server, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report['browser_version'] = browser.version
        ctx = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100))
        def bounded(route):
            req = route.request
            if not req.url.startswith(origin+'/'):
                report['external_requests'] += 1
                route.abort()
            elif req.method == 'POST' and urlsplit(req.url).path != '/login':
                report['post_requests'] += 1
                route.abort()
            else:
                if req.resource_type == 'script': report['script_requests'] += 1
                route.continue_()
        ctx.route('**/*', bounded)
        p = ctx.new_page()
        def visit(path):
            response = p.goto(origin+path, wait_until='networkidle')
            assert response.status == 200
            assert response.headers['cache-control'] == 'no-store'
        try:
            visit('/login')
            p.get_by_label('Username or Email').fill('alice@example.com')
            p.get_by_label('Password', exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            p.get_by_role('button', name='Sign In', exact=True).click()
            p.wait_for_load_state('networkidle')
            visit('/mailboxes')
            p.locator('.welcome-shortcut[href="/settings?section=security"]').focus()
            p.keyboard.press('Enter')
            p.wait_for_url('**/settings?section=security')
            expect(p.get_by_role('heading', name='Security Controls')).to_be_visible()
            assert p.locator('.security-control button:not([disabled])').count() == 0
            p.get_by_role('link', name='Manage sessions', exact=True).click()
            p.wait_for_url('**/sessions')
            visit('/settings?section=security')
            p.locator('.security-heading a').click()
            p.wait_for_url('**/settings?section=privacy')
            p.get_by_role('navigation', name='Settings sections').get_by_role('link', name='Authentication & Recovery', exact=True).click()
            p.wait_for_url('**/settings?section=authentication')
            expect(p.get_by_role('heading', name='Authentication', exact=True)).to_be_visible()
            assert p.locator('.authentication-cards button:not([disabled])').count() == 0
            p.get_by_role('link', name='Manage sessions', exact=True).click()
            p.wait_for_url('**/sessions')
            visit('/settings?q=authentication')
            assert p.locator('main a[href="/settings?section=authentication"]').count() > 0
            other = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100))
            other.route('**/*', bounded)
            bob = other.new_page()
            bob.goto(origin+'/login', wait_until='networkidle')
            bob.get_by_label('Username or Email').fill('bob@example.com')
            bob.get_by_label('Password', exact=True).fill('correct horse battery staple')
            bob.get_by_label('TOTP Code').fill('123456')
            bob.get_by_role('button', name='Sign In', exact=True).click()
            bob.wait_for_url('**/mailboxes')
            for section in ('security', 'authentication'):
                response = bob.goto(origin+'/settings?section='+section, wait_until='networkidle')
                assert response.status == 200
                expect(bob.locator('main')).to_contain_text('1 active browser sessions')
                assert 'alice@example.com' not in bob.locator('body').inner_text()
                visit('/settings?section='+section)
                expect(p.locator('main')).to_contain_text('1 active browser sessions')
                assert 'bob@example.com' not in p.locator('body').inner_text()
            report['account_isolation'] = 'PASS: each of two real session stores exposes only its account session'
            other.close()
            for section in ('security', 'authentication'):
                for scheme in ('light', 'dark'):
                    for width in (1600, 360):
                        for forced in ('none', 'active'):
                            p.set_viewport_size(dict(width=width, height=1100))
                            p.emulate_media(color_scheme=scheme, forced_colors=forced)
                            visit('/settings?section='+section)
                            assert p.locator('script').count() == 0
                            overflow = p.evaluate('document.documentElement.scrollWidth > innerWidth')
                            audit = p.evaluate(TEXT_AUDIT)
                            file = f'{section}-{scheme}-{width}-{forced}.png'
                            p.screenshot(path=str(args.output/file), full_page=True)
                            report['captures'].append(dict(file=file, overflow=overflow, contrast=audit, boxes=p.locator('.security-card').evaluate_all('els=>els.map(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom}))')))
                            assert not overflow and not audit['failures'] and not audit['ui_failures'], file
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
