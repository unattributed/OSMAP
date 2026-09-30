#!/usr/bin/env python3
"""Synthetic native page-load UTC clock and responsive layout qualification."""
import argparse
import json
from datetime import datetime, timezone
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
    with tempfile.TemporaryDirectory(prefix='osmap-clock-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
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
            for page_name, route in [('welcome','/mailboxes'),('settings','/settings?section=security'),('general','/settings'),('compose','/compose'),('expanded','/compose'),('notice','/mailbox/shortcut?kind=archive')]:
                for scheme in (('light',) if page_name in ('general','compose','expanded') else ('light','dark')):
                    for width in ((1600,1199) if page_name in ('general','compose','expanded') else (1600,360)):
                        for forced in (('none',) if page_name in ('general','compose','expanded') else ('none','active')):
                            p.set_viewport_size(dict(width=width,height=1100))
                            p.emulate_media(color_scheme=scheme,forced_colors=forced)
                            before=datetime.now(timezone.utc)
                            visit(route)
                            after=datetime.now(timezone.utc)
                            if page_name == 'expanded':
                                p.locator('label[for=compose-expanded]').click()
                                assert p.locator('#compose-expanded').is_checked()
                                assert p.locator('.compose-shell').evaluate('el=>getComputedStyle(el).position') == 'fixed'
                            clock=p.locator('.shell-request-clock')
                            value=clock.locator('time').get_attribute('datetime')
                            instant=datetime.fromisoformat(value.replace('Z','+00:00'))
                            assert before.timestamp()-1 <= instant.timestamp() <= after.timestamp()
                            expect(clock).to_contain_text('UTC')
                            expect(clock).to_contain_text('Updated on page load')
                            heading=p.locator('main h1').first.bounding_box()
                            box=clock.bounding_box()
                            overlap=not(box['x']+box['width']<=heading['x'] or heading['x']+heading['width']<=box['x'] or box['y']+box['height']<=heading['y'] or heading['y']+heading['height']<=box['y'])
                            # Heading padding reserves the clock lane; measure actual text, not its padded box.
                            overlap=p.locator('main h1').first.evaluate('(el)=>{const r=document.createRange();r.selectNodeContents(el);const t=r.getBoundingClientRect(),c=document.querySelector(".shell-request-clock").getBoundingClientRect();return !(t.right<=c.left||t.left>=c.right||t.bottom<=c.top||t.top>=c.bottom)}')
                            assert not overlap
                            overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                            audit=p.evaluate(TEXT_AUDIT)
                            file=f'clock-{page_name}-{scheme}-{width}-{forced}.png'
                            p.screenshot(path=str(args.output/file),full_page=True)
                            report['captures'].append(dict(file=file,overflow=overflow,contrast=audit,clock_box=box,heading_overlap=overlap))
                            assert not overflow and not audit['failures'] and not audit['ui_failures'],file
            visit('/login')
            assert p.locator('.shell-request-clock').count()==0
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
