#!/usr/bin/env python3
"""Synthetic native Labels management and assignment; no message mutations."""
import argparse
import hashlib
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
    with tempfile.TemporaryDirectory(prefix='osmap-labels-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
        root = Path(temp)
        server, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report['browser_version'] = browser.version
        ctx = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100),user_agent='OSMAP/ManyMessages')
        def bounded(route):
            req = route.request
            if not req.url.startswith(origin+'/'):
                report['external_requests'] += 1
                route.abort()
            elif req.method == 'POST' and urlsplit(req.url).path not in ('/login','/labels/change','/message/move'):
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
            p.get_by_role('link',name='Labels Organize messages',exact=True).click()
            p.wait_for_load_state('networkidle')
            p.get_by_label('Label name',exact=True).fill('Project <Aurora>')
            p.get_by_role('button',name='Create label',exact=True).click();p.wait_for_load_state('networkidle')
            expect(p.get_by_role('heading',name='Project <Aurora>',exact=True)).to_be_visible()
            stale=ctx.new_page();stale.goto(origin+'/labels',wait_until='networkidle')
            p.locator('.label-editor').first.locator('summary').click()
            p.get_by_label('New label name',exact=True).fill('Security review')
            p.get_by_role('button',name='Save name',exact=True).click();p.wait_for_load_state('networkidle')
            stale.get_by_label('Label name',exact=True).fill('Stale proposal')
            with stale.expect_navigation(wait_until='networkidle') as response: stale.get_by_role('button',name='Create label',exact=True).click()
            assert response.value.status == 409
            expect(stale.get_by_label('Label name',exact=True)).to_have_value('Stale proposal')
            expect(stale.get_by_role('button',name='Create label',exact=True)).to_be_disabled();stale.close()
            visit('/message?mailbox=INBOX&uid=123')
            p.locator('.reader-labels summary').click()
            p.get_by_role('link',name='Edit message labels',exact=True).click();p.wait_for_load_state('networkidle')
            p.get_by_role('button',name='Attach label',exact=True).click();p.wait_for_load_state('networkidle')
            expect(p.get_by_text('Assigned',exact=True)).to_be_visible()
            p.get_by_role('button',name='Detach label',exact=True).click();p.wait_for_load_state('networkidle')
            p.get_by_role('button',name='Attach label',exact=True).click();p.wait_for_load_state('networkidle')
            assigned_path=p.get_by_role('link',name='Reload labels',exact=True).get_attribute('href')
            stop_server(server,root);server,origin=start_server(root,Path(__file__).resolve().parents[2],log)
            visit(assigned_path);expect(p.get_by_text('Assigned',exact=True)).to_be_visible()
            bob=browser.new_context(java_script_enabled=False);bob.route('**/*',bounded);bp=bob.new_page()
            bp.goto(origin+'/login',wait_until='networkidle');bp.get_by_label('Username or Email').fill('bob@example.com');bp.get_by_label('Password',exact=True).fill('correct horse battery staple');bp.get_by_label('TOTP Code').fill('123456');bp.get_by_role('button',name='Sign In',exact=True).click();bp.wait_for_load_state('networkidle');bp.goto(origin+'/labels',wait_until='networkidle')
            expect(bp.get_by_text('No labels yet. Create one above to begin.',exact=True)).to_be_visible();bob.close()
            for scheme in ('light','dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced)
                        visit('/message?mailbox=INBOX&uid=123')
                        p.locator('.reader-labels summary').click()
                        ra=p.evaluate(TEXT_AUDIT);ro=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        rf=f'reader-labels-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/rf),full_page=True)
                        report['captures'].append(dict(file=rf,overflow=ro,contrast=ra))
                        assert not ro and not ra['failures'] and not ra['ui_failures']
                        visit(assigned_path)
                        audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        file=f'labels-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/file),full_page=True)
                        report['captures'].append(dict(file=file,overflow=overflow,contrast=audit))
                        assert not overflow and not audit['failures'] and not audit['ui_failures']
            p.get_by_role('link',name='Back to message',exact=True).click();p.wait_for_load_state('networkidle')
            p.locator('.reader-more-actions > summary').click();p.get_by_role('button',name='Move to Bin',exact=True).click();p.wait_for_load_state('networkidle')
            visit('/mailbox?name=INBOX')
            assert p.locator('.message-subject-link').filter(has_text='Message 123').count() == 0
            visit('/mailbox?name=Trash')
            targets=p.locator('.message-subject-link, .archive-subject').filter(has_text='Message 123').evaluate_all('(nodes)=>nodes.map(n=>n.getAttribute("href"))')
            assert 1 <= len(targets) <= 2
            found=False
            for target in targets:
                visit(target);p.locator('.reader-labels summary').click();p.get_by_role('link',name='Edit message labels',exact=True).click();p.wait_for_load_state('networkidle')
                found=found or p.get_by_text('Assigned',exact=True).count() == 1
            assert found
            visit('/labels');expect(p.locator('.labels-usage')).to_contain_text('1 of 2,000')
            p.locator('.label-delete summary').click();p.get_by_label('Confirm delete label and its assignments',exact=True).check();p.get_by_role('button',name='Delete label',exact=True).click();p.wait_for_load_state('networkidle')
            expect(p.get_by_text('No labels yet. Create one above to begin.',exact=True)).to_be_visible()
            report['native_checks']=['Welcome entry and escaped create','native rename','stale409 preserves submitted name','reader attach/detach','restart persistence','Bob isolation','confirmed move carries label to verified Trash identity','delete confirmation removes label and assignment']
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
