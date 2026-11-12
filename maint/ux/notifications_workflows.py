#!/usr/bin/env python3
"""Synthetic native Notifications settings and presentation; no message mutations."""
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
    with tempfile.TemporaryDirectory(prefix='osmap-notifications-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
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
            elif req.method == 'POST' and urlsplit(req.url).path not in ('/login','/notifications/read','/sessions/revoke'):
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
            visit('/settings?section=notifications')
            assert p.locator('.notification-settings-card').count() == 2
            assert p.locator('.notification-settings-card input:not([disabled])').count() == 0
            p.get_by_role('link', name='Open notifications', exact=True).focus()
            with p.expect_navigation(wait_until='networkidle'): p.keyboard.press('Enter')
            expect(p.get_by_role('heading', name='Notifications', exact=True)).to_be_visible()
            expect(p.locator('.notification-event').first).to_be_visible()
            assert 'Browser session started' in p.locator('.notification-events').inner_text()
            alice_ids=set(p.locator('input[name=event_id]').evaluate_all('(nodes)=>nodes.map(n=>n.value)'))
            stale=ctx.new_page()
            stale.goto(origin+'/notifications',wait_until='networkidle')
            p.get_by_role('button',name='Mark read',exact=True).first.click()
            p.wait_for_load_state('networkidle')
            expect(p.get_by_role('button',name='Mark unread',exact=True).first).to_be_visible()
            with stale.expect_navigation(wait_until='networkidle') as refused:
                stale.get_by_role('button',name='Mark read',exact=True).first.click()
            assert refused.value.status == 409
            expect(stale.locator('[role=alert]')).to_be_visible()
            stale.close()
            p.get_by_role('button',name='Mark unread',exact=True).first.click()
            p.wait_for_load_state('networkidle')
            p.reload(wait_until='networkidle')
            expect(p.get_by_role('button',name='Mark read',exact=True).first).to_be_visible()
            bob=browser.new_context(java_script_enabled=False)
            bob.route('**/*',bounded)
            bp=bob.new_page()
            bp.goto(origin+'/login',wait_until='networkidle')
            bp.get_by_label('Username or Email').fill('bob@example.com')
            bp.get_by_label('Password',exact=True).fill('correct horse battery staple')
            bp.get_by_label('TOTP Code').fill('123456')
            bp.get_by_role('button',name='Sign In',exact=True).click()
            bp.wait_for_load_state('networkidle')
            bp.goto(origin+'/notifications',wait_until='networkidle')
            bob_ids=set(bp.locator('input[name=event_id]').evaluate_all('(nodes)=>nodes.map(n=>n.value)'))
            assert bob_ids and alice_ids.isdisjoint(bob_ids)
            bob.close()
            other=browser.new_context(java_script_enabled=False)
            other.route('**/*',bounded)
            op=other.new_page()
            op.goto(origin+'/login',wait_until='networkidle')
            op.get_by_label('Username or Email').fill('alice@example.com')
            op.get_by_label('Password',exact=True).fill('correct horse battery staple')
            op.get_by_label('TOTP Code').fill('123456')
            op.get_by_role('button',name='Sign In',exact=True).click()
            op.wait_for_load_state('networkidle')
            other.close()
            visit('/sessions')
            p.get_by_role('button',name='Revoke',exact=True).first.click()
            p.wait_for_load_state('networkidle')
            visit('/notifications')
            expect(p.get_by_role('heading',name='Browser session revoked',exact=True).first).to_be_visible()
            p.get_by_role('button',name='Mark read',exact=True).first.click()
            p.wait_for_load_state('networkidle')
            retained_reads=p.locator('.notification-event[data-read=true]').count()
            stop_server(server,root)
            server,origin=start_server(root,Path(__file__).resolve().parents[2],log)
            visit('/notifications')
            assert p.locator('.notification-event[data-read=true]').count() == retained_reads
            report['native_checks']=['actual session start', 'mark read and unread', 'stale revision 409', 'Bob event isolation', 'actual session revoke', 'read state survives restart']
            for scheme in ('light', 'dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        p.set_viewport_size(dict(width=width,height=1100))
                        p.emulate_media(color_scheme=scheme,forced_colors=forced)
                        for surface,path in [('settings','/settings?section=notifications'),('inbox','/notifications')]:
                            visit(path)
                            audit=p.evaluate(TEXT_AUDIT)
                            overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                            file=f'notifications-{surface}-{scheme}-{width}-{forced}.png'
                            p.screenshot(path=str(args.output/file),full_page=True)
                            report['captures'].append(dict(file=file,overflow=overflow,contrast=audit,cards=p.locator('.notification-settings-card').evaluate_all('(nodes)=>nodes.map(n=>{const b=n.getBoundingClientRect();return {x:b.x,y:b.y,width:b.width,height:b.height}})')))
                            assert not overflow and not audit['failures'] and not audit['ui_failures'],file
            record=root/'settings'/(hashlib.sha256(b'osmap-notifications-v1\0alice@example.com').hexdigest()+'.json')
            saved_bytes=record.read_bytes()
            record.write_bytes(b'{')
            try:
                failed=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100))
                failed.route('**/*',bounded)
                fp=failed.new_page()
                fp.goto(origin+'/login',wait_until='networkidle')
                fp.get_by_label('Username or Email').fill('alice@example.com')
                fp.get_by_label('Password',exact=True).fill('correct horse battery staple')
                fp.get_by_label('TOTP Code').fill('123456')
                fp.get_by_role('button',name='Sign In',exact=True).click()
                fp.wait_for_load_state('networkidle')
                expect(fp.get_by_role('heading',name='Signed in',exact=True)).to_be_visible()
                expect(fp.get_by_role('link',name='Continue',exact=True)).to_be_visible()
                fp.screenshot(path=str(args.output/'notification-recording-unconfirmed.png'),full_page=True)
                fp.get_by_role('link',name='Continue',exact=True).click()
                fp.wait_for_load_state('networkidle')
                response=fp.goto(origin+'/notifications',wait_until='networkidle')
                assert response.status == 503
                assert fp.locator('form[action="/notifications/read"]').count() == 0
                fp.screenshot(path=str(args.output/'notification-inbox-unavailable.png'),full_page=True)
                assert record.read_bytes() == b'{'
                failed.close()
            finally: record.write_bytes(saved_bytes)
            report['native_checks'].append('recording failure preserves actual login and corrupt inbox refuses mutations')
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
