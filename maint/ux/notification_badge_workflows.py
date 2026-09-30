#!/usr/bin/env python3
"""Owned notification badge through native synthetic login/read forms; no email."""
import argparse, hashlib, json, tempfile
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output',type=Path)
    ap.add_argument('--engine',default='chromium')
    ap.add_argument('--browser',default='/usr/bin/microsoft-edge-stable')
    a=ap.parse_args(); a.output.mkdir(parents=True,exist_ok=True)
    report=dict(result='FAIL',captures=[],blocked=[],scripts=0)
    with tempfile.TemporaryDirectory(prefix='osmap-badge-') as tmp, (a.output/'server.log').open('w') as log, sync_playwright() as pw:
        root=Path(tmp); server,origin=start_server(root,Path(__file__).resolve().parents[2],log)
        browser=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True)
        report['browser_version']=browser.version
        def bounded(route):
            r=route.request
            if not r.url.startswith(origin+'/') or (r.method=='POST' and urlsplit(r.url).path not in ('/login','/notifications/read')):
                report['blocked'].append(r.resource_type); route.abort()
            else:
                if r.resource_type=='script': report['scripts']+=1
                route.continue_()
        def login(account):
            c=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100)); c.route('**/*',bounded)
            p=c.new_page(); p.goto(origin+'/login',wait_until='networkidle')
            assert p.locator('.header-notifications').count()==0
            p.get_by_label('Username or Email').fill(account)
            p.get_by_label('Password',exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            p.get_by_role('button',name='Sign In',exact=True).click(); p.wait_for_load_state('networkidle')
            return c,p
        def badge(p,count,account='alice@example.com'):
            expect(p.locator('.header-notifications')).to_have_attribute('data-unread',str(count))
            expect(p.locator('.header-notifications')).to_have_attribute('data-notification-account',account)
        def visit(p,path):
            r=p.goto(origin+path,wait_until='networkidle'); assert r.status==200
        try:
            c,p=login('alice@example.com'); visit(p,'/mailboxes'); badge(p,1)
            p.locator('.header-notifications').focus()
            with p.expect_navigation(wait_until='networkidle'): p.keyboard.press('Enter')
            assert urlsplit(p.url).path=='/notifications'; badge(p,1)
            p.get_by_role('button',name='Mark read',exact=True).click(); p.wait_for_load_state('networkidle'); badge(p,0)
            visit(p,'/mailboxes'); badge(p,0)
            visit(p,'/notifications'); p.get_by_role('button',name='Mark unread',exact=True).click(); p.wait_for_load_state('networkidle')
            visit(p,'/settings?section=notifications'); badge(p,1)
            bc,bp=login('bob@example.com'); visit(bp,'/notifications'); badge(bp,1,'bob@example.com')
            bp.get_by_role('button',name='Mark read',exact=True).click(); bp.wait_for_load_state('networkidle'); badge(bp,0,'bob@example.com')
            visit(p,'/mailboxes'); badge(p,1); bc.close()
            record=root/'settings'/(hashlib.sha256(b'osmap-notifications-v1\0alice@example.com').hexdigest()+'.json')
            saved=record.read_bytes()
            for unknown in (False,True):
                if unknown: record.write_bytes(b'{')
                try:
                    for scheme in ('light','dark'):
                        for width in (1600,360):
                            for forced in ('none','active'):
                                p.set_viewport_size(dict(width=width,height=1100)); p.emulate_media(color_scheme=scheme,forced_colors=forced)
                                visit(p,'/mailboxes'); badge(p,'unknown' if unknown else 1)
                                audit=p.evaluate(TEXT_AUDIT); overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth')
                                file=f'badge-{unknown}-{scheme}-{width}-{forced}.png'; p.screenshot(path=str(a.output/file),full_page=True)
                                report['captures'].append(dict(file=file,overflow=overflow,contrast=audit))
                                assert not overflow and not audit['failures'] and not audit['ui_failures'],file
                finally:
                    if unknown: record.write_bytes(saved)
            visit(p,'/mailboxes'); badge(p,1)
            assert not report['blocked'] and report['scripts']==0
            report['checks']=['keyboard bell navigation','read and unread reflected after native navigation','Bob read state isolated','corrupt store keeps ordinary page usable and count unknown','restored store count returns','no external requests or scripts or mail mutations']
            report['result']='PASS'
        finally:
            (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n'); browser.close(); stop_server(server,root)
    print(json.dumps(dict(result=report['result'],captures=len(report['captures']))))
if __name__=='__main__': main()
