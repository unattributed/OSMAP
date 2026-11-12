#!/usr/bin/env python3
"""Native standalone previous/next using only bounded synthetic loopback mail."""
import argparse,json,tempfile
from pathlib import Path
from urllib.parse import quote,parse_qs,urlsplit
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(parents=True,exist_ok=True)
 report=dict(result='FAIL',checks=[],captures=[],external=0,sends=0)
 with tempfile.TemporaryDirectory(prefix='osmap-after-archive-') as temporary,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temporary);server,origin=start_server(root,Path(__file__).resolve().parents[2],log)
  browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);report['browser']=browser.version
  context=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100));p=context.new_page()
  def bounded(route):
   if route.request.url.split('?')[0]==origin+'/send':report['sends']+=1;route.abort()
   elif route.request.url.startswith(origin+'/'):route.continue_()
   else:report['external']+=1;route.abort()
  context.route('**/*',bounded)
  def visit(path):return p.goto(origin+path,wait_until='networkidle')
  def uid():return parse_qs(urlsplit(p.url).query)['uid'][0]
  try:
   visit('/login');p.get_by_label('Username or Email').fill('alice@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_url('**/mailboxes')
   visit('/settings?section=reading');expect(p.get_by_label('After archive',exact=True)).to_have_value('list');p.get_by_label('After archive',exact=True).select_option('next');p.get_by_role('button',name='Save after-archive choice',exact=True).click();p.wait_for_load_state('networkidle');expect(p.get_by_label('After archive',exact=True)).to_have_value('next')
   for scheme in ['light','dark']:
    for width in [1600,360]:
     for forced in ['none','active']:
      p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);p.get_by_label('After archive',exact=True).focus();audit=p.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];assert p.evaluate('document.documentElement.scrollWidth<=innerWidth');name=f'after-archive-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/name),full_page=True);report['captures'].append(name)
   p.set_viewport_size(dict(width=1600,height=1100));p.emulate_media(color_scheme='light',forced_colors='none');visit('/settings?section=copies');p.locator('#copies-archive').select_option('INBOX.Projects');p.get_by_role('button',name='Save archive folder',exact=True).click();p.wait_for_load_state('networkidle')
   back='/mailbox?name=INBOX&sort=received&dir=desc&page=1';visit('/message?mailbox=INBOX&uid=10&return_to='+quote(back,safe=''));p.get_by_role('button',name='Archive message',exact=True).click();p.wait_for_load_state('networkidle');assert uid()=='9';assert 'mailbox_guid=' in p.url and 'return_to=' in p.url
   p.get_by_role('button',name='Archive message',exact=True).click();p.wait_for_load_state('networkidle');assert urlsplit(p.url).path=='/mailbox';assert parse_qs(urlsplit(p.url).query)['name']==['INBOX'];report['checks'].append('Native persisted Next preference; confirmed Archive10 opens version-bound9 with Back context; final row Archive returns list')
   assert report['external']==report['sends']==0;report['result']='PASS'
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');browser.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],checks=len(report['checks']),captures=len(report['captures']))))
if __name__=='__main__':main()
