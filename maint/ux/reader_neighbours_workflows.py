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
 with tempfile.TemporaryDirectory(prefix='osmap-reader-neighbours-') as temporary,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
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
   back='/mailbox?name=INBOX&filter=unread';path='/message?mailbox=INBOX&uid=10&return_to='+quote(back,safe='')
   assert visit(path).status==200
   expect(p.get_by_role('button',name='Previous message',exact=True)).to_be_disabled()
   link=p.get_by_role('link',name='Next message',exact=True);assert 'message_guid=' in link.get_attribute('href');link.press('Enter');p.wait_for_load_state('networkidle');assert uid()=='9'
   expect(p.get_by_role('button',name='Next message',exact=True)).to_be_disabled()
   p.get_by_role('link',name='Previous message',exact=True).click();p.wait_for_load_state('networkidle');assert uid()=='10'
   p.locator('.reader-icon-toolbar form:has(input[name=flag][value=seen]) button').click();p.wait_for_load_state('networkidle');assert 'return_to=' in p.url and 'message_guid=' in p.url
   p.locator('.reader-more-actions > summary').click()
   p.locator('.reader-icon-toolbar form:has(input[name=flag][value=flagged]) button').click();p.wait_for_load_state('networkidle');assert 'return_to=' in p.url
   p.get_by_role('button',name='Use Dark theme',exact=True).click();p.wait_for_load_state('networkidle');assert 'return_to=' in p.url and 'message_guid=' in p.url
   p.get_by_role('link',name='Back to list',exact=True).click();p.wait_for_load_state('networkidle');assert parse_qs(urlsplit(p.url).query)['filter']==['unread']
   report['checks'].append('Newest-first native next/back preserves validated return filter; first and last boundaries disabled; links include verified versions')
   visit('/settings?section=reading');p.get_by_label('Message ordering',exact=True).select_option('oldest');p.get_by_role('button',name='Save reading preferences',exact=True).click();p.wait_for_load_state('networkidle');visit(path)
   expect(p.get_by_role('button',name='Next message',exact=True)).to_be_disabled();p.get_by_role('link',name='Previous message',exact=True).click();p.wait_for_load_state('networkidle');assert uid()=='9';expect(p.get_by_role('button',name='Previous message',exact=True)).to_be_disabled()
   report['checks'].append('Real saved Reading oldest-first preference reverses native neighbour order')
   current=p.url.removeprefix(origin)
   for scheme in ['light','dark']:
    visit(current);p.get_by_role('button',name=f'Use {scheme.title()} theme',exact=True).click();p.wait_for_load_state('networkidle')
    assert p.locator('html').get_attribute('data-appearance')==scheme
    for width in [1600,360]:
     for forced in ['none','active']:
      p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);visit(current);p.get_by_role('link',name='Next message',exact=True).focus()
      name=f'reader-neighbours-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/name),full_page=True)
      overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');audit=p.evaluate(TEXT_AUDIT);assert not overflow and not audit['failures'] and not audit['ui_failures']
      report['captures'].append(dict(file=name,overflow=overflow,contrast=audit))
   p.locator('.reader-more-actions > summary').click();p.get_by_text('Loaded mailbox order',exact=True).click();expect(p.locator('.reader-order-scope')).to_contain_text('do not follow list filters or search results')
   assert visit('/message?mailbox=INBOX&uid=10&mailbox_guid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&message_guid=changed').status==503
   assert p.locator('#reading-pane').count()==0
   context.set_extra_http_headers({'User-Agent':'OSMAP/LegacyMetadata'});assert visit('/message?mailbox=INBOX&uid=10').status==200
   expect(p.get_by_role('button',name='Previous message',exact=True)).to_be_disabled();expect(p.get_by_role('button',name='Next message',exact=True)).to_be_disabled();p.locator('.reader-more-actions > summary').click();p.get_by_text('Loaded mailbox order',exact=True).click();expect(p.locator('.reader-order-scope')).to_contain_text('Navigation unavailable')
   report['checks'].append('Changed link version refuses body; absent summary metadata disables both neighbours with truthful scope')
   assert report['external']==report['sends']==0;report['result']='PASS'
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');browser.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],checks=len(report['checks']),captures=len(report['captures']))))
if __name__=='__main__':main()
