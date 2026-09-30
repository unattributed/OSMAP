#!/usr/bin/env python3
"""Native synthetic Snooze proof, no mail movement or outbound traffic."""
import argparse,json,tempfile,datetime
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(parents=True,exist_ok=True,mode=0o700)
 report=dict(result='FAIL',checks=[],captures=[],external=0,scripts=0,mail_mutations=0)
 with tempfile.TemporaryDirectory(prefix='osmap-snooze-ui-') as temporary,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temporary);server,origin=start_server(root,Path(__file__).resolve().parents[2],log);browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True)
  def login(account='alice@example.com'):
   c=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100))
   def guard(r):
    path=r.request.url.split('?')[0]
    if path in [origin+'/send',origin+'/message/move',origin+'/messages/move',origin+'/messages/archive']:report['mail_mutations']+=1;r.abort()
    elif r.request.resource_type=='script':report['scripts']+=1;r.abort()
    elif r.request.url.startswith(origin+'/'):r.continue_()
    else:report['external']+=1;r.abort()
   c.route('**/*',guard);p=c.new_page();p.goto(origin+'/login');p.get_by_label('Username or Email').fill(account);p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_load_state('networkidle');return p
  p=login()
  def visit(path):return p.goto(origin+path,wait_until='networkidle')
  try:
   visit('/message?mailbox=INBOX&uid=9');p.get_by_role('link',name='Snooze message',exact=True).press('Enter');p.wait_for_load_state('networkidle');form_url=p.url
   expect(p.get_by_label('Return at (UTC)',exact=True)).to_be_visible();expect(p.locator('.snooze-scope')).to_contain_text('Search and direct Reader access remain available')
   stale=p.context.new_page();stale.goto(form_url);
   value=(datetime.datetime.strptime(p.locator('#snooze-until').get_attribute('min'),'%Y-%m-%dT%H:%M')+datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M');p.get_by_label('Return at (UTC)',exact=True).fill(value);p.get_by_role('button',name='Save snooze',exact=True).press('Enter');p.wait_for_load_state('networkidle')
   stale_value=(datetime.datetime.strptime(value,'%Y-%m-%dT%H:%M')+datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M');stale.get_by_label('Return at (UTC)',exact=True).fill(stale_value)
   with stale.expect_response(lambda r: r.url.endswith('/snooze/change')) as conflict: stale.get_by_role('button',name='Save snooze',exact=True).click()
   assert conflict.value.status==409;expect(stale.get_by_label('Return at (UTC)',exact=True)).to_have_value(stale_value);expect(stale.get_by_role('button',name='Save snooze',exact=True)).to_be_disabled();stale.get_by_role('link',name='Reload saved snooze',exact=True).click();expect(stale.get_by_role('button',name='Save snooze',exact=True)).to_be_enabled();stale.get_by_label('Return at (UTC)',exact=True).fill(stale_value);stale.get_by_role('button',name='Save snooze',exact=True).click();stale.wait_for_load_state('networkidle');assert '/snooze/change' not in stale.url;report['checks'].append('Stale native tab returns409, retains submitted UTC, disables mutation and requires explicit reload')
   visit('/mailbox?name=INBOX');assert p.locator('.message-card').filter(has_text='Quarterly report').count()==0
   visit('/mailboxes');assert p.locator('.welcome-recent-link').filter(has_text='Quarterly report').count()==0
   assert visit('/message?mailbox=INBOX&uid=9').status==200;expect(p.locator('#reading-pane')).to_be_visible()
   visit('/snoozed');expect(p.locator('.snooze-count')).to_contain_text('1 of 100');report['checks'].append('Native UTC snooze hides source list and Welcome; direct Reader remains accessible; actual marker visible')
   bob=login('bob@example.com');bob.goto(origin+'/snoozed');expect(bob.get_by_text('No active snooze markers.',exact=True)).to_be_visible()
   fresh=login();fresh.goto(origin+'/snoozed');expect(fresh.locator('.snooze-count')).to_contain_text('1 of 100');report['checks'].append('Fresh authenticated context reads durable marker; Bob sees independent empty store')
   for scheme in ['light','dark']:
    visit('/snoozed');p.get_by_role('button',name=f'Use {scheme.title()} theme',exact=True).click();p.wait_for_load_state('networkidle')
    for width in [1600,360]:
     for forced in ['none','active']:
      p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced)
      for path,label in [(form_url.removeprefix(origin),'snooze-form'),('/snoozed','snooze-markers'),('/message?mailbox=INBOX&uid=9','snooze-reader')]:
       visit(path);focus=p.get_by_role('link',name='Snooze message',exact=True) if label=='snooze-reader' else p.get_by_role('button',name='Cancel snooze',exact=True);focus.focus();expect(focus).to_be_focused();audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');name=f'{label}-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/name),full_page=True);height=p.locator('.reader-toolbar').evaluate('e=>e.getBoundingClientRect().height') if label=='snooze-reader' else None;report['captures'].append(dict(file=name,overflow=overflow,contrast=audit,toolbar_height=height));assert height is None or width!=1600 or height<=60,(name,height);assert not overflow and not audit['failures'] and not audit['ui_failures'],name
   visit('/snoozed');p.get_by_role('button',name='Cancel snooze',exact=True).click();p.wait_for_load_state('networkidle');visit('/mailbox?name=INBOX');assert p.locator('.message-card').filter(has_text='Quarterly report').count()==1;visit('/snoozed');expect(p.get_by_text('No active snooze markers.',exact=True)).to_be_visible();report['checks'].append('Native cancel removes owned marker and restores source-list visibility')
   assert report['external']==report['scripts']==report['mail_mutations']==0;report['result']='PASS'
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');browser.close();stop_server(server,root)
if __name__=='__main__':main()
