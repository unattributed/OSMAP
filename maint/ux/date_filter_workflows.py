"""Received-date range proof using only native forms and synthetic loopback mail."""
import argparse,json,tempfile
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',checks=[],captures=[],external=0,scripts=0,sends=0)
with tempfile.TemporaryDirectory() as t,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 root=Path(t);proc,origin=start_server(root,Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True);r['browser']=b.version
 def login(ua):
  c=b.new_context(java_script_enabled=False,user_agent=ua,viewport=dict(width=1600,height=1100))
  def guard(rt):
   if rt.request.resource_type=='script':r['scripts']+=1
   if rt.request.url.split('?')[0]==origin+'/send':r['sends']+=1
   if rt.request.url.startswith(origin+'/'):rt.continue_()
   else:r['external']+=1;rt.abort()
  c.route('**/*',guard);p=c.new_page();p.goto(origin+'/login');p.get_by_label('Username or Email').fill('alice@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_url('**/mailboxes');return p
 def visit(path):
  res=page.goto(origin+path);assert res.status==200;assert page.locator('script').count()==0
 def dates(start,end):
  if page.locator('.sent-filter-menu').count():page.locator('.sent-filter-menu > summary').press('Enter')
  page.locator('.date-filter > summary').press('Enter');form=page.locator('.date-filter form');assert form.locator('[name=after]').count()==form.locator('[name=before]').count()==1
  page.get_by_label('From date (UTC)',exact=True).fill(start);page.get_by_label('Through date (UTC)',exact=True).fill(end);page.get_by_role('button',name='Apply dates',exact=True).press('Enter');page.wait_for_load_state()
 try:
  page=login('DateBrowser');visit('/mailbox?name=INBOX');assert page.locator('.message-card').count()==2;dates('2026-03-28','2026-03-28');assert page.locator('.message-card').count()==1;expect(page.locator('.message-subject-link')).to_have_text('Follow-up');r['checks'].append('Native UTC day range excludes March 27 and retains actual March 28 summary')
  for value in ['2026-02-29','2026-1-01','0000-01-01']:
   assert page.goto(origin+'/mailbox?name=INBOX&after='+value).status==400
  assert page.goto(origin+'/mailbox?name=INBOX&after=2026-03-29&before=2026-03-28').status==400
  page=login('OSMAP/ManyMessages');visit('/mailbox?name=INBOX&filter=unread');dates('2026-09-30','2026-09-30');q=parse_qs(urlsplit(page.url).query);assert q['filter']==['unread'];page.get_by_role('link',name='Next page',exact=True).click();page.wait_for_load_state();assert 'after=2026-09-30' in page.url;page.locator('.message-subject-link').first.click();page.wait_for_load_state();page.get_by_role('link',name='Back to list',exact=True).click();page.wait_for_load_state();assert 'before=2026-09-30' in page.url
  ret=page.locator('[data-header-return]').first.get_attribute('value');assert 'after=2026-09-30' in ret and 'before=2026-09-30' in ret
  visit('/search?q=reader-fixture&scope=all&field=subject&filter=unread&attachment=unknown');dates('2026-09-30','2026-09-30');q=parse_qs(urlsplit(page.url).query);assert q['field']==['subject'] and q['scope']==['all'] and q['q']==['reader-fixture'];page.locator('.message-sort summary').press('Enter');page.get_by_role('link',name='Sort by Subject ascending',exact=True).click();page.wait_for_load_state();assert 'after=2026-09-30' in page.url
  page.locator('.date-filter > summary').press('Enter');page.get_by_role('link',name='Clear dates',exact=True).click();page.wait_for_load_state();assert 'after=' not in page.url and 'before=' not in page.url and 'attachment=unknown' in page.url;r['checks'].append('Combined unread/attachment filters, paging, reader/back, header return, search field/scope, sort and clear retain finite context')
  for width in [1600,360]:
   for scheme in ['light','dark']:
    for forced in ['none','active']:
     page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);visit('/mailbox?name=Sent&after=2026-09-30&before=2026-09-30');toolbar=page.locator('.mail-list-toolbar').bounding_box();assert width!=1600 or toolbar['height']<=65
     page.locator('.sent-filter-menu > summary').press('Enter');page.locator('.date-filter > summary').press('Enter');page.get_by_label('From date (UTC)',exact=True).focus();assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=page.evaluate(TEXT_AUDIT);file=f'dates-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/file),full_page=False);r['captures'].append(dict(file=file,contrast=audit,toolbar=toolbar));assert not audit['failures'] and not audit['ui_failures'],file
  assert r['external']==r['scripts']==r['sends']==0;r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(proc,root)
