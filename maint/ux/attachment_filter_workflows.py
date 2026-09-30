"""Native attachment metadata filtering against disposable synthetic mail."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',captures=[],external=0,sends=0,checks=[])
with tempfile.TemporaryDirectory() as tmp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 process,origin=start_server(Path(tmp),Path(__file__).resolve().parents[2],log)
 b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True);c=b.new_context(java_script_enabled=False,user_agent='OSMAP/ManyMessages;AttachmentFilter',viewport=dict(width=1600,height=1100));page=c.new_page()
 def guard(route):
  if route.request.url.split('?')[0]==origin+'/send':r['sends']+=1
  if route.request.url.startswith(origin+'/'):route.continue_()
  else:r['external']+=1;route.abort()
 c.route('**/*',guard)
 def visit(path):
  response=page.goto(origin+path);assert response.status==200;assert page.locator('script').count()==0
 def subjects():return page.locator('.message-subject-link').all_text_contents()
 try:
  visit('/login');page.get_by_label('Username or Email').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click()
  for mailbox in ['INBOX','Sent','Archive','Trash']:
   visit('/mailbox?name='+mailbox);page.locator('.attachment-filter summary').press('Enter');page.get_by_role('link',name='Has attachment',exact=True).click();assert len(subjects())==31;assert all(int(x.split()[-1])%4==3 for x in subjects())
  r['checks'].append('Native attachment links select actual metadata on Inbox/Sent/Archive/Trash')
  page.get_by_role('link',name='Unread',exact=True).click();assert len(subjects())==31
  page.locator('.attachment-filter summary').click();page.get_by_role('link',name='Attachment status unknown',exact=True).click();assert len(subjects())==32
  visit('/mailbox?name=INBOX&attachment=unknown');assert len(subjects())==50;page.get_by_role('link',name='Next page',exact=True).click();assert len(subjects())==13;assert 'attachment=unknown' in page.url
  visit('/search?q=reader-fixture&scope=all&field=subject&attachment=with&filter=unread');assert len(subjects())==50;page.locator('.message-subject-link').first.click();assert 'attachment=with' in page.url;assert 'scope=all' in page.url;assert 'field=subject' in page.url;assert page.get_by_role('link',name='Back to list',exact=True).count()==1
  page.get_by_role('link',name='Back to list',exact=True).click();assert 'attachment=with' in page.url
  r['checks'].append('Unread composition, unknown paging and search/reader context persist')
  for width in [1600,360]:
   for scheme in ['light','dark']:
    for forced in ['none','active']:
     page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);visit('/mailbox?name=INBOX&attachment=with');page.locator('.attachment-filter summary').press('Enter');assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=page.evaluate(TEXT_AUDIT);name=f'attachment-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/name),full_page=True);r['captures'].append(dict(file=name,contrast=audit));assert not audit['failures'] and not audit['ui_failures']
  assert not r['sends'] and not r['external'];r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(process,Path(tmp))
