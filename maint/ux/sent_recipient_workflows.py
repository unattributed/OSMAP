"""Native Sent header projection using only disposable synthetic fixtures."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',checks=[],captures=[],external=0,scripts=0,sends=0)
with tempfile.TemporaryDirectory() as tmp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 process,origin=start_server(Path(tmp),Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True);r['browser']=b.version;c=b.new_context(java_script_enabled=False,user_agent='OSMAP/ManyMessages;SentRecipients',viewport=dict(width=1600,height=1100));page=c.new_page()
 def guard(route):
  if route.request.resource_type=='script':r['scripts']+=1
  if route.request.url.split('?')[0]==origin+'/send':r['sends']+=1
  if route.request.url.startswith(origin+'/'):route.continue_()
  else:r['external']+=1;route.abort()
 c.route('**/*',guard)
 def visit(path):
  response=page.goto(origin+path);assert response.status==200;assert page.locator('script').count()==0
 try:
  visit('/login');page.get_by_label('Username or Email').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click()
  visit('/mailbox?name=Sent');expect(page.locator('.column-sender')).to_have_text('Recipient');expect(page.locator('.message-sender').first).to_have_text('To: <img src=x> & recipient@example.test');expect(page.locator('.message-sender').nth(1)).to_have_text('Recipient unavailable');assert page.locator('img').count()==0;assert page.locator('[title="Initials from the recipient header"]').count()==50
  page.get_by_role('link',name='Next page',exact=True).click();assert 'page=2' in page.url;assert page.locator('.message-sender').first.inner_text().startswith('To: Recipient 075')
  page.locator('.sent-filter-menu summary').first.press('Enter');page.get_by_role('link',name='Unread',exact=True).click();assert 'filter=unread' in page.url;assert page.locator('.message-sender').first.inner_text().startswith('To:')
  page.locator('.message-subject-link').first.press('Enter');assert 'selected_uid=125' in page.url;expect(page.get_by_role('link',name='Back to list',exact=True)).to_be_visible();expect(page.locator('.column-sender')).to_have_text('Recipient');expect(page.locator('.message-sender').first).to_have_text('To: <img src=x> & recipient@example.test');page.get_by_role('link',name='Back to list',exact=True).click();assert 'filter=unread' in page.url
  r['checks'].append('Sent actual To/unknown/literal hostile/Unicode header projection persists across paging, unread and coordinated reader')
  for path in ['/mailbox?name=INBOX','/search?q=reader-fixture&scope=all']:
   visit(path);expect(page.locator('.column-sender')).to_have_text('From');assert page.locator('.message-sender').first.inner_text().startswith('Synthetic Sender');assert page.locator('[title="Initials from the recipient header"]').count()==0
  r['checks'].append('Inbox and all-mailbox Search retain From semantics')
  visit('/mailbox?name=Sent');page.locator('.sent-filter-menu > summary').press('Enter');page.locator('.attachment-filter summary').press('Enter');page.get_by_role('link',name='Has attachment',exact=True).click();assert 'attachment=with' in page.url
  page.locator('.message-sort summary').press('Enter');page.get_by_role('link',name='Sort by From ascending',exact=True).click();assert 'attachment=with' in page.url and 'sort=from' in page.url
  r['checks'].append('Grouped Sent filters and explicit From sort are keyboard reachable and preserve attachment state')
  for width in [1600,360]:
   for scheme in ['light','dark']:
    for forced in ['none','active']:
     page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);visit('/mailbox?name=Sent');assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.locator('.message-subject-link').first.focus();audit=page.evaluate(TEXT_AUDIT);toolbar=page.locator('.mail-list-toolbar').bounding_box();assert width!=1600 or toolbar['height']<=65;name=f'sent-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/name),full_page=False);r['captures'].append(dict(file=name,contrast=audit,overflow=False,toolbar=toolbar));assert not audit['failures'] and not audit['ui_failures'],name
  assert r['sends']==r['external']==r['scripts']==0;r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(process,Path(tmp))
