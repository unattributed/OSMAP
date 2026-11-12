"""Native Archive/Bin controls against existing disposable synthetic stores."""
import argparse,json,tempfile
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',checks=[],captures=[],external=0,scripts=0,sends=0)
with tempfile.TemporaryDirectory() as tmp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 root=Path(tmp);process,origin=start_server(root,Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True);r['browser']=b.version
 def login(ua='OSMAP/ManyMessages',account='alice'):
  c=b.new_context(java_script_enabled=False,user_agent=ua,viewport=dict(width=1600,height=1100))
  def guard(route):
   if route.request.resource_type=='script':r['scripts']+=1
   if route.request.url.split('?')[0]==origin+'/send':r['sends']+=1
   if route.request.url.startswith(origin+'/'):route.continue_()
   else:r['external']+=1;route.abort()
  c.route('**/*',guard);page=c.new_page();page.goto(origin+'/login');page.get_by_label('Username or Email').fill(account+'@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_url('**/mailboxes');return page
 def capture(file):
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=page.evaluate(TEXT_AUDIT);page.screenshot(path=str(a.output/file),full_page=False);r['captures'].append(dict(file=file,contrast=audit,overflow=False));assert not audit['failures'] and not audit['ui_failures'],file
 def visit(path):
  response=page.goto(origin+path);assert response.status==200;assert page.locator('script').count()==0
 try:
  page=login();visit('/settings?section=copies');page.locator('#copies-archive').select_option('INBOX.Projects');page.get_by_role('button',name='Save archive folder',exact=True).click();page.wait_for_url('**updated=1');visit('/mailbox/shortcut?kind=archive');expect(page.locator('h1')).to_have_text('Archive / Bin');expect(page.locator('.archive-tabs [aria-current]')).to_have_text('Archive');assert page.locator('.archive-table tbody tr').count()==50;expect(page.locator('.list-window')).to_contain_text('125 loaded matches');assert 'Archived' not in page.locator('thead').inner_text();expect(page.get_by_role('button',name='Delete permanently')).to_be_disabled();capture('archive-dense-1600.png')
  page.get_by_role('link',name='Next page',exact=True).click();page.wait_for_load_state();assert 'page=2' in page.url;page.locator('.sent-filter-menu > summary').press('Enter');page.get_by_role('link',name='Unread',exact=True).click();page.wait_for_load_state();assert 'filter=unread' in page.url
  page.locator('.message-sort summary').press('Enter');page.get_by_role('link',name='Sort by Subject ascending',exact=True).click();page.wait_for_load_state();assert 'filter=unread' in page.url and 'sort=subject' in page.url;page.locator('.archive-subject').first.press('Enter');page.wait_for_load_state();expect(page.get_by_role('link',name='Back to list',exact=True)).to_be_visible();capture('archive-reader-1600.png');page.set_viewport_size(dict(width=360,height=1100));capture('archive-reader-360.png');page.set_viewport_size(dict(width=1600,height=1100));page.get_by_role('link',name='Back to list',exact=True).click();page.wait_for_load_state();assert 'filter=unread' in page.url
  r['checks'].append('Owned Archive destination, 125 bounded loaded matches, paging/filter/sort/reader/back state and received-date semantics')
  visit('/mailbox?name=INBOX.Projects&sort=received&dir=desc&filter=all&attachment=all&selected_mailbox=INBOX.Projects&selected_uid=125')
  page.locator('.sent-filter-menu > summary').press('Enter');page.locator('.date-filter > summary').press('Enter');form=page.locator('.date-filter form');assert form.locator('[name=after]').count()==form.locator('[name=before]').count()==1
  page.get_by_label('From date (UTC)',exact=True).fill('2026-09-30');page.get_by_label('Through date (UTC)',exact=True).fill('2026-09-30');page.get_by_role('button',name='Apply dates',exact=True).press('Enter');page.wait_for_load_state();query=parse_qs(urlsplit(page.url).query)
  for key,value in [('name','INBOX.Projects'),('selected_mailbox','INBOX.Projects'),('selected_uid','125'),('after','2026-09-30'),('before','2026-09-30'),('filter','all'),('attachment','all')]:assert query[key]==[value]
  expect(page.locator('#message-title')).to_have_text('Message 125');page.get_by_role('link',name='Back to list',exact=True).click();page.wait_for_load_state();assert 'after=2026-09-30' in page.url and 'selected_uid' not in page.url
  page.locator('.archive-table input[type=checkbox]').first.check();subject=page.locator('.archive-subject').first.inner_text();page.locator('#bulk-destination-mailbox').select_option('INBOX');page.get_by_role('button',name='Move Selected',exact=True).click();page.wait_for_load_state();expect(page.locator('.list-window')).to_contain_text('124 loaded matches');assert page.get_by_role('link',name=subject,exact=True).count()==0
  query=parse_qs(urlsplit(page.url).query);assert query['name']==['INBOX.Projects'] and query['after']==['2026-09-30'] and query['before']==['2026-09-30'];assert 'selected_uid' not in query;r['checks'].append('Native Archive date form preserves folder/selection; reader Back and successful move preserve dates while clearing selected identity')
  page.locator('.archive-tabs').get_by_role('link',name='Bin',exact=True).click();page.wait_for_load_state();expect(page.locator('.archive-tabs [aria-current]')).to_have_text('Bin');query=parse_qs(urlsplit(page.url).query);assert query['after']==query['before']==['2026-09-30'] and query['sort']==['received'] and 'selected_uid' not in query and 'page' not in query;page.locator('.archive-table input[type=checkbox]').first.check();bin_subject=page.locator('.archive-subject').first.inner_text();page.get_by_role('button',name='Restore Selected to Inbox',exact=True).press('Enter');page.wait_for_load_state();expect(page.locator('.list-window')).to_contain_text('124 loaded matches');assert page.get_by_role('link',name=bin_subject,exact=True).count()==0
  r['checks'].append('Native Archive move and Bin restore refresh counts; switching tabs retains dates and ordering while clearing page and selected identity')
  page.get_by_label('Search this folder',exact=True).fill('reader-fixture');page.locator('.archive-search button').press('Enter');page.wait_for_load_state();q=parse_qs(urlsplit(page.url).query);assert q['mailbox']==['Trash'] and q['q']==['reader-fixture'];r['checks'].append('Visible native search keeps the current folder scope')
  # Ordinary fixture has two real summary rows, without changing backend fixtures for the design.
  page=login('ArchiveBrowser')
  for width in [1600,360]:
   for scheme in ['light','dark']:
    for forced in ['none','active']:
     page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced)
     for name,folder in [('archive','INBOX.Projects'),('bin','Trash')]:
      visit('/mailbox?name='+folder);assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.locator('.archive-subject').first.focus();audit=page.evaluate(TEXT_AUDIT);file=f'{name}-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/file),full_page=True);r['captures'].append(dict(file=file,contrast=audit,overflow=False,toolbar=page.locator('.mail-list-toolbar').bounding_box()));assert not audit['failures'] and not audit['ui_failures'],(file,audit)
  assert r['external']==r['scripts']==r['sends']==0;r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(process,root)
