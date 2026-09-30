import sys,os,tempfile,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from browser_workflows import start_server,stop_server
from playwright.sync_api import sync_playwright,expect
from contrast_audit import TEXT_AUDIT
out=Path(sys.argv[1]);out.mkdir(exist_ok=True,parents=True)
engine=sys.argv[2] if len(sys.argv)>2 else 'chromium'
final=True

with tempfile.TemporaryDirectory() as t,(out/'server.log').open('w') as log,sync_playwright() as p:
 root=Path(t);proc,origin=start_server(root,Path(__file__).resolve().parents[2],log)
 browser=getattr(p,engine).launch(executable_path='/usr/bin/microsoft-edge-stable' if engine=='chromium' else '/home/foo/.cache/ms-playwright/firefox-1543/firefox/firefox',headless=True)
 ctx=browser.new_context(java_script_enabled=False,viewport={'width':1600,'height':1100},user_agent='FolderCreateValid')
 blocked=[]
 def limit(r):
  if r.request.url.startswith(origin+'/') and '/send' not in r.request.url:r.continue_()
  else:blocked.append(r.request.resource_type);r.abort()
 ctx.route('**/*',limit);page=ctx.new_page();page.goto(origin+'/login');page.get_by_label('Username').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_url('**/mailboxes')
 try:
  page.goto(origin+'/settings?section=copies&folder=INBOX');page.get_by_role('link',name='New subfolder',exact=True).click()
  page.get_by_label('Subfolder name').fill('Native test');page.get_by_role('button',name='Review creation',exact=True).click();assert page.get_by_role('heading',name='Review creation').is_visible()
  review=page.url;assert page.get_by_label('Subfolder name').input_value()=='Native test'
  for scheme in ['light','dark']:
   for width in [1600,360]:
    for forced in ['none','active']:
     page.set_viewport_size({'width':width,'height':1100});page.emulate_media(color_scheme=scheme,forced_colors=forced);audit=page.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.screenshot(path=str(out/f'{scheme}-{width}-{forced}.png'),full_page=True)
  page.get_by_role('button',name='Confirm create folder').click();page.wait_for_url(lambda u: 'folder=INBOX.Native' in u);assert page.locator('.copies-details h3').last.inner_text()=='INBOX.Native test'
  page.goto(origin+'/settings/folders/create?parent=INBOX');page.get_by_label('Subfolder name').fill('Native test')
  with page.expect_navigation() as response:page.get_by_role('button',name='Review creation').click()
  assert response.value.status==409;assert page.get_by_label('Requested name').input_value()=='Native test';assert page.get_by_text('A folder with this name already exists.',exact=False).is_visible();assert page.locator('form[action="/settings/folders/create"]').count()==0
  for username,mode in [('alice@example.com','FolderCreateUnknown'),('bob@example.com','FolderCreateValid')]:
   other=browser.new_context(java_script_enabled=False,user_agent=mode);q=other.new_page();q.goto(origin+'/login');q.get_by_label('Username').fill(username);q.get_by_label('Password',exact=True).fill('correct horse battery staple');q.get_by_label('TOTP code').fill('123456');q.get_by_role('button',name='Sign In',exact=True).click();q.wait_for_url('**/mailboxes');q.goto(origin+'/settings?section=copies&folder=INBOX')
   if username.startswith('bob'):assert q.locator('.copies-tree').get_by_text('INBOX.Native test',exact=True).count()==0
   else:
    q.get_by_role('link',name='New subfolder',exact=True).click();q.get_by_label('Subfolder name').fill('Uncertain');q.get_by_role('button',name='Review creation').click();q.get_by_role('button',name='Confirm create folder').click();assert q.get_by_label('Requested name').input_value()=='Uncertain';assert q.get_by_text('Creation could not be confirmed.',exact=False).is_visible();assert q.locator('form[action="/settings/folders/create"]').count()==0;q.screenshot(path=str(out/'unknown.png'),full_page=True)
   other.close()
  assert not blocked;(out/'report.json').write_text(json.dumps({'status':'PASS','engine':engine,'external_requests':len(blocked)}))
 finally:
  page.screenshot(path=str(out/'last-state.png'),full_page=True);(out/'last-url.txt').write_text(page.url);browser.close();stop_server(proc,root)
