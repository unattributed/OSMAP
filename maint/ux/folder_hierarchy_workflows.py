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
 ctx=browser.new_context(java_script_enabled=False,viewport={'width':1600,'height':1100},user_agent='FolderTreeValid')
 blocked=[]
 def limit(r):
  if r.request.url.startswith(origin+'/') and '/send' not in r.request.url:r.continue_()
  else:blocked.append(r.request.resource_type);r.abort()
 ctx.route('**/*',limit);page=ctx.new_page();page.goto(origin+'/login');page.get_by_label('Username').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_url('**/mailboxes')
 try:
  page.goto(origin+'/settings?section=copies');page.screenshot(path=str(out/'baseline.png'),full_page=True)
  if final:
   row=page.locator('.copies-tree a').filter(has_text='INBOX').first;row.focus();page.keyboard.press('Enter');page.wait_for_url('**/settings?section=copies&folder=INBOX');expect(page.locator('.copies-tree [aria-current=true]')).to_have_text('INBOX');assert page.locator('#copies-archive').input_value()=='';assert page.locator('.folder-display-only').filter(has_text='Shared/Team/Review').count()==1;assert page.locator('.copies-tree a').filter(has_text='Shared/').count()==0
   assert page.locator('.folder-display-only').filter(has_text='Public/Old/News').count()==1
   assert page.locator('.folder-display-only').filter(has_text='Not selectable').count()==1
   assert page.locator('.folder-display-only').filter(has_text='Nonexistent').count()==1
   disclosure=page.locator('.copies-tree details').first;disclosure.locator('summary').first.press('Enter');assert disclosure.get_attribute('open') is None;disclosure.locator('summary').first.press('Enter')
   secondary=page.locator('.copies-secondary');assert secondary.get_attribute('open') is None;secondary.locator('summary').press('Enter');expect(page.locator('[data-folder-vsize]')).to_have_text('8192 bytes');expect(page.locator('[data-folder-unread]')).to_have_text('1');secondary.locator('summary').press('Enter')
   geometry=page.locator('.copies-management').bounding_box();assert 945<=geometry['y']+geometry['height']<=970,geometry
   for scheme in ['light','dark']:
    for width in [1600,360]:
     for forced in ['none','active']:
      page.set_viewport_size({'width':width,'height':1100});page.emulate_media(color_scheme=scheme,forced_colors=forced);page.locator('.copies-tree [aria-current=true]').focus();audit=page.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];page.screenshot(path=str(out/f'{scheme}-{width}-{forced}.png'),full_page=True);assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
   page.locator('#copies-archive').select_option('INBOX.Projects');page.get_by_role('button',name='Save archive folder',exact=True).click();page.wait_for_url('**updated=1');page.goto(origin+'/settings?section=copies&folder=INBOX');expect(page.locator('#copies-archive')).to_have_value('INBOX.Projects')
   page.get_by_role('link',name='Open folder',exact=True).click();page.wait_for_url('**/mailbox?name=INBOX')
  for mode in ['FolderTreeMalformed','FolderTreeWrongOwner']:
   bad=browser.new_context(java_script_enabled=False,user_agent=mode);b=bad.new_page();b.goto(origin+'/login');b.get_by_label('Username').fill('alice@example.com');b.get_by_label('Password',exact=True).fill('correct horse battery staple');b.get_by_label('TOTP code').fill('123456');b.get_by_role('button',name='Sign In',exact=True).click();b.wait_for_url('**/mailboxes');b.goto(origin+'/settings?section=copies');assert b.get_by_text('Hierarchy unavailable.',exact=False).is_visible();assert b.locator('.copies-tree a').count()==6;assert b.locator('.copies-tree details').count()==0;bad.close()
  assert not blocked
  (out/'report.json').write_text(json.dumps({'status':'PASS','engine':engine,'baseline_only':not final,'external_requests':len(blocked),'management_bounds':geometry},indent=2))
 finally:
  browser.close();stop_server(proc,root)
