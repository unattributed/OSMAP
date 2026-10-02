import sys,tempfile,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from browser_workflows import start_server,stop_server
from playwright.sync_api import sync_playwright,expect
from contrast_audit import TEXT_AUDIT
out=Path(sys.argv[1]);out.mkdir(exist_ok=True,parents=True)
engine=sys.argv[2] if len(sys.argv)>2 else 'chromium'

with tempfile.TemporaryDirectory() as t,(out/'server.log').open('w') as log,sync_playwright() as p:
 root=Path(t);proc,origin=start_server(root,Path(__file__).resolve().parents[2],log)
 browser=getattr(p,engine).launch(executable_path='/usr/bin/microsoft-edge-stable' if engine=='chromium' else '/home/foo/.cache/ms-playwright/firefox-1543/firefox/firefox',headless=True)
 ctx=browser.new_context(java_script_enabled=False,viewport={'width':1600,'height':1100},user_agent='KeyInventoryListed')
 blocked=[]
 def limit(r):
  if r.request.url.startswith(origin+'/') and '/send' not in r.request.url:r.continue_()
  else:blocked.append(r.request.resource_type);r.abort()
 ctx.route('**/*',limit);page=ctx.new_page();page.goto(origin+'/login');page.get_by_label('Username').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_url('**/mailboxes')
 try:
  page.goto(origin+'/settings/keys');expect(page.get_by_role('heading',name='OpenPGP Key Management')).to_be_visible();assert page.locator('.public-key-row').count()==1
  bounds=page.locator('.key-management-card').first.bounding_box();assert 220<=bounds['y']<=224 and 360<=bounds['height']<=364,bounds
  for scheme in ['light','dark']:
   for width in [1600,768,360]:
    for forced in ['none','active']:
     page.set_viewport_size({'width':width,'height':1100});page.emulate_media(color_scheme=scheme,forced_colors=forced);audit=page.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'],audit;assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');page.screenshot(path=str(out/f'{scheme}-{width}-{forced}.png'),full_page=True)
  page.locator('details:has(> .public-key-row) > summary').press('Enter');page.locator('.public-key-row > summary').press('Enter');fingerprint=page.get_by_label('Full public fingerprint').first;expect(fingerprint).to_have_value('0123456789ABCDEF0123456789ABCDEF01234567');fingerprint.focus();page.keyboard.press('Control+a');assert page.evaluate('document.activeElement.selectionEnd-document.activeElement.selectionStart')==40;assert page.get_by_text('Does not expire',exact=True).is_visible();page.screenshot(path=str(out/'expanded.png'),full_page=True)
  for mode,text in [('KeyInventoryEmpty','No public keys were reported'),('KeyInventoryForeign','Public inventory unavailable'),('KeyInventoryUnavailable','Public inventory unavailable')]:
   other=browser.new_context(java_script_enabled=False,user_agent=mode);other.route('**/*',limit);q=other.new_page();q.goto(origin+'/login');q.get_by_label('Username').fill('alice@example.com');q.get_by_label('Password',exact=True).fill('correct horse battery staple');q.get_by_label('TOTP code').fill('123456');q.get_by_role('button',name='Sign In',exact=True).click();q.wait_for_url('**/mailboxes');q.goto(origin+'/settings/keys');q.locator('summary').filter(has_text='Public key inventory').press('Enter');assert q.get_by_text(text,exact=False).is_visible();assert q.locator('.public-key-row').count()==0;other.close()
  assert not blocked;(out/'report.json').write_text(json.dumps({'status':'PASS','engine':engine,'bounds':bounds,'external_requests':len(blocked)}))
 finally:
  browser.close();stop_server(proc,root)
