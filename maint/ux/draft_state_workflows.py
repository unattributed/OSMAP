"""PAGE06 native draft/attempt state proof, synthetic loopback only."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--engine',default='chromium');parser.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=parser.parse_args();out=args.output;out.mkdir(parents=True,exist_ok=True,mode=0o700)
report={'result':'FAIL','checks':[],'captures':[],'external':0,'sends':0}
with tempfile.TemporaryDirectory() as t,(out/'server.log').open('w') as log,sync_playwright() as pw:
 root=Path(t);process,origin=start_server(root,Path(__file__).resolve().parents[2],log);browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);report['browser']=browser.version
 def visit(p,path):
  r=p.goto(origin+path,wait_until='networkidle');assert r.status==200
 def submit(p,label,status=200):
  with p.expect_navigation(wait_until='networkidle') as nav:p.get_by_role('button',name=label,exact=True).click()
  assert nav.value.status==status
 def login(account='alice',marker='SendUnconfirmed'):
  ctx=browser.new_context(java_script_enabled=False,user_agent='OSMAP/'+marker,viewport={'width':1600,'height':1100})
  def route(r):
   if r.request.url==origin+'/send' and r.request.method=='POST':report['sends']+=1
   if r.request.url.startswith(origin+'/'):r.continue_()
   else:report['external']+=1;r.abort()
  ctx.route('**/*',route);p=ctx.new_page();visit(p,'/login');p.get_by_label('Username or Email').fill(account+'@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');submit(p,'Sign In');return p
 def save(p,subject):
  visit(p,'/compose');p.get_by_label('To',exact=True).fill('recipient@example.test');p.get_by_label('Subject',exact=True).fill(subject);p.get_by_label('Body',exact=True).fill('Synthetic saved source');submit(p,'Save Draft')
 try:
  p=login();save(p,'Editable companion');save(p,'Attempt under review');visit(p,'/drafts')
  assert p.locator('tr[data-draft-state=editable]').count()==2
  p.get_by_role('link',name='Attempt under review',exact=True).click();p.get_by_label('Body',exact=True).fill('Changed attempted source');p.locator('#compose-attachment').set_input_files({'name':'attempt.txt','mimeType':'text/plain','buffer':b'synthetic-file'});submit(p,'Send Message',503);assert report['sends']==1
  visit(p,'/drafts');row=p.locator('tr[data-draft-state=paused]');expect(row).to_contain_text('Attempt under review');expect(row.locator('input[type=checkbox]')).to_be_disabled();expect(row.get_by_role('button',name='Star unavailable')).to_be_disabled();assert row.locator('form').count()==0;assert 'continue editing' not in row.inner_text();expect(p.locator('.draft-storage-status')).to_contain_text('Retained attempts: 1')
  row.locator('summary').click();expect(row.get_by_role('button',name='Delete unavailable')).to_be_disabled();row.get_by_role('link',name='View attempt',exact=True).click();expect(p.get_by_label('Attempt body source',exact=True)).to_have_value('Changed attempted source');assert p.locator('[data-attempt-attachment]').count()==1;assert p.locator('main form,input[name=send_intent]').count()==0;assert report['sends']==1
  visit(p,'/drafts');p.locator('tr[data-draft-state=paused] summary').click();p.get_by_role('link',name='Saved version',exact=True).click();expect(p.get_by_label('Body',exact=True)).to_have_value('Synthetic saved source');assert p.locator('main form,input[name=send_intent]').count()==0;assert report['sends']==1
  visit(p,'/drafts');p.get_by_label('Search drafts',exact=True).fill('Attempt');submit(p,'Apply');assert p.locator('tbody tr').count()==1;expect(p.get_by_role('button',name='Review discard',exact=True)).to_be_disabled()
  report['checks'].append('Native save and uncertain synthetic send; consumed original is read-only, selection/star/delete disabled; exact attempt and saved comparison accessible without another submission; filter preserved')
  bob=login('bob');visit(bob,'/drafts');expect(bob.locator('.draft-list')).to_contain_text('No saved drafts');save(bob,'Bob editable');visit(bob,'/drafts');bob.get_by_role('button',name='Star draft',exact=True).click();bob.wait_for_load_state('networkidle');expect(bob.get_by_role('button',name='Unstar draft',exact=True)).to_be_visible();bob.locator('.draft-select input').check();submit(bob,'Review discard');submit(bob,'Discard 1 drafts');expect(bob.locator('.draft-list')).to_contain_text('No saved drafts')
  report['checks'].append('Second account isolated; its editable Star and native review-confirm discard remain functional')
  for subject in ['Project Aurora Follow Up','Security Plan Outline','Meeting Notes','Vendor Assessment','Quarterly Update','Sent copy retained']:
   save(p,subject)
  accepted=login(marker='SentCopyUnconfirmed');visit(accepted,'/drafts');accepted.get_by_role('link',name='Sent copy retained',exact=True).click();accepted.get_by_label('Body',exact=True).fill('Accepted synthetic attempt');submit(accepted,'Send Message');assert report['sends']==2
  visit(p,'/drafts');assert p.locator('tbody tr').count()==8;assert p.locator('tr[data-draft-state=editable]').count()==6;assert p.locator('tr[data-draft-state=paused]').count()==1;assert p.locator('tr[data-draft-state=attempted]').count()==1
  for state in ['paused','attempted']:
   row=p.locator('tr[data-draft-state='+state+']');expect(row.locator('input[type=checkbox]')).to_be_disabled();expect(row.get_by_role('button',name='Star unavailable')).to_be_disabled();assert row.locator('form').count()==0;row.locator('summary').click();expect(row.get_by_role('button',name='Delete unavailable')).to_be_disabled();expect(row.get_by_role('link',name='View attempt',exact=True)).to_be_visible();row.locator('summary').click()
  expect(p.locator('.draft-storage-status')).to_contain_text('Retained attempts: 2')
  report['checks'].append('Eight actual native saved drafts:6editable,1genuine uncertain attempt,1accepted with Sentcopyunconfirmed; consumed actionsdisabled; exactly2synthetic SendPOSTs')
  for scheme in ['light','dark']:
   for width in [1600,360]:
    for forced in ['none','active']:
     p.set_viewport_size({'width':width,'height':1100});p.emulate_media(color_scheme=scheme,forced_colors=forced);visit(p,'/drafts');assert p.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=p.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];geometry=p.locator('table').bounding_box();assert width!=1600 or 490<=geometry['height']<=530;name=f'drafts-{scheme}-{width}-{forced}.png';p.screenshot(path=str(out/name),full_page=True);report['captures'].append({'file':name,'contrast':audit,'overflow':False,'table_geometry':geometry})
  import hashlib
  index=root/'send-recovery'/'index'/(hashlib.sha256(b'send-recovery-v1\0alice@example.com').hexdigest()+'.json');original=index.read_bytes()
  try:
   index.write_bytes(b'{"version":99}\n')
   for scheme in ['light','dark']:
    for width in [1600,360]:
     for forced in ['none','active']:
      p.set_viewport_size({'width':width,'height':1100});p.emulate_media(color_scheme=scheme,forced_colors=forced);visit(p,'/drafts');assert p.locator('tr[data-draft-state=unknown]').count()==6;assert p.locator('tr[data-draft-state=editable]').count()==0;expect(p.get_by_role('button',name='Review discard',exact=True)).to_be_disabled()
      for row in p.locator('tr[data-draft-state=unknown]').all():
       expect(row.locator('input[type=checkbox]')).to_be_disabled();expect(row.get_by_role('button',name='Star unavailable')).to_be_disabled();assert row.locator('form').count()==0
      assert p.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=p.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];name=f'drafts-unknown-{scheme}-{width}-{forced}.png';p.screenshot(path=str(out/name),full_page=True);report['captures'].append({'file':name,'contrast':audit,'overflow':False})
  finally:index.write_bytes(original)
  visit(p,'/drafts');assert p.locator('tr[data-draft-state=editable]').count()==6;assert p.locator('tbody tr').count()==8
  report['checks'].append('Private fixture recoveryindex invalidversion gives6Unknown plus2recorded outcomes, disabledcontrols, then exactbyte restore returns6Editable withoutmutation orSend')
  assert report['external']==0 and report['sends']==2;report['result']='PASS'
 finally:
  (out/'report.json').write_text(json.dumps(report,indent=2));browser.close();stop_server(process,root)
