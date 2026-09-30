"""Native PAGE06 geometry and editable draft controls; disposable stores only."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
ap=argparse.ArgumentParser();ap.add_argument('output',type=Path);ap.add_argument('--engine',default='chromium');ap.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');ap.add_argument('--baseline',action='store_true');a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=True)
r=dict(result='FAIL',captures=[],checks=[],external=0,sends=0,scripts=0)
with tempfile.TemporaryDirectory() as t,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 root=Path(t);server,origin=start_server(root,Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True);r['browser']=b.version;c=b.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100));p=c.new_page()
 def guard(route):
  req=route.request
  if req.resource_type=='script':r['scripts']+=1
  if not req.url.startswith(origin+'/'):r['external']+=1;route.abort()
  elif req.url.split('?')[0]==origin+'/send':r['sends']+=1;route.abort()
  else:route.continue_()
 c.route('**/*',guard)
 def go(path):
  response=p.goto(origin+path,wait_until='networkidle');assert response.status==200
 def click(name):p.get_by_role('button',name=name,exact=True).click();p.wait_for_load_state('networkidle')
 try:
  go('/login');p.get_by_label('Username or Email').fill('alice@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');click('Sign In')
  subjects=['Project Aurora — Follow Up','Security Plan Outline','Meeting Notes','Vendor Assessment','Policy Draft','Quarterly Update','Personal Notes','Release Checklist <literal>']
  for i,subject in enumerate(subjects):
   go('/compose');p.get_by_label('To',exact=True).fill(f'Recipient {i+1} <recipient{i+1}@example.test>');p.get_by_label('Subject',exact=True).fill(subject);p.get_by_label('Body',exact=True).fill('Actual synthetic saved text '+str(i))
   if i in [0,2,5]:p.locator('#compose-attachment').set_input_files(dict(name=f'notes-{i}.txt',mimeType='text/plain',buffer=b'bounded native attachment'))
   click('Save Draft')
  go('/drafts?sort=subject');assert p.locator('tbody tr').count()==8
  if not a.baseline:
   p.locator('.draft-selection-menu > summary').press('Enter');p.get_by_role('link',name='Select up to 10 editable drafts shown',exact=True).press('Enter');p.wait_for_load_state('networkidle');assert p.locator('.draft-select input:checked').count()==8
   click('Review discard');p.get_by_role('link',name='Keep drafts',exact=True).click();p.wait_for_load_state('networkidle');assert p.locator('.draft-select input:checked').count()==0
   p.locator('.draft-selection-menu > summary').press('Enter');p.get_by_role('link',name='Select up to 10 editable drafts shown',exact=True).click();p.wait_for_load_state('networkidle');p.locator('.draft-selection-menu > summary').press('Enter');p.get_by_role('link',name='Clear selection',exact=True).press('Enter');p.wait_for_load_state('networkidle');assert p.locator('.draft-select input:checked').count()==0
   p.get_by_label('Draft filter',exact=True).select_option('attachments');click('Apply');assert p.locator('tbody tr').count()==3
   p.get_by_role('button',name='Star draft',exact=True).first.press('Enter');p.wait_for_load_state('networkidle');assert 'filter=attachments' in p.url
   p.get_by_label('Draft filter',exact=True).select_option('starred');click('Apply');assert p.locator('tbody tr').count()==1
   p.get_by_label('Draft filter',exact=True).select_option('all');p.get_by_label('Draft order',exact=True).select_option('subject');p.get_by_label('Search drafts',exact=True).fill('Aurora');click('Apply');assert p.locator('tbody tr').count()==1
   p.get_by_role('link',name=subjects[0],exact=True).press('Enter');p.wait_for_load_state('networkidle');expect(p.get_by_label('Body',exact=True)).to_have_value('Actual synthetic saved text 0');expect(p.locator('.saved-attachment-list')).to_contain_text('notes-0.txt');go('/drafts?sort=subject')
   p.locator('.draft-select input').first.check();click('Review discard');expect(p.get_by_role('heading',name='Discard selected drafts?',exact=True)).to_be_visible();p.get_by_role('link',name='Keep drafts',exact=True).click();p.wait_for_load_state('networkidle');assert 'sort=subject' in p.url;assert p.locator('tbody tr').count()==8
   r['checks']=['8 native saved drafts and3actual attachments','native filter/sort/search and star retains filter','resume exact stored body and file','review writes nothing; Keep retains sort and all8drafts']
  for scheme in (['light'] if a.baseline else ['light','dark']):
   for width in ([1600] if a.baseline else [1600,360]):
    for forced in (['none'] if a.baseline else ['none','active']):
     p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);go('/drafts?sort=subject');audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');name=f'drafts-{scheme}-{width}-{forced}.png';p.screenshot(path=str(a.output/name),full_page=False);boxes=p.locator('.draft-list-toolbar,thead,tbody tr').evaluate_all('es=>es.map(e=>({tag:e.tagName,box:e.getBoundingClientRect().toJSON()}))');r['captures'].append(dict(file=name,boxes=boxes,contrast=audit,overflow=overflow));assert not overflow and not audit['failures'] and not audit['ui_failures']
  if not a.baseline:
   go('/drafts?sort=subject');p.locator('.draft-select input').first.check();click('Review discard');click('Discard 1 drafts');assert p.locator('tbody tr').count()==7;assert p.locator('.draft-select input:checked').count()==0;r['checks'].append('native confirmed discard removes only selected revision')
  assert r['external']==r['sends']==r['scripts']==0;r['result']='PASS'
 finally:(a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(server,root)
