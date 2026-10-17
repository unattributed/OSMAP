"""Native General preference controls against disposable real account stores."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');p.add_argument('--changed-settings-only',action='store_true',help='Only changed timezone and General Reset behavior; no unchanged visual/workflow suite');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',checks=[],captures=[],external=0,sends=0)
with tempfile.TemporaryDirectory() as tmp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 process,origin=start_server(Path(tmp),Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True)
 def login(account):
  c=b.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100));page=c.new_page()
  def guard(route):
   if not route.request.url.startswith(origin+'/'):r['external']+=1;route.abort();return
   if route.request.url==origin+'/send':r['sends']+=1;route.abort();return
   route.continue_()
  c.route('**/*',guard);page.goto(origin+'/login');page.get_by_label('Username or Email').fill(account+'@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();return c,page
 try:
  c,page=login('alice');page.goto(origin+'/settings');token=page.locator('input[name=csrf_token]').first.input_value()
  def post(path,data):return c.request.post(origin+path,form=dict(csrf_token=token,**data),headers={'Origin':origin})
  if a.changed_settings_only:
   # Real stores under the existing synthetic-auth fixture. Only record booleans,
   # not cookies, CSRF, settings bytes or form contents in retained evidence.
   assert post('/settings/reading',dict(start_page='inbox',date_order='oldest')).status==200
   page.goto(origin+'/settings?section=general')
   page.get_by_label('Timezone',exact=True).select_option('+05:45')
   page.get_by_role('button',name='Save timezone',exact=True).press('Enter')
   page.reload();assert page.get_by_label('Timezone',exact=True).input_value()=='+05:45'
   page.goto(origin+'/message?mailbox=INBOX&uid=7')
   assert page.get_by_role('heading',name='Message Reader',exact=True).count()==1
   assert '2026-03-27 16:45:00 UTC+05:45' in page.locator('body').inner_text()
   page.goto(origin+'/settings?section=general')
   saved={name:page.get_by_label(name,exact=True).input_value() for name in ('Theme','Density','Default start page','Reply placement','Timezone')}
   def snapshot():return {str(f.relative_to(Path(tmp)/'settings')):f.read_bytes() for f in (Path(tmp)/'settings').rglob('*') if f.is_file()}
   before=snapshot();assert before
   mutations=[]
   page.on('request',lambda req:mutations.append(req.method) if req.method!='GET' else None)
   for name,value in [('Theme','dark' if saved['Theme']!='dark' else 'light'),('Density','compact' if saved['Density']!='compact' else 'comfortable'),('Default start page','drafts'),('Reply placement','below' if saved['Reply placement']!='below' else 'above'),('Timezone','-05:00')]:
    page.get_by_label(name,exact=True).select_option(value)
   assert page.get_by_label('Default start page',exact=True).input_value()=='drafts'
   page.get_by_role('link',name='Reset this section',exact=True).press('Enter')
   assert page.url==origin+'/settings?section=general'
   assert {name:page.get_by_label(name,exact=True).input_value() for name in saved}==saved
   assert snapshot()==before and not mutations
   assert page.locator('script').count()==0
   page.goto(origin+'/settings?section=reading');assert page.locator('[name=date_order]').input_value()=='oldest'
   c.close();c,page=login('bob');page.goto(origin+'/settings');assert page.get_by_label('Default start page',exact=True).input_value()=='mailbox';assert page.get_by_label('Timezone',exact=True).input_value()=='UTC'
   c.close();assert not r['external'] and not r['sends']
   r.update(status='PASS',scope='changed timezone and General Reset only; synthetic authentication and mail, real private account stores',checks=['Keyboard timezone save/reload and exact owned synthetic mail-time conversion','Keyboard GET Reset restores five independently edited General controls to saved values','No POST or store-byte mutation during unsaved edit/reset; unrelated Reading date order retained','Bob independent defaults; no script, external request or Send'])
   raise SystemExit(0)
  assert post('/settings/signature',dict(signature_revision='0',operation='definition',selection='default',return_section='identity',text='Public <literal> footer')).status==200
  page.reload();assert page.get_by_label('Signature',exact=True).input_value()=='default'
  # Keep this rendered General page open while another save changes Reading.
  assert post('/settings/reading',dict(start_page='inbox',date_order='oldest')).status==200
  page.get_by_label('Default start page',exact=True).select_option('drafts');page.get_by_role('button',name='Save start page',exact=True).press('Enter');assert page.url==origin+'/settings?section=general'
  page.goto(origin+'/settings?section=reading');assert page.locator('[name=date_order]').input_value()=='oldest';assert not page.locator('[name=show_source_shortcut]').is_checked();assert not page.locator('[name=attachment_details]').is_checked()
  page.goto(origin+'/settings');page.get_by_label('Signature',exact=True).select_option('none');page.get_by_role('button',name='Save signature choice',exact=True).press('Enter');assert page.url==origin+'/settings?section=general';assert page.get_by_label('Signature',exact=True).input_value()=='none'
  page.goto(origin+'/settings?section=identity');page.get_by_text('Edit Default signature text',exact=True).click();assert page.locator('textarea[name=text]').input_value()=='Public <literal> footer'
  page.goto(origin+'/settings');old=page.locator('[name=signature_revision]').input_value();assert post('/settings/signature',dict(signature_revision=old,operation='selection',selection='default',return_section='general')).status==200
  page.get_by_label('Signature',exact=True).select_option('none');page.get_by_role('button',name='Save signature choice',exact=True).click();assert page.get_by_role('heading',name='Signature change not confirmed').count()==1;assert page.locator('fieldset[disabled]').count()==1
  c.close();c,page=login('alice');assert '/drafts' in page.url;page.goto(origin+'/settings');assert page.get_by_label('Signature',exact=True).input_value()=='default';assert page.get_by_label('Default start page',exact=True).input_value()=='drafts'
  r['checks'].append('Interleaved start-page save preserves other fields; selection CAS preserves footer; stale refuses; fresh login restores values')
  for width,scheme,forced in [(1600,'light','none'),(1600,'dark','none'),(360,'light','none'),(360,'dark','none'),(360,'light','active')]:
   page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);page.reload();assert page.locator('script').count()==0;assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=page.evaluate(TEXT_AUDIT);file=f'general-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/file),full_page=True);r['captures'].append(dict(file=file,contrast=audit));assert not audit['failures'] and not audit['ui_failures']
  page.get_by_role('link',name='View authentication settings',exact=True).first.press('Enter');assert 'section=authentication' in page.url
  c.close();c,page=login('bob');page.goto(origin+'/settings');assert page.get_by_label('Default start page',exact=True).input_value()=='mailbox';assert page.get_by_label('Signature',exact=True).input_value()=='none';c.close();r['checks'].append('Real settings navigation and Bob isolation');assert not r['external'] and not r['sends'];r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(process,Path(tmp))
