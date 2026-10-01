#!/usr/bin/env python3
"""Disposable public homes; execute real Rust client, signed dispatcher and confined C worker."""
import hashlib,json,os,pathlib,socket,subprocess,tempfile
assert socket.gethostname() == 'obsd1.blackbagsecurity.com'
os.umask(0o077)
source=pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='osmap-inventory-service-') as directory:
 root=pathlib.Path(directory);homes=[]
 env=dict(os.environ,PATH='/usr/local/bin:/usr/bin:/bin',LC_ALL='C',GNUPGHOME=str(root/'NEVER_DEFAULT'))
 def run(args,data=b''):
  r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=60)
  assert r.returncode == 0, 'fixture command refused'
  return r.stdout
 def gpg(h,args,data=b''):return run(['/usr/local/bin/gpg','--no-options','--homedir',str(h),'--batch','--pinentry-mode','loopback','--passphrase','']+args,data)
 def home(name):
  p=root/name;p.mkdir(mode=0o700);homes.append(p);return p
 def manifest(h):return {str(p.relative_to(h)):(p.lstat().st_mode,hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None) for p in h.rglob('*')}
 try:
  worker=root/'inventory';run(['/usr/bin/cc','-std=c99','-Wall','-Wextra','-Werror','-I/usr/local/include',str(source/'maint/openpgp-runtime/inventory.c'),'-L/usr/local/lib','-lgpgme','-lgpg-error','-o',str(worker)])
  mappings=[];before={}
  for account in ['alice','bob','empty']:
   public=home(account)
   if account != 'empty':
    secret=home('generate-'+account);gpg(secret,['--quick-generate-key','Synthetic '+account+' <'+account+'@fixture.test>','ed25519','sign','0'])
    fp=next(l.split(':')[9] for l in gpg(secret,['--with-colons','--list-keys']).decode().splitlines() if l.startswith('fpr:'))
    gpg(public,['--import'],gpg(secret,['--export',fp]));(root/(account+'.fingerprint')).write_text(fp)
   else:gpg(public,['--list-keys'])
   mappings.append({'account':account,'home':str(public)});before[account]=manifest(public)
  (root/'key').write_bytes(os.urandom(32));(root/'foreign-key').write_bytes(os.urandom(32))
  (root/'config.json').write_text(json.dumps({'version':1,'worker':str(worker),'engine':'/usr/local/bin/gpg','socket':str(root/'inventory.sock'),'trusted_web_uid':os.getuid(),'accounts':mappings}))
  env['OSMAP_PUBLIC_INVENTORY_FIXTURE']=str(root)
  r=subprocess.run(['cargo','test','--offline','--lib','openpgp_inventory_runtime::tests::native_signed_service_client_and_confined_worker','--','--exact','--ignored','--nocapture'],cwd=source,env=env,timeout=1200)
  assert r.returncode == 0
  assert not (root/'NEVER_DEFAULT').exists()
  for account,old in before.items():assert manifest(root/account)==old
  print('native_signed_inventory_two_accounts_empty_unknown_foreign=PASS; public_homes_unchanged=PASS')
 finally:
  for h in homes:subprocess.run(['/usr/local/bin/gpgconf','--homedir',str(h),'--kill','gpg-agent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
print('private_fixture_cleanup=PASS')
