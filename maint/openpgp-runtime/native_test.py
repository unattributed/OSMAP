#!/usr/bin/env python3
"""Explicit obsd1 scratch qualification; never reads a default or real key home."""
import hashlib,json,os,pathlib,socket,subprocess,tempfile

def main():
 assert socket.gethostname()=='obsd1.blackbagsecurity.com'
 os.umask(0o077)
 source=pathlib.Path(__file__).with_name('inventory.c')
 with tempfile.TemporaryDirectory(prefix='osmap-inventory-test-') as directory:
  root=pathlib.Path(directory); homes=[]
  def home(name):
   p=root/name;p.mkdir(mode=0o700);homes.append(p);return p
  def run(args, data=b'',timeout=15):
   return subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env={'PATH':'/usr/bin:/bin:/usr/local/bin','LC_ALL':'C','GNUPGHOME':str(root/'NEVER_DEFAULT')})
  def gpg(h,args,data=b'',timeout=30):
   r=run(['/usr/local/bin/gpg','--homedir',str(h),'--batch','--no-options','--pinentry-mode','loopback','--passphrase','']+args,data,timeout);assert r.returncode==0, 'fixture GPG failed';return r.stdout
  def manifest(h):
   return {str(p.relative_to(h)):(p.lstat().st_mode,hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None) for p in h.rglob('*')}
  binary=root/'inventory'
  cc=run(['/usr/bin/cc','-std=c99','-Wall','-Wextra','-Werror','-I/usr/local/include',str(source),'-L/usr/local/lib','-lgpgme','-lgpg-error','-o',str(binary)],timeout=30)
  if cc.returncode:print(cc.stderr.decode());raise AssertionError('compile')
  cases={};fingerprints=[]
  def inventory(h,expected):
   before=manifest(h) if h.exists() else None
   r=run([str(binary),str(h)]);assert len(r.stdout)<=65536;result=json.loads(r.stdout)
   assert result['ok']==expected and (r.returncode==0)==expected
   assert before==(manifest(h) if h.exists() else None),'worker changed home'
   assert not (root/'NEVER_DEFAULT').exists()
   assert b'Synthetic' not in r.stdout and b'@fixture.test' not in r.stdout
   return result
  try:
   empty=home('empty');gpg(empty,['--list-keys']);cases['initialized_empty']=inventory(empty,True)['keys']==[]
   corrupt=home('corrupt');gpg(corrupt,['--list-keys']);(corrupt/'pubring.kbx').write_bytes(b'not a keybox');cases['malformed_refused']=not inventory(corrupt,False)['ok']
   for who in ['Alice','Bob']:
    secret=home('generate-'+who);public=home('public-'+who)
    gpg(secret,['--quick-generate-key',f'Synthetic {who} <{who.lower()}@fixture.test>','rsa3072','cert,sign','0'],timeout=120)
    listed=gpg(secret,['--with-colons','--list-keys']).decode();fp=next(l.split(':')[9] for l in listed.splitlines() if l.startswith('fpr:'))
    gpg(secret,['--quick-add-key',fp,'rsa3072','encrypt','0'],timeout=120)
    gpg(public,['--import'],gpg(secret,['--export',fp]));r=inventory(public,True)
    assert len(r['keys'])==1 and r['keys'][0]['primary']['fingerprint']==fp and len(r['keys'][0]['subkeys'])==1
    fingerprints.append(fp);cases[who+'_public']=True
    if who=='Alice':
     for _ in range(8):gpg(secret,['--quick-add-key',fp,'rsa3072','encrypt','0'],timeout=120)
     gpg(public,['--import'],gpg(secret,['--export',fp]));cases['nine_subkeys_refused']=not inventory(public,False)['ok']
    else:
     box=public/'pubring.kbx';box.write_bytes(box.read_bytes()[:-8]);cases['truncated_keybox_refused']=not inventory(public,False)['ok']

   cases['account_homes_distinct']=fingerprints[0]!=fingerprints[1]
   probe=root/'confinement-probe'
   c=run(['/usr/bin/cc','-std=c99','-Wall','-Wextra','-Werror','-I/usr/local/include',str(source.with_name('confinement_test.c')),'-L/usr/local/lib','-lgpgme','-lgpg-error','-o',str(probe)],timeout=30);assert c.returncode==0,c.stderr.decode()
   outside=root/'synthetic-global.conf';outside.write_text('use-keyboxd\n')
   assert run([str(probe),str(empty),str(outside)]).returncode==0
   assert run([str(probe),str(empty),str(root/'public-Bob'/'pubring.kbx')]).returncode==0
   cases['outside_config_and_other_home_denied_in_parent_and_child']=True

   cases['missing_refused']=not inventory(root/'missing',False)['ok']
   uninit=home('uninitialized');cases['uninitialized_refused']=not inventory(uninit,False)['ok']
   bad=root/'bad-engine';c=run(['/usr/bin/cc','-std=c99','-I/usr/local/include','-DINVENTORY_ENGINE="/nonexistent/osmap-gpg"',str(source),'-L/usr/local/lib','-lgpgme','-lgpg-error','-o',str(bad)],timeout=30);assert c.returncode==0
   before=manifest(empty);r=run([str(bad),str(empty)]);assert r.returncode!=0 and not json.loads(r.stdout)['ok'] and before==manifest(empty);cases['engine_failure']=True
   print(json.dumps({'checks':cases,'public_primary_fingerprints':fingerprints,'all_passed':all(cases.values())},sort_keys=True))
  finally:
   for h in homes:
    run(['/usr/local/bin/gpgconf','--homedir',str(h),'--kill','gpg-agent'])
 print('scratch_cleanup=PASS')
if __name__=='__main__':main()
