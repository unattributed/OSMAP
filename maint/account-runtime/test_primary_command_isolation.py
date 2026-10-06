"""Exact command/environment and actual owned public subprocess controls.

The CLI is synthetic, not Dovecot; no native server or authentication claim.
"""
import importlib.util,json,os,signal,subprocess,sys,unittest
from pathlib import Path
P=Path(__file__).resolve().parent
PROCESS_CUSTODY=r'''
import re
class Processes:
 def __init__(self,budget):self.budget=budget;self.children=[];self.queries=[]
 def cap(self,seconds):
  left=min(seconds,self.budget.remaining())
  assert left>0
  return left
 def spawn(self,args,kwargs,uid,original):
  assert signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL
  previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
  try:
   child=original(args,**kwargs);self.children.append(child)
   query=original(('/bin/ps','-p',str(child.pid),'-o','pid=,ppid=,pgid=,uid='),
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
    close_fds=True,start_new_session=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
   self.queries.append(query)
   try:
    out,err=query.communicate(timeout=self.cap(.5))
    assert query.returncode==0 and not err and 0<len(out)<=512 and len(out.splitlines())==1
    assert re.fullmatch(rb'\s*[0-9]{1,10}\s+[0-9]{1,10}\s+[0-9]{1,10}\s+[0-9]{1,10}\s*',out)
    assert tuple(map(int,out.split()))==(child.pid,os.getpid(),os.getpgrp(),uid)
    assert child.returncode is None
   finally:
    if query.returncode is None:
     try:os.kill(query.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     query.wait(timeout=self.cap(.5))
    query.stdout.close();query.stderr.close()
   return child
  finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
 def finish(self):
  previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
  try:
   for child in self.children+self.queries:
    if child.returncode is None:
     try:os.kill(child.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     child.wait(timeout=self.cap(1))
    for stream in (child.stdin,child.stdout,child.stderr):
     if stream is not None and not stream.closed:stream.close()
   assert all(c.returncode is not None for c in self.children+self.queries)
   self.budget.remaining()
  finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
'''
PUBLIC_CLI=r'''
import os,sys
mode=sys.argv[1];args=tuple(sys.argv[2:]);public='public synthetic password'
expected=('-O','-o','stats_writer_socket_path=','auth','test','-a','/var/dovecot/auth-client','-x','service=imap','alice@example.test')
environment={'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''}
if args!=expected or {k:os.environ.get(k) for k in environment}!=environment:
 raise SystemExit(78)
if any(k in os.environ for k in ('OSMAP_PUBLIC_UNTRUSTED_ENV','DOVECONF_ENV','LD_PRELOAD')):raise SystemExit(78)
raw=sys.stdin.buffer.read(1026)
if os.getpgrp()!=os.getppid():raise SystemExit(78)
if raw!=(public+'\n').encode():
 print('passdb: alice@example.test auth failed');raise SystemExit(77)
print('passdb: alice@example.test auth succeeded')
print('extra fields:')
print('  user='+('bob@example.test' if mode=='foreign' else 'alice@example.test'))
'''
WORKER=r'''
import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from native_transport_test_support import fixture_primary
from operation_budget import OperationBudget
exec(sys.argv[5])
from authoritative_password import Refused
spec=importlib.util.spec_from_file_location('mutation_primary_under_test',sys.argv[2]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
mode=sys.argv[3];cli=sys.argv[4]
budget=OperationBudget(int(time.time())+8,maximum_seconds=8);budget.attach_owned_process_group()
p=Processes(budget);real=subprocess.Popen
calls=[];accepted=False;refused=False
expected=('/usr/local/bin/doveadm','-O','-o','stats_writer_socket_path=','auth','test','-a','/var/dovecot/auth-client','-x','service=imap','alice@example.test')
environment={'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''}
def spawn(args,**kwargs):
 assert tuple(args)==expected and kwargs['env']==environment
 assert kwargs['start_new_session']is False and kwargs['close_fds']is True and callable(kwargs['preexec_fn']) and kwargs['shell']is False
 calls.append(True)
 return p.spawn((sys.executable,'-I','-B','-c',cli,mode)+tuple(args[1:]),kwargs,os.getuid(),real)
subprocess.Popen=spawn
try:
 v=fixture_primary(m.NativePrimaryVerifier,'alice@example.test',budget)
 password='public synthetic password' if mode!='changed' else 'public synthetic passwore'
 try:accepted=v('alice@example.test',password)
 except Refused:refused=True
 p.finish()
 if mode=='foreign':assert refused and not accepted
 elif mode=='changed':assert not refused and not accepted
 else:assert accepted and not refused
 assert len(calls)==1 and len(p.children)==1 and len(p.queries)==1
 assert not v._uncertain and not v._retained and all(c.returncode is not None for c in p.children+p.queries)
 assert all(pipe is None or pipe.closed for child in p.children+p.queries for pipe in (child.stdin,child.stdout,child.stderr))
 print(json.dumps({'mode':mode,'accepted':accepted,'refused':refused,'tracked':2,'all_reaped':True,'descriptors_closed':True,'owned_group':os.getpid()==os.getpgrp(),'no_native_auth':True}))
finally:p.finish()
'''
class PrimaryIsolation(unittest.TestCase):
    def target(self):return os.environ.get('PRIMARY_ISOLATION_SOURCE',str(P/'mutation_primary.py'))
    def load(self):
        sys.path.insert(0,str(P))
        spec=importlib.util.spec_from_file_location('primary_isolation_source',self.target())
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def owned(self,mode):
        child=subprocess.Popen((sys.executable,'-I','-B','-c',WORKER,str(P),self.target(),mode,PUBLIC_CLI,PROCESS_CUSTODY),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OSMAP_PUBLIC_UNTRUSTED_ENV':'public marker',
                'CONFIG_FILE':'/public/untrusted/config','STATS_WRITER_SOCKET_PATH':'/public/untrusted/stats'})
        try:
            out,err=child.communicate(timeout=10)
            self.assertEqual(child.returncode,0,err.decode());self.assertEqual(err,b'')
            receipt=json.loads(out);self.assertTrue(receipt['all_reaped']);self.assertTrue(receipt['descriptors_closed'])
            self.assertEqual(receipt['tracked'],2);self.assertTrue(receipt['owned_group']);self.assertTrue(receipt['no_native_auth'])
            with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
            return receipt
        finally:
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=2)
            child.stdout.close();child.stderr.close()
    def test_exact_source_owned_socket_and_isolated_native_command(self):
        m=self.load();from operation_budget import OperationBudget
        from native_transport_test_support import fixture_primary
        import time
        v=fixture_primary(m.NativePrimaryVerifier,'alice@example.test',OperationBudget(int(time.time())+8,maximum_seconds=8))
        self.assertEqual(v._command(),('/usr/local/bin/doveadm','-O','-o','stats_writer_socket_path=','auth','test','-a','/var/dovecot/auth-client','-x','service=imap','alice@example.test'))
        with self.assertRaises(TypeError):m.NativePrimaryVerifier('alice@example.test',v._budget,v._material,socket_path='/public/untrusted/socket')
    def test_actual_owned_positive_closed_environment_and_cleanup(self):
        r=self.owned('positive');self.assertTrue(r['accepted']);self.assertFalse(r['refused'])
    def test_actual_changed_password_is_negative_and_clean(self):
        r=self.owned('changed');self.assertFalse(r['accepted']);self.assertFalse(r['refused'])
    def test_actual_foreign_authenticated_identity_refuses_and_cleans(self):
        r=self.owned('foreign');self.assertFalse(r['accepted']);self.assertTrue(r['refused'])
if __name__=='__main__':unittest.main(verbosity=2)
