"""Actual owned private files/Unix peers/child groups, public synthetic inputs.
These tests do not qualify root native startup, SQL or SMTP containment.
"""
import json
import hashlib
import hmac
import os
from pathlib import Path
import socket
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from account_mutation_supervisor import _Bootstrap,_Supervisor,_Listener,Unavailable,AUTHORITY,PURPOSE
import test_guarded_mutation_worker as fixture
from test_account_mutation_worker import frame,KEY,ACCOUNT

class BootstrapTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=str(Path.home()))
  self.root=Path(self.tmp.name)
  self.config=dict(version=1,authority=AUTHORITY,purpose=PURPOSE,
   accounts=[ACCOUNT],trusted_relay_uid=os.getuid())
  self.write('config.json',json.dumps(self.config).encode())
  self.write('mutation.key',KEY);self.write('session-proof.key',fixture.SESSION_KEY)
 def tearDown(self):self.tmp.cleanup()
 def write(self,name,data):
  p=self.root/name;p.write_bytes(data);p.chmod(0o600)
 def read(self):return _Bootstrap._read(self.root,os.getuid())
 def test_exact_helper_owned_separate_keys_and_authoritative_config(self):
  b=self.read();self.assertEqual(b.accounts,frozenset([ACCOUNT]));self.assertNotIn(KEY.hex(),repr(b))
 def test_duplicate_unknown_foreign_authority_and_account_refuse(self):
  original=self.config.copy()
  for key,value in [('authority','obsd1.blackbagsecurity.com'),('purpose','mailbox'),
    ('accounts',[ACCOUNT,ACCOUNT]),('trusted_relay_uid',True),('socket','/tmp/guessed')]:
   with self.subTest(field=key):
    self.write('config.json',json.dumps(dict(original,**{key:value})).encode())
    with self.assertRaises(Unavailable):self.read()
  self.write('config.json',b'{"version":1,"version":1}')
  with self.assertRaises(Unavailable):self.read()
 def test_symlink_hardlink_broad_permissions_and_same_keys_refuse(self):
  p=self.root/'mutation.key';p.chmod(0o640)
  with self.assertRaises(Unavailable):self.read()
  p.chmod(0o600);os.link(p,self.root/'extra')
  with self.assertRaises(Unavailable):self.read()
  (self.root/'extra').unlink();p.unlink();p.symlink_to(self.root/'session-proof.key')
  with self.assertRaises(Unavailable):self.read()
  p.unlink();self.write('mutation.key',fixture.SESSION_KEY)
  with self.assertRaises(Unavailable):self.read()
 def test_native_refuses_before_any_operator_file_or_hostname_read(self):
  with patch('account_mutation_supervisor._directory',side_effect=AssertionError),\
       patch('socket.gethostname',side_effect=AssertionError):
   with self.assertRaises(Unavailable):_Bootstrap.native()

class SupervisorTests(unittest.TestCase):
 def bootstrap(self):return _Bootstrap(KEY,fixture.SESSION_KEY,frozenset([ACCOUNT]),os.getuid())
 def raw(self,millis=1000):
  sent=int(time.time()*1000);now=sent//1000
  raw=fixture.guarded(frame(issued=now,expires=now+300),sent=sent,deadline=sent+millis)
  value=json.loads(raw);p=value['session_proof']
  p['session_expires']=now+500;p['idle_expires']=now+400
  p['signature']=hmac.new(fixture.SESSION_KEY,fixture.payload(p),hashlib.sha256).hexdigest()
  return fixture.encoded(value)
 def exchange(self,mode='reply',*,uid=None,raw=None,cleanup_failure=False):
  server,client=socket.socketpair();s=_Supervisor(self.bootstrap());errors=[]
  script=str(Path(__file__).with_name('account_mutation_supervisor_fixture.py'))
  command=(sys.executable,'-I',script,mode)
  def run():
   try:
    with patch.object(s,'_command',return_value=command):
     if cleanup_failure:
      with patch.object(s,'_cleanup',side_effect=Unavailable('public cleanup uncertainty')):
       s.connection(server)
     else:s.connection(server)
   except BaseException as e:errors.append(type(e))
   finally:server.close()
  if uid is not None:s._bootstrap=_Bootstrap(KEY,fixture.SESSION_KEY,frozenset([ACCOUNT]),uid)
  t=threading.Thread(target=run);t.start();client.settimeout(2)
  raw=self.raw() if raw is None else raw
  try:
   client.sendall(len(raw).to_bytes(4,'big')+raw)
   if mode=='coordinator':
    def exact(n):
     out=bytearray()
     while len(out)<n:
      data=client.recv(n-len(out))
      if not data:raise EOFError
      out.extend(data)
     return bytes(out)
    from account_mutation_continuity import verify,signed
    n=int.from_bytes(exact(4),'big');self.assertLessEqual(n,2048)
    challenge=verify(exact(n),KEY,'challenge');ack=dict(challenge,phase='ack');ack.pop('signature')
    reply=signed(ack,KEY);client.sendall(len(reply).to_bytes(4,'big')+reply)
    client.shutdown(socket.SHUT_WR)
   out=bytearray()
   while True:
    p=client.recv(4096)
    if not p:break
    out.extend(p)
  except (ConnectionResetError,BrokenPipeError):out=bytearray()
  finally:client.close();t.join(timeout=2)
  self.assertFalse(t.is_alive())
  if cleanup_failure:
   # Fixture cleanup is identity-bound: the unreaped Popen owner still owns
   # its PID. Never signal a numeric PID retained after poll/wait.
   for child in s._retained:
    self.assertIsNone(child.returncode)
    try:os.killpg(child.pid,9)
    except ProcessLookupError:pass
    child.wait(timeout=1)
    for h in (child.stdin,child.stderr):
     if h is not None and not h.closed:h.close()
  return s,bytes(out),errors
 def test_actual_private_peer_frame_child_group_cleanup_precedes_terminal_publication(self):
  s,out,errors=self.exchange();self.assertEqual(out,b'\x00\x00\x00\x02{}')
  self.assertEqual(errors,[]);self.assertFalse(s._uncertain)
 def test_actual_supervised_guarded_coordinator_pending_ack_journal_and_terminal(self):
  s,out,errors=self.exchange('coordinator')
  self.assertEqual(errors,[]);self.assertFalse(s._uncertain)
  n=int.from_bytes(out[:4],'big');self.assertEqual(n,len(out)-4)
  value=json.loads(out[4:]);self.assertEqual(value['outcome']['status'],'changed')
  self.assertEqual(value['outcome']['epoch'],1)
 def test_wrong_actual_peer_and_tampered_guard_never_spawn(self):
  with patch('account_mutation_supervisor.subprocess.Popen',side_effect=AssertionError):
   self.assertEqual(self.exchange(uid=os.getuid()+1)[1],b'')
   self.assertEqual(self.exchange(raw=b'{}')[1],b'')
 def test_actual_private_listener_peer_and_inode_cleanup(self):
  with tempfile.TemporaryDirectory(dir=str(Path.home())) as directory:
   path=Path(directory)/'mutation.sock';listener=_Listener(self.bootstrap());errors=[]
   script=str(Path(__file__).with_name('account_mutation_supervisor_fixture.py'))
   def serve():
    try:
     with patch.object(listener._supervisor,'_command',return_value=(sys.executable,'-I',script,'reply')):
      listener._one(path)
    except BaseException as e:errors.append(type(e))
   t=threading.Thread(target=serve);t.start()
   end=time.monotonic()+1
   while not path.exists() and time.monotonic()<end:time.sleep(.001)
   client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(1)
   try:
    # Path creation precedes chmod/listen. Only an actual connected listener
    # establishes that private mode installation has completed.
    while True:
     try:client.connect(str(path));break
     except ConnectionRefusedError:
      if time.monotonic()>=end:raise
      time.sleep(.001)
    self.assertEqual(path.stat().st_mode&0o777,0o600)
    raw=self.raw();client.sendall(len(raw).to_bytes(4,'big')+raw)
    result=bytearray()
    while True:
     data=client.recv(4096)
     if not data:break
     result.extend(data)
    self.assertEqual(bytes(result),b'\x00\x00\x00\x02{}')
   finally:client.close();t.join(timeout=2)
   self.assertFalse(t.is_alive());self.assertEqual(errors,[]);self.assertFalse(path.exists())
 def test_child_completion_marker_with_nonzero_exit_never_publishes_success(self):
  s,out,errors=self.exchange('badexit')
  self.assertEqual(out,b'');self.assertEqual(errors,[Unavailable]);self.assertFalse(s._uncertain)
 def test_external_auto_reap_handler_refuses_before_child_spawn(self):
  with patch('account_mutation_supervisor.signal.getsignal',return_value=signal.SIG_IGN),       patch('account_mutation_supervisor.subprocess.Popen',side_effect=AssertionError):
   s,out,errors=self.exchange();self.assertEqual(out,b'');self.assertEqual(errors,[Unavailable])
 def test_timeout_kills_and_reaps_owned_child_within_original_budget(self):
  began=time.monotonic();s,out,errors=self.exchange('wait',raw=self.raw(300))
  self.assertLess(time.monotonic()-began,.65);self.assertEqual(out,b'')
  self.assertEqual(errors,[Unavailable]);self.assertFalse(s._uncertain)
 def test_unconfirmed_cleanup_never_publishes_terminal_and_latches(self):
  s,out,errors=self.exchange(cleanup_failure=True)
  self.assertEqual(out,b'');self.assertTrue(s._uncertain)
  self.assertEqual(errors,[Unavailable]);self.assertEqual(len(s._retained),1)
 def test_trailing_worker_frame_and_bad_completion_never_publish_terminal(self):
  for mode in ('trailing','badmarker'):
   with self.subTest(mode=mode):self.assertEqual(self.exchange(mode)[1],b'')

if __name__=='__main__':unittest.main()
