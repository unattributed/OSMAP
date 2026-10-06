"""Actual granted local serial listener; no native root/helper/mail effects."""
import os
import json
import hashlib
import hmac
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from account_mutation_supervisor import _Bootstrap,_Listener,Unavailable
from account_mutation_grant import _ConnectorGrant
from test_account_mutation_worker import KEY,ACCOUNT,frame
import test_guarded_mutation_worker as fixture
import test_account_mutation_supervisor as supervisor_fixture

class PersistentTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=str(Path.home()));self.parent=Path(self.tmp.name)
  self.parent.chmod(0o710);self.path=self.parent/'mutation.sock'
  b=_Bootstrap(KEY,fixture.SESSION_KEY,frozenset([ACCOUNT]),os.getuid())
  self.listener=_Listener(b,_ConnectorGrant(self.path,os.getuid(),os.getuid(),os.getgid()))
  self.stop=threading.Event();self.ready=threading.Event();self.errors=[];self.thread=None;self.frames=0
 def tearDown(self):
  self.stop.set()
  if self.thread is not None:self.thread.join(timeout=2);self.assertFalse(self.thread.is_alive())
  for child in self.listener._supervisor._retained:
   self.assertIsNone(child.returncode)
   try:os.killpg(child.pid,9)
   except ProcessLookupError:pass
   child.wait(timeout=1)
  self.tmp.cleanup()
 def start(self,*,uncertain=False):
  script=str(Path(supervisor_fixture.__file__).with_name('account_mutation_supervisor_fixture.py'))
  actual_listen=socket.socket.listen
  def published(server,*args,**kwargs):
   result=actual_listen(server,*args,**kwargs)
   if server.getsockname()==str(self.path):self.ready.set()
   return result
  def run():
   try:
    with patch.object(socket.socket,'listen',published),patch.object(self.listener._supervisor,'_command',return_value=(sys.executable,'-I',script,'reply')):
     if uncertain:
      with patch.object(self.listener._supervisor,'_cleanup',side_effect=Unavailable('public uncertainty')):
       self.listener._serve(self.path,self.stop.is_set)
     else:self.listener._serve(self.path,self.stop.is_set)
   except BaseException as exc:self.errors.append(type(exc))
  self.thread=threading.Thread(target=run);self.thread.start()
  # Path existence precedes inode capture and grant publication. Wait for the
  # actual owned listener to finish listen; no extra connection or frame is sent.
  self.assertTrue(self.ready.wait(timeout=1),"owned listener publication incomplete")
 def exchange(self,raw=None):
  client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(1)
  end=time.monotonic()+1
  try:
   while True:
    try:client.connect(str(self.path));break
    except (FileNotFoundError,ConnectionRefusedError):
     if time.monotonic()>=end:raise
     time.sleep(.001)
   if raw is None:
    self.frames+=1;sent=int(time.time()*1000);now=sent//1000
    action=frame(intent_reference=f'{self.frames:064x}',request_id=f'public-service-{self.frames}',issued=now,expires=now+300)
    value=json.loads(fixture.guarded(action,sent=sent,deadline=sent+1000))
    proof=value['session_proof'];proof['session_expires']=now+500;proof['idle_expires']=now+400
    proof['signature']=hmac.new(fixture.SESSION_KEY,fixture.payload(proof),hashlib.sha256).hexdigest()
    raw=fixture.encoded(value)
   client.sendall(len(raw).to_bytes(4,'big')+raw)
   out=bytearray()
   while True:
    part=client.recv(4096)
    if not part:break
    out.extend(part)
   return bytes(out)
  finally:client.close()
 def stop_and_check(self):
  self.stop.set();self.thread.join(timeout=1)
  self.assertFalse(self.thread.is_alive());self.assertEqual(self.errors,[])
  self.assertFalse(self.path.exists())
 def test_actual_two_separately_authenticated_connections_keep_same_listener_inode(self):
  self.start();self.assertEqual(self.exchange(),b'\x00\x00\x00\x02{}')
  inode=self.path.stat().st_ino;self.assertTrue(self.thread.is_alive())
  self.assertEqual(self.exchange(),b'\x00\x00\x00\x02{}')
  self.assertEqual(self.path.stat().st_ino,inode);self.stop_and_check()
 def test_actual_refused_connection_does_not_respawn_worker_or_resend_then_new_request_succeeds(self):
  self.start()
  with patch('account_mutation_supervisor.subprocess.Popen',side_effect=AssertionError):
   self.assertEqual(self.exchange(b'{}'),b'')
  self.assertTrue(self.thread.is_alive());self.assertEqual(self.exchange(),b'\x00\x00\x00\x02{}')
  self.stop_and_check()
 def test_idle_poll_does_not_exit_or_reset_per_connection_budget(self):
  self.start();time.sleep(.15);self.assertTrue(self.thread.is_alive())
  self.assertEqual(self.exchange(),b'\x00\x00\x00\x02{}');self.stop_and_check()
 def test_uncertain_owned_cleanup_withholds_reply_stops_admission_and_keeps_owned_child(self):
  self.start(uncertain=True);self.assertEqual(self.exchange(),b'')
  self.thread.join(timeout=1);self.assertFalse(self.thread.is_alive())
  self.assertEqual(self.errors,[Unavailable]);self.assertTrue(self.listener._supervisor._uncertain)
  self.assertFalse(self.path.exists());self.assertEqual(len(self.listener._supervisor._retained),1)
 def test_graceful_idle_stop_unlinks_only_owned_socket(self):
  self.start();self.stop_and_check();self.assertEqual(self.parent.stat().st_mode&0o777,0o710)
 def test_replaced_namespace_socket_refuses_and_preserves_replacement_inode(self):
  self.start();self.path.unlink();replacement=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   replacement.bind(str(self.path));replacement_inode=self.path.stat().st_ino
   self.thread.join(timeout=1);self.assertFalse(self.thread.is_alive())
   self.assertEqual(self.errors,[Unavailable]);self.assertEqual(self.path.stat().st_ino,replacement_inode)
  finally:replacement.close()
 def test_readiness_waits_for_actual_listener_publication_after_bind(self):
  actual_bind=socket.socket.bind;bound=threading.Event();release=threading.Event();done=threading.Event();failures=[]
  def delayed_bind(server,address):
   result=actual_bind(server,address)
   if address==str(self.path):
    bound.set()
    if not release.wait(timeout=1):raise AssertionError('owned bind release incomplete')
   return result
  def starting():
   try:self.start()
   except BaseException as error:failures.append(error)
   finally:done.set()
  caller=threading.Thread(target=starting)
  with patch.object(socket.socket,'bind',delayed_bind):
   caller.start()
   try:
    self.assertTrue(bound.wait(timeout=1),'actual owned bind not reached')
    self.assertFalse(done.wait(timeout=.02),'path existence was treated as listener publication')
   finally:
    release.set();caller.join(timeout=1)
   self.assertFalse(caller.is_alive());self.assertEqual(failures,[])
  self.stop_and_check()
 def test_native_service_default_off_before_namespace_and_no_grant_cannot_run_persistent(self):
  from account_mutation_supervisor import serve_native
  with patch('account_mutation_grant._ConnectorGrant.native',side_effect=AssertionError),       patch('account_mutation_supervisor._directory',side_effect=AssertionError):
   with self.assertRaises(Unavailable):serve_native()
  private=_Listener(self.listener._supervisor._bootstrap)
  with self.assertRaises(Unavailable):private._serve(self.path)
 def test_stop_during_accept_closes_new_connection_without_dispatch_or_worker_spawn(self):
  original_accept=socket.socket.accept
  actual_connection=self.listener._supervisor.connection
  def accepted_then_stop(server,*args,**kwargs):
   result=original_accept(server,*args,**kwargs);self.stop.set();return result
  with patch.object(socket.socket,'accept',accepted_then_stop),\
       patch.object(self.listener._supervisor,'connection',wraps=actual_connection) as dispatch:
   self.start()
   try:reply=self.exchange()
   except (ConnectionResetError,BrokenPipeError):reply=b''
   self.thread.join(timeout=1);self.assertFalse(self.thread.is_alive())
   self.assertEqual(reply,b'','stop during accept must not execute a new request')
   dispatch.assert_not_called()
  self.assertEqual(self.errors,[]);self.assertFalse(self.path.exists())
 def test_signal_entry_restores_handlers_and_only_removes_admission(self):
  import signal,account_mutation_service
  original={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
  def service(stop):
   self.assertFalse(stop());signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None);self.assertTrue(stop())
  with patch.object(account_mutation_service.resource,'setrlimit') as core,\
       patch.object(account_mutation_service,'serve_native',side_effect=service):
   account_mutation_service.main()
   core.assert_called_once_with(account_mutation_service.resource.RLIMIT_CORE,(0,0))
  self.assertEqual({sig:signal.getsignal(sig) for sig in original},original)
if __name__=='__main__':unittest.main()
