"""Actual owned files/Unix socket grants; public inputs, not native provisioning."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from account_mutation_grant import _ConnectorGrant,SOCKET,CONNECTOR,GROUP
from account_mutation_supervisor import _Bootstrap,_Listener,AUTHORITY,PURPOSE,Unavailable
import test_account_mutation_supervisor as supervisor_fixture
from test_account_mutation_worker import KEY,ACCOUNT
import test_guarded_mutation_worker as fixture

class GrantTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=str(Path.home()));self.root=Path(self.tmp.name)
  self.namespace=self.root/'purpose';self.namespace.mkdir(mode=0o710)
  self.namespace.chmod(0o710);self.path=self.namespace/'mutation.sock'
  self.bootstrap=_Bootstrap(KEY,fixture.SESSION_KEY,frozenset([ACCOUNT]),os.getuid())
  self.grant=_ConnectorGrant(self.path,os.getuid(),os.getuid(),os.getgid())
 def tearDown(self):self.tmp.cleanup()
 def test_actual_group_traverse_namespace_listener_publishes_exact_grant_before_accept(self):
  listener=_Listener(self.bootstrap,self.grant);errors=[]
  script=str(Path(__file__).with_name('account_mutation_supervisor_fixture.py'))
  def run():
   try:
    with patch.object(listener._supervisor,'_command',return_value=(sys.executable,'-I',script,'reply')):
     listener._one(self.path)
   except BaseException as exc:errors.append(type(exc))
  thread=threading.Thread(target=run);thread.start();end=time.monotonic()+1
  client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(1)
  try:
   while True:
    try:client.connect(str(self.path));break
    except (FileNotFoundError,ConnectionRefusedError):
     if time.monotonic()>=end:raise
     time.sleep(.001)
   m=self.path.stat();self.assertEqual(m.st_mode&0o777,0o660)
   self.assertEqual((m.st_uid,m.st_gid),(os.getuid(),os.getgid()))
   raw=supervisor_fixture.SupervisorTests().raw();client.sendall(len(raw).to_bytes(4,'big')+raw)
   out=bytearray()
   while True:
    data=client.recv(4096)
    if not data:break
    out.extend(data)
   self.assertEqual(bytes(out),b'\x00\x00\x00\x02{}')
  finally:client.close();thread.join(timeout=2)
  self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertFalse(self.path.exists())
  self.assertEqual(self.namespace.stat().st_mode&0o777,0o710)
 def test_endpoint_reachability_does_not_authorize_tampered_frame(self):
  listener=_Listener(self.bootstrap,self.grant);errors=[]
  def run():
   try:
    with patch('account_mutation_supervisor.subprocess.Popen',side_effect=AssertionError):listener._one(self.path)
   except BaseException as exc:errors.append(type(exc))
  thread=threading.Thread(target=run);thread.start();end=time.monotonic()+1
  client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(1)
  try:
   while True:
    try:client.connect(str(self.path));break
    except (FileNotFoundError,ConnectionRefusedError):
     if time.monotonic()>=end:raise
     time.sleep(.001)
   client.sendall(b'\x00\x00\x00\x02{}');self.assertEqual(client.recv(1),b'')
  finally:client.close();thread.join(timeout=2)
  self.assertFalse(thread.is_alive());self.assertEqual(errors,[Unavailable])
 def test_missing_broad_foreign_symlink_namespace_and_caller_path_refuse_before_bind(self):
  for mode in (0o700,0o750,0o770,0o711,0o777):
   with self.subTest(mode=mode):
    self.namespace.chmod(mode)
    with self.assertRaises(Unavailable):self.grant.open_namespace()
  self.namespace.chmod(0o710)
  with self.assertRaises(Unavailable):_Listener(self.bootstrap,self.grant)._one(self.root/'foreign.sock')
  with self.assertRaises(Unavailable):_Listener(self.bootstrap,_ConnectorGrant(self.path,os.getuid(),os.getuid()+1,os.getgid()))
  alias=self.root/'alias';alias.symlink_to(self.namespace,target_is_directory=True)
  with self.assertRaises(Unavailable):_ConnectorGrant(alias/'mutation.sock',os.getuid(),os.getuid(),os.getgid()).open_namespace()
 def test_inode_replacement_hardlink_and_namespace_swap_refuse(self):
  fd=self.grant.open_namespace();s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);replacement=None
  try:
   s.bind(str(self.path));m=self.path.lstat();inode=(m.st_dev,m.st_ino)
   self.grant.publish(fd,inode);self.grant.verify(fd,inode)
   os.link(self.path,self.namespace/'alias.sock')
   with self.assertRaises(Unavailable):self.grant.verify(fd,inode)
   (self.namespace/'alias.sock').unlink();self.path.unlink()
   replacement=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);replacement.bind(str(self.path))
   with self.assertRaises(Unavailable):self.grant.publish(fd,inode)
   moved=self.root/'moved';self.namespace.rename(moved);self.namespace.mkdir(mode=0o710)
   with self.assertRaises(Unavailable):self.grant.verify(fd,inode)
  finally:s.close();os.close(fd)
  if replacement is not None:replacement.close()
 def test_private_grant_config_binds_authority_purpose_identity_and_bootstrap_uid(self):
  config=dict(version=1,authority=AUTHORITY,purpose=PURPOSE,connector=CONNECTOR,
              group=GROUP,trusted_relay_uid=os.getuid())
  path=self.root/'connector-grant.json'
  def write(value):path.write_text(json.dumps(value));path.chmod(0o600)
  def load():return _ConnectorGrant._read(self.root,os.getuid(),self.bootstrap,lambda uid:(uid,os.getgid()))
  write(config);g=load();self.assertEqual(g.path,SOCKET);self.assertEqual(g.connector_uid,os.getuid())
  for k,v in [('authority','obsd1.blackbagsecurity.com'),('purpose','mailbox'),
              ('group','osmaprt'),('trusted_relay_uid',os.getuid()+1),('socket','/tmp/other')]:
   write(dict(config,**{k:v}))
   with self.assertRaises(Unavailable):load()
  write(config);path.chmod(0o640)
  with self.assertRaises(Unavailable):load()
  path.chmod(0o600);os.link(path,self.root/'linked')
  with self.assertRaises(Unavailable):load()
 def test_native_group_resolution_refuses_unrelated_members_and_primary_collision(self):
  user=NS(pw_uid=1001,pw_gid=1003,pw_name=CONNECTOR)
  group=NS(gr_gid=5000,gr_mem=[CONNECTOR])
  with patch('account_mutation_grant.pwd.getpwnam',return_value=user),       patch('account_mutation_grant.grp.getgrnam',return_value=group),       patch('account_mutation_grant.pwd.getpwall',return_value=[user]),       patch('account_mutation_grant.os.getgrouplist',return_value=[1003,5000]):
   self.assertEqual(_ConnectorGrant._native_identity(1001),(1001,5000))
   group.gr_mem=[CONNECTOR,'public-bob']
   with self.assertRaises(Unavailable):_ConnectorGrant._native_identity(1001)
   group.gr_mem=[CONNECTOR]
   with patch('account_mutation_grant.pwd.getpwall',return_value=[user,NS(pw_gid=5000,pw_name='public-bob')]):
    with self.assertRaises(Unavailable):_ConnectorGrant._native_identity(1001)
   with self.assertRaises(Unavailable):_ConnectorGrant._native_identity(1002)
 def test_native_false_before_private_files_users_groups_or_namespace(self):
  with patch('account_mutation_grant._directory',side_effect=AssertionError),       patch('account_mutation_grant.pwd.getpwnam',side_effect=AssertionError),       patch('account_mutation_grant.os.geteuid',side_effect=AssertionError):
   with self.assertRaises(Unavailable):_ConnectorGrant.native(self.bootstrap)
 def test_actual_fixed_connector_rejects_foreign_or_injected_ssh_purpose(self):
  script=str(Path(__file__).with_name('osmap_account_mutation_connector'))
  for marker in ('','mailbox','osmap-account-mutation;touch /tmp/not-executed'):
   value=subprocess.run(['/usr/bin/ksh',script],env={'SSH_ORIGINAL_COMMAND':marker},
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1)
   self.assertEqual(value.returncode,1);self.assertEqual(value.stdout,b'')
if __name__=='__main__':unittest.main()
