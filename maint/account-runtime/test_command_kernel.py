"""Kernel-seal lifecycle and authority discriminators; native calls mocked."""
import importlib.util,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import account_command_kernel as m
from operation_budget import OperationBudget
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
class SealTests(unittest.TestCase):
 def setUp(self):self.b=OperationBudget(int(time.time())+8,maximum_seconds=8)
 def make(self,rows=(('/fixed/public-program',b'rx'),),promises=b'stdio rpath exec'):
  with patch.object(self.b,'inherited_group',return_value=True):return m.CommandKernelSeal._fixture(A.HASH_PROGRAM,A.HASH_ARGS,None,self.b,rows,promises)
 def test_native_absent_graph_and_caller_report_refuse_before_kernel_or_files(self):
  with patch.object(m.ctypes,'CDLL',side_effect=AssertionError),patch.object(m.os,'open',side_effect=AssertionError):
   with self.assertRaises(Refused):m.CommandKernelSeal.native()
   with self.assertRaises(Refused):m.CommandKernelSeal({'PASS':True})
 def test_rows_and_promises_cannot_transport_traversal_duplicate_or_network(self):
  for rows in ((('/fixed/../operator',b'r'),),(('/fixed//operator',b'r'),),(('/fixed',b'rr'),),(('/fixed',b'r'),('/fixed',b'w'))):
   with self.assertRaises(Refused):self.make(rows)
  for promises in (b'stdio inet',b'stdio dns',b'stdio stdio',b'stdio  exec'):
   with self.assertRaises(Refused):self.make(promises=promises)
 def test_exact_command_original_group_and_budget_required_before_closure(self):
  seal=self.make()
  with patch.object(self.b,'inherited_group',return_value=True):
   with self.assertRaises(Refused):seal.preexec(A.HASH_PROGRAM,('-D',)+A.HASH_ARGS)
  with patch.object(self.b,'inherited_group',return_value=False):
   with self.assertRaises(Refused):seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS)
  self.assertIs(seal._budget,self.b)
 def test_unveil_complete_closure_then_matching_exec_promises(self):
  seal=self.make();calls=[]
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):calls.append((self.name,args));return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  with patch.object(self.b,'inherited_group',return_value=True):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS)
  with patch.object(m.sys,'platform','openbsd7'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m.ctypes,'CDLL',return_value=Lib()):guard()
  self.assertEqual(calls,[('unveil',(b'/fixed/public-program',b'rx')),('unveil',(None,None)),('pledge',(b'stdio rpath exec',)*2)])
 def test_each_kernel_failure_refuses_and_never_continues_after_failed_unveil(self):
  seal=self.make()
  with patch.object(self.b,'inherited_group',return_value=True):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS)
  for fail_at in (1,2,3):
   calls=[]
   class Fn:
    def __call__(self,*args):calls.append(args);return -1 if len(calls)==fail_at else 0
   class Lib:unveil=Fn();pledge=Fn()
   with patch.object(m.sys,'platform','openbsd7'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m.ctypes,'CDLL',return_value=Lib()):
    with self.assertRaises(Refused):guard()
   self.assertEqual(len(calls),fail_at)
 def test_spawn_always_binds_kernel_hook_closed_env_and_fixed_popen_options(self):
  seal=self.make();child=object()
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(m.subprocess,'Popen',return_value=child) as popen:
   self.assertIs(seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,time.monotonic()+1),child)
  args,kwargs=popen.call_args;self.assertEqual(args,((A.HASH_PROGRAM,)+A.HASH_ARGS,))
  self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''})
  self.assertTrue(callable(kwargs['preexec_fn']));self.assertFalse(kwargs['start_new_session'] or kwargs['shell']);self.assertTrue(kwargs['close_fds'])
  with patch.object(m.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn('/foreign/program',A.HASH_ARGS,time.monotonic()+1)
 def test_original_phase_expires_before_fork_and_child_seal(self):
  seal=self.make()
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(m.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,time.monotonic()-1)
  clock=[100.0]
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),patch.object(m.subprocess,'Popen') as popen:
   seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,101.0);guard=popen.call_args.kwargs['preexec_fn']
   clock[0]=102.0
   with patch.object(m.ctypes,'CDLL',side_effect=AssertionError):
    with self.assertRaises(Refused):guard()
 def test_child_kernel_setup_cannot_outlive_original_phase_before_exec(self):
  seal=self.make();clock=[100.0];calls=[]
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):
    calls.append((self.name,args))
    if self.name=='pledge':clock[0]=102.0
    return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),patch.object(m.subprocess,'Popen') as popen:
   seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,101.0);guard=popen.call_args.kwargs['preexec_fn']
   with patch.object(m.sys,'platform','openbsd7'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m.ctypes,'CDLL',return_value=Lib()):
    with self.assertRaises(Refused):guard()
  self.assertEqual(len(calls),3)
 def test_non_native_platform_refuses_before_libc(self):
  seal=self.make()
  with patch.object(self.b,'inherited_group',return_value=True):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS)
  with patch.object(m.sys,'platform','linux'),patch.object(m.ctypes,'CDLL',side_effect=AssertionError):
   with self.assertRaises(Refused):guard()
 def test_real_owned_child_applies_mocked_guard_before_synthetic_exec(self):
  code=r'''
import os,subprocess,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);import account_command_kernel as m
from operation_budget import OperationBudget
from authoritative_password import AuthoritativePasswordAdapter as A
b=OperationBudget(int(time.time())+8,maximum_seconds=8);b.attach_owned_process_group()
seal=m.CommandKernelSeal._fixture(A.HASH_PROGRAM,A.HASH_ARGS,None,b,(('/fixed/public-program',b'rx'),),b'stdio rpath exec');guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS)
r,w=os.pipe2(os.O_CLOEXEC);seen=[]
class Fn:
 def __init__(self,name):self.name=name
 def __call__(self,*args):
  seen.append((self.name,args))
  if self.name=='pledge':
   assert len(seen)==3 and seen[1]==('unveil',(None,None));assert os.write(w,b'P')==1
  return 0
class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
def pre():
 with patch.object(m.sys,'platform','openbsd7'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m.ctypes,'CDLL',return_value=Lib()):guard()
 os.close(w)
c=None
try:
 c=subprocess.Popen((sys.executable,'-I','-B','-c','import sys;assert sys.stdin.buffer.read()==b"public fixture";print("PUBLIC_OK")'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(w,),preexec_fn=pre,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=False)
 os.close(w);w=None;assert os.read(r,2)==b'P'
 out,err=c.communicate(b'public fixture',timeout=2);assert c.returncode==0 and out==b'PUBLIC_OK\n' and not err
 assert c.pid!=os.getpgrp();assert c.returncode is not None
 print('PUBLIC_OWNED_REAPED_KERNEL_MOCKED')
finally:
 if c is not None and c.returncode is None:c.kill();c.wait(timeout=2)
 if c is not None:
  for stream in (c.stdin,c.stdout,c.stderr):
   if stream is not None and not stream.closed:stream.close()
 if w is not None:os.close(w)
 os.close(r)
'''
  c=subprocess.Popen((sys.executable,'-I','-B','-c',code,str(R)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=c.communicate(timeout=10);self.assertEqual(c.returncode,0,err);self.assertEqual(out,b'PUBLIC_OWNED_REAPED_KERNEL_MOCKED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(c.pid,0)
  finally:
   if c.returncode is None:c.kill();c.wait(timeout=2)
   c.stdout.close();c.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
