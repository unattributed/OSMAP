"""Kernel peer wrapper controls; synthetic libc here, actual native separately."""
import ctypes
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'mail-backend'))
import mutation_relay as relay
import account_mutation_supervisor as supervisor
import account_mutation_worker as worker

class PublicFunction:
 def __init__(self,uid=1001,gid=1003,rc=0,err=0):self.uid=uid;self.gid=gid;self.rc=rc;self.err=err;self.calls=[]
 def __call__(self,fd,uid,gid):
  self.calls.append(fd);ctypes.cast(uid,ctypes.POINTER(ctypes.c_uint))[0]=self.uid
  ctypes.cast(gid,ctypes.POINTER(ctypes.c_uint))[0]=self.gid;ctypes.set_errno(self.err);return self.rc
class NoMethod:
 def fileno(self):return 7
class PeerTests(unittest.TestCase):
 def test_openbsd_missing_python_method_uses_exact_kernel_uid_gid_pointer_contract(self):
  for module in (relay,supervisor,worker):
   function=PublicFunction()
   with self.subTest(module=module.__name__),patch.object(module.sys,'platform','openbsd7'),        patch.object(ctypes,'CDLL',return_value=NS(getpeereid=function)):
    self.assertEqual(module._peer(NoMethod()),1001)
    self.assertEqual(function.calls,[7]);self.assertEqual(function.restype,ctypes.c_int)
    self.assertEqual(function.argtypes,[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)])
 def test_failed_native_errno_missing_symbol_unknown_uid_gid_and_negative_fd_refuse(self):
  for module in (relay,supervisor,worker):
   for f in (PublicFunction(rc=-1,err=9),PublicFunction(uid=2**32-1),PublicFunction(gid=2**32-1)):
    with self.subTest(module=module.__name__,result=f.rc),patch.object(module.sys,'platform','openbsd7'),         patch.object(ctypes,'CDLL',return_value=NS(getpeereid=f)):
     with self.assertRaises(module.Unavailable):module._peer(NoMethod())
   with patch.object(module.sys,'platform','openbsd7'),patch.object(ctypes,'CDLL',return_value=NS()):
    with self.assertRaises(module.Unavailable):module._peer(NoMethod())
   with patch.object(module.sys,'platform','openbsd7'),patch.object(ctypes,'CDLL',side_effect=AssertionError):
    with self.assertRaises(module.Unavailable):module._peer(NS(fileno=lambda:-1))
 def test_method_and_linux_unknown_credential_values_refuse(self):
  for module in (relay,supervisor,worker):
   for ids in ((-1,1003),(True,1003),(1001,-1),(2**32-1,1003)):
    with self.subTest(module=module.__name__,ids=ids):
     with self.assertRaises(module.Unavailable):module._peer(NS(getpeereid=lambda:ids))
   with patch.object(module.sys,'platform','linux'):
    with self.assertRaises(module.Unavailable):module._peer(NS(getsockopt=lambda *_args:__import__('struct').pack('3i',5,-1,1003)))
 def test_actual_linux_kernel_socket_peer_positive_and_different_uid_admission_refusal(self):
  if not sys.platform.startswith('linux'):self.skipTest('Linux fallback control only')
  a,b=socket.socketpair()
  try:
   self.assertEqual(relay._peer(a),os.getuid());self.assertEqual(supervisor._peer(a),os.getuid());self.assertEqual(worker._peer(a),os.getuid())
   rejected=relay._Relay(os.getuid()+1)
   with patch.object(relay.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(relay.Unavailable):rejected.connection(a)
  finally:a.close();b.close()
 def test_worker_kernel_peer_precedes_any_frame_read_and_dispatch(self):
  class Stream(NoMethod):
   def __init__(self):self.data=bytearray((2).to_bytes(4,'big')+b'{}');self.reads=0;self.sent=[]
   def settimeout(self,value):self.timeout=value
   def recv(self,size):self.reads+=1;part=bytes(self.data[:size]);del self.data[:size];return part
   def sendall(self,value):self.sent.append(value)
  instance=object.__new__(worker.MutationWorker);instance._monotonic=lambda:1.0
  calls=[];instance.execute=lambda raw,**kwargs:calls.append(raw) or b'{}'
  function=PublicFunction()
  with patch.object(worker.sys,'platform','openbsd7'),patch.object(ctypes,'CDLL',return_value=NS(getpeereid=function)):
   stream=Stream();instance._connection(stream,1001)
   self.assertEqual(calls,[b'{}']);self.assertEqual(stream.sent,[(2).to_bytes(4,'big')+b'{}'])
   for uid in (1002,True,2**32-1):
    stream=Stream();calls.clear()
    with self.assertRaises(worker.Unavailable):instance._connection(stream,uid)
    self.assertEqual(stream.reads,0);self.assertEqual(calls,[])
 def test_openbsd_native_libc_load_failure_refuses_for_all_endpoints(self):
  for module in (relay,supervisor,worker):
   with self.subTest(module=module.__name__),patch.object(module.sys,'platform','openbsd7'),patch.object(ctypes,'CDLL',side_effect=OSError):
    with self.assertRaises(module.Unavailable):module._peer(NoMethod())
if __name__=='__main__':unittest.main()
