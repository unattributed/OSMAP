"""Real local MaterialExecutor/read-custody/owned children; kernel/IDs/SQL projected."""
import os,subprocess,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import account_command_kernel as k,account_hash_graph as g,account_hash_identity as h
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from operation_budget import OperationBudget
from account_native_material import NativeMaterial,MaterialExecutor,Unavailable
from test_native_material import MaterialFixture
from test_hash_graph import GraphTests
helper=MaterialFixture();helper.setUp();gh=GraphTests();gh.setUp();children=[];real_popen=subprocess.Popen;guards=[];mint_roles=[];mode=['positive'];original_native=k.CommandKernelSeal.native
millis=int(time.time()*1000);b=OperationBudget.from_original_deadline((millis+60000)//1000,received_mono=time.monotonic(),received_millis=millis,sent_millis=millis,deadline_millis=millis+12000,wall_millis=lambda:int(time.time()*1000));b.attach_owned_process_group();helper.budget=b;gh.b=b;gh.end=time.monotonic()+10
r,w=os.pipe2(os.O_CLOEXEC);w_open=True
try:
 material=helper.load();directory,names,objects,aux=gh.fixture()
 with gh.context(objects,((aux,65536),),directory,names):
  graph=object.__new__(g.HashInstalledGraph);graph._budget=b;graph._states=g.HashInstalledGraph._observe(b,gh.end)
 rows=tuple((row[0],b'r') for row in objects)+((str(aux),b'r'),(str(directory),b'r'))
 identity=object.__new__(h.HashChildIdentity);identity._budget=b
 def native(role,typed,budget,account=None):
  assert typed is material and budget is b;mint_roles.append(role)
  if role=='sql':
   # Private local SQL constructor placeholder only; NEVER dispatched.
   value=k.CommandKernelSeal._fixture(A.SQL_PROGRAM,A.SQL_ARGS,None,b,((A.SQL_PROGRAM,b'rx'),),b'stdio rpath exec');value._material=typed;return value
  return original_native(role,typed,budget,account)
 original_recheck=g.HashInstalledGraph.recheck
 def recheck(typed,budget,deadline):
  assert typed is graph and budget is b
  with gh.context(objects,((aux,65536),),directory,names):original_recheck(typed,budget,deadline)
  assert os.write(w,b'G')==1
 def drop(typed,budget,deadline):
  assert typed is identity and budget is b and os.getpgrp()==b._owned_group and os.getpid()!=b._owned_group
  b.remaining();assert os.write(w,b'I')==1
 def popen(command,**options):
  assert command==(A.HASH_PROGRAM,)+A.HASH_ARGS
  assert options['env']=={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''}
  assert options['shell']is False and options['close_fds']is True and options['start_new_session']is False and all(options[n]==subprocess.PIPE for n in ('stdin','stdout','stderr'))
  original_guard=options['preexec_fn'];calls=[]
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):
    calls.append((self.name,args))
    if self.name=='pledge':
     assert calls[-2]==('unveil',(None,None)) and len(calls)==len(rows)+2 and args==(g.PROMISES,g.PROMISES);assert os.write(w,b'K')==1
    return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  def guard():
   with patch.object(k.sys,'platform','openbsd7'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(k.ctypes,'CDLL',return_value=Lib()):original_guard()
  options['preexec_fn']=guard;options['pass_fds']=(w,)
  output='print("PUBLIC_HASH_OK")' if mode[0]=='positive' else 'print("X"*4097)'
  body='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_HASH\\n";'+output
  child=real_popen((sys.executable,'-I','-B','-c',body),**options);children.append(child);return child
 with patch.object(k,'_PROFILES',('hash',)),patch.object(k.CommandKernelSeal,'native',side_effect=native),patch.object(g.HashInstalledGraph,'rows',return_value=rows),patch.object(g.HashInstalledGraph,'native',return_value=graph),patch.object(g.HashInstalledGraph,'recheck',side_effect=recheck,autospec=True),patch.object(h.HashChildIdentity,'native',return_value=identity),patch.object(h.HashChildIdentity,'drop',side_effect=drop,autospec=True),patch.object(subprocess,'Popen',side_effect=popen):
  # Actual source constructor reaches actual hash native producer, not a fixture
  # returned for hash. Real material full files/socket custody rechecks on request.
  executor=MaterialExecutor(b,material);assert mint_roles==['sql','hash'];seal=executor._seals[(A.HASH_PROGRAM,A.HASH_ARGS)];assert seal._material is material and seal._budget is b and seal._hash_identity_required and seal._hash_graph_required
  assert executor(A.HASH_PROGRAM,A.HASH_ARGS,b'PUBLIC_HASH\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)==(0,b'PUBLIC_HASH_OK\n',b'')
  mode[0]='output'
  try:executor(A.HASH_PROGRAM,A.HASH_ARGS,b'PUBLIC_HASH\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
  except Refused:pass
  else:raise AssertionError('output bound accepted')
  # Real local material content mutation prevents another Popen.
  helper.config.write_bytes(helper.valid.replace(b'123',b'124'))
  try:executor(A.HASH_PROGRAM,A.HASH_ARGS,b'PUBLIC_HASH\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
  except Unavailable:pass
  else:raise AssertionError('changed material accepted')
  assert len(children)==2
 os.close(w);w_open=False;assert os.read(r,7)==b'GIKGIK' and os.read(r,1)==b''
 assert all(child.returncode is not None and all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)) for child in children)
 # Startup and both rechecks sent zero SQL/auth bytes to the controlled peer.
 for _ in range(3):
  peer,_=helper.server.accept()
  with peer:assert peer.recv(1)==b''
 print('PUBLIC_ROLE_BOUND_MINT_MATERIAL_TRANSPORT_2_CHILDREN_REAPED_KERNEL_ID_SQL_MOCKED')
finally:
 for child in children:
  if child.returncode is None:child.kill();child.wait(timeout=2)
  for stream in (child.stdin,child.stdout,child.stderr):
   if not stream.closed:stream.close()
 if w_open:os.close(w)
 os.close(r);gh.doCleanups();helper.tearDown()
