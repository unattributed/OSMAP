"""Owned local executable fixture; test substitutions supply no native claims."""
import os,subprocess,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);sys.path.append(sys.argv[2])
from operation_budget import OperationBudget
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from account_native_material import NativeMaterial,MaterialExecutor
from mutation_primary import NativePrimaryVerifier,PROGRAM,ARGS
import account_command_kernel as k
b=OperationBudget(int(time.time())+12,maximum_seconds=12);b.attach_owned_process_group();material=object.__new__(NativeMaterial)
account='fixture@example.invalid';children=[];guards=0;checks=[];mode=['positive'];real_popen=subprocess.Popen

def factory(role,typed,budget,who=None):
 assert typed is material and budget is b
 program,args=(A.SQL_PROGRAM,A.SQL_ARGS) if role=='sql' else (A.HASH_PROGRAM,A.HASH_ARGS) if role=='hash' else (PROGRAM,ARGS+(who,))
 return k.CommandKernelSeal._fixture(program,args,who,b,((program,b'rx'),),b'stdio rpath exec')
def recheck(typed,budget):assert typed is material and budget is b;checks.append(b.remaining())
def popen(command,**options):
 global guards
 assert callable(options['preexec_fn']) and options['shell']is False and options['close_fds']is True and options['start_new_session']is False
 assert all(options[s]==subprocess.PIPE for s in ('stdin','stdout','stderr'))
 if command==(A.SQL_PROGRAM,)+A.SQL_ARGS:
  assert options['env']=={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'}
  target='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_SQL\\n";print("PUBLIC_SQL_OK")'
 elif command==(A.HASH_PROGRAM,)+A.HASH_ARGS:
  assert options['env']=={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''}
  target='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_HASH\\n";print("PUBLIC_HASH_OK")'
 else:
  assert command==(PROGRAM,)+ARGS+(account,)
  assert options['env']=={'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C','CONFIG_FILE':'/dev/null','STATS_WRITER_SOCKET_PATH':''}
  if mode[0]=='changed':target='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_CHANGED\\n";print("auth failed");sys.exit(77)'
  elif mode[0]=='foreign':target='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_PASSWORD\\n";print("auth succeeded\\nuser=foreign@example.invalid")'
  elif mode[0]=='output':target='import sys;sys.stdin.buffer.read();print("X"*4097)'
  elif mode[0]=='slow':target='import sys,time;sys.stdin.buffer.read();time.sleep(3)'
  else:target='import sys;assert sys.stdin.buffer.read()==b"PUBLIC_PASSWORD\\n";print("auth succeeded\\nuser=fixture@example.invalid")'
 r,w=os.pipe2(os.O_CLOEXEC);seen=[];original_guard=options['preexec_fn']
 class Fn:
  def __init__(self,name):self.name=name
  def __call__(self,*args):
   seen.append((self.name,args))
   if self.name=='pledge':assert len(seen)==3 and seen[1]==('unveil',(None,None));assert os.write(w,b'P')==1
   return 0
 class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
 def guard():
  with patch.object(k.sys,'platform','openbsd7'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(k.ctypes,'CDLL',return_value=Lib()):original_guard()
  os.close(w)
 # Target command, receipt fd and syscall mocks are LOCAL TEST substitutions.
 # The real source transports cannot supply these options or execution paths.
 options['preexec_fn']=guard;options['pass_fds']=(w,)
 try:
  child=real_popen((sys.executable,'-I','-B','-c',target),**options);children.append(child)
  os.close(w);w=None;assert os.read(r,2)==b'P';guards+=1;return child
 finally:
  if w is not None:os.close(w)
  os.close(r)
try:
 with patch.object(k.CommandKernelSeal,'_for_material',side_effect=factory),patch.object(NativeMaterial,'recheck',autospec=True,side_effect=recheck),patch.object(subprocess,'Popen',side_effect=popen):
  executor=MaterialExecutor(b,material)
  assert executor(A.SQL_PROGRAM,A.SQL_ARGS,b'PUBLIC_SQL\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)==(0,b'PUBLIC_SQL_OK\n',b'')
  assert executor(A.HASH_PROGRAM,A.HASH_ARGS,b'PUBLIC_HASH\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)==(0,b'PUBLIC_HASH_OK\n',b'')
  primary=NativePrimaryVerifier(account,b,material);assert primary(account,'PUBLIC_PASSWORD')is True
  mode[0]='changed';assert primary(account,'PUBLIC_CHANGED')is False
  for fail in ('foreign','output'):
   mode[0]=fail
   try:primary(account,'PUBLIC_PASSWORD')
   except Refused:pass
   else:raise AssertionError('primary failure admitted')
  mode[0]='slow'
  with patch.object(sys.modules['mutation_primary'],'PHASE_SECONDS',.15):
   try:primary(account,'PUBLIC_PASSWORD')
   except Refused:pass
   else:raise AssertionError('deadline admitted')
 assert len(children)==guards==len(checks)==7
 assert all(c.returncode is not None and all(s.closed for s in (c.stdin,c.stdout,c.stderr)) for c in children)
 assert primary._uncertain is False and not primary._retained
 print('PUBLIC_7_CHILDREN_REAPED_GUARDS_SEEN_KERNEL_CUSTODY_MOCKED')
finally:
 for child in children:
  if child.returncode is None:child.kill();child.wait(timeout=2)
  for stream in (child.stdin,child.stdout,child.stderr):
   if not stream.closed:stream.close()
