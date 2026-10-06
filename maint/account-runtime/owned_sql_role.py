"""Actual SQL producer/material transport; root/kernel/loader/SQL are local projections."""
import contextlib,hashlib,os,stat,subprocess,sys,time
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import account_command_kernel as k,account_sql_graph as q,account_native_material as m
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from operation_budget import OperationBudget
from test_native_material import MaterialFixture
helper=MaterialFixture();helper.setUp();children=[];real_popen=subprocess.Popen;real_lstat=m.Path.lstat;real_fstat=os.fstat;mode=['positive'];peer_uid=os.getuid();identity_source=lambda:peer_uid;real_peer=m._peer;local_platform=sys.platform
millis=int(time.time()*1000);b=OperationBudget.from_original_deadline((millis+60000)//1000,received_mono=time.monotonic(),received_millis=millis,sent_millis=millis,deadline_millis=millis+12000,wall_millis=lambda:int(time.time()*1000));b.attach_owned_process_group();helper.budget=b
read_fd,write_fd=os.pipe2(os.O_CLOEXEC);write_open=True

def project(info):
 keys=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns');v={name:getattr(info,name) for name in keys}
 if not stat.S_ISSOCK(info.st_mode):v.update(st_uid=0,st_gid=0)
 if stat.S_ISDIR(info.st_mode):v['st_mode']=stat.S_IFDIR|0o755
 return SimpleNamespace(**v)

try:
 helper.programs[0].chmod(0o755)
 with contextlib.ExitStack() as stack:
  stack.enter_context(patch.object(m.Path,'lstat',lambda path:project(real_lstat(path))))
  stack.enter_context(patch.object(m.os,'fstat',lambda fd:project(real_fstat(fd))))
  stack.enter_context(patch.object(m,'PLAN',helper.plan));stack.enter_context(patch.object(m,'CONFIG',helper.config));stack.enter_context(patch.object(m.NativeMaterial,'_server',staticmethod(identity_source)))
  stack.enter_context(patch.object(A,'SQL_ARGS',('--defaults-file='+str(helper.config),'-N','-B','--raw','--database=postfixadmin')))
  stack.enter_context(patch.object(q,'SQL_PROGRAM',A.SQL_PROGRAM))
  material=m.NativeMaterial._load(helper.plan,helper.config,0,m.NativeMaterial._server,b)
  program=helper.programs[0];metadata=q._identity(program.lstat());parents=tuple((str(parent),)+q._directory_identity(parent.lstat()) for parent in program.parents);row=(str(program),metadata,hashlib.sha256(program.read_bytes()).hexdigest(),parents)
  stack.enter_context(patch.object(q,'FILES',(row,)));stack.enter_context(patch.object(q,'_null',return_value=('readonly local null metadata projection',)))
  stack.enter_context(patch.object(q.sys,'platform','openbsd7'));stack.enter_context(patch.object(q.os,'getuid',return_value=0));stack.enter_context(patch.object(q.os,'geteuid',return_value=0));stack.enter_context(patch.object(q.os,'uname',return_value=SimpleNamespace(sysname='OpenBSD',release='7.9',machine='amd64')));stack.enter_context(patch.object(q.socket,'gethostname',return_value=q.AUTHORITY))
  def local_peer(stream):
   with patch.object(sys,'platform',local_platform):return real_peer(stream)
  stack.enter_context(patch.object(m,'_peer',side_effect=local_peer))
  stack.enter_context(patch.object(k,'_PROFILES',('sql','hash')))
  rows=q.SqlInstalledGraph.rows(material)
  def popen(command,**options):
   assert command==(A.SQL_PROGRAM,)+A.SQL_ARGS;assert options['env']=={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'}
   assert options['shell']is False and options['close_fds']is True and options['start_new_session']is False and all(options[n]==subprocess.PIPE for n in ('stdin','stdout','stderr'))
   original_guard=options['preexec_fn'];calls=[]
   class Fn:
    def __init__(self,name):self.name=name
    def __call__(self,*args):
     calls.append((self.name,args))
     if self.name=='pledge':
      assert calls[-2]==('unveil',(None,None)) and len(calls)==len(rows)+2 and args==(q.PROMISES,q.PROMISES);assert os.write(write_fd,b'K')==1
     return 0
   class Library:unveil=Fn('unveil');pledge=Fn('pledge')
   def guard():
    with patch.object(k.ctypes,'CDLL',return_value=Library()):original_guard()
   options['preexec_fn']=guard;options['pass_fds']=(write_fd,)
   text='print("1")' if mode[0]=='positive' else 'print("X"*4097)'
   body='import sys;assert sys.stdin.buffer.read()==b"SELECT 1;\\n";'+text
   child=real_popen((sys.executable,'-I','-B','-c',body),**options);children.append(child);return child
  with patch.object(subprocess,'Popen',side_effect=popen):
   executor=m.MaterialExecutor(b,material);sql=executor._seals[(A.SQL_PROGRAM,A.SQL_ARGS)];hashseal=executor._seals[(A.HASH_PROGRAM,A.HASH_ARGS)]
   assert sql._sql_graph_required and not sql._hash_identity_required and hashseal._hash_identity_required and sql._material is material
   assert executor(A.SQL_PROGRAM,A.SQL_ARGS,b'SELECT 1;\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)==(0,b'1\n',b'')
   mode[0]='output'
   try:executor(A.SQL_PROGRAM,A.SQL_ARGS,b'SELECT 1;\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
   except Refused:pass
   else:raise AssertionError('overlimit output admitted')
   helper.config.write_bytes(helper.valid.replace(b'123',b'124'))
   try:executor(A.SQL_PROGRAM,A.SQL_ARGS,b'SELECT 1;\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
   except m.Unavailable:pass
   else:raise AssertionError('changed client config dispatched')
   assert len(children)==2
  os.close(write_fd);write_open=False;assert os.read(read_fd,3)==b'KK' and os.read(read_fd,1)==b''
  assert all(child.returncode is not None and all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)) for child in children)
  # Every real typed material/graph preflight sent zero bytes to its actual peer.
  helper.server.settimeout(.1);peers=0
  while True:
   try:peer,_=helper.server.accept()
   except TimeoutError:break
   with peer:assert peer.recv(1)==b''
   peers+=1
  assert peers==8,peers
 print('PUBLIC_SQL_ROLE_SOURCE_TRANSPORT_2_CHILDREN_REAPED_KERNEL_ROOT_LOADER_SQL_PROJECTED')
finally:
 for child in children:
  if child.returncode is None:child.kill();child.wait(timeout=2)
  for stream in (child.stdin,child.stdout,child.stderr):
   if not stream.closed:stream.close()
 if write_open:os.close(write_fd)
 os.close(read_fd);helper.tearDown()
