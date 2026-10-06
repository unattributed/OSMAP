"""PRIVATE local test-only sealed fixtures; never imported by production modules.

Root/platform/custody/libc are mocked. The real source seal still runs before
exec, and every test substitution is confined to this helper context. No native
profile, operator material or actual auth/SQL is admitted.
"""
import contextlib,os,selectors,subprocess,sys,time
from unittest.mock import patch
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from operation_budget import OperationBudget
from account_native_material import NativeMaterial,MaterialExecutor
from mutation_primary import NativePrimaryVerifier as ProductionPrimary,PROGRAM,ARGS
import account_command_kernel as k

def _material():
 value=object.__new__(NativeMaterial);value._private_test_only=True;return value

def _mint(role,material,budget,account=None):
 assert type(material)is NativeMaterial and getattr(material,'_private_test_only',False)
 program,args=(A.SQL_PROGRAM,A.SQL_ARGS) if role=='sql' else (A.HASH_PROGRAM,A.HASH_ARGS) if role=='hash' else (PROGRAM,ARGS+(account,))
 return k.CommandKernelSeal._fixture(program,args,account,budget,((program,b'rx'),),b'stdio rpath exec')

@contextlib.contextmanager
def _construct():
 with patch.object(k.CommandKernelSeal,'_for_material',side_effect=_mint):yield

@contextlib.contextmanager
def _sealed_fixture(budget,material,target=None,*,real_material=False):
 original=subprocess.Popen;children=[];receipts=[]
 def guarded(command,**options):
  assert callable(options['preexec_fn']) and options['shell']is False and options['close_fds']is True and options['start_new_session']is False
  assert all(options[name]==subprocess.PIPE for name in ('stdin','stdout','stderr'))
  source_guard=options['preexec_fn'];r,w=os.pipe2(os.O_CLOEXEC);seen=[];child=None
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):
    seen.append((self.name,args))
    if self.name=='pledge':
     assert len(seen)==3 and seen[1]==('unveil',(None,None));assert os.write(w,b'P')==1
    return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  def guard():
   with patch.object(k.sys,'platform','openbsd7'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(k.ctypes,'CDLL',return_value=Lib()):source_guard()
   os.close(w)
  options['preexec_fn']=guard;options['pass_fds']=(w,)
  try:
   child=original(command if target is None else target(),**options);children.append(child)
   os.close(w);w=None
   with selectors.DefaultSelector() as selector:
    selector.register(r,selectors.EVENT_READ);assert selector.select(min(.5,budget.remaining()));assert os.read(r,2)==b'P'
   receipts.append(child.pid);return child
  except BaseException:
   if child is not None:
    if child.returncode is None:child.kill();child.wait(timeout=1)
    for stream in (child.stdin,child.stdout,child.stderr):
     if stream is not None:stream.close()
   raise
  finally:
   if w is not None:os.close(w)
   os.close(r)
 def recheck(typed,original_budget):
  assert typed is material and original_budget is budget;budget.remaining()
 with contextlib.ExitStack() as stack:
  if not real_material:stack.enter_context(patch.object(NativeMaterial,'recheck',autospec=True,side_effect=recheck))
  stack.enter_context(patch.object(subprocess,'Popen',side_effect=guarded))
  yield receipts
 # Successful returns must leave no unowned pending fixture child.
 assert len(receipts)==len(children)
 assert all(child.returncode is not None and all(p.closed for p in (child.stdin,child.stdout,child.stderr)) for child in children)

class PublicFixtureExecutor(MaterialExecutor):
 """Portable loop fixture; typed material and real mocked seal remain mandatory."""
 def __init__(self,operation_budget=None):
  budget=operation_budget or OperationBudget(int(time.time())+300)
  material=_material()
  with patch.object(budget,'inherited_group',return_value=True),_construct():super().__init__(budget,material)
 def __call__(self,*args):
  with patch.object(self._budget,'inherited_group',return_value=True),_sealed_fixture(self._budget,self._material):return super().__call__(*args)

class PublicFixturePrimary(ProductionPrimary):
 """Legacy public fixture API only; real production ctor still requires material."""
 def __init__(self,account,budget):
  material=_material()
  with patch.object(budget,'inherited_group',return_value=True),_construct():super().__init__(account,budget,material)
 def __call__(self,*args):
  with _sealed_fixture(self._budget,self._material,self._command):return super().__call__(*args)

def fixture_primary(source_class,account,budget):
 """Bind the explicitly selected source class, preserving old-source RED tests."""
 class SelectedPrimary(source_class):
  def __init__(self,account,budget):
   material=_material()
   with patch.object(budget,'inherited_group',return_value=True),_construct():super().__init__(account,budget,material)
  def __call__(self,*args):
   with _sealed_fixture(self._budget,self._material,self._command):return super().__call__(*args)
 return SelectedPrimary(account,budget)

@contextlib.contextmanager
def sealed_actual_material(budget,material):
 # A genuine private-file recheck discriminator must not replace recheck itself.
 material._private_test_only=True
 with _construct():executor=MaterialExecutor(budget,material)
 with _sealed_fixture(budget,material,real_material=True):yield executor

class OwnedFixtureExecutor(MaterialExecutor):
 """Deadline fixture: genuine owned-group checks remain active at every step."""
 def __init__(self,budget):
  material=_material()
  with _construct():super().__init__(budget,material)
 def __call__(self,*args):
  with _sealed_fixture(self._budget,self._material):return super().__call__(*args)
