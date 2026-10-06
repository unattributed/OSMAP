"""Purpose-private hash identity local records, real owned-file custody and ABI mocks."""
import hashlib,os,stat,sys,tempfile,time,unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R/'source' if (R/'source').is_dir() else R))
import account_hash_identity as h
from authoritative_password import Refused,AuthoritativePasswordAdapter as A
from operation_budget import OperationBudget
PASS=b'root:*:0:0:root:/root:/bin/ksh\n_osmap:*:1001:1003:public fixture:/var/empty:/sbin/nologin\n_osmaphash:*:12345:12346:public fixture:/var/empty:/sbin/nologin\n'
GROUP=b'wheel:*:0:root\n_osmap:*:1003:\n_osmaphash:*:12346:\n'
class IdentityTests(unittest.TestCase):
 def setUp(self):self.b=OperationBudget(int(time.time())+8,maximum_seconds=8);self.end=time.monotonic()+7
 def project(self,a,**change):
  fields={n:getattr(a,n) for n in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')};fields['st_uid']=0;fields.update(change);return NS(**fields)
 def fixture(self,tmp,*,lstat=None):
  r=Path(tmp);p=r/'passwd';g=r/'group';p.write_bytes(PASS);g.write_bytes(GROUP);p.chmod(0o644);g.chmod(0o644);actual=Path.lstat;fstat=os.fstat
  null=NS(st_dev=1024,st_ino=215899,st_uid=0,st_gid=0,st_mode=stat.S_IFCHR|0o666,st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1,st_rdev=514)
  def observed(path):
   if path==Path('/dev/null'):return null
   a=actual(path)
   if stat.S_ISDIR(a.st_mode):return self.project(a,st_mode=stat.S_IFDIR|0o755)
   return self.project(a)
  stack=ExitStack();stack.enter_context(patch.object(h,'PASSWD',p));stack.enter_context(patch.object(h,'GROUP',g));stack.enter_context(patch.object(h.sys,'platform','openbsd7'));stack.enter_context(patch.object(h.os,'uname',return_value=NS(sysname='OpenBSD',release='7.9',machine='amd64')));stack.enter_context(patch.object(h.socket,'gethostname',return_value='mail.blackbagsecurity.com'));stack.enter_context(patch.object(h.os,'getuid',return_value=0));stack.enter_context(patch.object(h.os,'geteuid',return_value=0));stack.enter_context(patch.object(self.b,'inherited_group',return_value=True));stack.enter_context(patch.object(Path,'lstat',lstat or observed));stack.enter_context(patch.object(h.os,'fstat',lambda fd:self.project(fstat(fd))));return stack,p,g,null,observed
 def test_fixed_source_authority_no_caller_identity_path_and_no_shared_fallback(self):
  self.assertEqual((h.NAME,str(h.PASSWD),str(h.GROUP),str(h.NULL_DEVICE),h.NULL_RDEV),('_osmaphash','/etc/passwd','/etc/group','/dev/null',514))
  for args in ((),({'uid':1001,'PASS':True},),('/etc/master.passwd',)):
   with self.assertRaises(Refused):h.HashChildIdentity(*args)
  for p in ('/etc/master.passwd','/etc/spwd.db','/etc/pwd.db','/etc/osmap/account-runtime.cnf','/caller/passwd'):
   with patch.object(h.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):h._read(Path(p),self.b,self.end,[0])
 def test_exact_private_identity_uses_public_local_records_no_lookup_or_ID_guess(self):
  self.assertEqual(h._selected(PASS,GROUP),(12345,12346))
  for raw in (PASS.replace(b'12345',b'1001'),PASS.replace(b'12346',b'1003'),PASS.replace(b'_osmaphash',b'_otherhash')):
   with self.assertRaises(Refused):h._selected(raw,GROUP)
 def test_duplicate_name_ID_primary_group_and_supplemental_membership_refuse(self):
  for passwd,group in ((PASS+PASS.splitlines(True)[-1],GROUP),(PASS+b'alias:*:12345:54321:fixture:/var/empty:/sbin/nologin\n',GROUP),(PASS+b'alias:*:54321:12346:fixture:/var/empty:/sbin/nologin\n',GROUP),(PASS,GROUP+b'alias:*:12346:\n'),(PASS,GROUP.replace(b'wheel:*:0:root',b'wheel:*:0:root,_osmaphash'))):
   with self.subTest(passwd=hashlib.sha256(passwd).hexdigest(),group=hashlib.sha256(group).hexdigest()):
    with self.assertRaises(Refused):h._selected(passwd,group)
 def test_root_nobody_reserved_ids_nonlogin_home_shell_and_group_members_refuse(self):
  cases=[(PASS.replace(b'12345',str(v).encode()),GROUP) for v in (0,32766,32767)]+[(PASS.replace(b'12346',str(v).encode()),GROUP.replace(b'12346',str(v).encode())) for v in (0,32766,32767)]+[(PASS.replace(b'/sbin/nologin',b'/bin/ksh'),GROUP),(PASS.replace(b'/var/empty',b'/home/user'),GROUP),(PASS,GROUP.replace(b'_osmaphash:*:12346:',b'_osmaphash:*:12346:root'))]
  for raw,groups in cases:
   with self.assertRaises(Refused):h._selected(raw,groups)
 def test_bounded_records_reject_YP_NUL_nonascii_nondecimal_overlong_and_oversize(self):
  for raw in (PASS+b'+:*:0:0:::\n',PASS+b'-user:*:0:0:::\n',PASS+b'\0',PASS+b'\xff',PASS.replace(b'12345',b'+12345'),PASS.replace(b'12345',b'4294967296'),PASS.replace(b'12345',b'2147483648'),PASS+b'a'*1025+b'\n',b'\n'*1025,PASS+b'#'+b'A'*65536):
   with self.assertRaises(Refused):h._selected(raw,GROUP)
 def test_unrelated_UTF8_gecos_names_empty_group_password_and_opaque_fields_compatible(self):
  # Pinned pwd_mkdb copies GECOS without ASCII conversion; group password is
  # optional in group.5. No unrelated field is exported or selects role IDs.
  passwd=PASS.replace(b'root:*:0:0:root',b'root:*:00:00:Jos\xc3\xa9').replace(b'_osmap:*:1001:1003:public fixture',b'name.with.dot:*:1001:1003:public fixture')
  groups=GROUP.replace(b'wheel:*:0:root',b'wheel::00:root').replace(b'_osmap:*:1003:',b'name.with.dot:OPAQUE_UNUSED_PUBLIC_FIELD:1003:other')
  self.assertEqual(h._selected(passwd,groups),(12345,12346))
  self.assertEqual(h._selected(PASS+b'long_unrelated_name_without_role_authority:*:4294967294:4294967294:opaque:/anywhere:/anything\n',GROUP+b'other::4294967294:opaque\n'),(12345,12346))
 def test_fixed_selected_name_and_attributes_do_not_infer_private_password_lock(self):
  # Public mask changes do not prove or disprove private credential lock. The
  # source-owned nologin/home and unique IDs are the actual bounded conditions.
  public=PASS.replace(b'_osmaphash:*:',b'_osmaphash:OPAQUE_PUBLIC_FIELD:')
  self.assertEqual(h._selected(public,GROUP),(12345,12346))
  for chosen in (b' _osmaphash',b'_osmaphash ',b'_osmaphashX'):
   with self.assertRaises(Refused):h._selected(PASS.replace(b'_osmaphash',chosen),GROUP)
 def test_actual_public_record_reads_hash_recheck_close_no_null_open(self):
  with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
   stack,p,g,null,observed=self.fixture(tmp);original=os.open;fstat=os.fstat;fds=[];paths=[]
   def opened(path,flags):self.assertIn(path,(p,g));self.assertTrue(flags&os.O_NOFOLLOW);paths.append(path);fd=original(path,flags);fds.append(fd);return fd
   with stack,patch.object(h.os,'open',opened):identity=h.HashChildIdentity.native(self.b,self.end);identity.recheck(self.b,self.end)
   self.assertEqual((identity._uid,identity._gid),(12345,12346));self.assertEqual(paths,[p,g]*3);self.assertEqual(identity._public[0][1],hashlib.sha256(PASS).digest())
   for fd in fds:
    with self.assertRaises(OSError):fstat(fd)
 def test_actual_symlink_hardlink_FIFO_nonpublic_modes_records_refuse_before_open(self):
  for kind in ('symlink','hardlink','fifo','writable','private','setid'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
    stack,p,g,_,_=self.fixture(tmp)
    if kind=='symlink':p.unlink();p.symlink_to(g.name)
    elif kind=='hardlink':os.link(p,p.with_name('alias'))
    elif kind=='fifo':p.unlink();os.mkfifo(p,0o644)
    else:p.chmod({'writable':0o666,'private':0o640,'setid':0o4644}[kind])
    with stack,patch.object(h.os,'open',side_effect=AssertionError):
     with self.assertRaises(Refused):h.HashChildIdentity.native(self.b,self.end)
 def test_actual_fd_inode_replacement_refuses_closes(self):
  with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
   stack,p,g,_,_=self.fixture(tmp);fstat=os.fstat;original=os.open;fds=[]
   def opened(*args):fd=original(*args);fds.append(fd);return fd
   with stack,patch.object(h.os,'open',opened),patch.object(h.os,'fstat',lambda fd:self.project(fstat(fd),st_ino=fstat(fd).st_ino+1)):
    with self.assertRaises(Refused):h.HashChildIdentity.native(self.b,self.end)
   self.assertEqual(len(fds),1)
   for fd in fds:
    with self.assertRaises(OSError):fstat(fd)
 def test_actual_record_changed_same_size_after_admission_refuses_recheck(self):
  with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
   stack,p,g,_,_=self.fixture(tmp)
   with stack:
    identity=h.HashChildIdentity.native(self.b,self.end);p.write_bytes(PASS.replace(b'12345',b'54321'))
    with self.assertRaises(Refused):identity.recheck(self.b,self.end)
 def test_public_file_exact_cap_positive_and_one_byte_over_or_total_over_refuse(self):
  with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
   stack,p,g,_,_=self.fixture(tmp);raw=PASS+b'#'+b'A'*(h.PUBLIC_FILE_CAP-len(PASS)-1);p.write_bytes(raw)
   with stack:
    state,value=h._read(p,self.b,self.end,[0]);self.assertEqual(len(value),65536);self.assertEqual(state[1],hashlib.sha256(raw).digest())
    p.write_bytes(raw+b'A')
    with patch.object(h.os,'open',side_effect=AssertionError):
     with self.assertRaises(Refused):h._read(p,self.b,self.end,[0])
    p.write_bytes(PASS)
    with patch.object(h.os,'open',side_effect=AssertionError):
     with self.assertRaises(Refused):h._read(p,self.b,self.end,[h.PUBLIC_TOTAL_CAP])
 def test_null_exact_root_DAC_character_leaf_and_ancestry_no_device_open(self):
  for field,value in (('st_uid',1001),('st_gid',1003),('st_nlink',2),('st_mode',stat.S_IFCHR|0o660),('st_mode',stat.S_IFREG|0o666),('st_rdev',515)):
   with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
    stack,p,g,null,_=self.fixture(tmp);setattr(null,field,value)
    with stack,patch.object(h.os,'open',side_effect=AssertionError):
     with self.assertRaises(Refused):h._null(self.b,self.end)
 def test_ancestry_root_protected_and_world_traversable_required_before_open(self):
  for mode,uid in ((0o777,0),(0o700,0),(0o755,1001)):
   with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
    stack,p,g,_,observed=self.fixture(tmp)
    def lstat(path):
     a=observed(path)
     if path==p.parent:return self.project(a,st_uid=uid,st_mode=stat.S_IFDIR|mode)
     return a
    with stack,patch.object(Path,'lstat',lstat),patch.object(h.os,'open',side_effect=AssertionError):
     with self.assertRaises(Refused):h.HashChildIdentity.native(self.b,self.end)
 def test_native_wrong_platform_nonroot_group_or_expired_phase_refuse_before_files(self):
  for platform,uid,group,end in (('linux',0,True,self.end),('openbsd7',1001,True,self.end),('openbsd7',0,False,self.end),('openbsd7',0,True,time.monotonic()-1),('openbsd7',0,True,float('nan'))):
   with patch.object(h.sys,'platform',platform),patch.object(h.os,'getuid',return_value=uid),patch.object(h.os,'geteuid',return_value=uid),patch.object(self.b,'inherited_group',return_value=group),patch.object(h.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):h.HashChildIdentity.native(self.b,end)
 def drop_fixture(self,identity,fail=None,expiry=False):
  calls=[];state={'uid':(0,0,0),'gid':(0,0,0),'groups':[0,1003]};stack=ExitStack();clock=[self.end-1]
  def set_value(key,args):
   calls.append((key,args))
   if key==fail:raise PermissionError(1,'fixture')
   state[key]=list(args) if key=='groups' else args
   if expiry and key=='groups':clock[0]=self.end+1
  stack.enter_context(patch.object(identity,'recheck',lambda budget,deadline:(self.assertIs(budget,self.b),self.assertEqual(deadline,self.end),calls.append(('recheck',())))))
  stack.enter_context(patch.object(self.b,'inherited_group',return_value=True));stack.enter_context(patch.object(h.time,'monotonic',lambda:clock[0]));stack.enter_context(patch.object(h.os,'chdir',lambda path:calls.append(('chdir',(path,)))))
  for key,method in (('groups','setgroups'),('gid','setresgid'),('uid','setresuid')):stack.enter_context(patch.object(h.os,method,(lambda key:(lambda *args:set_value(key,args[0] if key=='groups' else args)))(key)))
  for method,key,index in (('getuid','uid',0),('geteuid','uid',1),('getgid','gid',0),('getegid','gid',1)):stack.enter_context(patch.object(h.os,method,(lambda key,index:lambda:state[key][index])(key,index)))
  for method,key in (('getresuid','uid'),('getresgid','gid'),('getgroups','groups')):stack.enter_context(patch.object(h.os,method,(lambda key:lambda:state[key])(key)))
  return stack,calls,state
 def identity(self):
  identity=object.__new__(h.HashChildIdentity);identity._budget=self.b;identity._uid=12345;identity._gid=12346;return identity
 def test_child_drop_empty_groups_and_all_saved_real_effective_ids_exact_order(self):
  identity=self.identity();stack,calls,state=self.drop_fixture(identity)
  with stack:identity.drop(self.b,self.end)
  self.assertEqual(calls,[('recheck',()),('chdir',('/',)),('groups',()),('gid',(12346,)*3),('uid',(12345,)*3)]);self.assertEqual(state,{'groups':[],'gid':(12346,)*3,'uid':(12345,)*3})
 def test_each_drop_failure_stops_later_steps_and_phase_never_reset(self):
  for fail,expected in (('groups',3),('gid',4),('uid',5)):
   identity=self.identity();stack,calls,_=self.drop_fixture(identity,fail)
   with stack:
    with self.assertRaises(PermissionError):identity.drop(self.b,self.end)
   self.assertEqual(len(calls),expected)
  identity=self.identity();stack,calls,_=self.drop_fixture(identity,expiry=True)
  with stack:
   with self.assertRaises(Refused):identity.drop(self.b,self.end)
  self.assertEqual(calls[-1],('groups',()))
 def test_retained_savedroot_or_supplementary_groups_refuse(self):
  for method,value in (('getresuid',(12345,12345,0)),('getresgid',(12346,12346,0)),('getgroups',[1003])):
   identity=self.identity();stack,_,_=self.drop_fixture(identity)
   with stack,patch.object(h.os,method,return_value=value):
    with self.assertRaises(Refused):identity.drop(self.b,self.end)
 def test_changed_identity_budget_and_null_custody_before_drop_refuse(self):
  with tempfile.TemporaryDirectory(prefix='osmap-hash-identity-') as tmp:
   stack,p,g,null,_=self.fixture(tmp)
   with stack:
    identity=h.HashChildIdentity.native(self.b,self.end)
    with self.assertRaises(Refused):identity.recheck(OperationBudget(int(time.time())+8,maximum_seconds=8),self.end)
    null.st_ino+=1
    with patch.object(h.os,'setgroups',side_effect=AssertionError):
     with self.assertRaises(Refused):identity.drop(self.b,self.end)
if __name__=='__main__':unittest.main(verbosity=2)
