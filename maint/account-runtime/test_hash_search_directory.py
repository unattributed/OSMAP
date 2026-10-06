"""Real bounded directory/FD custody; explicit local owner/kernel projections."""
import ast,contextlib,hashlib,importlib.util,json,os,stat,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R/'source' if (R/'source').is_dir() else R))
import account_hash_graph as g,account_hash_graph_pins as pins,account_command_kernel as k
from authoritative_password import Refused
from operation_budget import OperationBudget

class SearchTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='osmap-search-local-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.search=self.root/'search';self.search.mkdir()
  (self.search/'auth').mkdir();(self.search/'dovecot-config').write_bytes(b'public package build fixture');(self.search/'liba.so').write_bytes(b'public ELF fixture')
  (self.search/'dovecot-config').chmod(0o644);(self.search/'liba.so').chmod(0o644)
  self.b=OperationBudget(int(time.time())+12,maximum_seconds=12);self.end=time.monotonic()+10
  self.lstat=Path.lstat;self.fstat=os.fstat;self.stat=os.stat;self.open=os.open
 def project(self,a):
  keys=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns');v={key:getattr(a,key) for key in keys};v['st_uid']=v['st_gid']=0
  if stat.S_ISDIR(a.st_mode):v['st_mode']=stat.S_IFDIR|0o755
  return SimpleNamespace(**v)
 def observed(self,path):return self.project(self.lstat(path))
 def rows(self):return tuple((os.fsencode(p.name),g._identity(self.observed(p))) for p in sorted(self.search.iterdir()))
 def parents(self):return tuple((str(p),)+g._identity(self.observed(p)) for p in self.search.parents)
 def context(self):
  s=contextlib.ExitStack();s.enter_context(patch.object(self.b,'inherited_group',return_value=True));s.enter_context(patch.object(g,'SEARCH_DIRECTORY',str(self.search)));s.enter_context(patch.object(g,'SEARCH_CUSTODY',g._identity(self.observed(self.search))));s.enter_context(patch.object(g,'SEARCH_ANCESTRY',self.parents()));s.enter_context(patch.object(g,'SEARCH_ENTRIES',self.rows()));s.enter_context(patch.object(Path,'lstat',lambda p:self.observed(p)));s.enter_context(patch.object(g.os,'fstat',lambda fd:self.project(self.fstat(fd))));s.enter_context(patch.object(g.os,'stat',lambda *args,**kwargs:self.project(self.stat(*args,**kwargs))));return s
 def test_exact_actual_observation_source_rows_and_only_new_read_grant(self):
  raw=(R/'fixtures/hash-search-directory-observation.json').read_bytes();v=json.loads(raw);keys=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
  self.assertEqual(hashlib.sha256(raw).hexdigest(),pins.SEARCH_OBSERVATION_SHA256)
  self.assertEqual(pins.SEARCH_CUSTODY,tuple(v['directory_before'][n] for n in keys));self.assertEqual(pins.SEARCH_ENTRIES,tuple((bytes.fromhex(row['name_hex']),tuple(row['metadata'][n] for n in keys)) for row in v['rows']))
  self.assertEqual(len(pins.SEARCH_ENTRIES),55);self.assertEqual(sum(stat.S_ISDIR(a[4]) for _,a in pins.SEARCH_ENTRIES),6)
  old_rows=tuple((name,b'rx' if name=='/usr/local/bin/doveadm' else b'r') for name,*_ in pins.FILES)+((pins.MODULE_DIRECTORY,b'r'),('/dev/null',b'rwc'))
  self.assertEqual(g.HashInstalledGraph.rows(),old_rows[:-1]+((pins.SEARCH_DIRECTORY,b'r'),)+old_rows[-1:]);self.assertEqual(g.PROMISES,b'stdio rpath wpath cpath prot_exec exec');self.assertEqual(k._PROFILES,())
 def test_actual_two_full_memberships_fds_closed_and_no_file_content_reads(self):
  before=set(os.listdir('/proc/self/fd'))
  with self.context(),patch.object(g.os,'read',side_effect=AssertionError('metadata only')):
   result=g._search_directory(self.b,self.end);self.assertEqual(result[2],g.SEARCH_ENTRIES)
  self.assertEqual(set(os.listdir('/proc/self/fd')),before)
 def test_foreign_hidden_renamed_removed_member_refuses_without_opening_member(self):
  for kind in ('added','hidden','renamed','removed'):
   with self.context():
    p=self.search/'liba.so';restore=None
    if kind in ('added','hidden'):q=self.search/('foreign.so' if kind=='added' else '.hidden');q.write_bytes(b'x');restore=lambda:q.unlink()
    elif kind=='renamed':q=self.search/'other.so';p.rename(q);restore=lambda:q.rename(p)
    else:raw=p.read_bytes();p.unlink();restore=lambda:p.write_bytes(raw)
    try:
     with self.assertRaises(Refused):g._search_directory(self.b,self.end)
    finally:restore()
 def test_changed_entry_identity_wrongowner_symlink_fifo_and_write_mode_refuse(self):
  for kind in ('metadata','owner','symlink','fifo','mode'):
   p=self.search/'liba.so';raw=p.read_bytes()
   with self.context():
    if kind=='metadata':p.write_bytes(raw+b'changed')
    elif kind=='symlink':p.unlink();p.symlink_to('dovecot-config')
    elif kind=='fifo':p.unlink();os.mkfifo(p)
    elif kind=='mode':p.chmod(0o666)
    else:
     real=g.os.stat
     def owner(*args,**kwargs):
      a=real(*args,**kwargs)
      if args[0]==b'liba.so':a.st_uid=1234
      return a
    try:
     with patch.object(g.os,'stat',owner) if kind=='owner' else contextlib.nullcontext():
      with self.assertRaises(Refused):g._search_directory(self.b,self.end)
    finally:
     if kind!='owner':p.unlink();p.write_bytes(raw);p.chmod(0o644)
 def test_actual_at_open_directory_inode_exchange_and_fifo_refuse_nonblocking(self):
  for fifo in (False,True):
   other=self.root/('other'+str(fifo));other.mkdir();opened=[]
   with self.context():
    def exchange(path,flags):
     self.assertTrue(flags&os.O_NONBLOCK and flags&os.O_NOFOLLOW and flags&os.O_DIRECTORY);self.search.rename(self.root/'retained')
     if fifo:os.mkfifo(self.search)
     else:other.rename(self.search)
     fd=self.open(path,flags);opened.append(fd);return fd
    try:
     with patch.object(g.os,'open',exchange):
      with self.assertRaises((Refused,OSError)):g._search_directory(self.b,self.end)
    finally:
     if self.search.is_dir():self.search.rmdir()
     else:self.search.unlink()
     (self.root/'retained').rename(self.search)
   for fd in opened:
    with self.assertRaises(OSError):os.fstat(fd)
 def test_second_actual_membership_and_parent_change_refuse(self):
  with self.context():
   real=g.os.stat;calls=[0]
   def change(*args,**kwargs):
    a=real(*args,**kwargs);calls[0]+=1
    if calls[0]>len(g.SEARCH_ENTRIES) and args[0]==b'liba.so':a.st_gid=99
    return a
   with patch.object(g.os,'stat',change):
    with self.assertRaisesRegex(Refused,'membership changed'):g._search_directory(self.b,self.end)
  with self.context(),patch.object(g,'_search_parents',side_effect=(self.parents(),())):
   with self.assertRaises(Refused):g._search_directory(self.b,self.end)
 def test_actual_entry_and_name_byte_bounds_refuse_same_phase(self):
  for i in range(257):(self.search/('entry'+str(i))).write_bytes(b'x')
  with self.context():
   with self.assertRaisesRegex(Refused,'bound'):g._search_directory(self.b,self.end)
  for p in self.search.iterdir():
   if p.name.startswith('entry'):p.unlink()
  for i in range(66):(self.search/(str(i)+'x'*248)).write_bytes(b'x')
  with self.context():
   with self.assertRaisesRegex(Refused,'bound'):g._search_directory(self.b,self.end)
 def test_expired_or_foreign_group_before_open_and_no_deadline_reset(self):
  with self.context(),patch.object(g.os,'open',side_effect=AssertionError('no open')):
   with self.assertRaises(Refused):g._search_directory(self.b,time.monotonic()-1)
   with patch.object(self.b,'inherited_group',return_value=False):
    with self.assertRaises(Refused):g._search_directory(self.b,self.end)
 def test_actual_source_recursive_sibling_read_FD_and_projected_write_refusal(self):
  # Only kernel permission checks and fixed source path/owner are projected.
  # Real open/fstat/close run; no native pledge/unveil/drop/loader claim.
  rows=g.HashInstalledGraph.rows();opened=[]
  def guard_open(path,flags,*args):
   path=str(path);mode=b'w' if flags&os.O_WRONLY else b'r'
   permitted=any(mode in permissions and (path==leaf or path.startswith(leaf+'/') and leaf==pins.SEARCH_DIRECTORY) for leaf,permissions in rows)
   if not permitted:raise OSError(13 if mode==b'w' else 2,'projected kernel path refusal')
   translated=self.search/Path(path).name;fd=self.open(translated,flags,*args);opened.append(fd);return fd
  with self.context(),patch.object(pins,'SEARCH_ENTRIES',self.rows()),patch.object(g.os,'open',guard_open),patch.object(g.os,'read',side_effect=AssertionError('no contents')):
   path=pins.SEARCH_DIRECTORY+'/dovecot-config';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
   try:self.assertEqual(g._identity(os.fstat(fd)),dict(self.rows())[b'dovecot-config'])
   finally:os.close(fd)
   with self.assertRaises(PermissionError):os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  self.assertEqual(len(opened),1)
  with self.assertRaises(OSError):os.fstat(opened[0])
 def test_kernel_scope_has_recursive_descendant_read_no_parent_or_writes(self):
  rows=g.HashInstalledGraph.rows();directory=pins.SEARCH_DIRECTORY
  def allows(path,mode):return any(mode in access and (path==leaf or leaf==directory and path.startswith(leaf+'/')) for leaf,access in rows)
  self.assertTrue(allows(directory+'/auth/previously-unhashed.so',b'r'));self.assertTrue(allows(directory+'/new-sibling',b'r'))
  self.assertFalse(allows('/usr/local/lib/new-sibling',b'r'));self.assertFalse(allows(directory+'/new-sibling',b'w'));self.assertFalse(allows(directory+'/new-sibling',b'c'))
 def test_complete_observe_rechecks_search_same_original_phase_around_full_file_read(self):
  p=self.search/'liba.so';row=(str(p),g._identity(self.observed(p)),hashlib.sha256(p.read_bytes()).hexdigest(),tuple((str(parent),)+g._directory_identity(self.observed(parent)) for parent in p.parents))
  with self.context(),patch.object(g,'FILES',(row,)),patch.object(g,'_modules',return_value=('unchanged local module fixture',)):
   states=g.HashInstalledGraph._observe(self.b,self.end);self.assertEqual(states[0],(row[1:],));self.assertEqual(states[2][2],g.SEARCH_ENTRIES)
   actual_read=g._read
   def changed_after_read(*args,**kwargs):
    result=actual_read(*args,**kwargs);(self.search/'new-member').write_bytes(b'x');return result
   with patch.object(g,'_read',changed_after_read):
    with self.assertRaises(Refused):g.HashInstalledGraph._observe(self.b,self.end)
if __name__=='__main__':unittest.main(verbosity=2)
