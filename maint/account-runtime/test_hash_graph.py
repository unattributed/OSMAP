"""Actual owned public-file admission; host/owner projections are local only."""
import contextlib,hashlib,json,os,stat,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R/'source'))
import account_hash_graph as g,account_hash_graph_pins as pins,account_command_kernel as k
from operation_budget import OperationBudget
from authoritative_password import Refused,AuthoritativePasswordAdapter as A

class GraphTests(unittest.TestCase):
 def setUp(self):
  self.b=OperationBudget(int(time.time())+12,maximum_seconds=12);self.end=time.monotonic()+10
  self.tmp=tempfile.TemporaryDirectory(prefix='osmap-hash-graph-local-');self.root=Path(self.tmp.name);self.addCleanup(self.tmp.cleanup)
  self.real_lstat=Path.lstat;self.real_fstat=os.fstat
 def project(self,a):
  keys=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  d={n:getattr(a,n) for n in keys};d.update(st_uid=0,st_gid=0)
  if stat.S_ISDIR(a.st_mode):d['st_mode']=stat.S_IFDIR|0o755
  return SimpleNamespace(**d)
 def observed(self,path):return self.project(self.real_lstat(path))
 def parent_rows(self,path):return tuple((str(p),)+g._directory_identity(self.observed(p)) for p in path.parents)
 def file(self,name='liblocal.so.1',raw=b'bounded public fixture',mode=0o444):
  p=self.root/name;p.write_bytes(raw);p.chmod(mode);return p
 def row(self,p):return (str(p),g._identity(self.observed(p)),hashlib.sha256(p.read_bytes()).hexdigest(),self.parent_rows(p))
 def context(self,files,aux=(),directory=None,names=()):
  search=self.root/'search';search.mkdir(exist_ok=True)
  if not (search/'public-sibling').exists():(search/'public-sibling').write_bytes(b'local public member');(search/'public-sibling').chmod(0o644)
  real_stat=os.stat
  s=contextlib.ExitStack();s.enter_context(patch.object(g,'SEARCH_DIRECTORY',str(search)));s.enter_context(patch.object(g,'SEARCH_CUSTODY',g._identity(self.observed(search))));s.enter_context(patch.object(g,'SEARCH_ANCESTRY',tuple((str(p),)+g._identity(self.observed(p)) for p in search.parents)));s.enter_context(patch.object(g,'SEARCH_ENTRIES',tuple((os.fsencode(p.name),g._identity(self.observed(p))) for p in sorted(search.iterdir()))));s.enter_context(patch.object(g.os,'stat',lambda *args,**kwargs:self.project(real_stat(*args,**kwargs))));s.enter_context(patch.object(g,'FILES',tuple(files)));s.enter_context(patch.object(g,'FILES',tuple(files)+tuple(self.row(p) for p,_ in aux)))
  s.enter_context(patch.object(self.b,'inherited_group',return_value=True));s.enter_context(patch.object(Path,'lstat',lambda path:self.observed(path)));s.enter_context(patch.object(g.os,'fstat',lambda fd:self.project(self.real_fstat(fd))))
  if directory is not None:
   s.enter_context(patch.object(g,'MODULE_DIRECTORY',str(directory)));s.enter_context(patch.object(g,'MODULE_NAMES',tuple(names)));s.enter_context(patch.object(g,'MODULE_CUSTODY',g._directory_identity(self.observed(directory))));s.enter_context(patch.object(g,'MODULE_ANCESTRY',self.parent_rows(directory)))
  return s
 def read(self,p,row=None,limit=65536):return g._read(p,self.b,self.end,[0],limit,None if row is None else row[1:])
 def fixture(self):
  directory=self.root/'modules';directory.mkdir();names=('liba.so','libb.so')
  objects=[]
  for n in names:
   p=directory/n;p.write_bytes(n.encode());p.chmod(0o444);objects.append(self.row(p))
  program=self.file('program',b'public executable',0o755);objects.append(self.row(program))
  aux=self.file('publicdb',b'opaque public database');return directory,names,objects,aux
 def test_source_pins_exact_observation_and_selected_transitive_closure(self):
  d=json.loads((R/'fixtures/hash-installed-inventory13.json').read_text());nodes={n['path']:n for n in d['public_nodes']}
  self.assertEqual(hashlib.sha256((R/'fixtures/hash-installed-inventory13.json').read_bytes()).hexdigest(),pins.INVENTORY_SHA256)
  needed={'/usr/local/bin/doveadm','/usr/libexec/ld.so'}|{pins.MODULE_DIRECTORY+'/'+n for n in pins.MODULE_NAMES}
  while True:
   old=set(needed)
   for e in d['dependency_edges']:
    if e['from']in needed:self.assertEqual(e['resolution'],'ONE_SOURCE_ROOT_CANDIDATE');self.assertEqual(len(e['candidates']),1);needed.update(e['candidates'])
   if needed==old:break
  self.assertEqual({r[0] for r in pins.FILES},needed|{'/var/run/ld.so.hints'});self.assertEqual(len(needed),19)
  keys=('device','inode','uid','gid','mode','links','bytes','mtime_ns','ctime_ns')
  for name,metadata,digest,ancestry in pins.FILES:
   n=nodes[name];self.assertEqual(metadata,tuple(n['metadata'][v] for v in keys));self.assertEqual(digest,n['sha256']);self.assertEqual(ancestry,tuple(tuple(v) for v in n['ancestry']))
 def test_actual_full_file_hash_and_all_fds_closed(self):
  p=self.file(raw=b'x'*8192+b'finaltail');row=self.row(p);before=set(os.listdir('/proc/self/fd'))
  with self.context((row,)):self.assertEqual(self.read(p,row),row[1:])
  self.assertEqual(set(os.listdir('/proc/self/fd')),before)
 def test_changed_final_byte_rejected_after_real_full_read(self):
  p=self.file(raw=b'A'*8192+b'end');old=self.row(p);p.chmod(0o644);p.write_bytes(b'A'*8192+b'enX');p.chmod(0o444);current=self.row(p);expected=(current[0],current[1],old[2],current[3])
  with self.context((expected,)),patch.object(g.os,'read',wraps=os.read) as actual:
   with self.assertRaisesRegex(Refused,'bytes changed'):self.read(p,expected)
  self.assertGreaterEqual(actual.call_count,3)
 def test_actual_public_hardlinks_bounded_and_startup_db_singlelink(self):
  p=self.file();os.link(p,self.root/'alias');row=self.row(p)
  with self.context((row,)):self.assertEqual(self.read(p,row),row[1:])
  q=self.file('publicdb');os.link(q,self.root/'dbalias')
  with self.context((),((q,65536),)),patch.object(g.os,'open',side_effect=AssertionError):
   with self.assertRaises(Refused):self.read(q)
 def test_symlink_fifo_owner_writegroup_setid_and_size_refuse_before_open(self):
  base=self.file('ordinary');link=self.root/'symbolic';link.symlink_to(base);fifo=self.root/'fifo';os.mkfifo(fifo)
  for p in (link,fifo):
   row=(str(p),(),'',())
   with self.context((row,)),patch.object(g.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):self.read(p)
  for mode in (0o666,0o4644):
   base.chmod(mode)
   with self.context((self.row(base),)),patch.object(g.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):self.read(base)
  base.chmod(0o444)
  with self.context((self.row(base),)),patch.object(g.os,'open',side_effect=AssertionError):
   with self.assertRaises(Refused):self.read(base,limit=1)
 def test_wrong_owner_link_zero_or_overbound_refuse_before_open(self):
  p=self.file();row=self.row(p)
  for updates in ({'st_uid':1234},{'st_nlink':0},{'st_nlink':65}):
   a=self.observed(p);a.__dict__.update(updates)
   with self.context((row,)),patch.object(Path,'lstat',lambda path:a if path==p else self.observed(path)),patch.object(g.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):self.read(p)
 def test_real_open_inode_substitution_refuses_and_closes(self):
  p=self.file();row=self.row(p);replacement=self.file('replacement');actual_open=os.open;fds=[]
  def exchange(path,flags):
   os.replace(replacement,p);fd=actual_open(path,flags);fds.append(fd);return fd
  with self.context((row,)),patch.object(g.os,'open',exchange):
   with self.assertRaises(Refused):self.read(p,row)
  with self.assertRaises(OSError):os.fstat(fds[0])
 def test_parent_change_after_real_read_refuses(self):
  p=self.file();row=self.row(p);changed=list(row[3]);changed[0]=changed[0][:4]+(99,)+changed[0][5:]
  with self.context((row,)),patch.object(g,'_parents',side_effect=(row[3],tuple(changed))):
   with self.assertRaises(Refused):self.read(p,row)
 def test_original_group_phase_total_and_closed_path_authority(self):
  p=self.file();row=self.row(p)
  with self.context((row,)):
   with self.assertRaises(Refused):g._read(p,self.b,time.monotonic()-1,[0],65536)
   with patch.object(self.b,'inherited_group',return_value=False),patch.object(g.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):self.read(p)
   with self.assertRaises(Refused):g._read(p,self.b,self.end,[g.TOTAL_CAP],65536)
   with self.assertRaises(Refused):self.read(self.root/'unknown')
 def test_actual_module_directory_and_opaque_public_startup_recheck(self):
  directory,names,objects,aux=self.fixture()
  with self.context(objects,((aux,65536),),directory,names):
   state=g.HashInstalledGraph._observe(self.b,self.end);v=object.__new__(g.HashInstalledGraph);v._budget=self.b;v._states=state;v.recheck(self.b,self.end)
   aux.chmod(0o644);aux.write_bytes(b'changed public');aux.chmod(0o444)
   with self.assertRaises(Refused):v.recheck(self.b,self.end)
   with self.assertRaises(Refused):v.recheck(OperationBudget(int(time.time())+8,maximum_seconds=8),self.end)
 def test_extra_hidden_nonmodule_or_symlink_module_directory_entry_rejected(self):
  for n in ('unexpected.so','.hidden','nonmodule'):
   directory,names,objects,aux=self.fixture() if not (self.root/'modules').exists() else (self.root/'modules',('liba.so','libb.so'),[],None)
   added=directory/n;added.write_bytes(b'new')
   with self.context(objects,(),directory,names):
    with self.assertRaises(Refused):g._modules(self.b,self.end)
   added.unlink()
  link=self.root/'diralias';link.symlink_to(directory,target_is_directory=True)
  with self.context((),(),directory,names),patch.object(g,'MODULE_DIRECTORY',str(link)):
   with self.assertRaises(Refused):g._modules(self.b,self.end)
 def test_real_directory_entry_bound_is_enforced(self):
  directory=self.root/'large';directory.mkdir()
  for i in range(g.DIRECTORY_ENTRY_CAP+1):(directory/('public'+str(i))).write_bytes(b'x')
  with self.context((),(),directory,()):
   with self.assertRaisesRegex(Refused,'directory bound'):g._modules(self.b,self.end)
 def test_phase_expiration_during_actual_read_stops_same_phase(self):
  p=self.file(raw=b'x'*8193);row=self.row(p);actual=os.read;now=[time.monotonic()]
  def expire(fd,count):
   part=actual(fd,count);now[0]=self.end+1;return part
  with self.context((row,)),patch.object(g.os,'read',expire),patch('time.monotonic',side_effect=lambda:now[0]):
   with self.assertRaisesRegex(Refused,'original phase'):self.read(p,row)
 def test_graph_native_authority_and_constructor_closed(self):
  with self.assertRaises(Refused):g.HashInstalledGraph(self.b,self.end)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(g.HashInstalledGraph,'_observe',side_effect=AssertionError):
   with self.assertRaises(Refused):g.HashInstalledGraph.native(self.b,self.end)
 def test_source_rows_no_directory_write_create_or_socket_or_network(self):
  rows=g.HashInstalledGraph.rows();self.assertEqual(len(rows),23)
  self.assertEqual([row for row in rows if b'w'in row[1] or b'c'in row[1]],[('/dev/null',b'rwc')]);self.assertEqual([row for row in rows if b'x'in row[1]],[('/usr/local/bin/doveadm',b'rx')]);self.assertEqual(rows[-2],(pins.SEARCH_DIRECTORY,b'r'));self.assertEqual(rows[-1],('/dev/null',b'rwc'));self.assertFalse({'/etc/pwd.db','/etc/group','/etc/passwd','/etc/spwd.db'}&{p for p,_ in rows})
  self.assertEqual(g.PROMISES.split(),[b'stdio',b'rpath',b'wpath',b'cpath',b'prot_exec',b'exec']);self.assertEqual(k._PROFILES,())
if __name__=='__main__':unittest.main(verbosity=2)
