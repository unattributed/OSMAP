"""Closed fixed SQL producer; real public custody and explicit local projections."""
import ast,hashlib,json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import account_command_kernel as k,account_sql_graph as q,account_sql_graph_pins as pins,account_native_material as m
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from operation_budget import OperationBudget
import test_hash_graph as graph_fixture

class SqlRoleTests(unittest.TestCase):
 def setUp(self):
  millis=int(time.time()*1000);self.b=OperationBudget.from_original_deadline((millis+60000)//1000,received_mono=time.monotonic(),received_millis=millis,sent_millis=millis,deadline_millis=millis+12000,wall_millis=lambda:int(time.time()*1000));self.end=time.monotonic()+10
  self.material=object.__new__(m.NativeMaterial);self.material._owner=0;self.material._plan=m.PLAN;self.material._config=m.CONFIG;self.material._endpoint=m._SqlEndpoint(Path(next(iter(m.SQL_SOCKETS))),4242);self.material._identity_source=m.NativeMaterial._server;self.material._states=((),(),(),())
 def context(self):return patch.object(k,'_PROFILES',('sql','hash'))
 def test_empty_registry_before_fixed_material_IO_and_no_profile_options(self):
  self.assertEqual(k._PROFILES,())
  with patch('os.open',side_effect=AssertionError),patch.object(q.SqlInstalledGraph,'native',side_effect=AssertionError):
   with self.assertRaises(Refused):k.CommandKernelSeal.native('sql',self.material,self.b)
  for kwargs in ({'rows':(('/tmp',b'r'),)},{'promises':b'stdio'},{'profile':'sql'},{'preexec_fn':lambda:None}):
   with self.assertRaises(TypeError):k.CommandKernelSeal.native('sql',self.material,self.b,**kwargs)
 def test_actual_SQL_producer_and_MaterialExecutor_SQL_then_hash_construction(self):
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'_fixture',side_effect=AssertionError),patch.object(k.CommandKernelSeal,'_hash_candidate',side_effect=AssertionError),patch('os.open',side_effect=AssertionError('constructor no IO')):
   executor=m.MaterialExecutor(self.b,self.material)
   sql=executor._seals[(A.SQL_PROGRAM,A.SQL_ARGS)];hashseal=executor._seals[(A.HASH_PROGRAM,A.HASH_ARGS)]
  self.assertTrue(sql._sql_graph_required);self.assertFalse(sql._hash_graph_required or sql._hash_identity_required);self.assertTrue(hashseal._hash_graph_required and hashseal._hash_identity_required);self.assertFalse(hashseal._sql_graph_required)
  self.assertEqual(sql._rows,q.SqlInstalledGraph.rows(self.material));self.assertEqual(sql._promises,q.PROMISES);self.assertIs(sql._material,self.material);self.assertIs(sql._budget,self.b)
 def test_wrong_role_account_generic_budget_and_private_material_source_refuse(self):
  generic=OperationBudget(int(self.b._expires)+1,maximum_seconds=10);generic._deadline=self.b._deadline;generic._expires=self.b._expires
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch.object(generic,'inherited_group',return_value=True):
   for call in (lambda:k.CommandKernelSeal.native('primary',self.material,self.b,'fixture@example.invalid'),lambda:k.CommandKernelSeal.native('sql',self.material,self.b,'fixture@example.invalid'),lambda:m.MaterialExecutor(generic,self.material)):
    with self.assertRaises(Refused):call()
   for field,value in (('_owner',1000),('_plan',Path('/tmp/foreign-plan')),('_config',Path('/tmp/foreign-config')),('_endpoint',m._SqlEndpoint(Path('/tmp/foreign-socket'),4242)),('_identity_source',lambda:4242),('_states',())):
    old=getattr(self.material,field);setattr(self.material,field,value)
    try:
     with self.assertRaises(Refused):m.MaterialExecutor(self.b,self.material)
    finally:setattr(self.material,field,old)
 def test_fixed_exact13_ELF_hints_inventory_and_minimum_rows(self):
  raw=(R/'fixtures/hash-installed-inventory13.json').read_bytes();d=json.loads(raw);self.assertEqual(hashlib.sha256(raw).hexdigest(),pins.INVENTORY_SHA256);nodes={n['path']:n for n in d['public_nodes']};needed={A.SQL_PROGRAM,'/usr/libexec/ld.so'}
  while True:
   old=set(needed)
   for edge in d['dependency_edges']:
    if edge['from']in needed:self.assertEqual(edge['resolution'],'ONE_SOURCE_ROOT_CANDIDATE');needed.update(edge['candidates'])
   if old==needed:break
  self.assertEqual(len(needed),13);self.assertEqual({v[0] for v in pins.FILES},needed|{'/var/run/ld.so.hints'})
  keys=('device','inode','uid','gid','mode','links','bytes','mtime_ns','ctime_ns')
  for name,metadata,digest,ancestry in pins.FILES:
   node=nodes[name];self.assertEqual(metadata,tuple(node['metadata'][key] for key in keys));self.assertEqual(digest,node['sha256']);self.assertEqual(ancestry,tuple(tuple(v) for v in node['ancestry']))
  rows=q.SqlInstalledGraph.rows(self.material);self.assertEqual(len(rows),17);self.assertEqual([r for r in rows if b'w'in r[1]],[(str(self.material._endpoint.path),b'w')]);self.assertFalse(any(b'c'in access for _,access in rows));self.assertEqual(rows[-1],('/dev/null',b'r'));self.assertEqual(q.PROMISES,b'stdio rpath unix prot_exec exec')
  self.assertFalse(any(name in ('/usr/lib','/usr/local/lib','/etc/passwd','/etc/group','/etc/pwd.db','/etc/ssl/openssl.cnf') for name,_ in rows))
 def test_actual_full_public_file_read_tail_mutation_nonblocking_FD_refusal(self):
  helper=graph_fixture.GraphTests();helper.setUp();self.addCleanup(helper.doCleanups);helper.b=self.b;helper.end=self.end;p=helper.file(raw=b'A'*8192+b'last');row=helper.row(p)
  with helper.context((row,)),patch.object(q,'FILES',(row,)):
   self.assertEqual(q._read(p,self.b,self.end,[0],65536,row[1:]),row[1:]);p.chmod(0o644);p.write_bytes(b'A'*8192+b'lasX');p.chmod(0o444);current=helper.row(p)
   with self.assertRaises(Refused):q._read(p,self.b,self.end,[0],65536,(current[1],row[2],current[3]))
  actual_open=os.open;before=set(os.listdir('/proc/self/fd'));replacement=helper.file('replacement')
  with helper.context((row,)),patch.object(q,'FILES',(row,)):
   row=helper.row(p)
   def exchange(path,flags):
    self.assertTrue(flags&os.O_NONBLOCK and flags&os.O_NOFOLLOW);os.replace(replacement,p);return actual_open(path,flags)
   with patch.object(q.os,'open',exchange):
    with self.assertRaises(Refused):q._read(p,self.b,self.end,[0],65536,row[1:])
  self.assertEqual(set(os.listdir('/proc/self/fd')),before)
 def test_actual_complete_SQL_graph_recheck_captures_material_and_public_bytes(self):
  helper=graph_fixture.GraphTests();helper.setUp();self.addCleanup(helper.doCleanups);helper.b=self.b;p=helper.file();row=helper.row(p);calls=[]
  with helper.context((row,)),patch.object(q,'FILES',(row,)),patch.object(m.NativeMaterial,'recheck',side_effect=lambda budget:calls.append(budget)),patch.object(q,'_null',return_value=('readonly null local metadata projection',)):
   states=q.SqlInstalledGraph._observe(self.b,self.end,self.material);value=object.__new__(q.SqlInstalledGraph);value._budget=self.b;value._material=self.material;value._states=states;value.recheck(self.b,self.end);self.assertEqual(calls,[self.b,self.b])
   p.chmod(0o644);p.write_bytes(b'changed');p.chmod(0o444)
   with self.assertRaises(Refused):value.recheck(self.b,self.end)
   with patch.object(q.os,'open',side_effect=AssertionError):
    with self.assertRaises(Refused):q.SqlInstalledGraph._observe(self.b,time.monotonic()-1,self.material)
 def test_SQL_custody_type_budget_material_or_extra_path_prevents_dispatch(self):
  with self.context(),patch.object(self.b,'inherited_group',return_value=True):seal=k.CommandKernelSeal._for_material('sql',self.material,self.b)
  for bad in (object(),None):
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(q.SqlInstalledGraph,'native',return_value=bad),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.spawn(A.SQL_PROGRAM,A.SQL_ARGS,self.end)
  graph=object.__new__(q.SqlInstalledGraph);graph._budget=self.b;graph._material=self.material
  for field,value in (('_budget',OperationBudget(int(time.time())+5,maximum_seconds=5)),('_material',object())):
   old=getattr(graph,field);setattr(graph,field,value)
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(q.SqlInstalledGraph,'native',return_value=graph),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.spawn(A.SQL_PROGRAM,A.SQL_ARGS,self.end)
   setattr(graph,field,old)
  original=seal._rows;seal._rows+=(('/tmp',b'r'),)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(q.SqlInstalledGraph,'native',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.preexec(A.SQL_PROGRAM,A.SQL_ARGS,deadline=self.end)
  seal._rows=original
 def test_actual_owned_SQL_role_source_transport_closed_children(self):
  child=subprocess.Popen((sys.executable,'-I','-B',str(R/'owned_sql_role.py'),str(R)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=child.communicate(timeout=15);self.assertEqual(child.returncode,0,err);self.assertEqual(out,b'PUBLIC_SQL_ROLE_SOURCE_TRANSPORT_2_CHILDREN_REAPED_KERNEL_ROOT_LOADER_SQL_PROJECTED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
  finally:
   if child.returncode is None:child.kill();child.wait(timeout=2)
   child.stdout.close();child.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
