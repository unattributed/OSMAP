"""Fixed argv and environment authority; actual local owned fixture transport."""
import json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
from authoritative_password import AuthoritativePasswordAdapter as Adapter,Refused
from native_transport_test_support import PublicFixtureExecutor as NativeExecutor

FIXTURE=r'''
import json,os,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from authoritative_password import AuthoritativePasswordAdapter as Adapter
from native_transport_test_support import PublicFixtureExecutor as NativeExecutor
from operation_budget import OperationBudget
budget=OperationBudget(int(time.time())+8,maximum_seconds=8);budget.attach_owned_process_group()
script="import json,os,sys;sys.stdin.buffer.read();print(json.dumps(dict(os.environ),sort_keys=True))"
role=sys.argv[2];attr='HASH' if role=='hash' else 'SQL'
with patch.object(Adapter,attr+'_PROGRAM',sys.executable),patch.object(Adapter,attr+'_ARGS',('-c',script)):
 code,out,err=NativeExecutor(budget)(sys.executable,('-c',script),b'public synthetic',10,4096)
assert code==0 and not err
print(out.decode().strip())
'''
class Isolation(unittest.TestCase):
    def test_exact_skip_configuration_hash_argv(self):
        self.assertEqual(Adapter.HASH_ARGS,('-O','pw','-s','ARGON2ID'))
    def test_old_or_extended_hash_command_refuses_before_spawn(self):
        cases=[('pw','-s','ARGON2ID'),('-O','pw','-s','BLF-CRYPT'),
               ('-O','-c','/tmp/caller-config','pw','-s','ARGON2ID'),
               ('-O','pw','-s','ARGON2ID','-p','caller password'),
               ('-O','-o','mail_plugins=caller','pw','-s','ARGON2ID')]
        with patch('subprocess.Popen',side_effect=AssertionError('dispatch must not occur')):
            for args in cases:
                with self.subTest(args=args),self.assertRaises(Refused):
                    NativeExecutor()(Adapter.HASH_PROGRAM,args,b'public',10,4096)
    def actual(self,role):
        # Outer test owns a distinct unreaped local session. The actual executor
        # receives its original inherited group budget, as on the helper.
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','CONFIG_FILE':'/tmp/foreign-config',
             'STATS_WRITER_SOCKET_PATH':'/tmp/foreign-stats','MAIL_PLUGINS':'foreign-plugin',
             'DOVECONF_ENV':'1','SECRET':'synthetic must not inherit'}
        child=subprocess.Popen((sys.executable,'-I','-B','-c',FIXTURE,str(Path(__file__).resolve().parent),role),
          stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=env)
        try:
            out,err=child.communicate(timeout=10)
            self.assertEqual(child.returncode,0,err.decode());self.assertEqual(err,b'')
            with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
            return json.loads(out)
        finally:
            if child.returncode is None:child.kill();child.wait(timeout=2)
            child.stdout.close();child.stderr.close()
    def test_actual_hash_transport_uses_fixed_closed_environment(self):
        self.assertEqual(self.actual('hash'),{'CONFIG_FILE':'/dev/null','LC_ALL':'C',
          'PATH':'/usr/bin:/usr/local/bin','STATS_WRITER_SOCKET_PATH':''})
    def test_actual_SQL_transport_keeps_its_original_environment(self):
        self.assertEqual(self.actual('sql'),{'LC_ALL':'C','PATH':'/usr/bin:/usr/local/bin'})
if __name__=='__main__':unittest.main(verbosity=2)
