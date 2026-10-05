"""Public, private-file/Unix-peer controls; zero SQL/auth/host changes."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import account_native_material as m
from account_mutation_worker import Unavailable
from authoritative_password import AuthoritativePasswordAdapter as Adapter, NativeExecutor
from operation_budget import OperationBudget


class MaterialFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.plan = self.root / 'sql-endpoint.json'
        self.config = self.root / 'client.cnf'
        self.path = self.root / 'mysql.sock'
        self.programs = [self.root / name for name in ('mariadb', 'doveadm', 'python3', 'worker.py')]
        for p in self.programs:
            p.write_bytes(b'public fixed fixture program\n'); p.chmod(0o500)
        self.engine_target = self.root / m.ENGINE_TARGET
        self.programs[2].rename(self.engine_target)
        self.programs[2].symlink_to(m.ENGINE_TARGET)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path)); self.server.listen(16)
        self.plan.write_text(json.dumps({'version': 1, 'authority': m.AUTHORITY, 'purpose': m.PURPOSE,
            'server': m.SERVER, 'socket': str(self.path), 'database_user': m.DATABASE_USER}))
        self.plan.chmod(0o600)
        self.valid = ('[client]\nuser=' + m.DATABASE_USER + '\npassword=public_synthetic_only_123\n'
                      'protocol=SOCKET\nsocket=' + str(self.path) + '\n').encode()
        self.config.write_bytes(self.valid); self.config.chmod(0o600)
        self.mono = 100.; self.wall = 1000.
        self.budget = OperationBudget(1060, monotonic=lambda: self.mono, wall=lambda: self.wall)
        self.patches = [patch.object(m, 'SQL_SOCKETS', frozenset([str(self.path)])),
            patch.object(Adapter, 'SQL_PROGRAM', str(self.programs[0])),
            patch.object(Adapter, 'HASH_PROGRAM', str(self.programs[1])),
            patch.object(m, 'ENGINE', str(self.programs[2])), patch.object(m, 'WORKER', str(self.programs[3])),
            patch.object(self.budget, 'inherited_group', return_value=True)]
        for p in self.patches: p.start()
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.server.close(); self.tmp.cleanup()
    def load(self):
        return m.NativeMaterial._load(self.plan, self.config, os.getuid(), lambda: os.getuid(), self.budget)


class NativeMaterialTests(MaterialFixture):
    def test_actual_private_files_and_local_peer_accept_without_protocol_bytes(self):
        material = self.load(); material.recheck(self.budget)
        self.assertIs(type(material), m.NativeMaterial)
        self.assertNotIn('synthetic', repr(material))
        for _ in range(2):
            peer, _ = self.server.accept()
            with peer: self.assertEqual(peer.recv(1), b'')
    def test_arbitrary_client_options_include_tcp_plugin_and_extra_group_refuse(self):
        for raw in (self.valid + b'!include=/etc/private.cnf\n', self.valid.replace(b'SOCKET', b'TCP'),
                    self.valid + b'plugin-dir=/tmp\n', self.valid + b'[mariadb]\ninit-command=SELECT 1\n',
                    self.valid.replace(b'password=', b'user='), self.valid.replace(b'public_synthetic_only_123', b'"quotedpassword123456789"')):
            self.config.write_bytes(raw)
            with self.assertRaises(Unavailable): self.load()
    def test_wrong_authority_principal_socket_and_duplicate_json_refuse(self):
        raw = self.plan.read_bytes()
        for data in (raw.replace(m.AUTHORITY.encode(), b'obsd1.blackbagsecurity.com'),
                     raw.replace(m.SERVER.encode(), b'root'), raw.replace(str(self.path).encode(), b'/tmp/foreign.sock'),
                     raw[:-1] + b',"version":1}'):
            self.plan.write_bytes(data)
            with self.assertRaises(Unavailable): self.load()
    def test_kernel_foreign_peer_refuses_no_credential_or_query_send(self):
        with patch.object(m, '_peer', return_value=os.getuid() + 1):
            with self.assertRaises(Unavailable): self.load()
        peer, _ = self.server.accept()
        with peer: self.assertEqual(peer.recv(1), b'')
    def test_symlink_hardlink_public_config_and_setuid_program_refuse(self):
        os.link(self.config, self.root / 'linked')
        with self.assertRaises(Unavailable): self.load()
        (self.root / 'linked').unlink(); self.config.chmod(0o644)
        with self.assertRaises(Unavailable): self.load()
        self.config.chmod(0o600); self.programs[0].chmod(0o4500)
        with self.assertRaises(Unavailable): self.load()
        self.programs[0].chmod(0o500)
        target = self.root / 'original'; self.config.rename(target); self.config.symlink_to(target)
        with self.assertRaises(Unavailable): self.load()
    def test_config_replacement_same_permissions_refuses_before_executor_spawn(self):
        material = self.load()
        replacement = self.root / 'replacement'; replacement.write_bytes(self.valid); replacement.chmod(0o600)
        replacement.replace(self.config)
        executor = m.MaterialExecutor(self.budget, material)
        with patch.object(NativeExecutor, '__call__', side_effect=AssertionError('dispatch forbidden')):
            with self.assertRaises(Unavailable): executor(Adapter.SQL_PROGRAM, Adapter.SQL_ARGS, b'', 10, 4096)
    def test_content_change_restoring_size_and_mtime_is_not_continuity(self):
        material = self.load(); info = self.config.stat()
        self.config.write_bytes(self.valid.replace(b'123', b'124'))
        os.utime(self.config, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_parent_generation_replacement_with_same_file_inodes_refuses(self):
        material = self.load(); saved = self.root.with_name(self.root.name + '.old-generation')
        self.root.rename(saved); self.root.mkdir(mode=0o700)
        for child in saved.iterdir(): child.rename(self.root / child.name)
        saved.rmdir()
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_program_replacement_refuses(self):
        material = self.load()
        replacement = self.root / 'new-program'
        replacement.write_bytes(b'changed fixed fixture program\n'); replacement.chmod(0o500)
        replacement.replace(self.programs[1])
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_exact_engine_alias_and_regular_target_have_distinct_custody(self):
        if os.environ.get('OSMAP_ENGINE_SUBJECT') == 'old_regular_gate':
            # Exact unchanged regular/O_NOFOLLOW routine that the pre-fix
            # factory used for ENGINE; the observed alias was permanently refused.
            with patch.object(m, '_engine', side_effect=lambda path, owner, budget:
                    m._read(path, owner, False, 64*1024*1024, budget, executable=True)[0]):
                material = self.load()
        else:
            material = self.load()
        material.recheck(self.budget)
        state = material._states[2][2]
        self.assertEqual(state[1], 'python3.13')
        self.assertNotEqual(state[0][:2], state[2][0][:2])
    def test_engine_alias_foreign_absolute_version_and_chain_refuse(self):
        for target in ('python3.12', str(self.engine_target), 'doveadm'):
            self.programs[2].unlink(); self.programs[2].symlink_to(target)
            with self.assertRaises(Unavailable): self.load()
        self.programs[2].unlink(); self.programs[2].symlink_to(m.ENGINE_TARGET)
        self.engine_target.unlink(); self.engine_target.symlink_to('doveadm')
        with self.assertRaises(Unavailable): self.load()
    def test_engine_target_public_writable_setuid_and_nonexecutable_refuse(self):
        for mode in (0o522, 0o4500, 0o400):
            self.engine_target.chmod(mode)
            with self.assertRaises(Unavailable): self.load()
    def test_engine_alias_same_literal_replacement_refuses(self):
        material = self.load()
        self.programs[2].unlink(); self.programs[2].symlink_to(m.ENGINE_TARGET)
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_engine_target_same_bytes_replacement_refuses(self):
        material = self.load(); replacement = self.root / 'new-engine'
        replacement.write_bytes(self.engine_target.read_bytes()); replacement.chmod(0o500)
        replacement.replace(self.engine_target)
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_foreign_engine_alias_or_target_owner_refuses(self):
        old_lstat = Path.lstat
        def foreign(path):
            info = old_lstat(path)
            if path == self.programs[2]:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=1)
            return info
        with patch.object(Path, 'lstat', foreign):
            with self.assertRaises(Unavailable): m._engine(self.programs[2], os.getuid(), self.budget)
        info = self.engine_target.stat()
        with patch.object(os, 'fstat', return_value=SimpleNamespace(
                st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=1)):
            with self.assertRaises(Unavailable): m._engine(self.programs[2], os.getuid(), self.budget)
    def test_socket_replacement_refuses(self):
        material = self.load()
        # A new same-principal socket also has a different custody identity.
        self.server.close(); self.path.unlink()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path)); self.server.listen(16)
        with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_original_deadline_expiry_during_probe_refuses(self):
        real = m._probe
        def late(*args):
            value = real(*args); self.mono = 160.; return value
        with patch.object(m, '_probe', side_effect=late):
            with self.assertRaises(Unavailable): self.load()
    def test_unowned_group_refuses(self):
        material = self.load()
        with patch.object(self.budget, 'inherited_group', return_value=False):
            with self.assertRaises(Unavailable): material.recheck(self.budget)
    def test_matching_executor_rechecks_each_dispatch_same_budget(self):
        material = self.load(); executor = m.MaterialExecutor(self.budget, material)
        with patch.object(NativeExecutor, '__call__', return_value=(0, b'', b'')) as dispatch:
            for program, args in ((Adapter.SQL_PROGRAM, Adapter.SQL_ARGS), (Adapter.HASH_PROGRAM, Adapter.HASH_ARGS)):
                self.assertEqual(executor(program, args, b'public only\n', 10, 4096), (0, b'', b''))
        self.assertEqual(dispatch.call_count, 2); self.assertIs(executor._budget, self.budget)
        self.assertIs(executor._material, material)
    def test_native_authority_and_direct_constructor_refuse_before_private_reads(self):
        with patch.object(m, '_read', side_effect=AssertionError):
            with self.assertRaises(Unavailable): m.NativeMaterial.native()
            with self.assertRaises(Unavailable): m.NativeMaterial({'PASS': True})
        with self.assertRaises(Unavailable): m.MaterialExecutor(self.budget, {'PASS': True})


class OldBoundaryDiscriminators(MaterialFixture):
    """Execute the existing metadata gate as RED, new exact loader as GREEN."""
    def setUp(self):
        super().setUp()
        path = os.environ.get('OSMAP_MATERIAL_FACTORY_SUBJECT')
        if path:
            spec = importlib.util.spec_from_file_location('old_material_subject', path)
            self.subject = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.subject)
        else:
            import account_mutation_native
            self.subject = account_mutation_native
    def admit(self):
        # Old gate assumes owner0. Remap ONLY measured file ownership and /tmp
        # ancestor mode for this unprivileged fixture; unsafe content stays exact.
        old_fstat = os.fstat; old_lstat = Path.lstat
        def mapped(info, ancestor=False):
            return SimpleNamespace(st_mode=(stat.S_IFDIR | 0o755) if ancestor else info.st_mode,
                st_uid=0, st_nlink=info.st_nlink, st_size=info.st_size)
        def lstat(path):
            info = old_lstat(path)
            return mapped(info, stat.S_ISDIR(info.st_mode))
        if hasattr(self.subject, 'NativeMaterial'):
            with patch.object(self.subject.NativeMaterial, 'native', side_effect=self.load):
                return self.subject._fixed_material()
        with patch.object(self.subject, 'SQL_CONFIG', self.config), patch.object(Path, 'lstat', lstat),\
                patch.object(os, 'fstat', side_effect=lambda fd: mapped(old_fstat(fd))):
            return self.subject._fixed_material()
    def test_metadata_only_include_file_must_refuse(self):
        self.config.write_bytes(self.valid + b'!include=/etc/foreign.cnf\n')
        with self.assertRaises(Unavailable): self.admit()
    def test_metadata_only_tcp_transport_must_refuse(self):
        self.config.write_bytes(self.valid.replace(b'SOCKET', b'TCP'))
        with self.assertRaises(Unavailable): self.admit()
    def test_metadata_only_missing_sql_peer_must_refuse(self):
        self.server.close(); self.path.unlink()
        with self.assertRaises(Unavailable): self.admit()


class FifoDeadlineDiscriminators(unittest.TestCase):
    def bounded_child(self, mode):
        # A real writerless FIFO and an actual replace-at-open race live only
        # in a disposable private child namespace. Parent owns the unreaped
        # process group and kills/reaps it on one1s bound; no stale PID signals.
        subject = os.environ.get('OSMAP_FIFO_MATERIAL_SUBJECT', str(Path(m.__file__)))
        source = str(Path(__file__).parent)
        code = '''
import contextlib,importlib.util,os,sys,time
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[sys.argv[1],'/home/foo/Workspace/OSMAP/maint/account-runtime']
from operation_budget import OperationBudget
from account_mutation_worker import Unavailable
spec=importlib.util.spec_from_file_location('fifo_subject',sys.argv[2])
subject=importlib.util.module_from_spec(spec);sys.modules[spec.name]=subject;spec.loader.exec_module(subject)
with contextlib.nullcontext(sys.argv[4]) as namespace:
 path=Path(namespace)/'fixed.cnf'
 if sys.argv[3]=='fifo':os.mkfifo(path,0o600)
 else:path.write_bytes(b'public bounded regular fixture\\n');path.chmod(0o600)
 budget=OperationBudget(int(time.time())+2,maximum_seconds=.25)
 budget.attach_owned_process_group()
 real_open=os.open;swapped=False
 def swap(candidate,flags,*args,**kwargs):
  global swapped
  if sys.argv[3]=='race' and Path(candidate)==path and not swapped:
   swapped=True;path.unlink();os.mkfifo(path,0o600)
  return real_open(candidate,flags,*args,**kwargs)
 try:
  with patch.object(os,'open',side_effect=swap):subject._read(path,os.getuid(),True,4096,budget)
 except Unavailable:print('REFUSED',flush=True)
 else:print('ADMITTED',flush=True)
'''
        owned = Path(tempfile.mkdtemp(prefix='osmap-native-material-fifo-'))
        info = owned.lstat(); namespace_lease = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        child = None
        try:
            child = subprocess.Popen((sys.executable, '-I', '-B', '-c', code, source, subject, mode, str(owned)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                start_new_session=True, close_fds=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            try:
                output, errors = child.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                # No wait/poll/reap precedes this signal of the owned group.
                try:os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:pass
                output, errors = child.communicate(timeout=1)
                result = 'BLOCKED_PAST_ORIGINAL_BUDGET'
            else:
                result = output.decode('ascii').strip()
                self.assertEqual(child.returncode, 0, errors[:200])
                self.assertEqual(errors, b'')
            self.assertLessEqual(len(output) + len(errors), 4096)
            try:os.killpg(child.pid, 0)
            except ProcessLookupError:pass
            else:self.fail('disposable owned group absence unconfirmed')
            return result
        finally:
            if child is not None:
                if child.returncode is None:
                    try:os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=1)
                for handle in (child.stdout, child.stderr):handle.close()
                try:os.killpg(child.pid, 0)
                except ProcessLookupError:pass
                else:self.fail('disposable group still present; namespace preserved')
            info = owned.lstat()
            self.assertEqual((info.st_dev, info.st_ino, info.st_uid, info.st_mode), namespace_lease)
            members = list(owned.iterdir())
            self.assertLessEqual(len(members), 1)
            for member in members:
                info = member.lstat()
                self.assertEqual(member.name, 'fixed.cnf')
                self.assertTrue(stat.S_ISREG(info.st_mode) or stat.S_ISFIFO(info.st_mode))
                self.assertEqual(info.st_uid, os.getuid()); self.assertEqual(info.st_nlink, 1)
                member.unlink()
            owned.rmdir()
            self.assertFalse(os.path.lexists(owned))
    def test_actual_writerless_fifo_refuses_inside_original_budget(self):
        self.assertEqual(self.bounded_child('fifo'), 'REFUSED')
    def test_actual_regular_to_fifo_open_race_refuses_inside_original_budget(self):
        self.assertEqual(self.bounded_child('race'), 'REFUSED')


if __name__ == '__main__': unittest.main()
