"""Integrated local regressions for the corrected Milestone 1 carrier."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load('candidate_stage', 'stage_root.py')
cleanup = load('candidate_cleanup', 'cleanup_owned_stages.py')
consumer = load('candidate_consumer', 'consume_startup.py')
binder = load('candidate_binder', 'bind_startup.py')
wrapper = load('candidate_wrapper', 'remote_wrapper.py')
startup = load('candidate_startup', 'startup_only.py')
schema = load('candidate_schema', 'sources/backend/stock_schema.py')
dispatch = load('candidate_dispatch', 'dispatch_startup.py')
journey = load('candidate_journey', 'sources/backend/local_journey.py')


class StockSchemaTests(unittest.TestCase):
    def valid(self, version='11.4.13-MariaDB'):
        return f'root@localhost\t{version}\n0\n0\nInnoDB\n0\n0\n'.encode()

    def test_current_and_future_patch_versions_are_observations(self):
        for version in ('11.4.12-MariaDB', '11.4.13-MariaDB',
                '12.0.1-MariaDB', '11.4.13-log-MariaDB'):
            with self.subTest(version=version):
                result = schema.stock_fresh_reserved_schema(self.valid(version))
                self.assertEqual(result['database_product'], 'MariaDB')
                self.assertEqual(result['database_identity'], 'root@localhost')

    def test_each_failed_condition_has_its_own_code(self):
        cases = {
            'stock_schema_row_count': b'root@localhost\t11.4.13-MariaDB\n0\n',
            'stock_database_identity': self.valid().replace(b'root@localhost', b'other@localhost'),
            'stock_database_compatibility': self.valid('11.4.13-OtherDB'),
            'stock_reserved_database_user_count': self.valid().replace(b'\n0\n0\nInnoDB', b'\n1\n0\nInnoDB'),
            'stock_controlled_rows_count': self.valid().replace(b'\n0\n0\nInnoDB', b'\n0\n2\nInnoDB'),
            'stock_mailbox_engine': self.valid().replace(b'InnoDB', b'MyISAM'),
            'stock_mailbox_triggers': self.valid().replace(b'InnoDB\n0\n0', b'InnoDB\n1\n0'),
            'stock_mailbox_foreign_keys': self.valid().replace(b'InnoDB\n0\n0', b'InnoDB\n0\n1'),
            'stock_schema_numeric': self.valid().replace(b'InnoDB\n0\n0', b'InnoDB\nno\n0'),
        }
        for expected, raw in cases.items():
            with self.subTest(expected=expected), self.assertRaises(schema.StockSchemaRefused) as caught:
                schema.stock_fresh_reserved_schema(raw)
            self.assertEqual(caught.exception.code, expected)

    def test_structured_refusal_survives_outer_sanitizer(self):
        error = SimpleNamespace(code='stock_mailbox_engine')
        self.assertEqual(startup.failure_reason(error), 'stock_mailbox_engine')
        self.assertEqual(startup.failure_reason(RuntimeError('private value with spaces')),
            'UNEXPECTED_SANITIZED')


class CarrierClosureTests(unittest.TestCase):
    def test_one_source_map_closes_packet_stager_and_wrapper(self):
        packet = binder.source_packet()
        self.assertEqual(set(packet['sources']), set(stage.SOURCE_PINS))
        for name, expected in stage.SOURCE_PINS.items():
            raw = base64.b64decode(packet['sources'][name], validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected, name)
        self.assertEqual(wrapper.ROOT_SOURCE_SHA256,
            hashlib.sha256((ROOT / 'stage_root.py').read_bytes()).hexdigest())
        backend = {Path(name).name for name in stage.SOURCE_PINS
            if name.startswith('backend/') and name != 'backend/startup_only.py'}
        frontend = {Path(name).name for name in stage.SOURCE_PINS
            if name.startswith('frontend/')}
        self.assertEqual(backend, journey.BACKEND_SOURCE_NAMES)
        self.assertEqual(frontend, journey.FRONTEND_SOURCE_NAMES)

    def test_isolated_custody_loader_resolves_schema_source(self):
        loader = ("import importlib.util,sys;"
            "s=importlib.util.spec_from_file_location('isolated_custody',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)")
        completed = subprocess.run([os.sys.executable, '-I', '-B', '-c', loader,
            str(ROOT/'sources/backend/custody.py')], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))

    def test_obsolete_retained_binary_is_not_admitted(self):
        with self.assertRaisesRegex(RuntimeError,
                'retained_build_obsolete_openbsd_authority'):
            binder.packet()

    def test_actual_producer_frames_satisfy_consumer(self):
        expiry = 2_000_000_000
        back = Path('/var/run/osmap-service-admission-root-0000000000000000')
        front = Path('/tmp/osmap-pxp-stage-0000000000000000')
        birth1 = stage.stage_birth_frame(back, None, expiry)
        birth2 = stage.stage_birth_frame(back, front, expiry)
        probes = {name: {'connected_ms': 1.0, 'handled_ms': 2.0,
            'cleanup_confirmed': True} for name in ('admission', 'mutation')}
        sockets = {name: {'uid': 0, 'gid': 1001, 'mode': stat.S_IFSOCK | 0o660}
            for name in ('/var/run/osmap-account-admission/admission.sock',
                '/var/run/osmap-account-mutation/mutation.sock')}
        readiness = {'startup_seconds': 0.5, 'startup_deadline_seconds': 5,
            'paired_sockets_published': True, 'parent_prepare': True, 'parent_seal': True,
            'acceptance_proof': 'AUTHORIZED_UID_CONNECT_EOF_HANDLED_ON_BOTH_SOCKETS',
            'service_binary_sha256': '7cd4cba76f27c34060c8ddbf843a1a2d71a06e64675c708327a1861b7bdb3092',
            'socket_metadata': sockets, 'probes': probes}
        actor = {'schema': 'osmap-single-host-startup-v1', 'result': 'PASS',
            'functional_result': 'PASS', 'disposition': 'CONFIRMED', 'password_mutation': False,
            'credential_request_frames': 0, 'public_service_controls': False,
            'public_config_writes': False, 'relay_operations': False,
            'credential_values_retained': False, 'authoritative_no_write': {
                'actual_write_observed': False, 'Alice_exact17_preserved': True,
                'Alice_epoch': 0, 'Alice_state': 'active', 'Alice_changed_at': None,
                'Bob_all17_preserved': True, 'Bob_epoch': 0, 'Bob_state': 'active'},
            'native_stages': {name: 'PASS' for name in ('ServiceStartup','ServiceFiles',
                'ServiceAdmission','ServiceAccounts','ServiceStore','AdmissionBind','MutationBind',
                'ParentPrepare','ParentSeal','AcceptanceLoop')},
            'service_readiness': readiness, 'owned_effects_report': {
                'cleanup_confirmed': True, 'public_original25_preserved': True,
                'public_master_preserved': True, 'owned_sql_hash_uids_absent': True,
                'observed_release': 'unrestricted'}, 'elapsed_millis': 500}
        ready = {'schema': 'osmap-single-host-stage-ready-v1', 'backend': str(back),
            'frontend': str(front), 'not_after_utc': expiry}
        transport = {'schema': 'osmap-single-host-transport-v1', 'result': 'COMPLETE',
            'born_child_reaped': True, 'born_group_gone': True, 'root_exit': 0,
            'stderr_bytes': 0, 'failure': None, 'frames': [birth1, birth2, ready, actor]}
        self.assertEqual(consumer.inspect(transport, 0, expiry)['result'], 'PASS')

    def test_transport_reap_uncertainty_cannot_be_called_confirmed(self):
        child = SimpleNamespace(returncode=0, pid=424242)
        record = {}
        with patch.object(dispatch.os, 'killpg', side_effect=PermissionError):
            dispatch.dispose(child, record)
        self.assertEqual(record['local_transport_disposition'], 'UNCERTAIN')
        self.assertTrue(record['local_transport_reaped'])


class CleanupTests(unittest.TestCase):
    def setUp(self):
        cleanup.report.update(result='FAIL', removed_files=0, removed_directories=0,
            service_or_account_operations=False)
        for key in ('failure','stage_paths_absent','open_leaf_references_absent'):
            cleanup.report.pop(key, None)

    @staticmethod
    def fstat_clear(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stderr=b'', stdout=b'USER CMD PID FD\n')

    def fixture(self, extra_birth=None, omit_birth=None, extra_leaf=False):
        temp = tempfile.TemporaryDirectory(prefix='osmap-cleanup-candidate-', dir='/tmp')
        root = Path(temp.name);back=root/'back';front=root/'front'
        back.mkdir(mode=0o700);front.mkdir(mode=0o700)
        owner = os.geteuid();packet = 'a' * 64;expiry = 2_000_000_000
        birth = stage.stage_birth_receipt(back, stage.identity(back.lstat()), packet, expiry)
        if extra_birth is not None:birth[extra_birth] = 'unexpected'
        if omit_birth is not None:birth.pop(omit_birth)
        (back/'stage-birth.json').write_bytes(stage.encode(birth));(back/'stage-birth.json').chmod(0o600)
        for path in (back/'backend.py', front/'frontend.py'):
            path.write_bytes(b'owned\n');path.chmod(0o600)
        files = {str(path): stage.identity(path.lstat())
            for path in (back/'backend.py', front/'frontend.py')}
        receipt = stage.stage_ownership_receipt(back, front, stage.identity(back.lstat()),
            stage.identity(front.lstat()), 'b'*64, packet, expiry, files)
        receipt['admission_sha256'] = 'c' * 64
        raw = stage.encode(receipt);(back/'stage-ownership.json').write_bytes(raw)
        (back/'stage-ownership.json').chmod(0o600)
        if extra_leaf:(front/'unowned').write_bytes(b'no')
        return temp,back,front,hashlib.sha256(raw).hexdigest(),owner

    def test_startup145_birth_without_frontend_cleans_exact_owned_graph(self):
        temp,back,front,digest,owner = self.fixture()
        try:
            cleanup.cleanup_owned(back, front, digest, owner, self.fstat_clear)
            self.assertFalse(back.exists());self.assertFalse(front.exists())
            self.assertEqual(cleanup.report['result'], 'PASS')
        finally:temp.cleanup()

    def test_missing_or_unexpected_birth_fields_refuse_before_deletion(self):
        for kwargs in ({'omit_birth':'packet_sha256'}, {'extra_birth':'frontend'}):
            with self.subTest(kwargs=kwargs):
                temp,back,front,digest,owner = self.fixture(**kwargs)
                try:
                    with self.assertRaises(RuntimeError):
                        cleanup.cleanup_owned(back, front, digest, owner, self.fstat_clear)
                    self.assertTrue(back.exists());self.assertTrue(front.exists())
                    self.assertTrue((back/'backend.py').exists())
                finally:temp.cleanup()

    def test_incomplete_effect_set_and_open_reference_refuse_before_deletion(self):
        temp,back,front,digest,owner = self.fixture(extra_leaf=True)
        try:
            with self.assertRaisesRegex(RuntimeError, 'exact_leaf_set'):
                cleanup.cleanup_owned(back, front, digest, owner, self.fstat_clear)
            self.assertTrue((front/'unowned').exists())
        finally:temp.cleanup()
        temp,back,front,digest,owner = self.fixture()
        try:
            uncertain = lambda *_args, **_kwargs: SimpleNamespace(returncode=1,
                stderr=b'', stdout=b'')
            with self.assertRaisesRegex(RuntimeError, 'fstat_result'):
                cleanup.cleanup_owned(back, front, digest, owner, uncertain)
            self.assertTrue((back/'backend.py').exists())
        finally:temp.cleanup()


if __name__ == '__main__':
    unittest.main(verbosity=2)
