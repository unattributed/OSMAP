"""Local real witness/command-gate/consumer regression; no native qualification."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


witness = load('mail_witness_actual', 'sources/backend/stock_mail_witness.py')
front = load('mail_witness_consumer', 'sources/frontend/native_http_front_driver.py')


class LocalCommands:
    """Controlled utility replies; real witness validates local filesystem state."""
    def run(self, argv, label, **kwargs):
        self.commands.append(tuple(argv))
        witness.require(kwargs['absolute'] <= self.end, 'local_original_deadline')
        if argv[:3] == ('/usr/local/bin/doveadm', 'user', '-f'):
            return self.values[argv[3]]
        if argv[-1] == 'mail_location':
            return self.location
        if argv[-1] == 'auth_cache_size':
            return self.cache
        raise RuntimeError('unexpected_local_command')


# Execute the actual run() command-gate body in its real class shape, replacing
# only the host-custody subprocess adapter. Importing the full module requires
# root-owned source files and is inappropriate for this unprivileged regression.
path = ROOT / 'sources/backend/stock_qualification.py'
tree = ast.parse(path.read_text())
cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Qualification')
cls.body = [next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'run')]
namespace = {'base': SimpleNamespace(Fixture=LocalCommands, SQL=('local-sql',), HASH=('local-hash',)),
    'require': witness.require, 'MAIN': witness.MAIN, 'HELPER': Path('/local-helper'), 'ROLES': ()}
exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path), 'exec'), namespace)


class LocalFixture(namespace['Qualification']):
    def __init__(self, root):
        self.end = time.monotonic() + 120
        self.lease = '0123456789abcdef'
        self.home = root / ('bob-' + self.lease)
        self.values = {'home': (str(self.home) + '\n').encode(), 'mail': b'',
            'uid': b'1001\n', 'gid': b'1001\n'}
        self.location = b'maildir:~/Maildir\n'
        self.cache = b'0\n'
        self.master = ('local-master', 1)
        self.current_master = self.master
        self.config_preserved = True
        self.commands = []
        self.config_checks = 0

    def original_config_current(self):
        self.config_checks += 1
        witness.require(self.config_preserved, 'local_public_config_changed')

    def master_row(self):
        return self.current_master


class MailWitnessTests(unittest.TestCase):
    def setUp(self):
        # Production rejects world-writable ancestors; use a protected workspace
        # directory rather than weaken that check to accommodate /tmp.
        self.temp = tempfile.TemporaryDirectory(prefix='local-mail-witness-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.fixture = LocalFixture(Path(self.temp.name))
        self.observer = witness.StockMailWitness(self.fixture, self.fixture.end)

    def consume(self, value):
        driver = object.__new__(front.FrontDriver)
        driver.snapshot_index = 4
        driver.node = SimpleNamespace(exchange=lambda *args: {'phase': 'MAIL_WITNESS', 'result': value})
        driver.verify_mail_containment(self.fixture.end)

    def test_real_witness_output_through_actual_consumer_without_mail_creation(self):
        self.observer.begin()
        value = self.observer.finish_after_change()
        self.consume(value)
        self.assertTrue(self.observer.closed)
        self.assertEqual(self.fixture.config_checks, 2)
        self.assertEqual(len(self.fixture.commands), 12)
        self.assertFalse(self.fixture.home.exists())
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])
        self.assertNotIn(str(self.fixture.home), json.dumps(value))
        self.assertNotIn('old_password_refused', value)
        self.assertNotIn('bob_auth_preserved', value)
        self.assertEqual(len(value['bob_projection_sha256']), 64)

    def test_explicit_userdb_mail_avoids_fallback_query(self):
        self.fixture.values['mail'] = b'maildir:%h/Maildir\n'
        self.observer.begin()
        self.consume(self.observer.finish_after_change())
        self.assertEqual(len(self.fixture.commands), 10)
        self.assertFalse(any(argv[-1] == 'mail_location' for argv in self.fixture.commands))

    def test_preexisting_home_refuses_before_write(self):
        self.fixture.home.mkdir()
        with self.assertRaisesRegex(RuntimeError, '^stock_bob_mail_must_be_absent$'):
            self.observer.begin()
        self.assertIsNone(self.observer.before)

    def test_unsafe_ancestor_refuses(self):
        target = Path(self.temp.name) / 'actual'
        target.mkdir()
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        self.fixture.values['home'] = (str(alias / self.fixture.home.name) + '\n').encode()
        with self.assertRaisesRegex(RuntimeError, '^stock_bob_ancestor_custody$'):
            self.observer.begin()

    def test_invalid_projection_or_userdb_reply_refuses(self):
        original = self.fixture.values.copy()
        cases = [('home', b'/foreign/home\n', 'stock_bob_nonce_home'),
            ('uid', b'0\n', 'stock_bob_maildir_projection'),
            ('gid', b'1\n2\n', 'stock_bob_userdb_field'),
            ('mail', b'mbox:~/mail\n', 'stock_bob_maildir_storage'),
            ('mail', b'maildir:/foreign/mail\n', 'stock_bob_maildir_projection'),
            ('mail', b'maildir:%h/../elsewhere\n', 'stock_bob_maildir_projection')]
        for field, raw, code in cases:
            with self.subTest(field=field, raw=raw):
                self.fixture.values = {**original, field: raw}
                with self.assertRaisesRegex(RuntimeError, '^' + code + '$'):
                    self.observer.begin()

    def test_after_state_change_is_refused_and_observer_closed(self):
        for fault, code in [('created', 'stock_bob_mail_must_be_absent'),
                ('uid', 'stock_bob_projection_changed'), ('cache', 'stock_actual_cache_not_zero'),
                ('master', 'stock_public_master_changed'), ('config', 'local_public_config_changed')]:
            with self.subTest(fault=fault):
                fixture = LocalFixture(Path(self.temp.name))
                observer = witness.StockMailWitness(fixture, fixture.end)
                observer.begin()
                if fault == 'created': fixture.home.mkdir()
                if fault == 'uid': fixture.values['uid'] = b'1002\n'
                if fault == 'cache': fixture.cache = b'1024\n'
                if fault == 'master': fixture.current_master = ('different-master', 2)
                if fault == 'config': fixture.config_preserved = False
                with self.assertRaisesRegex(RuntimeError, '^' + code + '$'):
                    observer.finish_after_change()
                self.assertTrue(observer.closed)
                if fault == 'created': fixture.home.rmdir()

    def test_fixed_command_gate_refuses_other_accounts_fields_and_mutations(self):
        for argv in [('/usr/local/bin/doveadm', 'user', '-f', 'home', 'operator@example.org'),
                ('/usr/local/bin/doveadm', 'user', '-f', 'password', witness.BOB),
                ('/usr/local/bin/doveadm', 'auth', 'cache', 'flush', witness.BOB),
                ('/usr/local/bin/doveconf', '-c', witness.MAIN, '-h', 'listen')]:
            with self.subTest(argv=argv), self.assertRaisesRegex(RuntimeError, '^stock_fixed_command_only$'):
                self.fixture.run(argv, 'local_negative')
        self.assertEqual(self.fixture.commands, [])

    def test_consumer_rejects_missing_preservation_and_invented_credential_claim(self):
        self.observer.begin()
        value = self.observer.finish_after_change()
        for key in ('bob_home_absent', 'bob_mail_absent', 'bob_mail_projection_preserved', 'public_cache_zero'):
            changed = copy.deepcopy(value)
            changed[key] = False
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.consume(changed)
        with self.assertRaises(RuntimeError):
            self.consume({**value, 'old_password_refused': True})


if __name__ == '__main__':
    unittest.main()
