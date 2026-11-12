"""Exercise the real rc startup functions with local OpenBSD utility projections.

This does not qualify native rc.subr or replace the recorded OpenBSD startup test.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parent / 'rc.d/osmap_account_password'
PRIMITIVES = '''import os, pathlib, stat, sys
kind, *args = sys.argv[1:]
if kind == 'id':
    print(os.environ.get('RC_TEST_UID', '0'))
elif kind == 'install':
    if args[:-1] != ['-d', '-o', 'root', '-g', 'osmapgpg', '-m', '0750']:
        sys.exit(2)
    p = pathlib.Path(args[-1])
    p.mkdir()
    p.chmod(0o750)
elif kind == 'stat':
    if args[:2] != ['-f', '%u:%Sg:%p']:
        sys.exit(2)
    mode = pathlib.Path(args[-1]).lstat().st_mode
    print(os.environ.get('RC_TEST_OWNER', '0') + ':' +
          os.environ.get('RC_TEST_GROUP', 'osmapgpg') + ':' + format(mode, 'o'))
else:
    sys.exit(2)
'''


@unittest.skipUnless(shutil.which('ksh'), 'ksh is required for the actual rc functions')
class AccountPasswordRcTests(unittest.TestCase):
    def exercise(self, setup=None, env=None):
        with tempfile.TemporaryDirectory(prefix='osmap-rc-test-') as directory:
            root = Path(directory)
            paths = [root / 'admission', root / 'mutation']
            if setup:
                setup(paths)
            before = {}
            for path in root.rglob('*'):
                before[path] = (path.lstat().st_ino, path.lstat().st_mode,
                    os.readlink(path) if path.is_symlink() else
                    path.read_bytes() if path.is_file() else None)
            primitive = root / 'primitive.py'
            primitive.write_text(PRIMITIVES)
            source = SCRIPT.read_text()
            runtime = source.split('rc_prepare_runtime() {', 1)[1].split('\nrc_prepare_log() {', 1)[0]
            runtime = 'rc_prepare_runtime() {' + runtime
            for old, new in zip(['/var/run/osmap-account-admission', '/var/run/osmap-account-mutation'], paths):
                runtime = runtime.replace(old, str(new))
            for name in ['id', 'install', 'stat']:
                runtime = runtime.replace('/usr/bin/' + name,
                    shlex.quote(sys.executable) + ' ' + shlex.quote(str(primitive)) + ' ' + name)
            start = 'rc_start() {' + source.split('rc_start() {', 1)[1].split('\nrc_check() {', 1)[0]
            launch = root / 'launched'
            program = runtime + '\n' + start + '\n' + '''
rc_configtest() { return 0; }
rc_prepare_log() { return 0; }
rc_exec() { : > "$RC_TEST_LAUNCH"; }
rc_start
'''
            result = subprocess.run(['ksh'], input=program, text=True, capture_output=True,
                env={**os.environ, 'RC_TEST_LAUNCH': str(launch), **(env or {})}, timeout=10)
            state = [(p.is_dir(), p.is_symlink(), p.lstat().st_mode & 0o7777 if p.exists() else None)
                     for p in paths]
            for path, expected in before.items():
                self.assertEqual((path.lstat().st_ino, path.lstat().st_mode,
                    os.readlink(path) if path.is_symlink() else
                    path.read_bytes() if path.is_file() else None), expected)
            return result, launch.exists(), state

    def test_missing_and_correct_existing_directories(self):
        def existing(paths):
            for path in paths:
                path.mkdir(mode=0o750)
                (path / 'preserved').write_text('unchanged')
        for setup in [None, existing]:
            with self.subTest(existing=setup is not None):
                result, launched, state = self.exercise(setup)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(launched)
                self.assertEqual(state, [(True, False, 0o750)] * 2)

    def test_unsafe_directory_types_and_permissions_refuse_launch(self):
        for index in [0, 1]:
            for kind in ['file', 'symlink', 'dangling', 'mode']:
                def setup(paths, index=index, kind=kind):
                    if kind == 'file':
                        paths[index].write_text('preserved')
                    elif kind in ['symlink', 'dangling']:
                        target = paths[index].parent / 'target'
                        if kind == 'symlink':
                            target.mkdir()
                        paths[index].symlink_to(target)
                    else:
                        paths[index].mkdir(mode=0o777)
                        paths[index].chmod(0o777)
                with self.subTest(index=index, kind=kind):
                    result, launched, _ = self.exercise(setup)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(launched)
                    self.assertIn('PRIVATE_RUNTIME_CUSTODY_REFUSED', result.stderr)

    def test_wrong_or_unresolved_identity_refuses_launch(self):
        for env in [{'RC_TEST_UID': '1001'}, {'RC_TEST_OWNER': '1001'},
                    {'RC_TEST_GROUP': 'wheel'}, {'RC_TEST_GROUP': '4099'}]:
            with self.subTest(env=env):
                result, launched, _ = self.exercise(env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(launched)

    def test_group_is_checked_by_name_without_fixed_numeric_id(self):
        source = SCRIPT.read_text()
        self.assertIn("'%u:%Sg:%p'", source)
        self.assertNotIn('0:1003:40750', source)
        result, launched, _ = self.exercise(env={'RC_TEST_GROUP': 'osmapgpg'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(launched)


if __name__ == '__main__':
    unittest.main()
