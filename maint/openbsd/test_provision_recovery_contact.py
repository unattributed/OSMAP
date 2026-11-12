"""Focused private publication and refusal contracts, with no host dispatch."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'provision_recovery_contact', Path(__file__).with_name('provision-recovery-contact.py'))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class PublicationTests(unittest.TestCase):
    def test_actual_publication_is_private_and_existing_state_is_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'record'
            data = provision.epoch_record()
            receipt = provision.exclusive(path, data, os.getuid(), os.getgid())
            self.assertEqual(receipt['inode'], path.stat().st_ino)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_bytes())['state'], 'active')
            with self.assertRaises(FileExistsError):
                provision.exclusive(path, b'changed', os.getuid(), os.getgid())
            self.assertEqual(path.read_bytes(), data)

    def test_symlink_is_refused_before_target_write(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / 'target'
            target.write_bytes(b'preserved')
            link = Path(name) / 'link'
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                provision.exclusive(link, b'changed', os.getuid(), os.getgid())
            self.assertEqual(target.read_bytes(), b'preserved')

    def test_same_bytes_substituted_inode_refuses_and_keeps_birth_identity(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'record'
            journal = []
            original_seek = os.lseek
            def substitute(fd, offset, whence):
                path.unlink()
                path.write_bytes(b'private')
                path.chmod(0o600)
                return original_seek(fd, offset, whence)
            with patch.object(provision.os, 'lseek', side_effect=substitute):
                with self.assertRaises(provision.Refused):
                    provision.exclusive(path, b'private', os.getuid(), os.getgid(),
                                        journal=journal)
            self.assertNotEqual(journal[0]['inode'], path.stat().st_ino)
            self.assertEqual(journal[0]['state'], 'FILE_BORN_UNVERIFIED')
            self.assertEqual(path.read_bytes(), b'private')

    def test_directory_substitution_cannot_change_foreign_permissions(self):
        with tempfile.TemporaryDirectory() as name:
            path, foreign = Path(name) / 'directory', Path(name) / 'foreign'
            foreign.mkdir(mode=0o755)
            original_mkdir = os.mkdir
            def substitute(path_arg, mode):
                original_mkdir(path_arg, mode)
                Path(path_arg).rename(Path(name) / 'born-retained')
                Path(path_arg).symlink_to(foreign)
            journal = []
            with patch.object(provision.os, 'mkdir', side_effect=substitute):
                with self.assertRaises(OSError):
                    provision.directory(path, os.getuid(), os.getgid(), 0o700, journal)
            self.assertEqual(foreign.stat().st_mode & 0o777, 0o755)
            self.assertEqual(journal[0]['state'], 'DIRECTORY_CREATION_ATTEMPTED')

    def test_partial_birth_is_retained_before_permission_failure(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'record'
            journal = []
            with patch.object(provision.os, 'fchown', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    provision.exclusive(path, b'private', journal=journal)
            self.assertEqual(journal[0]['inode'], path.stat().st_ino)
            self.assertEqual(journal[0]['state'], 'FILE_BORN_UNVERIFIED')
            directory = Path(name) / 'directory'
            journal = []
            with patch.object(provision.os, 'fchown', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    provision.directory(directory, os.getuid(), os.getgid(), 0o700, journal)
            self.assertEqual(journal[0]['inode'], directory.stat().st_ino)

    def test_real_failure_output_is_structured_without_exception_text(self):
        out = io.StringIO()
        with patch('sys.argv', ['provision', '--expected-host', 'foreign.invalid',
                                '--account', 'foreign@example.test']), contextlib.redirect_stdout(out):
            result = provision.main()
        receipt = json.loads(out.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(receipt['code'], 'TARGET_REFUSED')
        self.assertEqual(receipt['created'], [])
        self.assertNotIn('Traceback', out.getvalue())


if __name__ == '__main__':
    unittest.main()
