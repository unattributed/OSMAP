"""Portable configuration/lock regressions; no Dovecot or auth is invoked."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from account_epoch import EpochStore
from authoritative_password import Refused
from dovecot_auth_epoch import EpochPolicyFence
import dovecot_primary_auth_config as config


PUBLIC = b"""auth_policy_server_url = http://127.0.0.1:10058/epoch/
auth_policy_check_before_auth = yes
auth_policy_check_after_auth = yes
auth_cache_size = 1M
passdb {
  driver = sql
  args = /private/fixture/sql-passdb.conf
}
userdb {
  driver = static
  args = uid=1000 gid=1000
}
service auth {
  user = root
  group = wheel
}
service auth-worker {
  user = root
  group = wheel
}
"""


class PrivatePrimaryConfigTests(unittest.TestCase):
    def test_private_service_is_separate_and_public_bytes_are_preserved(self):
        rendered = config.add_private_primary_auth(PUBLIC)
        self.assertTrue(rendered.startswith(PUBLIC + b"\n"))
        private = rendered[len(PUBLIC) + 1:]
        self.assertEqual(private.count(b"service osmap-primary-auth {\n"), 1)
        self.assertIn(b"  executable = auth -o auth_policy_server_url= -o auth_cache_size=0\n", private)
        self.assertEqual(private.count(b"unix_listener "), 1)
        self.assertIn(b"  unix_listener /var/dovecot/osmap-account-auth-client {\n", private)
        self.assertIn(b"    mode = 0660\n    user = _dovecot\n    group = _osmapprimary\n", private)
        for unexpected in (b"inet_listener", b"passdb {", b"userdb {", b"service auth {", b"service auth-worker {"):
            self.assertNotIn(unexpected, private)

    def test_existing_private_authority_or_includes_are_refused(self):
        for body in (PUBLIC + b"# /var/dovecot/osmap-account-auth-client\n",
                     PUBLIC + b"unix_listener osmap-account-auth-client {\n}\n",
                     PUBLIC + b"service osmap-primary-auth {\n}\n",
                     PUBLIC + b"!include other.conf\n",
                     PUBLIC + b"service auth {\n}\n",
                     PUBLIC + b" " * (16384 - len(PUBLIC)),
                     PUBLIC.replace(b"service auth-worker {\n", b"service other {\n")):
            with self.subTest(body=body):
                with self.assertRaises(Refused):config.add_private_primary_auth(body)

    def test_template_cannot_change_executable_or_expose_another_listener(self):
        raw = Path(config.__file__).with_name("dovecot-private-primary.conf").read_bytes()
        for changed in (raw.replace(b" -o auth_policy_server_url=", b""),
                        raw.replace(b" -o auth_cache_size=0", b""),
                        raw + b"inet_listener public {\n  port = 12345\n}\n"):
            with self.subTest(changed=changed), patch.object(Path, "read_bytes", return_value=changed):
                with self.assertRaises(Refused):config.add_private_primary_auth(PUBLIC)

    def test_nonempty_session_alone_cannot_reenter_the_primary_lock(self):
        with tempfile.TemporaryDirectory(prefix="osmap-private-policy-") as scratch:
            root = Path(scratch);root.chmod(0o700)
            store = EpochStore(root, expected_uid=os.getuid())
            account = "alice@fixture.invalid";store.provision(account)
            fence = EpochPolicyFence(store, frozenset((account,)))
            def body(session):
                return json.dumps(dict(login=account, protocol="imap", session_id=session,
                                       phase="before", tls=False)).encode()
            before = {p.name:p.read_bytes() for p in root.glob("*.json")}
            self.assertEqual(fence.allow(body("Unlocked001")), fence.ALLOW)
            with store.locked(account):
                self.assertEqual(fence.allow(body("HeldLock001")), fence.DENY)
            self.assertEqual(fence.allow(body("Released001")), fence.ALLOW)
            self.assertEqual(before, {p.name:p.read_bytes() for p in root.glob("*.json")})


if __name__ == "__main__":unittest.main()
