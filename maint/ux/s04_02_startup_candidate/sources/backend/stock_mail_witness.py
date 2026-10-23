"""Read-only cache/config and disposable Bob mailbox-preservation witness.

Credential results belong to the actual Rust HTTP journey. This observer sends
no SMTP/IMAP requests, creates no mail storage and terminates no mail sessions.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

BOB = 'bob@osmap-password.invalid'
MAIN = '/etc/dovecot/dovecot.conf'


def require(value, code):
    if not value:
        raise RuntimeError(code)


def directory_path(value, code):
    """Accept directory suffix separators without changing traversal semantics."""
    require(value.startswith('/'), code + '_not_absolute')
    require('..' not in value.split('/'), code + '_parent_traversal')
    # The real mailbox.maildir fixture ends in '/', and the installed userdb
    # CONCAT projection preserves it. pathlib drops that directory suffix.
    # Trim only the suffix; other noncanonical spelling still refuses.
    value = value.rstrip('/') or '/'
    require(str(Path(value)) == value, code + '_noncanonical')
    return value


class StockMailWitness:
    def __init__(self, fixture, end):
        require(type(end) in (int, float) and math.isfinite(end) and end <= fixture.end
            and 3 < end - time.monotonic() <= 180, 'stock_mail_original_deadline')
        self.fixture, self.end = fixture, end
        self.before = None
        self.closed = False

    def projection(self):
        """Read the existing fixed userdb projection; require nonce-owned absence."""
        require(time.monotonic() < self.end, 'stock_mail_original_deadline')
        values = {}
        for field in ('home', 'mail', 'uid', 'gid'):
            raw = self.fixture.run(('/usr/local/bin/doveadm', 'user', '-f', field, BOB),
                'stock_bob_userdb_' + field, cap=4096, seconds=5, absolute=self.end)
            require((raw == b'' and field == 'mail') or raw.count(b'\n') == 1
                and raw.endswith(b'\n') and b'\0' not in raw, 'stock_bob_userdb_field')
            require(raw.isascii(), 'stock_bob_userdb_non_ascii')
            values[field] = raw.removesuffix(b'\n').decode('ascii')
        home = directory_path(values['home'], 'stock_bob_home')
        nonce = 'bob-' + self.fixture.lease
        require(nonce in Path(home).parts, 'stock_bob_nonce_home')
        mail = values['mail']
        if not mail:
            raw = self.fixture.run(('/usr/local/bin/doveconf', '-c', MAIN, '-h', 'mail_location'),
                'stock_bob_effective_mail_location', cap=4096, seconds=5, absolute=self.end)
            require(raw.count(b'\n') == 1 and raw.endswith(b'\n') and b'\0' not in raw,
                'stock_bob_mail_location')
            require(raw.isascii(), 'stock_bob_mail_location_non_ascii')
            mail = raw[:-1].decode('ascii')
        require(mail.startswith('maildir:') and ':' not in mail[8:], 'stock_bob_maildir_storage')
        mail = mail[8:]
        if mail == '~' or mail.startswith('~/'):
            mail = home + mail[1:]
        for key, value in {'%h': home, '%u': BOB, '%n': 'bob', '%d': 'osmap-password.invalid'}.items():
            mail = mail.replace(key, value)
        mail = directory_path(mail, 'stock_bob_mail')
        require('%' not in mail
            and Path(mail).is_relative_to(Path(home)) and nonce in Path(mail).parts
            and values['uid'].isdigit() and values['gid'].isdigit()
            and int(values['uid']) > 0 and int(values['gid']) > 0, 'stock_bob_maildir_projection')
        ancestors = []
        for path in reversed((Path(home), *Path(home).parents)):
            if os.path.lexists(path):
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o002,
                    'stock_bob_ancestor_custody')
                # Identity/permissions are stable authority; ancestor timestamps
                # can change when unrelated mail arrives and are not a prerequisite.
                ancestors.append((str(path), info.st_dev, info.st_ino,
                    info.st_uid, info.st_gid, info.st_mode))
        require(not os.path.lexists(home) and not os.path.lexists(mail), 'stock_bob_mail_must_be_absent')
        require(time.monotonic() < self.end, 'stock_mail_original_deadline')
        return {'home': home, 'mail': mail, 'uid': int(values['uid']),
            'gid': int(values['gid']), 'ancestors': ancestors}

    def public_state(self):
        actual = self.fixture.run(('/usr/local/bin/doveconf', '-c', MAIN, '-h', 'auth_cache_size'),
            'stock_actual_cache_policy', seconds=5, absolute=self.end)
        require(actual == b'0\n', 'stock_actual_cache_not_zero')
        self.fixture.original_config_current()
        require(self.fixture.master_row() == self.fixture.master, 'stock_public_master_changed')

    def begin(self):
        require(self.before is None and not self.closed, 'stock_mail_one_begin')
        self.public_state()
        self.before = self.projection()

    def finish_after_change(self):
        require(self.before is not None and not self.closed, 'stock_bob_absence_baseline')
        try:
            after = self.projection()
            require(after == self.before, 'stock_bob_projection_changed')
            self.public_state()
            digest = hashlib.sha256(json.dumps(after, sort_keys=True,
                separators=(',', ':')).encode('ascii')).hexdigest()
            return {'result': 'PASS', 'public_cache_zero': True,
                'public_original25_preserved': True, 'public_master_preserved': True,
                'bob_mail_projection_preserved': True, 'bob_home_absent': True,
                'bob_mail_absent': True, 'bob_projection_sha256': digest,
                'external_sessions_terminated': False, 'flush_performed': False}
        finally:
            self.close()

    def close(self):
        self.closed = True
