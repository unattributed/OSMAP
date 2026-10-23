"""Existing finite HTTP journey adapted to the current Rust account helper.

No process/service provisioner or executable entry. The existing root custodian
owns actual paired services, network transport, protected snapshot reads and
owned cleanup. Missing custodian wiring is NOT RUN, never a fabricated PASS.
"""
import hashlib
import json
from datetime import datetime
from pathlib import Path
import re
import secrets
import time

ALICE = 'alice@osmap-password.invalid'
BOB = 'bob@osmap-password.invalid'
ACCOUNTS = (ALICE, BOB)
COLUMNS = ('username', 'password', 'name', 'maildir', 'quota', 'local_part',
    'domain', 'created', 'modified', 'active', 'phone', 'email_other',
    'token', 'token_validity', 'password_expiry', 'totp_secret', 'smtp_active')
# Exactly15 immutable columns. modified is the database's legitimate write
# timestamp; password is the sole credential being changed.
NONCREDENTIAL_COLUMNS = tuple(name for name in COLUMNS if name not in ('password', 'modified'))
CONNECTIONS = 18
SNAPSHOT_FIELDS = {'account', 'row_count', 'row_sha256', 'noncredential_sha256',
    'password_sha256', 'epoch', 'state', 'changed_at', 'sql_changed_at'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_state_field')
        value[key] = item
    return value


def stamp(value):
    require(type(value) is str, 'timestamp_type')
    try:
        if re.fullmatch('[0-9]{14}', value):
            return datetime.strptime(value, '%Y%m%d%H%M%S').strftime('%Y%m%d%H%M%S')
        require(re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}', value),
            'timestamp_shape')
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').strftime('%Y%m%d%H%M%S')
    except ValueError:
        raise ValueError('timestamp_calendar') from None


def digest_fields(row, fields):
    require(type(row) is dict and set(row) == set(COLUMNS)
        and all(value is None or type(value) in (str, int) for value in row.values()), 'SQL_exact17_shape')
    raw = json.dumps([row[name] for name in fields], ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def file_identity(metadata):
    # Exact existing native custodian tuple, required by its full17 CAS cleanup.
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


class RustAuthoritativeCustodian:
    """Mixin for the EXISTING native Qualification, not a process/SQL runner.

    Place this before the preserved Qualification in its MRO. The inherited
    actual row_read/private_read/remaining methods are the only data producers.
    Its existing cleanup calls this inspect_state, then performs the same full17
    compare-and-delete and owned files/principals cleanup. No rollback is added.
    """
    def prepare_rust_journey(self):
        require(type(self.passwords) is list and len(self.passwords) == 2
            and all(type(value) is str and re.fullmatch('[a-f0-9]{64}', value)
                for value in self.passwords), 'actual_private_fixture_credentials')
        self.new_password = secrets.token_hex(32)

    def initial_password(self, account):
        require(account in ACCOUNTS, 'fixed_fixture_account')
        return self.passwords[ACCOUNTS.index(account)]

    def rust_rows(self, cleanup=False):
        rows = self.row_read(cleanup=cleanup)
        require(type(rows) is list and len(rows) == 2
            and tuple(row.get('username') for row in rows) == ACCOUNTS
            and all(set(row) == set(COLUMNS) for row in rows), 'actual_reserved_SQL17_rows')
        return rows

    def rust_epoch(self, account):
        require(account in ACCOUNTS, 'fixed_fixture_epoch_account')
        stem = hashlib.sha256(b'osmap-account-epoch-v1\0' + account.encode('ascii')).hexdigest()
        path = Path('/var/db/osmap-account/epoch') / (stem + '.json')
        record = json.loads(self.private_read(path, 4096), object_pairs_hook=unique)
        require(type(record) is dict and set(record) == {'epoch', 'state', 'changed_at', 'intent', 'used_intents'}
            and type(record['epoch']) is int and record['epoch'] in (0, 1)
            and record['state'] in ('active', 'pending', 'contained')
            and type(record['used_intents']) is list and len(record['used_intents']) <= 64,
            'actual_fixed_epoch_shape')
        if record['changed_at'] is not None:
            stamp(record['changed_at'])
        intents = record['used_intents']
        require(all(type(item) is list and len(item) == 2 and type(item[0]) is str
            and re.fullmatch('[a-f0-9]{64}', item[0]) and type(item[1]) is int and item[1] >= 0
            for item in intents) and len({item[0] for item in intents}) == len(intents), 'actual_used_intents')
        require(record['intent'] is None or type(record['intent']) is str
            and re.fullmatch('[a-f0-9]{64}', record['intent'])
            and record['intent'] in {item[0] for item in intents}, 'actual_pending_intent')
        return record, path

    def authoritative_snapshot(self, account, deadline, *, cleanup=False):
        # The caller's deadline remains the one fixed sequence deadline; no
        # alternate paths/accounts/query or caller-supplied observations enter.
        import time
        require(time.monotonic() < deadline, 'snapshot_original_deadline')
        self.remaining(True)
        rows = self.rust_rows(cleanup=cleanup)
        require(account in ACCOUNTS, 'fixed_snapshot_account')
        row = rows[ACCOUNTS.index(account)]
        epoch, _ = self.rust_epoch(account)
        require(time.monotonic() < deadline, 'snapshot_late')
        return snapshot({'account': account, 'row_count': 1,
            'row_sha256': digest_fields(row, COLUMNS),
            'noncredential_sha256': digest_fields(row, NONCREDENTIAL_COLUMNS),
            'password_sha256': hashlib.sha256(row['password'].encode('utf-8')).hexdigest(),
            'epoch': epoch['epoch'], 'state': epoch['state'], 'changed_at': epoch['changed_at'],
            'sql_changed_at': stamp(row['modified'])}, account)

    def inspect_state(self, *, after_test):
        # Existing cleanup must first establish stopped helper/owned groups.
        # Keep current rows for its exact full17 DELETE; never restore passwords.
        current = self.rust_rows(cleanup=True)
        require(type(self.baseline) is list and len(self.baseline) == 2
            and current[1] == self.baseline[1], 'Bob_all17_preserved')
        require(all(current[0][name] == self.baseline[0][name] for name in NONCREDENTIAL_COLUMNS),
            'Alice_exact15_preserved')
        changed = current[0]['password'] != self.baseline[0]['password']
        state_files = []
        alice_epoch = None
        for account in ACCOUNTS:
            record, path = self.rust_epoch(account)
            if account == BOB:
                require(record == {'epoch': 0, 'state': 'active', 'changed_at': None,
                    'intent': None, 'used_intents': []}, 'Bob_epoch_preserved')
            else:
                alice_epoch = record
                if changed:
                    require(record['state'] in ('pending', 'contained') and record['epoch'] == 0
                        or record['state'] == 'active' and record['epoch'] == 1, 'Alice_changed_epoch')
                    require(record['changed_at'] is None or stamp(record['changed_at']) == stamp(current[0]['modified']),
                        'Alice_known_time_matches_SQL')
                else:
                    require(current[0] == self.baseline[0], 'Alice_no_write_exact17')
                    require(record['epoch'] == 0 and record['changed_at'] is None
                        and (record['state'] != 'active' or record['intent'] is None),
                        'Alice_no_write_epoch')
                if after_test:
                    require(changed and record['state'] == 'active' and record['epoch'] == 1
                        and record['intent'] is None and stamp(record['changed_at']) == stamp(current[0]['modified']),
                        'confirmed_Rust_journey_outcome')
            state_files.append((path, file_identity(path.lstat())))
            marker = path.with_suffix('.uncertain')
            if marker.exists() or marker.is_symlink():
                require(account == ALICE and record['intent'] is not None
                    and self.private_read(marker, 256) == ('osmap-password-uncertain-v1\n'
                        + record['intent'] + '\n').encode('ascii'), 'actual_owned_uncertainty_marker')
                state_files.append((marker, file_identity(marker.lstat())))
        self.report.update(actual_write_observed=changed, Alice_epoch=alice_epoch['epoch'],
            Alice_state=alice_epoch['state'], Bob_all17_preserved=True, Alice_exact15_preserved=True)
        return current, state_files


def snapshot(value, account):
    """Closed metadata consumer; values come from actual fixed root reads.

    Hashes cover the exact17 SQL row and exact15 unchanged columns;
    neither reusable verifiers nor plaintext enter this consumer/report.
    This validates shape, not the truth of the root producer's observations.
    """
    require(type(value) is dict and set(value) == SNAPSHOT_FIELDS, 'snapshot_fields')
    require(value['account'] == account and type(value['row_count']) is int
        and value['row_count'] == 1, 'snapshot_account_or_row_count')
    require(all(type(value[name]) is str and re.fullmatch('[a-f0-9]{64}', value[name])
        for name in ('row_sha256', 'noncredential_sha256', 'password_sha256')),
        'snapshot_digest')
    require(type(value['epoch']) is int and value['epoch'] >= 0
        and value['state'] in ('active', 'pending', 'contained'), 'snapshot_authority')
    require(value['changed_at'] is None or type(value['changed_at']) is str
        and re.fullmatch('[0-9]{14}', value['changed_at']), 'snapshot_write_time')
    require(type(value['sql_changed_at']) is str and re.fullmatch('[0-9]{14}', value['sql_changed_at']),
        'snapshot_sql_time')
    stamp(value['sql_changed_at'])
    if value['changed_at'] is not None:
        stamp(value['changed_at'])
    return value


def confirmed_change(before, after, bob_before, bob_after):
    before, after = snapshot(before, ALICE), snapshot(after, ALICE)
    bob_before, bob_after = snapshot(bob_before, BOB), snapshot(bob_after, BOB)
    require(before['state'] == 'active' and before['epoch'] == 0
        and before['changed_at'] is None, 'initial_alice_state')
    require(after['state'] == 'active' and after['epoch'] == 1
        and after['changed_at'] is not None and after['changed_at'] == after['sql_changed_at']
        and after['sql_changed_at'] != before['sql_changed_at'], 'confirmed_alice_state')
    require(after['password_sha256'] != before['password_sha256']
        and after['row_sha256'] != before['row_sha256']
        and after['noncredential_sha256'] == before['noncredential_sha256'], 'confirmed_alice_preservation')
    require(bob_after == bob_before and bob_after['state'] == 'active'
        and bob_after['epoch'] == 0, 'bob_preservation')
    return after['changed_at']


def prewrite_refusal(before, after, writes_before, writes_after):
    """T04 observer consumer: actual replay/race producer remains root-owned."""
    before, after = snapshot(before, ALICE), snapshot(after, ALICE)
    require(type(writes_before) is int and type(writes_after) is int
        and 0 <= writes_before == writes_after, 'refusal_dispatched_sql')
    require(before == after, 'refusal_changed_account')


def postwrite_incomplete(before, after, bob_before, bob_after, witness):
    """T05 metadata consumer for one actual write and no automatic repeat.

    Lost terminal delivery can leave backend Active1 after successful effects;
    do not falsely report backend Contained when only the frontend quarantined.
    """
    before, after = snapshot(before, ALICE), snapshot(after, ALICE)
    require(snapshot(bob_before, BOB) == snapshot(bob_after, BOB), 'incomplete_bob_changed')
    require(type(witness) is dict and set(witness) == {'sql_writes', 'old_cookie_status',
        'repeat_sql_writes', 'credential_rollback', 'ui_incomplete', 'client_quarantined'},
        'incomplete_witness_fields')
    require(type(witness['sql_writes']) is int and witness['sql_writes'] == 1
        and type(witness['repeat_sql_writes']) is int and witness['repeat_sql_writes'] == 0
        and witness['old_cookie_status'] == 303 and witness['credential_rollback'] is False
        and witness['ui_incomplete'] is True and witness['client_quarantined'] is True,
        'incomplete_effects')
    require(after['password_sha256'] != before['password_sha256']
        and after['noncredential_sha256'] == before['noncredential_sha256']
        and after['changed_at'] is not None and after['changed_at'] == after['sql_changed_at']
        and ((after['state'] == 'active' and after['epoch'] == 1)
            or (after['state'] == 'contained' and after['epoch'] == 0)), 'incomplete_authoritative_state')
    return {'authoritative_state': after['state'], 'authoritative_epoch': after['epoch'],
        'known_write_time': after['changed_at']}


def journey(driver):
    """Run the preserved 18-request journey through root's actual transport.

    Existing request/login/settings_history/browser_record methods remain the
    finite HTTP consumers. authoritative_snapshot performs a fresh fixed backend
    read; finish_http consumes the original born HTTP report and process exit.
    No Python account worker, broker store or substituted mutation is invoked.
    """
    driver.mutation_submission_started = False
    driver.mutation_requests = 0
    driver.milestone_timings = {name: 0.0 for name in ('authentication_seconds',
        'totp_wait_seconds', 'mutation_seconds', 'authoritative_verification_seconds')}

    def timed(name, operation, *args, **kwargs):
        started = time.monotonic()
        try:
            return operation(*args, **kwargs)
        finally:
            driver.milestone_timings[name] += time.monotonic() - started

    def counter(minimum=0):
        return timed('totp_wait_seconds', driver.accepted_counter, end, minimum=minimum)

    def login(account, password, step):
        return timed('authentication_seconds', driver.login, account, password, step, end)

    def observe(account):
        return snapshot(timed('authoritative_verification_seconds',
            driver.authoritative_snapshot, account, end), account)

    def session_hash(record):
        return hashlib.sha256(record['session_id'].encode('ascii')).hexdigest()

    end = driver.sequence_end
    current_alice, current_bob = driver.initial_password(ALICE), driver.initial_password(BOB)
    new_password = driver.new_password
    require(all(type(value) is str and 15 <= len(value) <= 128
        for value in (current_alice, current_bob, new_password)), 'actual_runtime_credentials')
    require(driver.request('GET', '/login', end)[0] == 200, 'login_page')
    bob_counter = counter()
    bob_cookie = driver.session_cookie(login(BOB, current_bob, bob_counter))
    bob, _ = driver.browser_record(bob_cookie)
    require(driver.replay_counter(BOB) == bob_counter, 'bob_login_counter')
    bob_state = observe(BOB)
    initial = counter()
    alice_cookie = driver.session_cookie(login(ALICE, current_alice, initial))
    alice, _ = driver.browser_record(alice_cookie)
    require(driver.replay_counter(ALICE) == initial, 'alice_login_counter')
    other_counter = counter(initial + 1)
    other_cookie = driver.session_cookie(login(ALICE, current_alice, other_counter))
    other_alice, _ = driver.browser_record(other_cookie)
    require(driver.replay_counter(ALICE) == other_counter, 'other_alice_login_counter')
    require(other_cookie != alice_cookie and other_alice['session_id'] != alice['session_id'],
        'distinct_alice_sessions')
    before = observe(ALICE)
    now = int(time.time())
    for session, account in ((alice, ALICE), (other_alice, ALICE), (bob, BOB)):
        require(session['canonical_username'] == account and session['account_epoch'] == '0'
            and session['factor'] == 'totp' and session['revoked_at'] == ''
            and session['issued_at'].isdigit() and session['expires_at'].isdigit()
            and int(session['issued_at']) <= now < int(session['expires_at']), 'stored_login_epochs')
    driver.settings_history(alice_cookie, None, end)
    page = driver.request('GET', '/settings/password', end, cookie=alice_cookie)
    require(page[0] == 200 and b'id="password-change-form"' in page[2]
        and b'<fieldset disabled>' not in page[2], 'enabled_password_form')
    csrf = re.findall(rb'name="csrf_token" value="([a-f0-9]{64})"', page[2])
    require(csrf and len(set(csrf)) == 1 and csrf[0].decode('ascii') == alice['csrf_token'], 'stored_csrf')
    _, bob_bytes = driver.browser_record(bob_cookie)
    stepup = counter(other_counter + 1)
    # Submission uncertainty is irreversible: the custodian must retain owned
    # state on any later failure, even if no authenticated response arrives.
    driver.mutation_submission_started = True
    driver.mutation_requests = 1
    checkpoint = getattr(driver, 'mutation_submission_checkpoint', None)
    if checkpoint is not None:
        checkpoint()
    changed = timed('mutation_seconds', driver.request, 'POST', '/settings/password', end, cookie=alice_cookie,
        form={'csrf_token': alice['csrf_token'], 'current_password': current_alice,
            'new_password': new_password, 'confirmation': new_password, 'totp_code': driver.code(stepup)})
    require(changed[0] == 200 and b'Your password was changed' in changed[2]
        and any(name == 'set-cookie' and value.startswith('osmap_session=') and 'Max-Age=0' in value
            for name, value in changed[1]), 'confirmed_http_and_cookie')
    require(driver.replay_counter(ALICE) == stepup and driver.replay_counter(BOB) == bob_counter,
        'stepup_counter_and_bob')
    after = observe(ALICE)
    bob_after = observe(BOB)
    stamp = confirmed_change(before, after, bob_state, bob_after)
    revoked, _ = driver.browser_record(alice_cookie)
    other_revoked, _ = driver.browser_record(other_cookie)
    _, same_bob = driver.browser_record(bob_cookie)
    require(revoked['revoked_at'].isdigit() and revoked['account_epoch'] == '0'
        and other_revoked['revoked_at'].isdigit() and other_revoked['account_epoch'] == '0'
        and same_bob == bob_bytes, 'browser_containment_and_bob')
    for cookie in (alice_cookie, other_cookie):
        denied = driver.request('GET', '/settings/password', end, cookie=cookie)
        require(denied[0] == 303 and ('location', '/login') in denied[1], 'old_cookie')
    # Use an unused factor so a rejected login discriminates the old password
    # from a factor replay. A password rejection must leave this code available
    # for the immediately following successful new-password login.
    fresh = counter(stepup + 1)
    old_login = login(ALICE, current_alice, fresh)
    require(old_login[0] == 401 and not any(name == 'set-cookie' and value.startswith('osmap_session=')
        for name, value in old_login[1]) and driver.replay_counter(ALICE) == stepup, 'old_password')
    new_cookie = driver.session_cookie(login(ALICE, new_password, fresh))
    new_alice, _ = driver.browser_record(new_cookie)
    require(new_alice['canonical_username'] == ALICE and new_alice['account_epoch'] == '1'
        and new_alice['revoked_at'] == '', 'new_password_epoch')
    require(driver.replay_counter(ALICE) == fresh and driver.replay_counter(BOB) == bob_counter,
        'new_login_counter_and_bob')
    require(driver.request('GET', '/settings/password', end, cookie=new_cookie)[0] == 200, 'fresh_form')
    driver.settings_history(new_cookie, stamp, end)
    require(driver.request('GET', '/settings/password', end, cookie=bob_cookie)[0] == 200, 'bob_cookie')
    driver.settings_history(bob_cookie, None, end)
    bob_final, _ = driver.browser_record(bob_cookie)
    require({k: v for k, v in bob.items() if k != 'last_seen_at'}
        == {k: v for k, v in bob_final.items() if k != 'last_seen_at'}, 'bob_final_session')
    # Existing guardian validates18 HTTP requests, actual stale/current epoch
    # probes and born process exit. Real authoritative old/new/Bob/cache0 witnesses stay mandatory; existing external sessions are not terminated.
    driver.finish_http(end, CONNECTIONS)
    driver.verify_mail_containment(end)
    return {'observed_http_requests': CONNECTIONS, 'known_write_time': stamp,
        'timings': driver.milestone_timings.copy(),
        'mutation_evidence': {
            'mutation_requests': driver.mutation_requests,
            'old_password_refused': True, 'new_password_admitted': True,
            'bob_account_preserved': True,
            'alice_sessions': [{'session_id_sha256': session_hash(record), 'initial_epoch': 0,
                'revoked': True, 'old_cookie_status': 303} for record in (alice, other_alice)],
            'bob_session': {'session_id_sha256': session_hash(bob), 'epoch': 0, 'preserved': True},
            'new_alice_session': {'session_id_sha256': session_hash(new_alice), 'epoch': 1},
            'terminal_response_confirmed': True},
        'qualification': 'PENDING_ROOT_OWNED_DISPOSITION_AND_INDEPENDENT_REVIEW'}
