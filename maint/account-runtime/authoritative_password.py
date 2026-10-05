"""Narrow authoritative mailbox password adapter, never a browser/admin CLI.

Callers must supply canonical own-account authority after current-password/TOTP
step-up and hold the shared account lock. Enabling this adapter also requires a
qualified auth-epoch and browser/IMAP/SMTP containment coordinator. This module
never claims that a database write revokes existing authenticated connections.
"""
from dataclasses import dataclass
from datetime import datetime
import re


class Refused(Exception):
    """A pre-write refusal; the authoritative password was not changed."""


class Unconfirmed(Exception):
    """Dispatch began; inspect/contain the account, never retry automatically."""


@dataclass(frozen=True, repr=False)
class Snapshot:
    account: str
    password_hash: str
    modified: str
    smtp_active: bool


@dataclass(frozen=True)
class Receipt:
    changed_at: str
    credential_written: bool = True
    sessions_revoked: bool = False


class AuthoritativePasswordAdapter:
    """Fixed-program, stdin-only adapter for qualified postfixadmin mailbox SQL.

    The executor is the helper's bounded private process executor, not a web
    caller or executable string. Client configuration is a fixed administrator
    provisioned file; it must contain only the helper's narrowly scoped DB grant.
    Its existence/ownership and native confinement are admission prerequisites.
    """
    SQL_PROGRAM = '/usr/local/bin/mariadb'
    HASH_PROGRAM = '/usr/local/bin/doveadm'
    SQL_ARGS = ('--defaults-file=/etc/osmap/account-mariadb.cnf', '-N', '-B',
                '--raw', '--database=postfixadmin')
    HASH_ARGS = ('pw', '-s', 'ARGON2ID')
    LIMIT_SECONDS = 10
    OUTPUT_LIMIT = 4096

    ARGON2_PATTERN = r'\{ARGON2ID\}\$argon2id\$v=19\$m=65536,t=3,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}'
    BLF_PATTERN = r'\{BLF-CRYPT\}\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'

    def __init__(self, executor, *, before_write=None):
        if before_write is not None and not callable(before_write):
            raise Refused('credential write admission unavailable')
        self._execute = executor
        self._before_write = before_write

    @staticmethod
    def _account(value):
        # Deliberately narrow exact canonical addresses, never SQL/name syntax.
        if not isinstance(value,str):raise Refused('canonical account refused')
        try:length=len(value.encode('utf-8'))
        except UnicodeError:raise Refused('canonical account refused') from None
        if length > 255 or not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9._+-]{0,190}@[A-Za-z0-9][A-Za-z0-9.-]{0,63}', value):
            raise Refused('canonical account refused')
        return value

    @staticmethod
    def _hex(value):
        return 'CONVERT(0x' + value.encode('utf-8').hex() + ' USING utf8mb4)'

    @staticmethod
    def _stamp(value):
        if not re.fullmatch(r'\d{14}', value):
            raise Refused('authoritative timestamp unavailable')
        try:
            datetime.strptime(value, '%Y%m%d%H%M%S')
        except ValueError:
            raise Refused('authoritative timestamp unavailable') from None
        return value

    @staticmethod
    def validate_new(current, new, confirmation):
        # Passwords are borrowed strings: never Debug/repr, persisted or argv.
        if not all(isinstance(v, str) for v in (current, new, confirmation)):
            raise Refused('password input refused')
        try:
            encoded_length=len(new.encode('utf-8'))
        except UnicodeError:
            raise Refused('password input refused') from None
        if not (15 <= len(new) <= 128) or encoded_length > 512:
            raise Refused('passphrase length refused')
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in new):
            raise Refused('passphrase controls refused')
        if new != confirmation:
            raise Refused('confirmation differs')
        if new == current:
            raise Refused('unchanged passphrase refused')

    def _run(self, program, args, stdin, dispatched=False):
        error = Unconfirmed if dispatched else Refused
        try:
            code, out, err = self._execute(program, args, stdin, self.LIMIT_SECONDS,
                                           self.OUTPUT_LIMIT)
        except Exception:
            raise error('native operation unconfirmed' if dispatched else
                        'native operation unavailable') from None
        if (code != 0 or not isinstance(out, bytes) or not isinstance(err, bytes) or
                len(out) > self.OUTPUT_LIMIT or len(err) > self.OUTPUT_LIMIT or err):
            raise error('native operation unconfirmed' if dispatched else
                        'native operation unavailable')
        try:
            return out.decode('ascii')
        except UnicodeError:
            raise error('native result refused') from None

    def read(self, canonical_account):
        account = self._account(canonical_account)
        query = ("SELECT HEX(password),DATE_FORMAT(modified,'%Y%m%d%H%i%s'),active,smtp_active "
                 "FROM mailbox WHERE username=" + self._hex(account) + " LIMIT 2;\n")
        text = self._run(self.SQL_PROGRAM, self.SQL_ARGS, query.encode('ascii'))
        rows = text.splitlines()
        if len(rows) != 1:
            raise Refused('authoritative account unavailable')
        fields = rows[0].split('\t')
        if len(fields) != 4 or fields[2] != '1' or fields[3] not in ('0', '1'):
            raise Refused('authoritative account unavailable')
        try:
            encoded = fields[0]
            if not re.fullmatch(r'(?:[0-9A-F]{2}){1,255}', encoded):
                raise ValueError
            password_hash = bytes.fromhex(encoded).decode('ascii')
        except (ValueError, UnicodeError):
            raise Refused('authoritative password scheme unavailable') from None
        if not (re.fullmatch(self.BLF_PATTERN, password_hash) or
                re.fullmatch(self.ARGON2_PATTERN, password_hash)):
            raise Refused('authoritative password scheme unavailable')
        return Snapshot(account, password_hash, self._stamp(fields[1]), fields[3] == '1')

    def replace(self, snapshot, canonical_account, current, new, confirmation):
        account = self._account(canonical_account)
        if not isinstance(snapshot, Snapshot) or snapshot.account != account:
            raise Refused('account authority mismatch')
        self.validate_new(current, new, confirmation)
        self._stamp(snapshot.modified)
        if (not isinstance(snapshot.password_hash,str) or
                not (re.fullmatch(self.BLF_PATTERN,snapshot.password_hash) or
                     re.fullmatch(self.ARGON2_PATTERN,snapshot.password_hash)) or
                not isinstance(snapshot.smtp_active,bool)):
            raise Refused('authoritative snapshot refused')
        # Qualified native ARGON2ID processes every allowed UTF-8 byte. Existing
        # BLF-CRYPT credentials remain readable; new BLF-CRYPT would silently
        # truncate beyond 72 bytes, violating the accepted password policy.
        hashed = self._run(self.HASH_PROGRAM, self.HASH_ARGS,
                           (new + '\n' + new + '\n').encode('utf-8')).strip()
        if not re.fullmatch(self.ARGON2_PATTERN, hashed):
            raise Refused('native password hash refused')
        if hashed == snapshot.password_hash:
            raise Refused('native password hash unchanged')
        account_sql = self._hex(account)
        new_sql = self._hex(hashed)
        old_sql = self._hex(snapshot.password_hash)
        query = (
            'START TRANSACTION;\nUPDATE mailbox SET password=' + new_sql +
            ',modified=UTC_TIMESTAMP() WHERE username=' + account_sql +
            ' AND active=1 AND BINARY password=BINARY ' + old_sql +
            " AND modified=STR_TO_DATE('" + snapshot.modified + "','%Y%m%d%H%i%s');\n" +
            'SELECT ROW_COUNT();\nSELECT HEX(password),DATE_FORMAT(modified,\'%Y%m%d%H%i%s\') '
            'FROM mailbox WHERE username=' + account_sql + ';\nCOMMIT;\n')
        # A composed containment dependency checks topology after hashing and
        # before the one conditional SQL dispatch. Refusal here is pre-write.
        if self._before_write is not None:
            try:
                if self._before_write(account) is not True:
                    raise ValueError
            except Exception:
                raise Refused('credential write admission unavailable') from None
        text = self._run(self.SQL_PROGRAM, self.SQL_ARGS, query.encode('ascii'), dispatched=True)
        lines = text.splitlines()
        if len(lines) != 2:
            raise Unconfirmed('authoritative write receipt unavailable')
        if lines[0] == '0':
            raise Refused('authoritative account changed; reload before retrying')
        if lines[0] != '1':
            raise Unconfirmed('authoritative write count unconfirmed')
        fields = lines[1].split('\t')
        if len(fields) != 2 or fields[0] != hashed.encode('ascii').hex().upper():
            raise Unconfirmed('authoritative write verification unavailable')
        try:
            stamp = self._stamp(fields[1])
        except Refused:
            raise Unconfirmed('authoritative changed-at unavailable') from None
        # This is a database receipt only, never full password-change success.
        return Receipt(changed_at=stamp)


class NativeExecutor:
    """Private bounded process transport for exactly the two adapter commands.

    Requires helper startup to qualify the fixed client config and confinement.
    No shell, password argument, inherited credential environment, or raw error
    messages. Callers receive bounded bytes solely for strict in-memory parsing.
    """
    def __init__(self, operation_budget=None):
        if operation_budget is not None:
            from operation_budget import OperationBudget
            if type(operation_budget) is not OperationBudget:
                raise Refused('native operation budget refused')
        self._budget=operation_budget

    def __call__(self, program, args, stdin, seconds, limit):
        import os
        import selectors
        import subprocess
        import time
        if (program,args) not in (
                (AuthoritativePasswordAdapter.SQL_PROGRAM,AuthoritativePasswordAdapter.SQL_ARGS),
                (AuthoritativePasswordAdapter.HASH_PROGRAM,AuthoritativePasswordAdapter.HASH_ARGS)):
            raise Refused('native program authority refused')
        if (not isinstance(stdin,bytes) or len(stdin)>16384 or
                seconds!=AuthoritativePasswordAdapter.LIMIT_SECONDS or
                limit!=AuthoritativePasswordAdapter.OUTPUT_LIMIT):
            raise Refused('native process bounds refused')
        operation_seconds=self._budget.cap_seconds(seconds) if self._budget else seconds
        if self._budget:self._budget.inherited_group()
        child=subprocess.Popen((program,)+args,stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               shell=False,close_fds=True,
                               env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'})
        output=bytearray();error=bytearray();offset=0
        deadline=time.monotonic()+operation_seconds
        try:
            with selectors.DefaultSelector() as selector:
                for pipe,event,kind in ((child.stdin,selectors.EVENT_WRITE,'in'),
                                        (child.stdout,selectors.EVENT_READ,'out'),
                                        (child.stderr,selectors.EVENT_READ,'err')):
                    os.set_blocking(pipe.fileno(),False);selector.register(pipe,event,kind)
                while selector.get_map():
                    remaining=deadline-time.monotonic()
                    if self._budget:remaining=min(remaining,self._budget.remaining())
                    if remaining<=0:raise TimeoutError('native process deadline')
                    for key,_ in selector.select(min(remaining,0.1)):
                        if key.data=='in':
                            try:
                                wrote=os.write(key.fd,stdin[offset:offset+4096])
                                offset+=wrote
                            except BrokenPipeError:
                                offset=len(stdin)
                            if offset==len(stdin):selector.unregister(key.fileobj);key.fileobj.close()
                        else:
                            try:data=os.read(key.fd,4096)
                            except BlockingIOError:continue
                            if not data:selector.unregister(key.fileobj);key.fileobj.close();continue
                            destination=output if key.data=='out' else error
                            destination.extend(data)
                            if len(destination)>limit:raise Refused('native process output bound')
                remaining=deadline-time.monotonic()
                if self._budget:remaining=min(remaining,self._budget.remaining())
                if remaining<=0:raise TimeoutError('native process deadline')
                code=child.wait(timeout=remaining)
                if time.monotonic()>=deadline:raise TimeoutError('native process deadline')
                if self._budget:self._budget.remaining()
                return code,bytes(output),bytes(error)
        except BaseException:
            child.kill();child.wait(timeout=2)
            raise
        finally:
            for pipe in (child.stdin,child.stdout,child.stderr):
                if not pipe.closed:pipe.close()
