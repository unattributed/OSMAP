"""Actual fixed public SMTP AUTH witness; no message or connection-revocation claim."""
import base64,math,re,socket,ssl,time
ACCOUNTS=('alice@osmap-password.invalid','bob@osmap-password.invalid')
CAP=16384

def require(value,code):
    if not value:raise RuntimeError(code)

class StockSmtpProbe:
    def __init__(self, account, end):
        self.account, self.end, self.stream = account, end, None
        self.bytes, self.sequence = 0, 0
        require(account in ACCOUNTS, 'fixed_smtp_account')
        raw = None
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            raw = socket.create_connection(('127.0.0.1', 465), self.left())
            raw.settimeout(self.left())
            self.stream = context.wrap_socket(raw, server_hostname='mail.blackbagsecurity.com')
            raw = None
            require(self.stream.getpeername()[0] == '127.0.0.1', 'fixed_smtp_peer')
            self.reply(220)
            self.send(b'EHLO osmap-client.invalid')
            self.reply(250)
        except BaseException:
            if raw is not None: raw.close()
            self.close()
            raise

    def send(self, command):
        require(type(command) is bytes and len(command) <= 512
                and not any(c in command for c in (b'\r', b'\n', b'\0'))
                and self.sequence < 8, 'fixed_smtp_command_bound')
        self.sequence += 1
        self.stream.settimeout(self.left())
        self.stream.sendall(command + b'\r\n')

    def reply(self, expected):
        for _ in range(16):
            value = self.line()
            require(value[:3] == str(expected).encode('ascii')
                    and value[3:4] in (b' ', b'-'), 'actual_smtp_reply_code')
            if value[3:4] == b' ': return
        raise RuntimeError('smtp_reply_row_cap')

    def authenticate(self, password, accepted=True):
        require(type(password) is str and re.fullmatch('[a-f0-9]{64}', password)
                and type(accepted) is bool, 'actual_private_smtp_fixture_password')
        payload = base64.b64encode(b'\0' + self.account.encode('ascii') + b'\0' + password.encode('ascii'))
        self.send(b'AUTH PLAIN ' + payload)
        self.reply(235 if accepted else 535)

    def noop(self):
        self.send(b'NOOP')
        self.reply(250)

    def left(self):
        left = self.end - time.monotonic()
        require(left > 0, 'imap_original_caller_deadline')
        return min(left, 5)

    def line(self):
        value = bytearray()
        while not value.endswith(b'\r\n'):
            self.stream.settimeout(self.left())
            part = self.stream.recv(1)
            require(bool(part), 'imap_unexpected_eof')
            value.extend(part)
            self.bytes += len(part)
            require(len(value) <= 4096 and self.bytes <= CAP, 'imap_reply_cap')
        require(b'\0' not in value and value.count(b'\n') == 1, 'imap_reply_shape')
        return bytes(value)

    def close(self):
        if self.stream is not None:
            try:
                self.stream.close()
            finally:
                self.stream = None


class StockMailWitness:
    def __init__(self,fixture,end):
        require(type(end)in(int,float)and math.isfinite(end)and end<=fixture.end
            and 3<end-time.monotonic()<=180,'stock_mail_original_deadline')
        self.fixture,self.end=fixture,end
        self.bob=None
    def begin(self):
        try:
            self.bob=StockSmtpProbe(ACCOUNTS[1],self.end)
            self.bob.authenticate(self.fixture.initial_password(ACCOUNTS[1]))
        except BaseException:
            self.close();raise
    def finish_after_change(self):
        require(self.bob is not None,'stock_bob_born_connection')
        try:
            with_probe=[]
            try:
                old=StockSmtpProbe(ACCOUNTS[0],self.end);with_probe.append(old)
                old.authenticate(self.fixture.initial_password(ACCOUNTS[0]),accepted=False)
                new=StockSmtpProbe(ACCOUNTS[0],self.end);with_probe.append(new)
                new.authenticate(self.fixture.new_password)
                self.bob.noop()
            finally:
                for probe in with_probe:probe.close()
            actual=self.fixture.run(('/usr/local/bin/doveconf','-c','/etc/dovecot/dovecot.conf','-h','auth_cache_size'),
                'stock_actual_cache_policy',seconds=5,absolute=self.end)
            require(actual==b'0\n','stock_actual_cache_not_zero')
            self.fixture.original_config_current()
            require(self.fixture.master_row()==self.fixture.master,'stock_public_master_changed')
            return {'result':'PASS','old_password_refused':True,'new_password_admitted':True,
                'bob_auth_preserved':True,'public_cache_zero':True,
                'public_original25_preserved':True,'public_master_preserved':True,
                'external_sessions_terminated':False,'flush_performed':False}
        finally:self.close()
    def close(self):
        if self.bob is not None:self.bob.close();self.bob=None
