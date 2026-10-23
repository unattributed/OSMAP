"""Exact finite HTTP/file consumers extracted from existing controlled-workflow1.

No old Python factory, account worker, policy or SQL adapter is imported.
"""
import hashlib,hmac,json,os,re,socket,stat,threading,time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode

ALICE='alice@osmap-password.invalid'
BOB='bob@osmap-password.invalid'
WEB_UID=1001
WEB_GID=1001
HOST='password-pilot.osmap.invalid'
AGENT='OSMAP-fixed-genuine-HTTP-pilot'
HTTP_RESPONSE_BYTES=262144
JOURNEY_SECONDS=300
CANCEL=None

def require(value,reason='fixed_http_consumer_refused'):
    if not value:raise RuntimeError(reason)
def full_identity(m):
    return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
def http_remaining(end):
    require(CANCEL is None or not CANCEL.is_set(),'http_cancelled')
    left=end-time.monotonic();require(left>0,'original_http_deadline');return left
def left(end,maximum=5):return min(maximum,http_remaining(end))

def parse_response(raw):
    require(type(raw) is bytes and 0 < len(raw) <= HTTP_RESPONSE_BYTES)
    head, separator, body = raw.partition(b'\r\n\r\n')
    require(separator and len(head) <= 16384)
    lines = head.split(b'\r\n')
    match = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]{1,80}', lines[0])
    require(match is not None)
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        require(colon and re.fullmatch(rb'[A-Za-z0-9-]{1,64}', name)
            and not re.search(rb'[\x00-\x08\x0a-\x1f\x7f]', value))
        headers.append((name.decode('ascii').lower(), value.strip().decode('ascii')))
    lengths = [value for name, value in headers if name == 'content-length']
    require(len(lengths) == 1 and lengths[0].isdigit() and int(lengths[0]) == len(body)
        and not any(name == 'transfer-encoding' for name, _ in headers))
    return int(match[1]), headers, body

def session_cookie(reply):
    status, headers, _ = reply
    # Persistence-qualified pilot requires normal actual redirect; a real200
    # signed-in notice is insufficient and remains a visible bounded refusal.
    require(status == 303)
    values = [value for name, value in headers if name == 'set-cookie' and value.startswith('osmap_session=')]
    require(len(values) == 1 and '; Secure' in values[0] and '; HttpOnly' in values[0]
        and 'SameSite=Strict' in values[0])
    token = values[0].split(';', 1)[0].partition('=')[2]
    require(re.fullmatch('[a-f0-9]{64}', token))
    return 'osmap_session=' + token

def web_file(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == WEB_UID and before.st_gid == WEB_GID
        and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and 0 < before.st_size <= limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(full_identity(os.fstat(fd)) == full_identity(before))
        raw = os.read(fd, limit + 1)
        require(0 < len(raw) <= limit and full_identity(os.fstat(fd)) == full_identity(before)
            and full_identity(path.lstat()) == full_identity(before))
        return raw
    finally:
        os.close(fd)

def replay_counter(root, account):
    require(account in (ALICE, BOB))
    path = root / 'http-state/cache/totp-replay' / (account.encode('ascii').hex() + '.counter')
    raw = web_file(path, 64)
    require(re.fullmatch(rb'[0-9]{1,20}\n?', raw))
    return int(raw)

def record(root, cookie):
    require(re.fullmatch(r'osmap_session=[a-f0-9]{64}', cookie))
    token = cookie.partition('=')[2]
    session_id = hashlib.sha256(('session-id:' + token).encode('ascii')).hexdigest()
    raw = web_file(root / 'http-state/sessions' / (session_id + '.session'), 4096)
    fields = {}
    for line in raw.decode('utf-8').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields)
        fields[key] = value
    require(fields.get('session_id') == session_id and fields.get('remote_addr') == '127.0.0.1'
        and fields.get('user_agent') == AGENT and fields.get('factor') == 'totp'
        and re.fullmatch('[a-f0-9]{64}', fields.get('csrf_token', '')))
    return fields, raw

def code(counter):
    require(type(counter) is int and counter >= 0)
    digest = hmac.new(b'12345678901234567890', counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1000000
    return format(value, '06d')

def accepted_counter(deadline, minimum=0):
    require(type(minimum) is int and minimum >= 0)
    while True:
        remaining = http_remaining(deadline)
        now = time.time()
        current = int(now) // 30
        selected = max(minimum, current)
        # Mint from the real current clock, never deliberately current-1.
        # A replay minimum may use the existing +1 policy. If it is further
        # ahead, wait for that same window within the original sequence end.
        if selected <= current + 1:
            http_remaining(deadline)
            return selected, selected - current
        until_window = (minimum - 1) * 30 - now
        require(until_window > 0)
        time.sleep(min(until_window, remaining, .25))

class FrontDriver:
    session_cookie=staticmethod(session_cookie)
    code=staticmethod(code)
    def __init__(self,node,boot):
        global CANCEL
        self.node=node;self.boot=boot;CANCEL=node.cancelled
        self.http_sequence=0;self.http_connected_streams=0
        self.http_response_observation=None;self.phase='ready'
        self.auth_stage_id=0
        self.sequence_started=time.monotonic()
        self.http_port=node.ready['port'];self.sequence_end=node.sequence_end
        self.new_password=boot['new_password'];self.snapshot_index=0
        self.actual_http_report=None
    def initial_password(self,account):
        require(account in(ALICE,BOB));return self.boot['alice_password'if account==ALICE else'bob_password']
    def accepted_counter(self,end,minimum=0):return accepted_counter(end,minimum)[0]
    def browser_record(self,cookie):return record(self.node.http_root,cookie)
    def replay_counter(self,account):
        self.node.capture_replay_directory()
        return replay_counter(self.node.http_root,account)
    def authoritative_snapshot(self,account,end):
        tags=('SNAPSHOT_B0','SNAPSHOT_A0','SNAPSHOT_A1','SNAPSHOT_B1')
        require(self.snapshot_index<4 and account==(BOB if self.snapshot_index in(0,3)else ALICE))
        tag=tags[self.snapshot_index];self.snapshot_index+=1
        reply=self.node.exchange(tag,end);require(set(reply)=={'phase','snapshot'})
        return reply['snapshot']
    def verify_mail_containment(self,end):
        require(self.snapshot_index==4);reply=self.node.exchange('MAIL_WITNESS',end)
        http_remaining(end)
        require(set(reply)=={'phase','result'} and set(reply['result'])=={
            'result','public_cache_zero','public_original25_preserved','public_master_preserved',
            'bob_mail_projection_preserved','bob_home_absent','bob_mail_absent','bob_projection_sha256',
            'external_sessions_terminated','flush_performed'})
        value=reply['result']
        require(value['result']=='PASS' and all(value[k]is True for k in(
            'public_cache_zero','public_original25_preserved','public_master_preserved',
            'bob_mail_projection_preserved','bob_home_absent','bob_mail_absent'))
            and type(value['bob_projection_sha256'])is str
            and re.fullmatch('[a-f0-9]{64}',value['bob_projection_sha256'])
            and value['external_sessions_terminated']is False and value['flush_performed']is False)
    def finish_http(self,end,connections):
        require(connections==self.http_sequence==18)
        self.actual_http_report=self.node.finish_http(end)
    @contextmanager
    def connection(self,end):
        with self.node.socket_lock:
            require(not self.node.cancelled.is_set(),'http_cancelled')
            stream=socket.create_connection(('127.0.0.1',self.http_port),timeout=left(end,5))
            self.node.http_stream=stream
        try:yield stream
        finally:
            with self.node.socket_lock:
                if self.node.http_stream is stream:self.node.http_stream=None
                stream.close()

    def request(self, method, path, deadline, *, form=None, cookie=None):
            request_started=time.monotonic()
            self.http_response_observation = dict(request_ordinal=self.http_sequence + 1,
                stage='budget', received_bytes=0, eof_received=False,
                request_started=request_started,
                request_budget_at_start_ms=max(0,min(JOURNEY_SECONDS*1000,int((deadline-request_started)*1000))))
            http_remaining(deadline)
            require(method in ('GET', 'POST') and path in ('/login', '/settings/password', '/settings?section=security', '/settings?section=authentication') and self.http_sequence < 18)
            self.phase = 'http_request_' + str(self.http_sequence + 1)
            self.http_response_observation['stage']='connect'
            body = b'' if form is None else urlencode(form).encode('ascii')
            require(len(body) <= 8192)
            headers = [f'{method} {path} HTTP/1.1', f'Host: {HOST}', f'User-Agent: {AGENT}',
                'Connection: close', f'Content-Length: {len(body)}']
            if form is not None:
                headers += ['Content-Type: application/x-www-form-urlencoded', f'Origin: https://{HOST}']
            if cookie is not None:
                require(re.fullmatch(r'osmap_session=[a-f0-9]{64}', cookie))
                headers.append('Cookie: ' + cookie)
            raw = ('\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + body
            with self.connection(deadline) as stream:
                self.http_connected_streams += 1
                self.http_response_observation['stage'] = 'send'
                stream.settimeout(left(deadline, 5))
                stream.sendall(raw)
                response = bytearray()
                self.http_response_observation['stage'] = 'read'
                while True:
                    # Password route may take its actual60; do not impose5s on its
                    # response wait. Every iteration consumes the original bound.
                    stream.settimeout(http_remaining(deadline))
                    data = stream.recv(8192)
                    if not data:
                        self.http_response_observation['eof_received'] = True
                        break
                    response.extend(data)
                    self.http_response_observation['received_bytes'] = len(response)
                    if len(response) > HTTP_RESPONSE_BYTES:
                        self.http_response_observation['stage'] = 'response_cap'
                    require(len(response) <= HTTP_RESPONSE_BYTES)
            http_remaining(deadline)
            self.node.capture_generated_directories()
            self.http_sequence += 1
            self.http_response_observation['stage'] = 'parse'
            reply = parse_response(bytes(response))
            require(all(self.boot[name].encode() not in reply[2] for name in ('alice_password','bob_password','new_password')))
            self.http_response_observation['status'] = reply[0]
            # Counts only; never export header values, session tokens or body text.
            self.http_response_observation['session_cookie_headers'] = min(2, sum(
                name == 'set-cookie' and value.startswith('osmap_session=')
                for name, value in reply[1]))
            self.http_response_observation['stage'] = 'complete'
            return reply

    def failure_scalars(self):
        # Freeze only source-owned counts/state before containment closes sockets.
        # No URL, request/header/body, account, cookie or backend frame is exported.
        now=time.monotonic();value=self.http_response_observation
        stages={'budget':1,'connect':2,'send':3,'read':4,'response_cap':5,'parse':6,'complete':7}
        result={'http_auth_stage_id':self.auth_stage_id,'http_observation_known':value is not None,'http_request_ordinal':0,
            'http_stage_id':0,'http_received_bytes':0,'http_eof_received':False,
            'http_status':0,'http_session_cookie_headers':0,'http_request_budget_at_start_ms':0,
            'http_request_elapsed_ms':0,'http_sequence_elapsed_ms':max(0,min(1000000,int((now-self.sequence_started)*1000))),
            'http_original_remaining_ms':max(0,min(JOURNEY_SECONDS*1000,int((self.sequence_end-now)*1000)))}
        if value is not None:
            result.update(http_request_ordinal=value['request_ordinal'],
                http_stage_id=stages[value['stage']],http_received_bytes=value['received_bytes'],
                http_eof_received=value['eof_received'],http_status=value.get('status',0),
                http_session_cookie_headers=value.get('session_cookie_headers',0),
                http_request_budget_at_start_ms=value['request_budget_at_start_ms'],
                http_request_elapsed_ms=max(0,min(1000000,int((now-value['request_started'])*1000))))
        return result

    def login(self, account, password, counter, deadline):
            return self.request('POST', '/login', deadline,
                form={'username': account, 'password': password, 'totp_code': code(counter)})

    def settings_history(self,cookie,stamp,deadline):
            for section in ('security','authentication'):
                reply=self.request('GET','/settings?section='+section,deadline,cookie=cookie)
                require(reply[0]==200)
                if stamp is None:
                    require(b'Last change unknown'in reply[2] and b'Last changed 'not in reply[2])
                else:
                    rendered=('Last changed '+stamp[:4]+'-'+stamp[4:6]+'-'+stamp[6:8]+' '+stamp[8:10]+':'+stamp[10:12]+':'+stamp[12:]+' UTC').encode('ascii')
                    require(rendered in reply[2] and b'Last change unknown'not in reply[2])
