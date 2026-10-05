"""Disabled fixed guarded-mutation Unix/SSH transport; no MAC key custody.

The bridge authenticates its local peer and pinned, purpose-exclusive SSH route.
Exact request/session/epoch/action authority stays end-to-end with issuer/helper.
Unverified frame deadlines may only shorten this relay's60s resource cap; they
never authorize an account operation. Local SSH cleanup is not remote stop proof.
"""
import json
import math
import os
from pathlib import Path
import pwd
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

NATIVE_RELAY_QUALIFIED=False
REMOTE='216.128.179.75'
PEER_UID=1001
PURPOSE='osmap-account-mutation'
LISTEN=Path('/var/lib/osmap-bridge/run/mutation.sock')
IDENTITY=Path('/var/lib/osmap-bridge/keys/mutation')
KNOWN_HOSTS=Path('/var/lib/osmap-bridge/known_hosts')
SSH='/usr/bin/ssh'
LIMIT=12288
ACK_LIMIT=2048
RESPONSE_LIMIT=4096
RESERVE=.1

class Unavailable(Exception):
    """No no-write assurance, no reconnect/retry/reset or raw diagnostics."""

def _unique(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise ValueError
        value[k]=v
    return value

def _json(raw):
    return json.loads(raw.decode('utf-8'),object_pairs_hook=_unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))

def _uint(value):return type(value) is int and 0<=value<=2**64-1

def _millis():
    value=time.time()
    if not math.isfinite(value) or value<=0:raise Unavailable('mutation clock unavailable')
    return math.ceil(value*1000)

class _Deadline:
    def __init__(self,raw,received_mono,received_millis,initial_deadline):
        # Parsing is deliberately NOT a signature verification or an authority
        # constructor. The original opaque bytes are the only outbound request.
        try:
            outer=_json(raw)
            if type(outer) is not dict or set(outer)!={'budget','session_proof'}:raise ValueError
            b=outer['budget'];p=outer['session_proof']
            if (type(b) is not dict or type(p) is not dict
                or b.get('schema')!='osmap-account-mutation-budget-v1'
                or p.get('schema')!='osmap-guarded-session-proof-v1'
                or not all(_uint(b.get(k)) for k in ('sent_millis','deadline_millis'))
                or not 0<b['deadline_millis']-b['sent_millis']<=60000
                or not b['sent_millis']<=received_millis<b['deadline_millis']
                or p.get('checked_millis')!=b['sent_millis']
                or p.get('deadline_millis')!=b['deadline_millis']):raise ValueError
            self.wall_deadline=b['deadline_millis']
            self.mono_deadline=min(initial_deadline,
                received_mono+(self.wall_deadline-received_millis)/1000)
            self.last_wall=received_millis;self.last_mono=received_mono
            self.remaining()
        except Exception:raise Unavailable('mutation deadline unavailable') from None
    def remaining(self):
        mono=time.monotonic();wall=_millis()
        if mono<self.last_mono or wall<self.last_wall:raise Unavailable('mutation clock changed')
        self.last_wall=wall;self.last_mono=mono
        remaining=min(self.mono_deadline-mono,(self.wall_deadline-wall)/1000)
        if remaining<=0:raise Unavailable('mutation deadline expired')
        return remaining
    def io(self):
        remaining=self.remaining()-RESERVE
        if remaining<=0:raise Unavailable('mutation IO deadline expired')
        return remaining

def _peer(stream):
    if hasattr(stream,'getpeereid'):return stream.getpeereid()[0]
    if sys.platform.startswith('linux'):
        return struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
    raise Unavailable('mutation peer unavailable')

def ssh_argv():
    return (SSH,'-F','/dev/null','-T','-a','-x','-i',str(IDENTITY),
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
        '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
        '-o',f'UserKnownHostsFile={KNOWN_HOSTS}',
        # A daemonized multiplex master could outlive the owned workflow group;
        # do not reuse auth/mailbox authority or create a mutation master.
        '-o','ControlMaster=no','-o','ControlPersist=no','-o','ControlPath=none',
        '-o','ClearAllForwardings=yes','-o','ForwardAgent=no',
        '-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
        '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=1',
        f'_osmap@{REMOTE}',PURPOSE)

def _material():
    owner=os.geteuid()
    if owner==0 or pwd.getpwuid(owner).pw_name!='_osmapbridge':
        raise Unavailable('mutation bridge principal unavailable')
    for path,private in ((IDENTITY,True),(KNOWN_HOSTS,False)):
        for parent in path.parents:
            m=parent.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0,owner)
                    or m.st_mode&0o022 or parent.resolve()!=parent):
                raise Unavailable('mutation bridge ancestry unavailable')
        m=path.lstat()
        if (not stat.S_ISREG(m.st_mode) or m.st_nlink!=1 or m.st_size<=0
                or m.st_uid!=(owner if private else 0)
                or m.st_mode&(0o077 if private else 0o022)):
            raise Unavailable('mutation SSH material unavailable')
    m=LISTEN.parent.lstat()
    if (not stat.S_ISDIR(m.st_mode) or m.st_uid!=owner or m.st_mode&0o027
            or LISTEN.parent.resolve()!=LISTEN.parent
            or LISTEN.exists() or LISTEN.is_symlink()):
        raise Unavailable('mutation listener unavailable')

class _Relay:
    def __init__(self,trusted_uid):
        if type(trusted_uid) is not int or not 0<trusted_uid<=2**32-1:raise Unavailable('mutation peer unavailable')
        self._trusted_uid=trusted_uid;self._contained=False
        self._busy=threading.Lock();self._retained=[]
    @classmethod
    def native(cls):
        if not NATIVE_RELAY_QUALIFIED:raise Unavailable('native mutation relay unavailable')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        _material()
        return cls(PEER_UID)
    @staticmethod
    def _command():return ssh_argv()
    @staticmethod
    def _socket_exact(stream,size,seconds):
        data=bytearray()
        while len(data)<size:
            stream.settimeout(seconds());part=stream.recv(size-len(data))
            if not part:raise Unavailable('mutation framing unavailable')
            data.extend(part)
        return bytes(data)
    @classmethod
    def _socket_frame(cls,stream,limit,seconds):
        n=int.from_bytes(cls._socket_exact(stream,4,seconds),'big')
        if not 0<n<=limit:raise Unavailable('mutation framing unavailable')
        return cls._socket_exact(stream,n,seconds)
    @staticmethod
    def _pipe_read(pipe,size,deadline):
        result=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(pipe,selectors.EVENT_READ)
            while len(result)<size:
                if selector.select(min(deadline.io(),.01)):
                    try:part=os.read(pipe.fileno(),size-len(result))
                    except BlockingIOError:continue
                    if not part:raise Unavailable('mutation remote framing unavailable')
                    result.extend(part)
        deadline.remaining();return bytes(result)
    @classmethod
    def _pipe_frame(cls,pipe,limit,deadline):
        n=int.from_bytes(cls._pipe_read(pipe,4,deadline),'big')
        if not 0<n<=limit:raise Unavailable('mutation remote framing unavailable')
        return cls._pipe_read(pipe,n,deadline)
    @staticmethod
    def _pipe_write(pipe,raw,deadline):
        data=len(raw).to_bytes(4,'big')+raw
        with selectors.DefaultSelector() as selector:
            selector.register(pipe,selectors.EVENT_WRITE)
            while data:
                if selector.select(min(deadline.io(),.01)):
                    try:n=os.write(pipe.fileno(),data)
                    except BlockingIOError:continue
                    if not n:raise Unavailable('mutation SSH input unavailable')
                    data=data[n:]
        deadline.remaining()
    @staticmethod
    def _send(stream,raw,deadline):
        stream.settimeout(deadline.io());stream.sendall(len(raw).to_bytes(4,'big')+raw)
        deadline.remaining()
    @staticmethod
    def _cleanup(child,deadline):
        # No poll/wait precedes this signal; a nondefault SIGCHLD handler refuses
        # before spawn. Never signal the numerical group after direct reap.
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        code=child.wait(timeout=deadline.remaining())
        try:os.killpg(child.pid,0)
        except ProcessLookupError:
            deadline.remaining();return code
        raise Unavailable('mutation SSH cleanup unconfirmed')
    def connection(self,stream):
        if not self._busy.acquire(blocking=False):raise Unavailable('mutation relay busy')
        child=None;deadline=None
        try:
            if self._contained or _peer(stream)!=self._trusted_uid:raise ValueError
            initial=time.monotonic()+60
            def initial_remaining():
                left=initial-time.monotonic()-RESERVE
                if left<=0:raise Unavailable('mutation initial framing expired')
                return left
            raw=self._socket_frame(stream,LIMIT,initial_remaining)
            received_mono,received_millis=time.monotonic(),_millis()
            deadline=_Deadline(raw,received_mono,received_millis,initial)
            deadline.io()
            if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:raise ValueError
            child=subprocess.Popen(self._command(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            os.set_blocking(child.stdin.fileno(),False);os.set_blocking(child.stdout.fileno(),False)
            self._pipe_write(child.stdin,raw,deadline)
            first=self._pipe_frame(child.stdout,RESPONSE_LIMIT,deadline)
            meta=_json(first)
            if type(meta) is dict and meta.get('schema')=='osmap-account-mutation-continuity-v1':
                self._send(stream,first,deadline)
                ack=self._socket_frame(stream,ACK_LIMIT,deadline.io)
                stream.settimeout(deadline.io())
                if stream.recv(1)!=b'':raise Unavailable('mutation ACK trailing data')
                self._pipe_write(child.stdin,ack,deadline)
                child.stdin.close() # EOF is framing; helper authenticates ACK.
                reply=self._pipe_frame(child.stdout,RESPONSE_LIMIT,deadline)
            else:
                reply=first;child.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout,selectors.EVENT_READ)
                while True:
                    if selector.select(min(deadline.io(),.01)):
                        try:part=os.read(child.stdout.fileno(),1)
                        except BlockingIOError:continue
                        if part:raise Unavailable('mutation remote trailing data')
                        break
            try:code=self._cleanup(child,deadline)
            except Exception:
                self._contained=True;self._retained.append(child)
                for p in (child.stdin,child.stdout):
                    if not p.closed:p.close()
                child=None;raise
            child.stdout.close();child=None
            if code!=0:raise Unavailable('mutation SSH exit unconfirmed')
            self._send(stream,reply,deadline)
        except Exception:raise Unavailable('mutation relay unavailable') from None
        finally:
            failed=False
            if child is not None:
                try:self._cleanup(child,deadline)
                except Exception:self._contained=True;self._retained.append(child);failed=True
                for p in (child.stdin,child.stdout):
                    if not p.closed:p.close()
            self._busy.release()
            if failed:raise Unavailable('mutation SSH cleanup unconfirmed') from None


def serve_native():
    relay=_Relay.native() # false before principal/material/listener access
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);inode=None
    try:
        listener.bind(str(LISTEN));m=LISTEN.lstat();inode=(m.st_dev,m.st_ino)
        os.chmod(LISTEN,0o660);listener.listen(1)
        while not relay._contained:
            stream,_=listener.accept()
            with stream:
                try:relay.connection(stream)
                except Unavailable:pass
    finally:
        listener.close()
        if inode is not None:
            try:
                m=LISTEN.lstat()
                if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino)==inode:LISTEN.unlink()
            except FileNotFoundError:pass

if __name__=='__main__':
    try:serve_native()
    except Exception:raise SystemExit(1) from None
