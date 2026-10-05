"""Test-only actual guarded worker/coordinator with public synthetic dependencies.

No listener, native factory, SQL, password authentication, TOTP, provider or
operator state is used. Run only as an owned process-group leader. The test wall
clock is anchored to sender milliseconds and advances actual monotonic elapsed;
this does not qualify distributed clock synchronization. Stdout is framed wire
only. Stderr retains bounded synthetic counts/states, never request values.
"""
import json
import os
from pathlib import Path
import selectors
import stat
import tempfile
import time

from account_epoch import EpochStore
from account_mutation_worker import IntentStore, MutationWorker
from account_mutation_continuity import verify as verify_continuity
from authoritative_password import AuthoritativePasswordAdapter, Receipt, Refused
from prepared_password import PreparedPasswordCoordinator

ACCOUNT = 'alice@example.test'
REQUEST_KEY = bytes([17])*32
SESSION_KEY = bytes([19])*32
CURRENT = 'public-old-value'
NEW = 'public-new-passphrase'
FRAME_LIMIT = 12288
PROCESS_SECONDS = 60


class PublicBackend:
    _account = staticmethod(AuthoritativePasswordAdapter._account)
    validate_new = staticmethod(AuthoritativePasswordAdapter.validate_new)

    def __init__(self):
        self.writes = 0
        self.reads = 0
        self._credential = CURRENT

    def current(self, account, credential):
        return account == ACCOUNT and credential == self._credential

    def read(self, account):
        if account != ACCOUNT:
            raise Refused('synthetic fixture account refused')
        self.reads += 1
        return (account, self._credential)

    def replace(self, snapshot, account, current, new, confirmation):
        if (snapshot != (ACCOUNT, CURRENT) or account != ACCOUNT
                or current != self._credential or new != NEW or confirmation != NEW):
            raise Refused('synthetic fixture credential refused')
        self.validate_new(current, new, confirmation)
        self.writes += 1
        self._credential = new
        return Receipt('20261004170000')


class PublicContainment:
    """Fixture state witness only, never native session termination."""
    def __init__(self, backend):
        self.backend = backend
        self.state = 'new'

    def ready(self, account):
        if account != ACCOUNT or self.state != 'new' or self.backend.writes:
            raise Refused('synthetic containment refused')
        self.state = 'ready'
        return True

    def flush(self, account):
        if account != ACCOUNT or self.state != 'ready' or self.backend.writes != 1:
            raise Refused('synthetic flush refused')
        self.state = 'flushed'
        return True

    def verify_changed(self, account, credential):
        return self.state == 'flushed' and self.backend.current(account, credential)

    def finish(self, account):
        if account != ACCOUNT or self.state != 'flushed' or self.backend.writes != 1:
            raise Refused('synthetic finish refused')
        self.state = 'finished'
        return True


class FramedStdio:
    def __init__(self, end):
        self.end = end
        self.timeout_end = end
        self.before_challenge = None
        self.challenge_seen = False
        os.set_blocking(0, False)
        os.set_blocking(1, False)

    def settimeout(self, seconds):
        if type(seconds) not in (float, int) or seconds <= 0:
            raise TimeoutError
        self.timeout_end = min(self.end, time.monotonic()+seconds)

    def _wait(self, descriptor, event):
        remaining = min(self.end, self.timeout_end)-time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor,event)
            if not selector.select(remaining):
                raise TimeoutError
        if time.monotonic() >= min(self.end,self.timeout_end):
            raise TimeoutError

    def recv(self, size):
        if type(size) is not int or not 0 < size <= FRAME_LIMIT:
            raise ValueError
        self._wait(0,selectors.EVENT_READ)
        return os.read(0,size)

    def exact(self, size):
        value=bytearray()
        while len(value)<size:
            part=self.recv(size-len(value))
            if not part:
                raise EOFError
            value.extend(part)
        return bytes(value)

    def frame(self):
        size=int.from_bytes(self.exact(4),'big')
        if not 0<size<=FRAME_LIMIT:
            raise ValueError
        return self.exact(size)

    def sendall(self, raw):
        if type(raw) is not bytes or not 4<len(raw)<=4096+4 or int.from_bytes(raw[:4],'big')!=len(raw)-4:
            raise ValueError
        if not self.challenge_seen:
            # The actual worker supplies its nonce, deadline and signed exact
            # action. Observe the real pending file without reacquiring its lock.
            verify_continuity(raw[4:],REQUEST_KEY,'challenge')
            if self.before_challenge is None:
                raise ValueError
            self.before_challenge()
            self.challenge_seen=True
        remaining=memoryview(raw)
        while remaining:
            self._wait(1,selectors.EVENT_WRITE)
            count=os.write(1,remaining)
            if count<=0:
                raise OSError
            remaining=remaining[count:]

    def terminal(self, raw):
        if type(raw) is not bytes or not 0<len(raw)<=4096:
            raise ValueError
        if not self.challenge_seen:
            # A terminal KnownRefused can precede pending; it is not a nonce
            # challenge. Keep wire validation with Rust/Python response verifier.
            self.challenge_seen=True
        self.sendall(len(raw).to_bytes(4,'big')+raw)


class PrivateWitness:
    """Test-owned fixed basename, bounded atomic nonsecret observation only."""
    NAME = 'runtime-real-worker-witness.json'

    @staticmethod
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)

    def __init__(self, root):
        self.root=Path(root)
        if (not self.root.is_absolute() or len(str(self.root))>512
                or self.root.resolve(strict=True)!=self.root):
            raise ValueError
        for parent in tuple(reversed(self.root.parents))+(self.root,):
            info=parent.lstat()
            sticky=parent==Path('/tmp') and info.st_uid==0 and info.st_mode&stat.S_ISVTX
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid())
                    or (info.st_mode&0o022 and not sticky)):
                raise ValueError
        info=self.root.lstat()
        if info.st_uid!=os.getuid() or info.st_mode&0o077:
            raise ValueError
        self.directory=self.identity(info)
        self.path=self.root/self.NAME
        self.file=None

    def recheck(self):
        if self.root.resolve(strict=True)!=self.root or self.identity(self.root.lstat())!=self.directory:
            raise ValueError
        if self.file is not None and self.identity(self.path.lstat())!=self.file:
            raise ValueError

    def publish(self, metrics):
        encoded=json.dumps(metrics,sort_keys=True,separators=(',',':')).encode('ascii')
        if not 0<len(encoded)<=1024:
            raise ValueError
        self.recheck()
        if self.file is None:
            descriptor=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                self.file=self.identity(os.fstat(descriptor))
                if os.write(descriptor,encoded)!=len(encoded):raise OSError
                os.fsync(descriptor)
            finally:os.close(descriptor)
        else:
            descriptor,name=tempfile.mkstemp(prefix='.real-worker-witness-',dir=self.root)
            try:
                os.fchmod(descriptor,0o600)
                if os.write(descriptor,encoded)!=len(encoded):raise OSError
                os.fsync(descriptor)
                self.recheck()
                os.replace(name,self.path)
                self.file=self.identity(self.path.lstat())
            finally:
                os.close(descriptor)
                try:os.unlink(name)
                except FileNotFoundError:pass
        directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        self.recheck()


def run():
    began=time.monotonic()
    stream=FramedStdio(began+PROCESS_SECONDS)
    backend=PublicBackend()
    metrics={'fixture':'runtime-real-worker-v1','writer_calls':0,'reader_calls':0,
             'pending_before_challenge':False,'proof_and_budget_verified':False,'stage':'initial','journal_state':'empty','epoch_state':'active',
             'epoch':0,'terminal':'unavailable','cleanup_confirmed':False}
    result=1
    scratch=None
    witness=None
    try:
        witness_root=os.environ.get('OSMAP_TEST_REAL_WORKER_WITNESS_ROOT')
        if witness_root is not None:
            witness=PrivateWitness(witness_root)
            witness.publish(metrics)
        raw=stream.frame()
        # Only a clock anchor, never authority: actual independent session MAC,
        # budget MAC and inner request MAC are verified by execute_guarded.
        decoded=json.loads(raw)
        sent=decoded['budget']['sent_millis']
        if type(sent) is not int or not 0<sent<2**64:
            raise ValueError
        sample=lambda:sent+int((time.monotonic()-began)*1000)
        clock=lambda:sample()//1000
        scratch=tempfile.TemporaryDirectory(prefix='osmap-real-worker-fixture-',dir='/tmp')
        root=Path(scratch.name);root.chmod(0o700)
        epoch_root=root/'epochs';intent_root=root/'intents'
        epoch_root.mkdir(mode=0o700);intent_root.mkdir(mode=0o700)
        store=EpochStore(epoch_root,os.getuid());store.provision(ACCOUNT)
        journal=IntentStore(intent_root,os.getuid());journal.provision(ACCOUNT)
        def pending():
            record=store._read(store._paths(ACCOUNT)[1])
            if record['state']!='pending' or record['epoch']!=0 or backend.writes!=0:
                raise ValueError
            metrics['pending_before_challenge']=True
            metrics['epoch_state']='pending';metrics['journal_state']='pending';metrics['stage']='pending-before-challenge'
            if witness is not None:witness.publish(metrics)
        stream.before_challenge=pending
        def legacy_session(*args):
            raise AssertionError('independent guarded proof required')
        def builder(action,budget,authorize):
            metrics['proof_and_budget_verified']=True
            dependency=PublicContainment(backend)
            return PreparedPasswordCoordinator(store,backend,authorize,backend.current,
                dependency.verify_changed,dependency.ready,dependency.finish,clock,
                invalidate_changed_auth=dependency.flush)
        worker=MutationWorker(REQUEST_KEY,frozenset([ACCOUNT]),journal,store,builder,
            legacy_session,clock,time.monotonic,session_key=SESSION_KEY)
        try:
            response,budget=worker.execute_guarded(raw,clock_millis=sample,
                _continuity_stream=stream,_reply_budget=True)
            metrics['terminal']=json.loads(response)['outcome']['status']
            metrics['writer_calls']=backend.writes;metrics['reader_calls']=backend.reads
            current_epoch=store._read(store._paths(ACCOUNT)[1])
            metrics['epoch_state']=current_epoch['state'];metrics['epoch']=current_epoch['epoch']
            metrics['journal_state']='complete';metrics['stage']='terminal-before-reply'
            if witness is not None:witness.publish(metrics)
            budget.remaining();stream.settimeout(budget.remaining())
            stream.terminal(response);budget.remaining()
            result=0
        finally:
            metrics['writer_calls']=backend.writes;metrics['reader_calls']=backend.reads
            epoch=store._read(store._paths(ACCOUNT)[1])
            metrics['epoch_state']=epoch['state'];metrics['epoch']=epoch['epoch']
            paths=list(intent_root.glob('*.json'))
            if len(paths)!=1:
                raise ValueError
            record=json.loads(paths[0].read_bytes())
            entries=record['entries']
            metrics['journal_state']='empty' if not entries else entries[-1]['state']
    except Exception:
        # No raw exception/traceback/frame/request/credential/key is exported.
        result=1
    finally:
        if scratch is not None:
            path=Path(scratch.name)
            scratch.cleanup()
            metrics['cleanup_confirmed']=not path.exists()
        else:
            metrics['cleanup_confirmed']=True
        metrics['stage']='finished'
        if witness is not None:
            try:witness.publish(metrics)
            except Exception:result=2
        encoded=json.dumps(metrics,sort_keys=True,separators=(',',':')).encode('ascii')+b'\n'
        if len(encoded)>1024:
            return 2
        os.write(2,encoded)
    return result


if __name__=='__main__':
    raise SystemExit(run())
