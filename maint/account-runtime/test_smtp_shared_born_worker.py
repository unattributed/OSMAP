"""Actual supervisor-born child, private bootstrap pipe and separate parent broker.

Current SMTP peer PID metadata, SQL/primary and external TCP/IMAP are projections;
original worker/issuer/intent budget and parent-observed SASL EOF are actual.
"""
import fcntl,hashlib,hmac,json,os,secrets,signal,socket,subprocess,sys,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from account_epoch import EpochStore
from account_guarded_mutation import canonical,payload
from account_mutation_budget import envelope
from account_mutation_codec import encoded,SCHEMA,ACTION
from account_mutation_continuity import verify,signed
from account_mutation_supervisor import COMPLETE
from account_mutation_worker import IntentStore,Unavailable
from authoritative_password import Refused
import guarded_smtp_shared_worker_fixture as child_fixture
import smtp_auth_control_service as service
import smtp_control_authorization as proof
import test_smtp_control_service as fixtures

class BornSharedWorker(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ServiceTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.f.root;self.alice=fixtures.fixtures.ALICE;self.bob=fixtures.fixtures.BOB
        self.keys=[secrets.token_bytes(32)for _ in range(3)]
        self.f.authority=proof.ControlAuthority(self.keys[2],self.f.authority.accounts)
        self.f.supervisor=service.GuardedControlSupervisor(self.f.authority,self.f.fixture.registry,self.f.journal,self.f.routing,
            monotonic=time.monotonic,clock_millis=lambda:int(time.time()*1000))
        parent=self.root/'control';parent.mkdir(mode=0o700)
        self.listener=service.PrivateControlListener(parent/'control.sock',os.getuid(),self.f.supervisor)
        self.stop=threading.Event();self.results=[];self.wire=[]
        root=self.root/'mutation-intents';root.mkdir(mode=0o700);self.intents=IntentStore(root,os.getuid());self.intents.provision(self.alice)
        self.old,self.front,self.upstream=self.f.fixture.channel();self.untouched,_,_=self.f.fixture.channel(self.bob,2)
    def raw(self):
        sent=int(time.time()*1000);now=sent//1000;deadline=sent+1500
        source=json.loads(fixtures.guarded());value=json.loads(bytes.fromhex(source['budget']['request_hex']))
        value.update(issued=now,expires=now+300)
        fields=('account','epoch','intent_reference','session_id','request_id','source','issued','expires','current','new','confirmation')
        value['signature']=hmac.new(self.keys[0],encoded([SCHEMA,ACTION,'request',*[value[k]for k in fields]]),hashlib.sha256).hexdigest()
        raw=encoded(value);source['budget']=json.loads(envelope(raw,self.keys[0],sent,deadline))
        p=source['session_proof'];p.update(issued=now,expires=now+300,checked_millis=sent,deadline_millis=deadline,session_expires=now+500,idle_expires=now+400,
            request_sha256=hashlib.sha256(raw).hexdigest(),budget_sha256=hashlib.sha256(canonical(source['budget'])).hexdigest())
        p['signature']=hmac.new(self.keys[1],payload(p),hashlib.sha256).hexdigest()
        return encoded(source),deadline
    def exchange(self,mode='positive'):
        frame=self.f.supervisor._frame
        def observe(*args):
            raw=frame(*args);self.wire.append(json.loads(raw))
            for secret in (b'public synthetic credential',b'request_hex',*(k.hex().encode()for k in self.keys[:2])):self.assertNotIn(secret,raw)
            return raw
        def serve():
            try:self.results.append(self.listener.serve(self.stop))
            except Exception as error:self.results.append(error)
        end=time.monotonic()+4
        with patch.object(self.f.supervisor,'_frame',side_effect=observe):
            thread=threading.Thread(target=serve);thread.start()
            read,write=os.pipe();server,peer=socket.socketpair();child=None
            try:
                while not self.listener.path.exists()and time.monotonic()<end:time.sleep(.005)
                bootstrap={'version':1,'root':str(self.root),'key':self.keys[0].hex(),'session_key':self.keys[1].hex(),'control_key':self.keys[2].hex(),
                    'metadata':{k:v.decode('ascii')for k,v in self.f.f.metadata.items()}}
                child=subprocess.Popen((sys.executable,'-I','-B',str(Path(__file__).with_name('guarded_smtp_shared_worker_fixture.py')),'--fixture-bootstrap-fd',str(read)),
                    stdin=subprocess.PIPE,stdout=server,stderr=subprocess.PIPE,pass_fds=(read,),close_fds=True,start_new_session=True,
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                server.close();os.close(read);read=None
                raw,deadline=self.raw()
                if mode=='proof':
                    value=json.loads(raw);value['session_proof']['signature']='0'*64;raw=encoded(value)
                os.write(write,encoded(bootstrap));os.close(write);write=None
                child.stdin.write(len(raw).to_bytes(4,'big')+raw);child.stdin.close()
                def exact(size):
                    data=bytearray()
                    while len(data)<size:
                        peer.settimeout(max(.001,end-time.monotonic()));part=peer.recv(size-len(data))
                        if not part:raise EOFError
                        data.extend(part)
                    return bytes(data)
                challenge_seen=False;lock_held=False;reply=None
                try:
                    size=int.from_bytes(exact(4),'big');self.assertLessEqual(size,4096)
                    challenge=verify(exact(size),self.keys[0],'challenge');challenge_seen=True
                    info=json.loads((self.root/'shared-worker-report.json').read_bytes())
                    self.assertEqual((info['pid'],info['group'],info['owned_group']),(child.pid,child.pid,True))
                    remaining=min(.2,deadline/1000-time.time())
                    self.assertGreater(remaining,0)
                    current=subprocess.run(('/bin/ps','-p',str(child.pid),'-o','pid=,ppid=,pgid=,uid=,comm='),stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=remaining,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                    self.assertEqual(current.returncode,0);self.assertLessEqual(len(current.stdout),1024)
                    rows=current.stdout.decode('ascii').splitlines();self.assertEqual(len(rows),1)
                    fields=rows[0].split(maxsplit=4);self.assertEqual(len(fields),5)
                    self.assertEqual(tuple(map(int,fields[:4])),(child.pid,os.getpid(),child.pid,os.geteuid()))
                    self.assertIn(Path(fields[4]).name,('python3','python3.13','python3.14'))
                    self.assertEqual(info['deadline_millis'],deadline)
                    pending=self.f.fixture.store._read(self.f.fixture.store._paths(self.alice)[1])
                    self.assertEqual((pending['state'],pending['intent']),('pending','a'*64))
                    fd=os.open(self.intents._paths(self.alice)[0],os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        lock_held=True
                    finally:os.close(fd)
                    self.assertEqual(self.f.record()['entries'],[]);self.assertFalse(self.old.closed)
                    if mode=='eof':peer.shutdown(socket.SHUT_WR)
                    else:
                        ack=dict(challenge,phase='ack');ack.pop('signature')
                        if mode=='nonce':ack['nonce']='0'*64
                        if mode=='expired':
                            time.sleep(max(0,deadline/1000-time.time())+.01)
                        payload_raw=signed(ack,self.keys[0]);peer.sendall(len(payload_raw).to_bytes(4,'big')+payload_raw);peer.shutdown(socket.SHUT_WR)
                    size=int.from_bytes(exact(4),'big');self.assertLessEqual(size,4096);reply=json.loads(exact(size))
                    self.assertEqual(peer.recv(1),b'')
                except (EOFError,ConnectionResetError,BrokenPipeError):pass
                child.wait(timeout=max(.001,end-time.monotonic()))
                marker=child.stderr.read(len(COMPLETE)+1);self.assertLessEqual(len(marker),len(COMPLETE))
                with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
                info=json.loads((self.root/'shared-worker-report.json').read_bytes())
                self.stop.set();thread.join(2);self.assertFalse(thread.is_alive())
                return reply,info,challenge_seen,lock_held,marker,child.returncode
            finally:
                self.stop.set();peer.close();server.close()
                for descriptor in (read,write):
                    if descriptor is not None:os.close(descriptor)
                if child is not None:
                    if child.returncode is None:
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        child.wait(timeout=1)
                    child.stderr.close()
                thread.join(2)
    def test_actual_born_bootstrap_worker_held_intent_issuer_and_separate_broker_SASL(self):
        reply,info,challenge,lock,marker,code=self.exchange()
        self.assertEqual((code,marker),(0,COMPLETE));self.assertTrue(challenge and lock)
        self.assertEqual(reply['outcome']['status'],'changed');self.assertEqual(info['sql_calls'],1)
        self.assertTrue(info['capture']and info['owned_descriptor_closed']);self.assertEqual(self.results,[1])
        self.assertTrue(self.old.closed);self.assertFalse(self.untouched.closed)
        for stream in (self.front,self.upstream):stream.settimeout(.2);self.assertEqual(stream.recv(1),b'')
        self.assertEqual(self.f.fixture.store._read(self.f.fixture.store._paths(self.alice)[1])['state'],'active')
        self.assertEqual(self.f.record()['entries'][0]['state'],'complete');self.assertEqual(len(self.wire),1)
        self.assertFalse(self.listener.path.exists())
    def test_wrong_issuer_nonce_withholds_cross_process_broker_capture_SQL(self):
        reply,info,challenge,lock,marker,code=self.exchange('nonce')
        self.assertEqual((code,marker),(0,COMPLETE));self.assertTrue(challenge and lock)
        self.assertEqual(reply['outcome']['status'],'contained');self.assertEqual(info['sql_calls'],0);self.assertFalse(info['capture'])
        self.assertEqual(self.wire,[]);self.assertEqual(self.f.record()['entries'],[]);self.assertFalse(self.old.closed)
    def test_original_receipt_expiry_after_issuer_challenge_never_renews_broker_budget(self):
        reply,info,challenge,lock,marker,code=self.exchange('expired')
        self.assertTrue(challenge and lock);self.assertIsNone(reply);self.assertNotEqual(code,0);self.assertEqual(marker,b'')
        self.assertEqual(self.wire,[]);self.assertEqual(info['sql_calls'],0);self.assertFalse(info['capture'])
        self.assertEqual(self.f.record()['entries'],[]);self.assertFalse(self.old.closed)
    def test_forged_original_guard_refuses_before_issuer_flock_or_control(self):
        reply,info,challenge,lock,marker,code=self.exchange('proof')
        self.assertIsNone(reply);self.assertFalse(challenge or lock);self.assertNotEqual(code,0);self.assertEqual(marker,b'')
        self.assertEqual(self.wire,[]);self.assertEqual(info['sql_calls'],0);self.assertFalse(info['capture'])
        self.assertEqual(self.f.record()['entries'],[]);self.assertEqual(self.intents._record(self.intents._paths(self.alice)[1])['entries'],[])

class BootstrapClosedControls(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ServiceTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.value={'version':1,'root':str(self.f.f.root),'key':secrets.token_hex(32),'session_key':secrets.token_hex(32),'control_key':secrets.token_hex(32),
            'metadata':{k:v.decode('ascii')for k,v in self.f.f.metadata.items()}}
    def pipe(self,raw):
        read,write=os.pipe()
        try:os.write(write,raw)
        finally:os.close(write)
        return read
    def test_exact_supervisor_pipe_delivers_distinct_roles_and_existing_private_root(self):
        root,keys,metadata=child_fixture.read_bootstrap(self.pipe(encoded(self.value)))
        self.assertEqual(root,self.f.f.root);self.assertEqual(len(set(keys)),3);self.assertEqual(metadata,self.f.f.metadata)
    def test_reused_purpose_extra_fields_duplicate_keys_and_foreign_namespace_refuse(self):
        cases=[dict(self.value,control_key=self.value['key']),dict(self.value,PASS=True),dict(self.value,root='/tmp'),
            dict(self.value,metadata={**self.value['metadata'],'unknown':'x'})]
        for value in cases:
            with self.assertRaises((Refused,Unavailable)):child_fixture.read_bootstrap(self.pipe(encoded(value)))
        raw=encoded(self.value);raw=raw[:-1]+b',"version":1}'
        with self.assertRaises(ValueError):child_fixture.read_bootstrap(self.pipe(raw))
    def test_regular_file_cannot_substitute_birth_pipe_or_select_extra_factory(self):
        path=self.f.f.root/'public-fake-bootstrap';path.write_bytes(encoded(self.value));path.chmod(0o600)
        fd=os.open(path,os.O_RDONLY)
        try:
            with self.assertRaises(Refused):child_fixture.read_bootstrap(fd)
        finally:os.close(fd)
        for descriptor in (True,0,-1,1025):
            with self.assertRaises(Refused):child_fixture.read_bootstrap(descriptor)

if __name__=='__main__':unittest.main(verbosity=2)
