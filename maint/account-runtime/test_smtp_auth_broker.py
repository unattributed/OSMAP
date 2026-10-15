"""Three changed broker boundaries, synthetic backend and real local descriptors.

No operator keys, provider, production listener or native qualification.
"""
import base64
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch

from account_mutation_supervisor import _Bootstrap,AUTHORITY,PURPOSE
from authoritative_password import Refused
from operation_budget import OperationBudget
from smtp_control_startup import ControlStartup
import smtp_auth_broker as broker
import smtp_native_peer as native
import test_smtp_native_peer as peer_fixtures
import test_smtp_control_service as control_fixtures


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.peer=peer_fixtures.PerChannelOwnershipTests('runTest');self.peer.setUp();self.addCleanup(self.peer.doCleanups)
        self.case=self.peer.case;self.fixture=self.peer.fixture
        self.ownership=native.NativeSmtpOwnership._read(self.peer.inspector,self.case.routing)
        root=self.case.f.root/'broker-keys';root.mkdir(mode=0o700)
        boot=_Bootstrap(control_fixtures.KEY,control_fixtures.SESSION_KEY,self.case.authority.accounts,os.getuid())
        config={'version':1,'authority':AUTHORITY,'purpose':PURPOSE,'accounts':sorted(boot.accounts),'trusted_relay_uid':os.getuid()}
        for name,raw in (('config.json',json.dumps(config).encode()),('mutation.key',boot.mutation_key),('session-proof.key',boot.session_key),('smtp-control.key',control_fixtures.CONTROL_KEY)):
            p=root/name;p.write_bytes(raw);p.chmod(0o600)
        self.startup=ControlStartup._read(boot,root,os.getuid(),self.peer.budget)
        parent=self.case.f.root/'broker-backend';parent.mkdir(mode=0o700)
        self.path=parent/'auth.sock';self.listener=socket.socket(socket.AF_UNIX);self.addCleanup(self.listener.close)
        self.listener.bind(str(self.path));self.path.chmod(0o600);self.listener.listen(1)
        self.backend=broker.PrivateSmtpBackend(self.path,os.getuid(),(os.getuid(),os.getgid()))
        self.service=broker.AuthBroker._compose(self.startup,self.fixture.store,self.case.journal,self.case.routing,self.ownership,self.backend)
        self.fixture.registry=self.service.registry
        self.auth_frames=[];self.backend_errors=[];self.closed=threading.Event()

    def budget(self):
        value=OperationBudget(int(time.time())+3,maximum_seconds=3)
        owned=patch.object(value,'inherited_group',return_value=True);owned.start();self.addCleanup(owned.stop)
        self.peer.budget=value
        return value

    @staticmethod
    def line(stream):
        out=bytearray()
        while not out.endswith(b'\n'):
            part=stream.recv(1)
            if not part:return bytes(out)
            out.extend(part)
        return bytes(out)

    def backend_start(self):
        def run():
            try:
                stream,_=self.listener.accept()
                with stream:
                    stream.settimeout(1)
                    version=self.line(stream)
                    if not version:return
                    self.assertEqual(version,b'VERSION\t1\t0\n')
                    self.assertEqual(self.line(stream),b'CPID\t123\n')
                    stream.sendall(b'VERSION\t1\t0\nMECH\tPLAIN\tplaintext\nSPID\t1234\nCUID\t1\nCOOKIE\tpublic-synthetic-cookie\nDONE\n')
                    raw=self.line(stream)
                    if not raw:return
                    self.assertEqual(len(self.service.registry._channels),1,'credentials forwarded before shared registration')
                    self.auth_frames.append(raw)
                    stream.sendall(b'OK\t1\tuser='+control_fixtures.fixtures.ALICE.encode()+b'\n')
                    self.assertEqual(stream.recv(1),b'')
            except Exception as error:self.backend_errors.append(type(error).__name__)
            finally:self.closed.set()
        thread=threading.Thread(target=run);thread.start();self.addCleanup(lambda:thread.join(2));return thread

    def accepted(self):
        server,front=socket.socketpair();self.addCleanup(server.close);self.addCleanup(front.close)
        auth=base64.b64encode(b'\0'+control_fixtures.fixtures.ALICE.encode()+b'\0public synthetic phrase')
        front.sendall(b'VERSION\t1\t0\nCPID\t123\nAUTH\t1\tPLAIN\tservice=smtp\tresp='+auth+b'\n')
        return server,front

    def test_real_accepted_channel_actual_backend_ok_stays_shared_for_pending_cutoff(self):
        thread=self.backend_start();server,front=self.accepted()
        originals=[];connect=self.service.backend.connect
        def connected(budget):
            stream=connect(budget);originals.append(stream);return stream
        with patch.object(self.service.backend,'connect',side_effect=connected):
            channel=self.service.connection(server,self.budget())
        self.assertEqual(server.fileno(),-1);self.assertTrue(originals and all(s.fileno()==-1 for s in originals))
        self.addCleanup(self.service.registry.close,channel)
        self.assertIs(self.service.supervisor._registry,self.service.registry)
        self.assertIn(channel,self.service.registry._channels);self.assertTrue(channel.published)
        self.assertEqual(len(self.auth_frames),1);self.assertFalse(self.closed.is_set())
        front.settimeout(.2);received=front.recv(4096)
        self.assertIn(b'OK\t1\tuser='+control_fixtures.fixtures.ALICE.encode()+b'\n',received)
        self.fixture.state()
        with self.fixture.store.locked(control_fixtures.fixtures.ALICE):
            cutoff=self.service.supervisor._registry.pending_cutoff_locked(control_fixtures.fixtures.ALICE,self.case.fixture.budget)
            self.assertEqual(self.service.supervisor._registry.cancel_cutoff_locked(cutoff,self.case.fixture.budget),1)
        self.assertTrue(self.closed.wait(1));thread.join(1)
        self.assertEqual(self.backend_errors,[]);self.assertTrue(channel.closed)
        self.assertEqual(front.recv(1),b'')

    def test_pending_epoch_refuses_before_backend_credential_dispatch(self):
        self.fixture.state();thread=self.backend_start();server,_=self.accepted()
        with self.assertRaises(Refused):self.service.connection(server,self.budget())
        self.assertTrue(self.closed.wait(1));thread.join(1)
        self.assertEqual(self.auth_frames,[]);self.assertEqual(self.service.registry._channels,set())

    def test_unknown_native_backend_and_wrong_kernel_peer_refuse_before_protocol(self):
        with patch.object(broker,'BACKEND_BIND_PEER',None),patch.object(broker.os,'geteuid',return_value=0),patch.object(broker.PrivateSmtpBackend,'_current',side_effect=AssertionError):
            with self.assertRaises(Refused):broker.PrivateSmtpBackend.native(self.peer.budget)
            with patch.object(broker.lifecycle,'NATIVE_AUTH_BROKER_QUALIFIED',True),patch.object(broker.control,'NATIVE_CONTROL_SERVICE_QUALIFIED',True):
                with self.assertRaises(Refused):broker.AuthBroker.native(self.peer.budget)
        wrong=broker.PrivateSmtpBackend(self.path,os.getuid(),(os.getuid()+1,os.getgid()))
        self.service=broker.AuthBroker._compose(self.startup,self.fixture.store,self.case.journal,self.case.routing,self.ownership,wrong)
        thread=self.backend_start();server,_=self.accepted()
        with self.assertRaises(Refused):self.service.connection(server,self.budget())
        self.assertTrue(self.closed.wait(1));thread.join(1)
        self.assertEqual(self.auth_frames,[]);self.assertEqual(self.backend_errors,[])


class AcceptorTests(unittest.TestCase):
    setUp=BrokerTests.setUp
    budget=BrokerTests.budget
    line=staticmethod(BrokerTests.line)
    backend_start=BrokerTests.backend_start

    def prepare_listener(self):
        parent=self.case.f.root/'broker-control';parent.mkdir(mode=0o700)
        self.service.control_listener=broker.control.PrivateControlListener(parent/'control.sock',os.getuid(),self.service.supervisor)
        parent=self.case.f.root/'broker-front';parent.mkdir(mode=0o700)
        return parent/'osmap-account-smtp-auth'

    def test_actual_control_listen_barrier_one_auth_and_stop_remove_only_owned_endpoints(self):
        path=self.prepare_listener();stop=threading.Event();control_entered=threading.Event();control_release=threading.Event();front_ready=threading.Event();results=[]
        actual=socket.socket.listen
        def listen(stream,*args):
            if stream.getsockname()==str(self.service.control_listener.path):
                control_entered.set();self.assertTrue(control_release.wait(1))
            result=actual(stream,*args)
            if stream.getsockname()==str(path):front_ready.set()
            return result
        startup=self.budget()
        def run():
            try:results.append(self.service._serve(path,os.getuid(),stop,startup))
            except BaseException as error:results.append(type(error).__name__)
        with patch.object(socket.socket,'listen',listen),patch.object(self.service,'_authentication_budget',side_effect=self.budget)as mint:
            worker=threading.Thread(target=run);worker.start();self.addCleanup(stop.set);self.addCleanup(lambda:worker.join(2))
            self.assertTrue(control_entered.wait(1));self.assertFalse(path.exists());mint.assert_not_called()
            control_release.set();self.assertTrue(front_ready.wait(1));self.service.control_listener.recheck()
            backend_thread=self.backend_start()
            front=socket.socket(socket.AF_UNIX);self.addCleanup(front.close);front.settimeout(1);front.connect(str(path))
            auth=base64.b64encode(b'\0'+control_fixtures.fixtures.ALICE.encode()+b'\0public synthetic phrase')
            front.sendall(b'VERSION\t1\t0\nCPID\t123\nAUTH\t1\tPLAIN\tservice=smtp\tresp='+auth+b'\n')
            expected=b'OK\t1\tuser='+control_fixtures.fixtures.ALICE.encode()+b'\n';raw=bytearray()
            while not raw.endswith(expected):raw.extend(front.recv(4096))
            mint.assert_called_once();self.assertEqual(len(self.auth_frames),1)
            stop.set();worker.join(2);self.assertFalse(worker.is_alive());backend_thread.join(1)
        self.assertEqual(results,[1]);self.assertTrue(self.closed.is_set());self.assertEqual(self.backend_errors,[])
        self.assertEqual(self.service.registry._channels,set());self.assertFalse(path.exists());self.assertFalse(self.service.control_listener.path.exists())
        self.assertEqual(front.recv(1),b'')

    def test_preexisting_front_or_unprotected_parent_refuses_before_listener_or_auth(self):
        path=self.prepare_listener();path.write_bytes(b'public foreign preimage');path.chmod(0o600)
        with patch('socket.socket',side_effect=AssertionError),patch.object(self.service,'_authentication_budget',side_effect=AssertionError):
            with self.assertRaises(Refused):self.service._serve(path,os.getuid(),threading.Event(),self.budget())
        self.assertEqual(path.read_bytes(),b'public foreign preimage');self.assertFalse(self.service.control_listener.path.exists())
        path.unlink();path.parent.chmod(0o777)
        try:
            with patch('socket.socket',side_effect=AssertionError):
                with self.assertRaises(Refused):self.service._serve(path,os.getuid(),threading.Event(),self.budget())
            self.assertFalse(path.exists());self.assertFalse(self.service._serving.locked())
        finally:path.parent.chmod(0o700)


class NativeFactoryGateTests(unittest.TestCase):
    def test_each_existing_routing_gate_refuses_before_native_private_dependencies(self):
        budget=OperationBudget(int(time.time())+3,maximum_seconds=3)
        for routing,topology in ((False,True),(True,False)):
            with self.subTest(routing=routing,topology=topology),patch.object(broker.lifecycle,'NATIVE_AUTH_BROKER_QUALIFIED',True),patch.object(broker.control,'NATIVE_CONTROL_SERVICE_QUALIFIED',True),patch.object(broker,'BACKEND_BIND_PEER',(0,0)),patch.object(broker.routing_bootstrap,'NATIVE_ROUTING_BOOTSTRAP_QUALIFIED',routing),patch.object(broker.containment,'NATIVE_SMTP_TOPOLOGY_QUALIFIED',topology),patch.object(broker.PrivateSmtpBackend,'native',side_effect=AssertionError),patch.object(broker._Bootstrap,'native',side_effect=AssertionError):
                with self.assertRaises(Refused):broker.AuthBroker.native(budget)


class FrontContractTests(unittest.TestCase):
    def test_root_purpose_parent_admitted_but_actual_postfix_private_owner_refused(self):
        from types import SimpleNamespace
        purpose=Path('/var/spool/postfix/osmap-account-smtp/auth.sock')
        private=Path('/var/spool/postfix/private/auth.sock')
        self.assertEqual(broker.FRONT_SOCKET,purpose)
        def metadata(path):
            uid=507 if path==private.parent else 0
            mode=0o40710 if path==purpose.parent else (0o40700 if path==private.parent else 0o40755)
            return SimpleNamespace(st_dev=1,st_ino=2,st_uid=uid,st_gid=507 if path==purpose.parent else 0,st_mode=mode,st_nlink=2)
        with patch.object(Path,'resolve',lambda self,strict=False:self),patch.object(Path,'lstat',metadata):
            captured=broker.AuthBroker._front_parent(purpose,0)
            self.assertEqual(captured[0][1][2:5],(0,507,0o40710))
            with self.assertRaises(Refused):broker.AuthBroker._front_parent(private,0)


class TypedProfileTests(unittest.TestCase):
    setUp=BrokerTests.setUp

    def test_existing_typed_exact_port_profile_only_and_default_stays_strict(self):
        self.assertEqual(self.service.registry._authority._ok_fields,())
        args=(self.startup,self.fixture.store,self.case.journal,self.case.routing,self.ownership,self.backend)
        for profile in (True,object(),broker.lifecycle.DovecotProxyOkProfile(2526)):
            with self.subTest(kind=type(profile).__name__):
                with self.assertRaises(Refused):broker.AuthBroker._compose(*args,ok_profile=profile)
        value=broker.AuthBroker._compose(*args,ok_profile=broker.lifecycle.DovecotProxyOkProfile(2525))
        self.assertEqual(value.registry._authority._ok_fields,(b'proxy',b'host=127.0.0.1',b'port=2525',b'ssl=yes'))
        self.assertIs(value.supervisor._registry,value.registry)


if __name__=='__main__':unittest.main(verbosity=2)
