"""Owned local source regressions; no native authentication or listener use."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from account_epoch import EpochStore
from authoritative_password import Refused
from dovecot_auth_epoch import EpochPolicyFence
import dovecot_imap_peer as peer
import dovecot_imap_publication as publication
import dovecot_imap_service as service
from operation_budget import OperationBudget

ALICE='alice@example.test'
BOB='bob@example.test'
PID=31415


class PublicationTests(unittest.TestCase):
    def setUp(self):
        scratch=tempfile.TemporaryDirectory(prefix='osmap-imap-source-')
        self.addCleanup(scratch.cleanup)
        self.store=EpochStore(Path(scratch.name),os.getuid())
        self.store.provision(ALICE)
        self.fence=EpochPolicyFence(self.store,frozenset((ALICE,)))

    def body(self,phase,session='PublicSession001'):
        return json.dumps(dict(login=ALICE,protocol='imap',session_id=session,phase=phase,tls=False)).encode()

    def request(self,session='PublicSession001'):
        return json.dumps(dict(login=ALICE,protocol='imap',session_id=session,tls=False,pid=PID)).encode()

    def capture(self,session='PublicSession001'):
        self.assertEqual(self.fence.allow(self.body('before',session)),self.fence.ALLOW)
        self.assertEqual(self.fence.allow(self.body('after',session)),self.fence.ALLOW)

    def test_writer_after_both_allows_invalidates_final_ticket_before_observer(self):
        self.capture()
        with self.store.locked(ALICE)as path:
            value=self.store._read(path);value['epoch']=1;self.store._write(path,value)
        calls=[]
        self.assertFalse(self.fence.publish_imap(self.request(),lambda *_:calls.append(True)or True))
        self.assertEqual(calls,[])
        self.assertFalse(self.fence.publish_imap(self.request(),lambda *_:True))

    def test_registration_holds_exact_writer_lock_and_ticket_is_single_use(self):
        self.capture();observed=[]
        def registration(account,pid,deadline):
            self.assertEqual((account,pid),(ALICE,PID));self.assertGreater(deadline,time.monotonic())
            lock,_=self.store._paths(account);fd=self.store._private(lock,os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            observed.append(True);return True
        self.assertTrue(self.fence.publish_imap(self.request(),registration))
        self.assertFalse(self.fence.publish_imap(self.request(),registration))
        self.assertEqual(observed,[True])
        with self.store.locked(ALICE)as path:self.assertEqual(self.store._read(path)['epoch'],0)

    def test_missing_before_failed_registration_and_expired_original_deadline_refuse(self):
        self.assertFalse(self.fence.publish_imap(self.request(),lambda *_:True))
        self.capture()
        self.assertFalse(self.fence.publish_imap(self.request(),lambda *_:False))
        self.assertFalse(self.fence.publish_imap(self.request(),lambda *_:True))
        self.capture('PublicSession002')
        self.assertFalse(self.fence.publish_imap(self.request('PublicSession002'),lambda *_:True,
                                               original_deadline=time.monotonic()-1))

    def test_wrong_origin_refuses_and_outside_account_is_transparent(self):
        fixture=SimpleNamespace(admit=lambda *_:object(),validate=lambda *_,**kwargs:True)
        endpoint=publication.FixedPublicationEndpoint(self.fence,b'a'*64,fixture)
        self.assertEqual(endpoint.policy(self.body('before'),b'b'*64,'allow'),self.fence.DENY)
        self.assertEqual(endpoint.policy(json.dumps(dict(login=BOB)).encode(),b'a'*64,'allow'),self.fence.ALLOW)
        with self.assertRaises(Refused):endpoint.serve(None,None,None)


class PeerBootstrapTests(unittest.TestCase):
    def test_fixed_kernel_peer_abi_and_malformed_returns(self):
        class Get:
            def __init__(self,pid=PID,uid=101,gid=102,size=12,code=0):
                self.values=(pid,uid,gid,size,code)
            def __call__(self,fd,level,option,dest,size):
                self_case.assertEqual((level,option,size._obj.value),(0xffff,0x1022,12))
                dest._obj.pid,dest._obj.uid,dest._obj.gid,size._obj.value,code=self.values
                return code
        self_case=self
        a,b=socket.socketpair();self.addCleanup(a.close);self.addCleanup(b.close)
        def inspect(call):
            with (patch.object(peer.sys,'platform','openbsd'),
                  patch.object(peer.os,'uname',return_value=SimpleNamespace(
                      sysname='OpenBSD',release='unrestricted',machine='amd64')),
                  patch.object(peer.ctypes,'CDLL',return_value=SimpleNamespace(getsockopt=call))):
                return peer.kernel_peer(a)
        call=Get();self.assertEqual(inspect(call),(PID,101,102))
        self.assertEqual(call.argtypes,[ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)])
        self.assertIs(call.restype,ctypes.c_int)
        for bad in (Get(pid=1),Get(uid=2**32-1),Get(size=8),Get(code=-1)):
            with self.subTest(values=bad.values),self.assertRaises(Refused):inspect(bad)

    def test_submitted_pid_account_and_wrong_kernel_peer_cannot_supply_authority(self):
        inspector=peer.NativeImapPeerInspector.__new__(peer.NativeImapPeerInspector)
        inspector._accounts=frozenset((ALICE,))
        a,b=socket.socketpair();self.addCleanup(a.close);self.addCleanup(b.close)
        identity=peer.NativeSmtpPeerInspector._identity(os.fstat(a.fileno()));end=time.monotonic()+.5
        binding=peer._PeerBinding(inspector,a,a.fileno(),identity,(PID,101,102),(),(),None,end)
        with (patch.object(inspector,'_snapshot',return_value=((),()))as snapshot,
              patch.object(peer,'kernel_peer',return_value=(PID,101,102))):
            self.assertTrue(inspector.validate(binding,a,PID,ALICE,end))
            self.assertFalse(inspector.validate(binding,a,PID+1,ALICE,end))
            self.assertFalse(inspector.validate(binding,a,PID,BOB,end))
            self.assertEqual(snapshot.call_count,1)
        with tempfile.TemporaryDirectory(prefix='osmap-imap-peer-')as temp:
            store=EpochStore(Path(temp),os.getuid());store.provision(ALICE)
            endpoint=publication.FixedPublicationEndpoint(EpochPolicyFence(store,frozenset((ALICE,))),b'a'*64,inspector)
            stream=SimpleNamespace(recv=lambda *_:self.fail('wrong peer read'),
                sendall=lambda *_:self.fail('wrong peer reply'),close=lambda:closed.append(True))
            closed=[]
            with patch.object(peer,'kernel_peer',return_value=(PID,0,102)),self.assertRaises(Refused):
                endpoint.connection(stream,'final')
            self.assertEqual(closed,[True])

    def test_text_pcb_and_registration_acknowledgements_are_exact(self):
        binary=(os.makedev(4,2),123,0,0,0o100555)
        raw=(b'USER CMD PID FD DEV INUM MODE R/W SZ|DV\n'
             b'vmail imap 31415 text 4,2 123 100555 r 100\n'
             b'vmail imap 31415 8* unix stream 0xabc <-> 0xdef\n')
        self.assertEqual(peer.NativeImapPeerInspector._descriptors(raw,PID,'imap',binary),{8:(0xabc,0xdef)})
        for bad in (raw.replace(b'123 ',b'124 '),raw+raw.splitlines(keepends=True)[-1],raw.replace(b'0xabc',b'0x0')):
            with self.subTest(raw=bad),self.assertRaises(Refused):peer.NativeImapPeerInspector._descriptors(bad,PID,'imap',binary)
        header=publication.MailSessionContainment.WHO_HEADER
        row=b'alice@example.test\t1\timap\t(31415)\t(127.0.0.1)\n'
        with patch.object(publication,'bounded_who',return_value=(0,header+row,b'')):
            self.assertTrue(publication.observed_imap_registration(ALICE,PID,time.monotonic()+.5))
        for result in ((0,header+row.replace(b'alice@',b'bob@'),b''),
                       (0,header+row.replace(b'31415',b'31416'),b''),
                       (0,header+row.replace(b'\t1\t',b'\t2\t'),b''),(0,header+row,b'error'),(1,header+row,b'')):
            with self.subTest(result=result),patch.object(publication,'bounded_who',return_value=result):
                self.assertFalse(publication.observed_imap_registration(ALICE,PID,time.monotonic()+.5))

    def test_private_bootstrap_scope_changes_and_writerless_key_fifo_refuse(self):
        budget=OperationBudget(int(time.time())+5,maximum_seconds=5)
        with patch.object(service._Startup,'_read',side_effect=AssertionError('closed native read')):
            with self.assertRaises(Refused):service.PublicationService.native(budget)
        with tempfile.TemporaryDirectory(prefix='osmap-imap-bootstrap-',dir=str(Path.home()))as temp:
            root=Path(temp);root.chmod(0o700)
            config=dict(version=1,authority=service.AUTHORITY,purpose='osmap-account-mutation',
                        accounts=[ALICE],trusted_relay_uid=101)
            purpose=dict(version=1,authority=service.AUTHORITY,purpose=service.PURPOSE,master_pid=77,connector_gid=102)
            def write(name,value):
                path=root/name;path.write_bytes(value);path.chmod(0o600)
            write('config.json',json.dumps(config).encode())
            write('mutation.key',b'a'*64);write('session-proof.key',b'b'*64)
            write('imap-publication.json',json.dumps(purpose).encode());write('imap-policy.key',b'c'*64)
            startup=service._Startup._read(root,os.getuid(),budget)
            self.assertEqual(startup.bootstrap.accounts,frozenset((ALICE,)))
            config['accounts']=[BOB];write('config.json',json.dumps(config).encode())
            with self.assertRaises(Refused):startup.recheck(budget)
            config['accounts']=[ALICE];write('config.json',json.dumps(config).encode())
            (root/'imap-policy.key').unlink();os.mkfifo(root/'imap-policy.key',0o600)
            began=time.monotonic()
            with self.assertRaises(Refused):service._Startup._read(root,os.getuid(),budget)
            self.assertLess(time.monotonic()-began,.5)


class RetainedOwnershipTests(unittest.TestCase):
    def exercise(self,fail):
        released=threading.Event();entered=threading.Event();observed=threading.Event();errors=[];signals=[]
        class Child:
            stdin=stdout=stderr=None
            def poll(self):observed.set();return 0 if released.is_set()else None
            def wait(self,*_,**kwargs):raise AssertionError('request deadline renewed by wait')
            def kill(self):raise AssertionError('late kill after original deadline')
        child=Child();retained=[]
        class Running:
            def serve(self,stop,budget):
                retained.append(child);peer._MetadataExecutor._quarantined=True
                stop.set();entered.set()
                if fail:raise Refused('synthetic failed request already ended')
                return 0
        def run():
            try:service.main()
            except Exception as error:errors.append(type(error))
        with (patch.object(peer._MetadataExecutor,'_retained',retained),
              patch.object(peer._MetadataExecutor,'_quarantined',False),
              patch.object(subprocess,'Popen',Child),
              patch.object(service.PublicationService,'native',return_value=Running()),
              patch.object(service.sys,'argv',['dovecot_imap_service.py']),
              patch.object(service.os,'getuid',return_value=0),patch.object(service.os,'geteuid',return_value=0),
              patch.object(service.os,'getpgrp',side_effect=lambda:os.getpid()),
              patch.object(service.os,'getsid',side_effect=lambda _pid:os.getpid()),
              patch.object(service.os,'setsid',side_effect=AssertionError('session mutation in unit test')),
              patch.object(service.os,'killpg',side_effect=AssertionError('stale group signal')),
              patch.object(service.resource,'setrlimit'),
              patch.object(service.signal,'getsignal',return_value=service.signal.SIG_DFL),
              patch.object(service.signal,'signal',side_effect=lambda sig,handler:signals.append((sig,handler))or service.signal.SIG_DFL),
              patch.object(service,'OperationBudget',wraps=OperationBudget)as budgets):
            thread=threading.Thread(target=run);thread.start()
            try:
                self.assertTrue(entered.wait(.5));self.assertTrue(observed.wait(.5))
                self.assertTrue(thread.is_alive(),'owner exited with retained child')
                self.assertEqual(retained,[child]);self.assertEqual(len(signals),2,'handlers restored before reap')
                self.assertEqual(budgets.call_count,1,'new cleanup budget minted')
            finally:
                released.set();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertEqual(retained,[])
            self.assertTrue(peer._MetadataExecutor._quarantined,'quarantine was reset')
            self.assertEqual(len(signals),4)
        self.assertEqual(errors,[Refused]if fail else [])

    def test_failed_request_retains_owner_until_reap_without_new_deadline_or_signal(self):self.exercise(True)
    def test_graceful_stop_cannot_discard_retained_child(self):self.exercise(False)


if __name__=='__main__':unittest.main()
