"""Public private-file source fixtures; no native SQL/mail/topology qualification."""
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from account_epoch import EpochStore, PasswordCoordinator
from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed, Snapshot
from mail_session_containment import (MailSessionContainment, SmtpTerminationScope,
    OperatorOwnedProxyNamespace, OperatorOwnedSmtpTopology, SmtpProxyControl,
    TopologyExecutor, build_native_containment)
from operation_budget import OperationBudget

ACCOUNT = 'alice@example.test'
CURRENT = 'public old fixture'
NEW = 'long public new fixture'
HASH = '{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$' + 'A'*22 + '$' + 'B'*43
OLD = '{BLF-CRYPT}$2b$12$' + 'A'*53
HEADER = b'username proto src ip dest ip port\n'
OWN = b'alice@example.test submission 127.0.0.1 127.0.0.1 2525\n'
BOB = b'bob@example.test submission 127.0.0.1 127.0.0.1 2525\n'


class Clock:
    def __init__(self): self.now = 1000
    def __call__(self): return self.now


class RequiredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='osmap-required-source-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        (self.root/'epochs').mkdir(mode=0o700)
        (self.root/'run').mkdir(mode=0o700); (self.root/'run/login').mkdir(mode=0o700)
        self.config = self.root/'dovecot.conf'
        self.config.write_bytes(b'# synthetic qualified topology fixture only\n'); self.config.chmod(0o600)
        self.socket = socket.socket(socket.AF_UNIX); self.addCleanup(self.socket.close)
        self.socket.bind(str(self.root/'run/login/ipc-proxy')); (self.root/'run/login/ipc-proxy').chmod(0o600)
        self.namespace = OperatorOwnedProxyNamespace(self.root, os.getuid(), '127.0.0.1', 2525)
        self.clock = Clock(); self.budget = OperationBudget(1300, monotonic=self.clock, wall=self.clock)
        self.metadata = {('-M',): b'public fixed master profile\n', ('-P',): b'public fixed overrides\n',
                         ('-h', 'smtpd_sasl_auth_enable'): b'yes\n'}
        self.certificate = {'version':1, 'namespace_fingerprint':self.namespace._fingerprint,
            'backend_address':'127.0.0.1', 'backend_port':2525,
            'entrypoints':[{'address':'127.0.0.1','port':587,'service':'submission'},
                           {'address':'127.0.0.1','port':465,'service':'submission'}],
            'metadata_sha256':{name:hashlib.sha256(self.metadata[args]).hexdigest()
                for name,args in OperatorOwnedSmtpTopology.COMMANDS.items()}}
        self.certpath = self.root/'smtp-topology.json'; self.publish()
        self.calls = []; self.proxy_results = [(0,HEADER+OWN+BOB,b''), (0,b'1 connections kicked\n',b''),
                                               (0,HEADER+BOB,b'')]
        self.imap_results = [(0,MailSessionContainment.WHO_HEADER,b''),
                            (0,b'0 cache entries flushed\n',b''),
                            (68,b'no users kicked\n',b''), (0,MailSessionContainment.WHO_HEADER,b'')]
        self.sql_updates = 0; self.hash_hook = None; self.flush_hook = None

    def publish(self):
        self.certpath.write_text(json.dumps(self.certificate)); self.certpath.chmod(0o600)

    def probe(self, program, args, data, seconds, limit):
        self.assertEqual((program,data,limit),('/usr/local/sbin/postconf',b'',16384))
        self.assertLessEqual(seconds,10); self.calls.append(('topology',args))
        return 0,self.metadata[args],b''

    def proxy(self, program, args, data, seconds, limit):
        self.calls.append(('proxy',args)); result = self.proxy_results.pop(0)
        if isinstance(result,Exception): raise result
        return result

    def imap(self, program, args, data, seconds, limit):
        self.calls.append(('imap',args)); result = self.imap_results.pop(0)
        if args[0]=='auth' and self.flush_hook: self.flush_hook()
        return result

    def composed(self):
        topology = OperatorOwnedSmtpTopology(self.namespace,self.probe,self.budget)
        proxy = SmtpProxyControl(ACCOUNT,self.namespace,self.proxy,self.budget)
        return MailSessionContainment(ACCOUNT,self.imap,self.budget,SmtpTerminationScope.REQUIRED,
                                     proxy_control=proxy,topology=topology)

    def sql(self, program, args, data, seconds, limit):
        if program == AuthoritativePasswordAdapter.HASH_PROGRAM:
            self.calls.append(('hash',()))
            if self.hash_hook: self.hash_hook()
            return 0,(HASH+'\n').encode(),b''
        self.assertEqual(program,AuthoritativePasswordAdapter.SQL_PROGRAM)
        if data.startswith(b'SELECT HEX(password)'):
            return 0,(OLD.encode().hex().upper()+'\t20261004170000\t1\t1\n').encode(),b''
        self.assertTrue(data.startswith(b'START TRANSACTION;\nUPDATE mailbox'))
        self.sql_updates += 1; self.calls.append(('write',()))
        return 0,('1\n'+HASH.encode().hex().upper()+'\t20261004170100\n').encode(),b''

    def coordinator(self, dependency):
        epoch = self.root/'epochs'
        store = EpochStore(epoch,os.getuid()); store.provision(ACCOUNT)
        adapter = AuthoritativePasswordAdapter(self.sql,before_write=dependency.before_write)
        coordinator = PasswordCoordinator(store,adapter,lambda *a:True,
            lambda *a:self.calls.append(('new-auth',())) or True,
            dependency.ready,dependency.finish,dependency.invalidate_changed_auth)
        return store,coordinator

    def change(self, coordinator, intent='a'*64):
        return coordinator.change(ACCOUNT,0,intent,CURRENT,NEW,NEW,'synthetic factor',1000)

    def test_required_complete_composition_order_exact_alice_bob_preserved(self):
        dependency = self.composed(); store,coordinator = self.coordinator(dependency)
        self.assertEqual(self.change(coordinator),(1,'20261004170100'))
        self.assertEqual(store.admission(ACCOUNT),(1,'20261004170100')); self.assertEqual(self.sql_updates,1)
        meaningful = [kind if kind not in ('proxy','imap') else (kind,args)
                      for kind,args in self.calls if kind!='topology']
        self.assertEqual([item[0] for item in meaningful if isinstance(item,tuple)],
                         ['proxy','imap','imap','proxy','proxy','imap','imap'])
        self.assertLess(meaningful.index('write'), meaningful.index(('imap',dependency.commands(ACCOUNT)['flush'])))
        self.assertLess(meaningful.index(('imap',dependency.commands(ACCOUNT)['flush'])),meaningful.index('new-auth'))
        kicks = [args for kind,args in self.calls if kind in ('imap','proxy') and 'kick' in args]
        self.assertEqual(len(kicks),2); self.assertTrue(all(args[-1]==ACCOUNT for args in kicks))
        self.assertTrue(all('*' not in args and '-f' not in args for args in kicks))
        self.assertEqual(self.proxy_results,[])
        with self.assertRaises(Refused): self.change(coordinator,'b'*64)
        self.assertEqual(self.sql_updates,1)

    def test_attached_proxy_without_authority_zero_read_or_write(self):
        proxy=SmtpProxyControl(ACCOUNT,self.namespace,self.proxy,self.budget)
        dependency=MailSessionContainment(ACCOUNT,self.imap,self.budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy)
        store,coordinator=self.coordinator(dependency)
        before=next((self.root/'epochs').glob('*.json')).read_bytes()
        with self.assertRaises(Refused): self.change(coordinator)
        self.assertEqual(next((self.root/'epochs').glob('*.json')).read_bytes(),before)
        self.assertEqual(self.calls,[]); self.assertEqual(self.sql_updates,0)

    def test_namespace_change_during_hash_refuses_before_sql_preserves_epoch(self):
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        self.hash_hook=lambda:self.config.write_bytes(b'# changed during hash\n')
        with self.assertRaises(Refused): self.change(coordinator)
        self.assertEqual(store.admission(ACCOUNT),(0,None)); self.assertEqual(self.sql_updates,0)
        value=json.loads(next((self.root/'epochs').glob('*.json')).read_text())
        self.assertEqual((value['state'],len(value['used_intents'])),('active',1))

    def test_coverage_change_before_ready_zero_sql_and_unchanged_epoch_record(self):
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        path=next((self.root/'epochs').glob('*.json')); before=path.read_bytes()
        self.certificate['entrypoints'].pop(); self.publish()
        with self.assertRaises(Refused): self.change(coordinator)
        self.assertEqual(path.read_bytes(),before); self.assertEqual(self.sql_updates,0)

    def test_postwrite_topology_change_contained_and_never_repeat_sql(self):
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        self.flush_hook=lambda:self.metadata.update({('-M',):b'changed actual metadata\n'})
        with self.assertRaises(Unconfirmed): self.change(coordinator)
        with self.assertRaises(Refused): store.admission(ACCOUNT)
        with self.assertRaises(Refused): self.change(coordinator,'b'*64)
        self.assertEqual(self.sql_updates,1)
        self.assertFalse(any(kind=='proxy' and 'kick' in args for kind,args in self.calls))

    def test_partial_smtp_kick_keeps_account_contained_no_second_write(self):
        self.proxy_results[-1]=(0,HEADER+OWN+BOB,b'')
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        with self.assertRaises(Unconfirmed): self.change(coordinator)
        with self.assertRaises(Refused): store.admission(ACCOUNT)
        with self.assertRaises(Refused): self.change(coordinator,'b'*64)
        self.assertEqual(self.sql_updates,1)
        self.assertEqual(sum(kind=='proxy' and 'kick' in args for kind,args in self.calls),1)
        self.assertEqual(sum(kind=='imap' and 'kick' in args for kind,args in self.calls),0)

    def test_imap_refusal_after_smtp_success_contained(self):
        self.imap_results[-1]=(0,MailSessionContainment.WHO_HEADER+ACCOUNT.encode()+b'\t1\timap\t(1)\t(127.0.0.1)\n',b'')
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        with self.assertRaises(Unconfirmed): self.change(coordinator)
        with self.assertRaises(Refused): store.admission(ACCOUNT)
        self.assertEqual(self.sql_updates,1); self.assertEqual(self.proxy_results,[])

    def test_exact_budget_final_metadata_callback_cannot_renew(self):
        dependency=self.composed(); dependency.ready(ACCOUNT)
        original=self.probe
        def late(*args):
            value=original(*args); self.clock.now=1060; return value
        dependency._topology._execute=late
        with self.assertRaises(Refused): dependency.before_write(ACCOUNT)
        self.assertEqual(self.sql_updates,0)

    def test_foreign_account_budget_namespace_and_unknown_scope_refuse(self):
        dependency=self.composed()
        with self.assertRaises(Refused): dependency.ready('bob@example.test')
        with self.assertRaises(Refused): dependency._topology.recheck(OperationBudget(1300,monotonic=self.clock,wall=self.clock))
        dependency._smtp_scope=SmtpTerminationScope.UNKNOWN
        with self.assertRaises(Refused): dependency.ready(ACCOUNT)

    def test_empty_duplicate_foreign_untyped_coverage_refused(self):
        original=json.loads(json.dumps(self.certificate))
        for mutate in [lambda v:v.update(entrypoints=[]),
                       lambda v:v['entrypoints'].append(v['entrypoints'][0]),
                       lambda v:v.update(namespace_fingerprint='a'*64),
                       lambda v:v.update(backend_port=True),
                       lambda v:v['entrypoints'][0].update(port=True)]:
            self.certificate=json.loads(json.dumps(original)); mutate(self.certificate); self.publish()
            with self.assertRaises(Refused): self.composed()
        self.assertEqual(self.calls,[])

    def test_private_certificate_symlink_hardlink_permissions_replacement(self):
        for mode in (0o644,0o666):
            self.certpath.chmod(mode)
            with self.assertRaises(Refused): self.composed()
        self.certpath.chmod(0o600)
        link=self.root/'link'; os.link(self.certpath,link)
        with self.assertRaises(Refused): self.composed()
        link.unlink(); topology=OperatorOwnedSmtpTopology(self.namespace,self.probe,self.budget)
        moved=self.root/'old'; self.certpath.rename(moved); self.publish()
        with self.assertRaises(Refused): topology.recheck(self.budget)
        self.certpath.unlink(); self.certpath.symlink_to(moved)
        with self.assertRaises(Refused): self.composed()

    def test_fixed_topology_commands_native_factory_remains_unavailable(self):
        executor=TopologyExecutor(self.budget)
        for program,args,data,seconds,limit in [('/bin/sh',('-M',),b'',10,16384),
                ('/usr/local/sbin/postconf',('-e','a=b'),b'',10,16384),
                ('/usr/local/sbin/postconf',('-M',),b'input',10,16384),
                ('/usr/local/sbin/postconf',('-M',),b'',True,16384)]:
            with patch('subprocess.Popen') as child:
                with self.assertRaises(Refused): executor(program,args,data,seconds,limit)
                child.assert_not_called()
        with patch('pathlib.Path.lstat') as files:
            with self.assertRaises(Refused): build_native_containment(ACCOUNT,self.budget)
            files.assert_not_called()

    def test_no_overrides_does_not_infer_no_smtp_or_accept_empty_coverage(self):
        self.metadata[('-P',)]=b''
        self.certificate['metadata_sha256']['services']=hashlib.sha256(b'').hexdigest(); self.publish()
        dependency=self.composed(); dependency.ready(ACCOUNT)
        self.assertEqual(sum(kind=='proxy' for kind,args in self.calls),1)

    def test_bad_metadata_type_output_stderr_and_late_return_refuse(self):
        for result in [(True,self.metadata[('-M',)],b''), (0,b'x'*16385,b''),
                       (0,self.metadata[('-M',)],b'private fixture diagnostic'),
                       (0,b'',b''), (0,b'changed',b'')]:
            with self.assertRaises(Refused):
                OperatorOwnedSmtpTopology(self.namespace,lambda *a:result,self.budget)

    def test_duplicate_certificate_fields_refuse_without_metadata_probe(self):
        self.certpath.write_text('{"version":1,"version":1}')
        with self.assertRaises(Refused): self.composed()
        self.assertEqual(self.calls,[])

    def test_smtp_bad_ack_is_uncertain_not_success_even_empty_registry(self):
        self.proxy_results[1]=(0,b'no matching registry rows\n',b'')
        dependency=self.composed(); store,coordinator=self.coordinator(dependency)
        with self.assertRaises(Unconfirmed): self.change(coordinator)
        with self.assertRaises(Refused): store.admission(ACCOUNT)
        self.assertEqual(self.sql_updates,1)
        self.assertEqual(sum(kind=='proxy' and 'kick' in args for kind,args in self.calls),1)

    def test_late_smtp_ack_is_contained_on_original_budget(self):
        original=self.proxy
        def late(program,args,*rest):
            value=original(program,args,*rest)
            if 'kick' in args: self.clock.now=1060
            return value
        dependency=self.composed(); dependency._proxy_control._execute=late
        store,coordinator=self.coordinator(dependency)
        with self.assertRaises(Unconfirmed): self.change(coordinator)
        with self.assertRaises(Refused): store.admission(ACCOUNT)
        self.assertEqual(self.sql_updates,1)


if __name__=='__main__': unittest.main()
