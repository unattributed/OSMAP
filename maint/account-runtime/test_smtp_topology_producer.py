"""Owned public source fixtures; no native routing/SQL/termination qualification."""
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import mail_session_containment as containment
from authoritative_password import Refused, AuthoritativePasswordAdapter, Snapshot
from operation_budget import OperationBudget
from smtp_topology import FixedSmtpRouting


class Clock:
    def __init__(self): self.now = 1000
    def __call__(self): return self.now


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='osmap-topology-producer-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.planroot = self.root/'bootstrap'; self.planroot.mkdir(mode=0o700)
        self.namespace = self.root/'proxy'; self.namespace.mkdir(mode=0o700)
        (self.namespace/'run').mkdir(mode=0o700); (self.namespace/'run/login').mkdir(mode=0o700)
        self.config = self.namespace/'dovecot.conf'
        self.config.write_bytes(b'# public synthetic namespace only\n'); self.config.chmod(0o600)
        self.sock = socket.socket(socket.AF_UNIX); self.addCleanup(self.sock.close)
        self.sock.bind(str(self.namespace/'run/login/ipc-proxy'))
        (self.namespace/'run/login/ipc-proxy').chmod(0o600)
        self.clock = Clock(); self.budget = OperationBudget(1300, monotonic=self.clock, wall=self.clock)
        self.master = b'127.0.0.1:2525 inet n - n - - smtpd\nsmtpd pass - - n - - smtpd\n'
        self.services = b'127.0.0.1:2525/inet/smtpd_sasl_auth_enable = yes\n'
        self.frontend = (b'listen = 127.0.0.1\nservice submission-login {\n'
            b'  inet_listener submission {\n    port = 587\n  }\n'
            b'  inet_listener submissions {\n    port = 465\n  }\n}\n')
        self.metadata = {('master'):self.master, 'services':self.services, 'global_auth':b'no\n',
                         'frontend':self.frontend, 'filter':b'block in all\n'}
        self.plan = {'version':1, 'namespace_root':str(self.namespace),
            'backend_address':'127.0.0.1', 'backend_port':2525,
            'entrypoints':[{'address':'127.0.0.1','port':587,'service':'submission'},
                           {'address':'127.0.0.1','port':465,'service':'submission'}],
            'metadata_sha256':{key:hashlib.sha256(self.metadata[key]).hexdigest()
                for key in containment.OperatorOwnedSmtpTopology.COMMANDS},
            'routing_sha256':{key:hashlib.sha256(self.metadata[key]).hexdigest()
                for key in ('frontend','filter')}}
        self.planpath = self.planroot/'smtp-routing.json'; self.publish()
        self.calls = []; self.hook = None

    def publish(self):
        self.planpath.write_text(json.dumps(self.plan)); self.planpath.chmod(0o600)

    def refresh(self):
        for mapping in ('metadata_sha256','routing_sha256'):
            for key in self.plan[mapping]:
                self.plan[mapping][key] = hashlib.sha256(self.metadata[key]).hexdigest()
        self.publish()

    def execute(self, program, args, data, seconds, limit):
        self.assertEqual(data,b''); self.assertEqual(limit,16384); self.assertLessEqual(seconds,10)
        tuples = {(containment.OperatorOwnedSmtpTopology.PROGRAM,args):name
                  for name,args in containment.OperatorOwnedSmtpTopology.COMMANDS.items()}
        tuples.update({('/usr/local/bin/doveconf',('-c',str(self.config),'-n')):'frontend',
                       ('/sbin/pfctl',('-a','*','-sr')):'filter'})
        name = tuples[(program,args)]; self.calls.append(name)
        if self.hook: self.hook(name)
        return 0,self.metadata[name],b''

    def produce(self):
        return FixedSmtpRouting.produce(self.planroot,os.getuid(),self.budget,executor=self.execute)

    def no_certificate(self): self.assertFalse((self.namespace/'smtp-topology.json').exists())

    def test_native_fixed_topology_producer_dependency_exists(self):
        self.assertTrue(hasattr(containment,'RoutingMetadataExecutor'))

    def test_exact_private_plan_produces_consumable_v2_certificate_and_reuses_exact_file(self):
        namespace, topology = self.produce()
        self.assertEqual(topology._certificate_version,2)
        path = self.namespace/'smtp-topology.json'; identity = path.stat().st_ino
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        proxy = containment.SmtpProxyControl('alice@example.test',namespace,lambda *a:None,self.budget)
        self.assertTrue(topology.bound_to(proxy,self.budget))
        topology.recheck(self.budget)
        self.assertEqual(self.produce()[1]._certificate_version,2)
        self.assertEqual(path.stat().st_ino,identity)

    def test_missing_plan_refuses_before_metadata_or_publication(self):
        self.planpath.unlink()
        with self.assertRaises(Refused): self.produce()
        self.assertEqual(self.calls,[]); self.no_certificate()

    def test_insecure_plan_and_namespace_refuse_before_metadata(self):
        self.planpath.chmod(0o644)
        with self.assertRaises(Refused): self.produce()
        self.planpath.chmod(0o600); self.namespace.chmod(0o755)
        with self.assertRaises(Refused): self.produce()
        self.assertEqual(self.calls,[]); self.no_certificate()

    def test_changed_unapproved_metadata_refuses_without_certificate(self):
        self.metadata['master'] += b'public changed source\n'
        with self.assertRaises(Refused): self.produce()
        self.no_certificate()

    def test_actual_observed_direct_sasl_entrypoints_refuse_even_approved_digest(self):
        self.metadata['master'] += b'10.44.0.1:587 inet n - n - - smtpd\n'
        self.metadata['services'] += b'10.44.0.1:587/inet/smtpd_sasl_auth_enable = yes\n'
        self.refresh()
        with self.assertRaises(Refused): self.produce()
        self.no_certificate()

    def test_hidden_pass_sasl_or_global_yes_refuse_zero_publication(self):
        for services, global_auth in [(self.services+b'smtpd/pass/smtpd_sasl_auth_enable = yes\n',b'no\n'),
                                      (self.services,b'yes\n')]:
            with self.subTest(services=services):
                self.metadata['services']=services; self.metadata['global_auth']=global_auth; self.refresh()
                with self.assertRaises(Refused): self.produce()
                self.no_certificate()

    def test_missing_private_backend_refuses(self):
        self.metadata['services']=b''; self.refresh()
        with self.assertRaises(Refused): self.produce()
        self.no_certificate()

    def test_frontend_extra_missing_or_implicit_listener_refuses(self):
        variants = [self.frontend.replace(b'port = 465',b'port = 466'),
                    self.frontend.replace(b'listen = 127.0.0.1\n',b''),
                    self.frontend+b'service imap-login {\n inet_listener imap {\n port = 143\n }\n}\n']
        for data in variants:
            with self.subTest(data=data):
                self.metadata['frontend']=data; self.refresh()
                with self.assertRaises(Refused): self.produce()
                self.no_certificate()

    def test_empty_or_duplicate_coverage_refuses_before_metadata(self):
        for rows in [[],[self.plan['entrypoints'][0]]*2]:
            self.plan['entrypoints']=rows; self.publish()
            with self.assertRaises(Refused): self.produce()
        self.assertEqual(self.calls,[]); self.no_certificate()

    def test_plan_replaced_during_observation_refuses(self):
        def hook(name):
            if name=='filter':
                self.planpath.unlink(); self.publish()
        self.hook=hook
        with self.assertRaises(Refused): self.produce()
        self.no_certificate()

    def test_expired_original_budget_refuses_no_publication(self):
        self.hook=lambda name:setattr(self.clock,'now',1300) if name=='filter' else None
        with self.assertRaises(Exception): self.produce()
        self.no_certificate()

    def test_published_certificate_never_resets_after_changed_authority(self):
        self.produce(); path=self.namespace/'smtp-topology.json'; old=path.read_bytes()
        self.metadata['filter']=b'block return in all\n'; self.refresh()
        with self.assertRaises(Refused): self.produce()
        self.assertEqual(path.read_bytes(),old)

    def test_private_certificate_tamper_refuses_prewrite_continuity(self):
        _, topology=self.produce(); path=self.namespace/'smtp-topology.json'
        path.write_text('{}'); path.chmod(0o600)
        with self.assertRaises(Refused): topology.recheck(self.budget)

    def test_changed_plan_after_bootstrap_refuses_before_write(self):
        namespace, topology=self.produce()
        self.plan['entrypoints'][0]['port']=586; self.publish()
        with self.assertRaises(Refused): topology.recheck(self.budget)

    def test_changed_effective_frontend_after_hash_refuses_actual_adapter_zero_sql(self):
        namespace, topology=self.produce()
        proxy=containment.SmtpProxyControl('alice@example.test',namespace,
            lambda *args:(0,b'username proto src ip dest ip port\n',b''),self.budget)
        dependency=containment.MailSessionContainment('alice@example.test',
            lambda *args:(0,containment.MailSessionContainment.WHO_HEADER,b''),
            self.budget,containment.SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=topology)
        self.assertTrue(dependency.ready('alice@example.test'))
        writes=[]
        def executor(program,args,data,seconds,limit):
            if program==AuthoritativePasswordAdapter.HASH_PROGRAM:
                self.metadata['frontend']+=b'# changed effective metadata\n'
                value='{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$'+'A'*22+'$'+'B'*43
                return 0,(value+'\n').encode(),b''
            writes.append(data)
            raise AssertionError('must not dispatch SQL')
        adapter=AuthoritativePasswordAdapter(executor,before_write=dependency.before_write)
        snapshot=Snapshot('alice@example.test','{BLF-CRYPT}$2b$12$'+'A'*53,'20261004170000',True)
        with self.assertRaises(Refused):
            adapter.replace(snapshot,'alice@example.test','old fixture','long public new fixture','long public new fixture')
        self.assertEqual(writes,[])

    def test_duplicate_or_ambiguous_metadata_refuses_without_publication(self):
        variants=[('frontend',self.frontend.replace(b'port = 587',b'port = 586\n    port = 587')),
            ('services',self.services+self.services),
            ('master',self.master.replace(b'127.0.0.1:2525',b'localhost:2525')),
            ('master',self.master.replace(b' - smtpd\n',b' - smtpd -o smtpd_sasl_auth_enable=no\n',1))]
        originals=dict(self.metadata)
        for name,data in variants:
            with self.subTest(name=name,data=data):
                self.metadata=dict(originals); self.metadata[name]=data; self.refresh()
                with self.assertRaises(Refused): self.produce()
                self.no_certificate()

    def test_native_flag_refuses_before_any_private_file_or_probe(self):
        with patch.object(FixedSmtpRouting,'_private_read',side_effect=AssertionError('must not read')):
            with self.assertRaises(Refused): FixedSmtpRouting.native(self.budget)
            with self.assertRaises(Refused): containment.build_native_containment('alice@example.test',self.budget)

if __name__=='__main__': unittest.main()
