"""Closed measured Dovecot OK profile; synthetic sockets and epochs only."""
import os
import importlib.util
from pathlib import Path
import sys
import unittest
if os.environ.get('SMTP_PROXY_SOURCE'):
    spec=importlib.util.spec_from_file_location('smtp_auth_lifecycle',Path(os.environ['SMTP_PROXY_SOURCE']))
    loaded=importlib.util.module_from_spec(spec);sys.modules[spec.name]=loaded;spec.loader.exec_module(loaded)
import test_smtp_auth_lifecycle as baseline
from authoritative_password import Refused
import smtp_auth_lifecycle as lifecycle


class ProxyOkTests(baseline.LifecycleTests):
    def setUp(self):
        super().setUp()
        options=({'ok_profile':lifecycle.DovecotProxyOkProfile(2525)}
                 if hasattr(lifecycle,'DovecotProxyOkProfile') else {})
        self.authority=lifecycle.OwnedSmtpPeerAuthority(
            (os.getuid(),os.getgid()),(os.getuid(),os.getgid()),2525,
            lambda pid,deadline:self.identity,
            **options)
        self.registry=lifecycle.SmtpAuthLifecycle(self.store,frozenset((baseline.ALICE,baseline.BOB)),self.authority)

    def reply(self,extras=b'proxy\thost=127.0.0.1\tport=2525\tssl=yes',user=baseline.ALICE,request=b'1'):
        return b'OK\t'+request+b'\tuser='+user.encode()+b'\t'+extras+b'\n'

    def test_source_supported_metadata_publishes_exact_bytes_once(self):
        channel,front,_=self.channel()
        line=self.reply()
        receipt=self.registry.verified(channel,line)
        self.assertTrue(self.registry.publish(channel,receipt))
        front.settimeout(.2)
        self.assertEqual(front.recv(4096),line)
        with self.assertRaises(Refused):self.registry.publish(channel,receipt)

    def test_reordered_complete_metadata_is_supported(self):
        channel,front,_=self.channel()
        line=self.reply(b'ssl=yes\tport=2525\tproxy\thost=127.0.0.1')
        receipt=self.registry.verified(channel,line)
        self.registry.publish(channel,receipt)
        self.assertEqual(front.recv(4096),line)

    def test_unknown_credentials_mechanism_and_partial_metadata_refuse_before_publication(self):
        for extras in (b'proxy\thost=127.0.0.1\tport=2525',
                       b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tresp=eA==',
                       b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tpass=public-secret',
                       b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tnologin',
                       b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tother=x'):
            with self.subTest(extras=extras):
                channel,front,back=self.channel()
                with self.assertRaises(Refused):self.registry.verified(channel,self.reply(extras))
                self.eof(front);self.eof(back)

    def test_topology_tls_duplicates_and_identity_mismatch_refuse(self):
        samples=(self.reply(b'proxy\thost=127.0.0.2\tport=2525\tssl=yes'),
                 self.reply(b'proxy\thost=127.0.0.1\tport=2526\tssl=yes'),
                 self.reply(b'proxy\thost=127.0.0.1\tport=2525\tssl=no'),
                 self.reply(b'proxy=y\thost=127.0.0.1\tport=2525\tssl=yes'),
                 self.reply(b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tproxy'),
                 self.reply(b'proxy\thost=127.0.0.1\tport=2525\tssl=yes\tuser='+baseline.ALICE.encode()),
                 self.reply(user=baseline.BOB),self.reply(request=b'2'),
                 self.reply()+b'OK\n',self.reply().replace(b'ssl=yes',b'ssl=yes\r'),
                 self.reply().replace(b'ssl=yes',b'ssl=yes\0'))
        for line in samples:
            with self.subTest(line=line):
                channel,front,back=self.channel()
                with self.assertRaises(Refused):self.registry.verified(channel,line)
                self.eof(front);self.eof(back)

    def test_startup_port_binding_and_minimal_profile_are_distinct(self):
        with self.assertRaises(Refused):
            lifecycle.OwnedSmtpPeerAuthority((0,0),(0,0),2525,lambda pid,deadline:None,
                ok_profile=lifecycle.DovecotProxyOkProfile(2526))
        with self.assertRaises(Refused):
            lifecycle.OwnedSmtpPeerAuthority((0,0),(0,0),2525,lambda pid,deadline:None,ok_profile=True)
        channel,front,back=self.channel()
        with self.assertRaises(Refused):self.registry.verified(channel,b'OK\t1\tuser='+baseline.ALICE.encode()+b'\n')
        self.eof(front);self.eof(back)

    def test_valid_proxy_receipt_still_loses_to_current_epoch_or_lock(self):
        channel,front,back=self.channel()
        receipt=self.registry.verified(channel,self.reply())
        self.state(epoch=1,state='active')
        with self.assertRaises(Refused):self.registry.publish(channel,receipt)
        self.eof(front);self.eof(back)
        channel,front,back=self.channel()
        receipt=self.registry.verified(channel,self.reply())
        with self.store.locked(baseline.ALICE):
            with self.assertRaises(Refused):self.registry.publish(channel,receipt)
        self.eof(front);self.eof(back)


# Only new proxy controls are selected here; inherited minimal-profile controls
# run against their unchanged baseline class separately.
def load_tests(loader,tests,pattern):
    return unittest.TestSuite(ProxyOkTests(name) for name in ProxyOkTests.__dict__ if name.startswith('test_'))

if __name__=='__main__':unittest.main()
