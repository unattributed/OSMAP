"""Real private master template and closed Postfix datagram logger admission."""
import unittest
from pathlib import Path
from smtp_topology import FixedSmtpRouting
from authoritative_password import Refused

class LoggerTopologyControls(unittest.TestCase):
    def setUp(self):
        # Exact public private-template rendering at backend24002; the
        # adjacent whole-executor test also reads/render-checks the real file.
        master=(b'127.0.0.1:24002 inet n - n - 4 smtpd\n  -o smtpd_sasl_auth_enable=yes\n'
          b'anvil unix - - n - 1 anvil\npostlog unix-dgram n - n - 1 postlogd\n'
          b'tlsmgr unix - - n 1000? 1 tlsmgr\n')
        self.metadata={'master':master,
          'services':b'127.0.0.1:24002/inet/smtpd_sasl_auth_enable = yes\n','global_auth':b'no\n'}
        self.routing={'backend_address':'127.0.0.1','backend_port':24002}
    def test_complete_real_private_master_with_exact_postlog_datagram_accepted(self):
        FixedSmtpRouting._postfix(self.metadata,self.routing)
    def test_unknown_datagram_command_service_extra_options_and_SMTP_refuse(self):
        original=self.metadata['master']
        for row in (b'postlog unix-dgram n - n - 1 smtpd',b'postlog unix-dgram n - n - 1 unknown',
                    b'foreign unix-dgram n - n - 1 postlogd',b'postlog unix-dgram n - n - 1 postlogd -o smtpd_sasl_auth_enable=yes'):
            self.metadata['master']=original.replace(b'postlog unix-dgram n - n - 1 postlogd',row)
            with self.assertRaises(Refused):FixedSmtpRouting._postfix(self.metadata,self.routing)
    def test_duplicate_datagram_or_extra_network_AUTH_still_refuse(self):
        for row in (b'postlog unix-dgram n - n - 1 postlogd\n',b'127.0.0.1:24003 inet n - n - 1 smtpd\n  -o smtpd_sasl_auth_enable=yes\n'):
            metadata=dict(self.metadata,master=self.metadata['master']+row)
            if b'24003'in row:metadata['services']+=b'127.0.0.1:24003/inet/smtpd_sasl_auth_enable = yes\n'
            with self.assertRaises(Refused):FixedSmtpRouting._postfix(metadata,self.routing)

if __name__=='__main__':unittest.main(verbosity=2)
