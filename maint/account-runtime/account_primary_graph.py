"""Fixed primary public-code custody; no profile activation or caller graph.

Reuse the installed Doveadm leaf reader, exact ALL-five plugin membership and
fixed read-only loader search directory. Its read grant is recursive; existing
custody measures immediate entries, not all descendant bytes or immutability.
Private-ID drop and ordinary filesystem DAC remain necessary. Existing null rwc
and wpath/cpath support tagged Doveadm lib_init/debug-sink startup only, after
fixed private-ID drop and existing null/device-parent custody. Actual primary
loader/authentication compatibility remains unqualified.
The independent PrimaryChildIdentity binds the private socket and kernel peer.
"""
import os,socket,sys
from pathlib import Path
import account_hash_graph as common
from account_hash_identity import _bound,AUTHORITY
from account_primary_identity import SOCKET
from authoritative_password import Refused
from mutation_primary import PROGRAM,ARGS,AUTH_CLIENT_SOCKET

PROMISES=b'stdio rpath unix prot_exec exec wpath cpath'

def _command():
    if (PROGRAM!='/usr/local/bin/doveadm' or AUTH_CLIENT_SOCKET!=str(SOCKET)
            or ARGS!=('-O','-o','stats_writer_socket_path=','auth','test','-a',
                      str(SOCKET),'-x','service=imap')):
        raise Refused('primary fixed command/socket unavailable')

class PrimaryInstalledGraph:
    def __init__(self,*_args,**_kwargs):raise Refused('primary graph construction unavailable')
    @classmethod
    def native(cls,budget,deadline):
        # Retired duplicate Python candidate. The maintained Rust helper owns
        # installed dependency admission. Do not revive historical graph pins
        # by enabling a legacy profile or replaying a qualification fixture.
        raise Refused('legacy Python graph retired; use Rust account helper')
    @staticmethod
    def _observe(budget,deadline):
        _bound(budget,deadline);_command()
        directory=common._modules(budget,deadline)
        search=common._search_directory(budget,deadline);total=[0];states=[]
        for name,metadata,digest,parents in common.FILES:
            states.append(common._read(Path(name),budget,deadline,total,common.FILE_CAP,
                                       (metadata,digest,parents)))
        if common._modules(budget,deadline)!=directory:
            raise Refused('primary plugin membership changed')
        if common._search_directory(budget,deadline)!=search:
            raise Refused('primary search directory changed')
        _bound(budget,deadline);return tuple(states),directory,search
    def recheck(self,budget,deadline):
        if type(self)is not PrimaryInstalledGraph or budget is not self._budget:
            raise Refused('primary graph original budget unavailable')
        if type(self)._observe(budget,deadline)!=self._states:
            raise Refused('primary graph custody changed')
        _bound(budget,deadline)
    @staticmethod
    def rows():
        _command()
        return tuple((name,b'rx' if name==PROGRAM else b'r')
            for name,*_ in common.FILES)+((common.MODULE_DIRECTORY,b'r'),
                                        (common.SEARCH_DIRECTORY,b'r'),
                                        ('/dev/null',b'rwc'),(str(SOCKET),b'rw'))
