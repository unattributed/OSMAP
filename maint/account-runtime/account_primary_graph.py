"""Fixed primary public-code custody; no profile activation or caller graph.

Reuse the installed Doveadm leaf reader and exact ALL-five plugin membership.
Do not inherit hash's recursive library search-directory or null write/create
grant. Actual primary loader/authentication compatibility remains unqualified.
The independent PrimaryChildIdentity binds the private socket and kernel peer.
"""
import os,socket,sys
from pathlib import Path
import account_hash_graph as common
from account_hash_identity import _bound,AUTHORITY
from account_primary_identity import SOCKET
from authoritative_password import Refused
from mutation_primary import PROGRAM,ARGS,AUTH_CLIENT_SOCKET

PROMISES=b'stdio rpath unix prot_exec exec'

def _command():
    if (PROGRAM!='/usr/local/bin/doveadm' or AUTH_CLIENT_SOCKET!=str(SOCKET)
            or ARGS!=('-O','-o','stats_writer_socket_path=','auth','test','-a',
                      str(SOCKET),'-x','service=imap')):
        raise Refused('primary fixed command/socket unavailable')

class PrimaryInstalledGraph:
    def __init__(self,*_args,**_kwargs):raise Refused('primary graph construction unavailable')
    @classmethod
    def native(cls,budget,deadline):
        _bound(budget,deadline);_command();system=os.uname()
        if (sys.platform!='openbsd7' or system.sysname!='OpenBSD' or system.release!='7.9'
                or system.machine!='amd64' or sys.byteorder!='little'
                or socket.gethostname()!=AUTHORITY or os.getuid()!=0 or os.geteuid()!=0):
            raise Refused('primary graph authority unavailable')
        value=object.__new__(cls);value._budget=budget
        value._states=cls._observe(budget,deadline);return value
    @staticmethod
    def _observe(budget,deadline):
        _bound(budget,deadline);_command()
        directory=common._modules(budget,deadline);total=[0];states=[]
        for name,metadata,digest,parents in common.FILES:
            states.append(common._read(Path(name),budget,deadline,total,common.FILE_CAP,
                                       (metadata,digest,parents)))
        if common._modules(budget,deadline)!=directory:
            raise Refused('primary plugin membership changed')
        _bound(budget,deadline);return tuple(states),directory
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
                                        ('/dev/null',b'r'),(str(SOCKET),b'rw'))
