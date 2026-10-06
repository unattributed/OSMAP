"""Irreversible command-child sealing; installed production profiles unavailable.

This component accepts no wire paths, promises or callback. Production source
must admit exact installed executable/library/module/null/socket custody before
adding a profile. The disposable hash fixture is not a production profile.
"""
import ctypes
import os
import sys
import time
import math
import subprocess
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Refused
from operation_budget import OperationBudget
from mutation_primary import PROGRAM as PRIMARY_PROGRAM,ARGS as PRIMARY_ARGS

# Deliberately no installed production profile is qualified yet. Each future
# entry must be source-owned and separately reviewed against admitted custody;
# never populate this from operator JSON, caller reports or environment.
_PROFILES=()

class CommandKernelSeal:
    def __init__(self,*_args,**_kwargs):
        raise Refused('native command kernel construction unavailable')

    @classmethod
    def native(cls,role=None,material=None,budget=None,account=None):
        # Empty source profiles refuse before operator files, libc or spawn.
        if not _PROFILES:
            raise Refused('native installed command kernel graph unavailable')
        # This is the fixed hash producer only. SQL/private config and primary
        # socket/identity profiles require separate installed qualification.
        if _PROFILES!=('hash',) or role!='hash':
            raise Refused('native installed custody qualification unavailable')
        from account_native_material import NativeMaterial, _SqlEndpoint
        from operation_budget import _OriginalReceipt
        if (type(material)is not NativeMaterial or type(budget)is not OperationBudget
                or account is not None or not budget.inherited_group()
                or type(getattr(material,'_endpoint',None))is not _SqlEndpoint
                or type(getattr(material,'_states',None))is not tuple
                or len(material._states)!=4):
            raise Refused('native command material dependency unavailable')
        receipt=budget._original_receipt
        if type(receipt)is not _OriginalReceipt:
            raise Refused('native kernel original budget unavailable')
        budget.require_original(sent_millis=receipt.sent_millis,
            deadline_millis=receipt.deadline_millis,expires_at=receipt.expires_at)
        from account_hash_graph import HashInstalledGraph,PROMISES
        value=cls._mint(Adapter.HASH_PROGRAM,Adapter.HASH_ARGS,None,budget,
                        HashInstalledGraph.rows(),PROMISES)
        value._material=material
        value._hash_identity_required=True;value._hash_graph_required=True
        return value

    @classmethod
    def _for_material(cls,role,material,budget,account=None):
        # Called only by source-owned transport constructors. No caller profile,
        # path report, callback or options can mint a production seal.
        from account_native_material import NativeMaterial
        if (type(material)is not NativeMaterial or type(budget)is not OperationBudget
                or role not in ('sql','hash','primary') or not budget.inherited_group()
                or (role!='primary' and account is not None)):
            raise Refused('native command material dependency unavailable')
        if role=='primary':Adapter._account(account)
        budget.remaining()
        # Observational inventory and local fixture guards are not profiles.
        # Installed full custody/null/socket admission must implement this path.
        value=cls.native(role,material,budget,account)
        # Required for every future source-admitted hash profile. SQL/primary
        # keep separate private config/socket identities; no role-wide drop.
        if (type(value)is not cls or value._budget is not budget or value._command_identity[3]!=role
                or value._command_identity[2]!=account or value._material is not material):raise Refused('native kernel seal unavailable')
        value._hash_identity_required=role=='hash'
        value._hash_graph_required=role=='hash'
        return value

    @classmethod
    def _hash_candidate(cls,budget):
        # Private reviewed qualification lane only. No production composition
        # calls it, and _PROFILES stays empty. Caller supplies no paths/profile,
        # UID/GID/command/callback; admission occurs inside the original phase.
        from account_hash_graph import HashInstalledGraph,PROMISES
        value=cls._fixture(Adapter.HASH_PROGRAM,Adapter.HASH_ARGS,None,budget,
                           HashInstalledGraph.rows(),PROMISES)
        value._hash_identity_required=True;value._hash_graph_required=True
        return value

    @staticmethod
    def _command(program,args,account):
        if type(program)is not str or type(args)is not tuple:
            raise Refused('native kernel command authority refused')
        if (program,args)==(Adapter.HASH_PROGRAM,Adapter.HASH_ARGS):return 'hash'
        if (program,args)==(Adapter.SQL_PROGRAM,Adapter.SQL_ARGS):return 'sql'
        if account is not None:
            canonical=Adapter._account(account)
            if (program,args)==(PRIMARY_PROGRAM,PRIMARY_ARGS+(canonical,)):return 'primary'
        raise Refused('native kernel command authority refused')

    @classmethod
    def _fixture(cls,program,args,account,budget,rows,promises):
        # Private local discriminator only; no production constructor calls it.
        return cls._mint(program,args,account,budget,rows,promises)

    @classmethod
    def _mint(cls,program,args,account,budget,rows,promises):
        # Shared primitive validation. The native producer above supplies only
        # its source-owned command/graph; private fixtures cannot admit profiles.
        role=cls._command(program,args,account)
        if type(budget)is not OperationBudget or not budget.inherited_group():
            raise Refused('native kernel original budget unavailable')
        if (type(rows)is not tuple or not 1<=len(rows)<=128 or
                type(promises)is not bytes or not promises or len(promises)>256):
            raise Refused('native kernel profile unavailable')
        seen=set()
        for row in rows:
            if (type(row)is not tuple or len(row)!=2 or type(row[0])is not str or
                    not row[0].startswith('/') or '\x00'in row[0] or
                    any(p in ('.','..','') for p in row[0].split('/')[1:]) or
                    type(row[1])is not bytes or any(c not in b'rwxc' for c in row[1]) or
                    len(set(row[1]))!=len(row[1]) or row[0]in seen):
                raise Refused('native kernel profile unavailable')
            seen.add(row[0])
        words=promises.split(b' ')
        allowed={b'stdio',b'rpath',b'wpath',b'cpath',b'proc',b'exec',b'unix',b'prot_exec'}
        if len(set(words))!=len(words) or any(w not in allowed for w in words):
            raise Refused('native kernel promises unavailable')
        budget.remaining()
        value=object.__new__(cls)
        value._command_identity=(program,args,account,role)
        value._rows=rows;value._promises=promises;value._budget=budget
        value._material=None
        value._hash_identity_required=False
        value._hash_graph_required=False
        return value

    def preexec(self,program,args,account=None,*,deadline=None):
        # Bind a closure before fork; never accept a caller preexec replacement.
        role=self._command(program,args,account)
        if (program,args,account,role)!=self._command_identity:
            raise Refused('native kernel profile command mismatch')
        self._budget.remaining()
        if not self._budget.inherited_group():raise Refused('native kernel owned group unavailable')
        identity=None;graph=None
        if self._hash_graph_required:
            from account_hash_graph import HashInstalledGraph,PROMISES
            if (role!='hash' or not self._hash_identity_required
                    or self._rows!=HashInstalledGraph.rows() or self._promises!=PROMISES):
                raise Refused('native hash fixed graph unavailable')
            graph=HashInstalledGraph.native(self._budget,deadline)
            if type(graph)is not HashInstalledGraph or graph._budget is not self._budget:
                raise Refused('native hash graph unavailable')
        if self._hash_identity_required:
            if role!='hash':raise Refused('native hash identity role unavailable')
            from account_hash_identity import HashChildIdentity
            # Public record/null admission spends the captured original phase
            # before Popen. Only typed fixed local source identity is accepted.
            identity=HashChildIdentity.native(self._budget,deadline)
            if type(identity)is not HashChildIdentity or identity._budget is not self._budget:raise Refused('native hash identity unavailable')
        def apply():
            # Pledge/unveil in the CHILD, after Python imports/material custody
            # and before exec. Parent keeps independent watchdog/reap authority.
            if not sys.platform.startswith('openbsd') or os.getuid()!=0 or os.geteuid()!=0:
                raise Refused('native kernel platform authority unavailable')
            if graph is not None:
                # Recheck fixed public code, exact module membership and public
                # startup database leases before losing privileged setup.
                graph.recheck(self._budget,deadline)
            if identity is not None:
                # Root custody recheck, empty groups and irreversible saved /
                # real / effective IDs, before the final locked kernel graph.
                identity.drop(self._budget,deadline)
            libc=ctypes.CDLL(None,use_errno=True)
            unveil=libc.unveil;unveil.argtypes=(ctypes.c_char_p,ctypes.c_char_p);unveil.restype=ctypes.c_int
            pledge=libc.pledge;pledge.argtypes=(ctypes.c_char_p,ctypes.c_char_p);pledge.restype=ctypes.c_int
            for path,access in self._rows:
                if unveil(os.fsencode(path),access)!=0:raise Refused('native kernel unveil unavailable')
            if unveil(None,None)!=0:raise Refused('native kernel closure unavailable')
            if pledge(self._promises,self._promises)!=0:raise Refused('native kernel pledge unavailable')
        return apply

    def spawn(self,program,args,deadline,account=None):
        # Exactly source-owned command and closed env; callers supply neither
        # kernel callback nor Popen options. Existing transport consumes stdin,
        # bounds phase/output and reaps this returned owned child.
        if (type(deadline)not in (int,float) or not math.isfinite(deadline)
                or deadline<=time.monotonic()):
            raise Refused('native command original phase unavailable')
        guard=self.preexec(program,args,account,deadline=deadline)
        original_guard=guard
        def guard():
            # Creation and irreversible child setup spend the original phase;
            # imports/custody checks never mint a replacement deadline.
            if time.monotonic()>=deadline:raise Refused('native command phase expired')
            self._budget.remaining();original_guard()
            if time.monotonic()>=deadline:raise Refused('native command phase expired')
        role=self._command_identity[3]
        environment={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'}
        if role in ('hash','primary'):
            environment.update(CONFIG_FILE='/dev/null',STATS_WRITER_SOCKET_PATH='')
        if role=='primary':environment['PATH']='/usr/local/bin:/usr/bin:/bin'
        return subprocess.Popen((program,)+args,stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,
            close_fds=True,start_new_session=False,env=environment,preexec_fn=guard)
