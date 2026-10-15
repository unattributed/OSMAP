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
        # Fixed hash and SQL producers remain disabled until independently
        # qualified source registry admission. Primary needs separate socket/ID
        # custody; no generic role/caller profile can select these graphs.
        if _PROFILES not in (('hash',),('sql','hash'),('sql','hash','primary')) or role not in _PROFILES:
            raise Refused('native installed custody qualification unavailable')
        from account_native_material import NativeMaterial, _SqlEndpoint
        from operation_budget import _OriginalReceipt
        if (type(material)is not NativeMaterial or type(budget)is not OperationBudget
                or (role!='primary' and account is not None) or not budget.inherited_group()
                or type(getattr(material,'_endpoint',None))is not _SqlEndpoint
                or type(getattr(material,'_states',None))is not tuple
                or len(material._states)!=4):
            raise Refused('native command material dependency unavailable')
        receipt=budget._original_receipt
        if type(receipt)is not _OriginalReceipt:
            raise Refused('native kernel original budget unavailable')
        budget.require_original(sent_millis=receipt.sent_millis,
            deadline_millis=receipt.deadline_millis,expires_at=receipt.expires_at)
        if role=='primary':
            canonical=Adapter._account(account)
            from account_primary_graph import PrimaryInstalledGraph,PROMISES as PRIMARY_PROMISES
            value=cls._mint(PRIMARY_PROGRAM,PRIMARY_ARGS+(canonical,),canonical,budget,
                            PrimaryInstalledGraph.rows(),PRIMARY_PROMISES)
            value._material=material
            value._primary_identity_required=True;value._primary_graph_required=True
            return value
        if role=='sql':
            from account_sql_graph import SqlInstalledGraph,PROMISES as SQL_PROMISES
            value=cls._mint(Adapter.SQL_PROGRAM,Adapter.SQL_ARGS,None,budget,
                            SqlInstalledGraph.rows(material),SQL_PROMISES)
            value._material=material;value._sql_graph_required=True;return value
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
        value._sql_graph_required=role=='sql'
        value._primary_identity_required=role=='primary'
        value._primary_graph_required=role=='primary'
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
        # Only the fixed SQL command needs its measured stdin window probe.
        # Never transfer tty authority to hash or primary command children.
        if role=='sql':allowed.add(b'tty')
        if len(set(words))!=len(words) or any(w not in allowed for w in words):
            raise Refused('native kernel promises unavailable')
        budget.remaining()
        value=object.__new__(cls)
        value._command_identity=(program,args,account,role)
        value._rows=rows;value._promises=promises;value._budget=budget
        value._material=None;value._sql_graph_required=False
        value._hash_identity_required=False
        value._hash_graph_required=False
        value._primary_identity_required=False;value._primary_graph_required=False
        return value

    def preexec(self,program,args,account=None,*,deadline=None):
        # Bind a closure before fork; never accept a caller preexec replacement.
        role=self._command(program,args,account)
        if (program,args,account,role)!=self._command_identity:
            raise Refused('native kernel profile command mismatch')
        self._budget.remaining()
        if not self._budget.inherited_group():raise Refused('native kernel owned group unavailable')
        identity=None;graph=None;sql_graph=None;primary_identity=None;primary_graph=None
        if self._primary_identity_required or self._primary_graph_required:
            from account_primary_identity import PrimaryChildIdentity
            from account_primary_graph import PrimaryInstalledGraph,PROMISES as PRIMARY_PROMISES
            if (role!='primary' or not self._primary_identity_required or not self._primary_graph_required
                    or self._hash_identity_required or self._hash_graph_required or self._sql_graph_required
                    or self._rows!=PrimaryInstalledGraph.rows() or self._promises!=PRIMARY_PROMISES):
                raise Refused('native primary fixed graph unavailable')
            # Selected private endpoint admission refuses an unobserved binder
            # before any public file/socket access; no ordinary-listener fallback.
            primary_identity=PrimaryChildIdentity.native(self._budget,deadline)
            if type(primary_identity)is not PrimaryChildIdentity or primary_identity._budget is not self._budget:
                raise Refused('native primary identity unavailable')
            primary_graph=PrimaryInstalledGraph.native(self._budget,deadline)
            if type(primary_graph)is not PrimaryInstalledGraph or primary_graph._budget is not self._budget:
                raise Refused('native primary graph unavailable')
        if self._sql_graph_required:
            from account_sql_graph import SqlInstalledGraph,PROMISES as SQL_PROMISES
            if (role!='sql' or self._hash_identity_required or self._hash_graph_required
                    or self._rows!=SqlInstalledGraph.rows(self._material) or self._promises!=SQL_PROMISES):
                raise Refused('native SQL fixed graph unavailable')
            sql_graph=SqlInstalledGraph.native(self._budget,deadline,self._material)
            if (type(sql_graph)is not SqlInstalledGraph or sql_graph._budget is not self._budget
                    or sql_graph._material is not self._material):
                raise Refused('native SQL graph unavailable')
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
            if primary_graph is not None:
                primary_graph.recheck(self._budget,deadline)
            if primary_identity is not None:
                primary_identity.drop(self._budget,deadline)
            if sql_graph is not None:
                # SQL has separate public/private/socket custody. No hash drop
                # or null w/c authority is inherited; spend the captured phase.
                sql_graph.recheck(self._budget,deadline)
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


# Admission supervisor authority is separate from command-child profiles. Its
# early pledge permits the unchanged primary preexec; the filesystem cannot lock
# until that child has forked. No request supplies a path/promise/UID/callback.
_ADMISSION_ROOT='/var/db/osmap-account/epoch'
_ADMISSION_UID=0
_ADMISSION_EARLY=b'stdio rpath wpath cpath flock unix proc exec prot_exec id getpw unveil'
_ADMISSION_FINAL=b'stdio rpath wpath cpath flock proc'


class AdmissionWorkerStartup:
    def __init__(self):
        raise Refused('admission worker startup unavailable')

    @staticmethod
    def _authority():
        if (not sys.platform.startswith('openbsd') or os.getuid()!=0 or os.geteuid()!=0
                or os.getcwd()!='/' or os.getpid()<=1 or os.getpid()!=os.getpgrp()):
            raise Refused('admission worker authority unavailable')

    @staticmethod
    def _libc():
        libc=ctypes.CDLL(None,use_errno=True)
        for name in ('pledge','unveil'):
            value=getattr(libc,name)
            value.argtypes=(ctypes.c_char_p,ctypes.c_char_p);value.restype=ctypes.c_int
        return libc

    @classmethod
    def native(cls):
        # Runs before stdin read. No new clock/budget or filesystem grant.
        cls._authority()
        libc=cls._libc()
        if libc.pledge(_ADMISSION_EARLY,None)!=0:
            raise Refused('admission worker early pledge unavailable')
        value=object.__new__(cls)
        value._pid=os.getpid();value._lib=libc;value._bound=False
        return value

    def bind(self,account,store,budget,material=None):
        from account_epoch import EpochStore
        from account_native_material import NativeMaterial
        from pathlib import Path
        self._authority()
        if (self._bound or self._pid!=os.getpid() or type(store)is not EpochStore
                or store.root!=Path(_ADMISSION_ROOT) or store.uid!=_ADMISSION_UID
                or (material is not None and type(material)is not NativeMaterial)):
            raise Refused('admission worker binding unavailable')
        self._bound=True
        AdmissionWorkerSeal._original(budget)
        value=object.__new__(AdmissionWorkerSeal)
        value._account=Adapter._account(account);value._store=store
        value._budget=budget;value._material=material;value._startup=self
        value._receipt=budget._original_receipt;value._phase='bound'
        value._directories=value._observe_directories()
        value._paths=store._paths(value._account)
        return value


class AdmissionWorkerSeal:
    def __init__(self):
        raise Refused('admission worker seal unavailable')

    @staticmethod
    def _original(budget):
        from operation_budget import _OriginalReceipt
        receipt=getattr(budget,'_original_receipt',None)
        if (type(budget)is not OperationBudget or type(receipt)is not _OriginalReceipt
                or not budget.inherited_group()):
            raise Refused('admission worker original budget unavailable')
        budget.require_original(sent_millis=receipt.sent_millis,
            deadline_millis=receipt.deadline_millis,expires_at=receipt.expires_at)

    def _observe_directories(self):
        import stat
        from pathlib import Path
        root=Path(_ADMISSION_ROOT);rows=[]
        for path in reversed((root,)+tuple(root.parents)):
            self._original(self._budget)
            info=path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=_ADMISSION_UID
                    or info.st_mode&0o022 or (path==root and info.st_mode&0o077)):
                raise Refused('admission worker directory custody unavailable')
            rows.append((str(path),(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
        return tuple(rows)

    def _binding(self,account,material,budget):
        # Exact object/budget/receipt authority, never a caller Boolean or hook.
        from pathlib import Path
        if (type(self._startup)is not AdmissionWorkerStartup
                or self._startup._pid!=os.getpid() or os.getpgrp()!=os.getpid()
                or account!=self._account or material is not self._material
                or budget is not self._budget or budget._original_receipt is not self._receipt
                or self._store.root!=Path(_ADMISSION_ROOT) or self._store.uid!=_ADMISSION_UID
                or self._paths!=self._store._paths(account)):
            raise Refused('admission worker seal binding unavailable')
        self._original(budget)

    def check(self,account,material,budget):
        self._binding(account,material,budget)
        if self._phase!='bound':raise Refused('admission worker seal already attempted')

    def require_sealed(self,account,material,budget):
        self._binding(account,material,budget)
        if self._phase!='sealed':raise Refused('admission worker sealing incomplete')

    def apply(self,account,material,budget,child=None):
        self.check(account,material,budget)
        # Authentication seals only after its actual owned primary child exists;
        # admit seals without material/child, before taking the durable lock.
        if self._material is None:
            if child is not None:raise Refused('admission worker child unavailable')
        elif (child is None or type(child.pid)is not int or child.pid<=1
                or child.pid==os.getpid() or os.getpgid(child.pid)!=os.getpgrp()):
            raise Refused('admission worker child unavailable')
        if self._observe_directories()!=self._directories:
            raise Refused('admission worker directory custody changed')
        self._phase='sealing'  # Any partial native failure is terminal, never retried.
        libc=self._startup._lib
        for path,_identity in self._directories:
            if libc.unveil(os.fsencode(path),b'')!=0:
                raise Refused('admission worker ancestor veil unavailable')
            self._original(budget)
        lock,record=self._paths
        for path,access in ((record,b'r'),(lock,b'rwc')):
            if libc.unveil(os.fsencode(path),access)!=0:
                raise Refused('admission worker epoch veil unavailable')
            self._original(budget)
        if libc.unveil(None,None)!=0:
            raise Refused('admission worker filesystem closure unavailable')
        if libc.pledge(_ADMISSION_FINAL,_ADMISSION_FINAL)!=0:
            raise Refused('admission worker steady pledge unavailable')
        # Locked unveil binds the prechecked directory inodes; hidden ancestor
        # pathname stats are not permitted (actual parent observation ENOENT).
        # This replaces repeated path metadata, not continuous owner/mode checks.
        # Trusted administration preserves the preseal protected ancestry.
        self._phase='sealed'
        self.require_sealed(account,material,budget)
