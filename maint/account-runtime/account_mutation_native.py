"""Fixed disabled authoritative dependency composition, never provisioning.

Native SQL grant/hash/auth/confinement, complete SMTP termination, cross-host
routing/clock/issuer failure and original-budget watchdog remain qualifications.
This composition has no caller-selected file, account writer, callback or policy.
"""
import os
from pathlib import Path
import stat
import time

from account_epoch import EpochStore
from account_mutation_worker import IntentStore,MutationWorker,Unavailable
from account_mutation_supervisor import _Bootstrap
from authoritative_password import AuthoritativePasswordAdapter,NativeExecutor,Refused
from mail_session_containment import build_native_containment
from mutation_primary import NativePrimaryVerifier
from operation_budget import OperationBudget
from prepared_password import PreparedAction,PreparedPasswordCoordinator

NATIVE_DEPENDENCIES_QUALIFIED=False
EPOCH_ROOT='/var/db/osmap-account/epoch'
INTENT_ROOT='/var/db/osmap-account/intents'
SQL_CONFIG=Path('/etc/osmap/account-mariadb.cnf')


def _legacy_authority_unavailable(*_args):
    # Guarded worker replaces this dependency with independent exact session
    # proof + durable pending issuer ACK. Never offer a constant-True fallback.
    raise Unavailable('legacy mutation session authority unavailable')


def _fixed_material():
    # Metadata only: this loader never retrieves or retains SQL configuration
    # contents. Actual scoped grant/schema/engine qualification remains separate.
    for path,private,limit in (
            (SQL_CONFIG,True,16384),
            (Path(AuthoritativePasswordAdapter.SQL_PROGRAM),False,64*1024*1024),
            (Path(AuthoritativePasswordAdapter.HASH_PROGRAM),False,64*1024*1024)):
        for ancestor in path.parents:
            m=ancestor.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022
                    or ancestor.resolve()!=ancestor):
                raise Unavailable('native mutation material ancestry unavailable')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            m=os.fstat(fd)
            if (not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_nlink!=1
                    or m.st_mode&(0o077 if private else 0o022)
                    or not 0<m.st_size<=limit
                    or (not private and m.st_mode&0o111==0)):
                raise Unavailable('native mutation material unavailable')
        finally:os.close(fd)


class NativeDependencies:
    def __init__(self,bootstrap,journal,epoch_store,clock=lambda:int(time.time())):
        if (type(bootstrap) is not _Bootstrap or type(journal) is not IntentStore
                or type(epoch_store) is not EpochStore or not callable(clock)
                or journal.root==epoch_store.root or journal.uid!=epoch_store.uid):
            raise Unavailable('native mutation dependency unavailable')
        self.bootstrap=bootstrap
        self.journal=journal
        self.epoch_store=epoch_store
        self.clock=clock

    @classmethod
    def native(cls):
        # Refuse before operator files/store construction or program metadata.
        if not NATIVE_DEPENDENCIES_QUALIFIED:
            raise Unavailable('native mutation dependencies unavailable')
        bootstrap=_Bootstrap.native()
        _fixed_material()
        # No record/root creation, recovery/reset, imported session or callback
        # attestation occurs here. Missing/corrupt owned stores remain unavailable.
        return cls(bootstrap,IntentStore(INTENT_ROOT,0),EpochStore(EPOCH_ROOT,0))

    def _build(self,action,budget,authorize):
        if (type(action) is not PreparedAction or type(budget) is not OperationBudget
                or action.account not in self.bootstrap.accounts or not callable(authorize)
                or not budget.inherited_group()):
            raise Unavailable('native mutation action unavailable')
        budget.remaining()
        executor=NativeExecutor(budget)
        primary=NativePrimaryVerifier(action.account,budget)
        # Current fixed native factory correctly refuses: SMTP termination is
        # REQUIRED, not silently optional or inferred N/A from absent cache rows.
        containment=build_native_containment(action.account,budget)
        adapter=AuthoritativePasswordAdapter(executor,before_write=containment.before_write)
        budget.remaining()
        return PreparedPasswordCoordinator(self.epoch_store,adapter,authorize,
            primary,primary,containment.ready,containment.finish,self.clock,
            containment.invalidate_changed_auth)

    def worker(self):
        return MutationWorker(self.bootstrap.mutation_key,self.bootstrap.accounts,
            self.journal,self.epoch_store,self._build,_legacy_authority_unavailable,
            self.clock,session_key=self.bootstrap.session_key)
