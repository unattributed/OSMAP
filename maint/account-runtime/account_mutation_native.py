"""Fixed disabled authoritative dependency composition, never provisioning.

Native SQL grant/hash/auth/confinement, complete SMTP termination, cross-host
routing/clock/issuer failure and original-budget watchdog remain qualifications.
This composition has no caller-selected file, account writer, callback or policy.
"""
import time

from account_epoch import EpochStore
from account_mutation_worker import IntentStore,MutationWorker,Unavailable
from account_mutation_supervisor import _Bootstrap
from authoritative_password import AuthoritativePasswordAdapter
from mail_session_containment import build_native_containment
from mutation_primary import NativePrimaryVerifier
from operation_budget import OperationBudget
from prepared_password import PreparedAction,PreparedPasswordCoordinator
from account_native_material import NativeMaterial,MaterialExecutor,CONFIG as SQL_CONFIG
from smtp_guarded_builder import GuardedSmtpBinding
from account_guarded_mutation import VerifiedGuardedMutation

NATIVE_DEPENDENCIES_QUALIFIED=False
EPOCH_ROOT='/var/db/osmap-account/epoch'
INTENT_ROOT='/var/db/osmap-account/intents'


def _legacy_authority_unavailable(*_args):
    # Guarded worker replaces this dependency with independent exact session
    # proof + durable pending issuer ACK. Never offer a constant-True fallback.
    raise Unavailable('legacy mutation session authority unavailable')


def _fixed_material():
    return NativeMaterial.native()


class NativeDependencies:
    def __init__(self,bootstrap,journal,epoch_store,clock=lambda:int(time.time()),*,material=None,smtp_control=None):
        if (type(bootstrap) is not _Bootstrap or type(journal) is not IntentStore
                or type(epoch_store) is not EpochStore or not callable(clock)
                or journal.root==epoch_store.root or journal.uid!=epoch_store.uid
                or (material is not None and type(material) is not NativeMaterial)
                or (smtp_control is not None and
                    (type(smtp_control) is not GuardedSmtpBinding or smtp_control.bootstrap is not bootstrap))):
            raise Unavailable('native mutation dependency unavailable')
        self.bootstrap=bootstrap
        self.journal=journal
        self.epoch_store=epoch_store
        self.clock=clock
        self._material=material
        self._smtp_control=smtp_control

    @classmethod
    def native(cls):
        # Refuse before operator files/store construction or program metadata.
        if not NATIVE_DEPENDENCIES_QUALIFIED:
            raise Unavailable('native mutation dependencies unavailable')
        bootstrap=_Bootstrap.native()
        material=_fixed_material()
        # No record/root creation, recovery/reset, imported session or callback
        # attestation occurs here. Missing/corrupt owned stores remain unavailable.
        return cls(bootstrap,IntentStore(INTENT_ROOT,0),EpochStore(EPOCH_ROOT,0),material=material)

    def _build(self,action,budget,authorize):
        if (type(action) is not PreparedAction or type(budget) is not OperationBudget
                or action.account not in self.bootstrap.accounts or not callable(authorize)
                or type(self._material) is not NativeMaterial
                or not budget.inherited_group()):
            raise Unavailable('native mutation action unavailable')
        budget.remaining()
        self._material.recheck(budget)
        executor=MaterialExecutor(budget,self._material)
        primary=NativePrimaryVerifier(action.account,budget,self._material)
        # Current fixed native factory correctly refuses: SMTP termination is
        # REQUIRED, not silently optional or inferred N/A from absent cache rows.
        containment=build_native_containment(action.account,budget)
        adapter=AuthoritativePasswordAdapter(executor,before_write=containment.before_write)
        budget.remaining()
        return PreparedPasswordCoordinator(self.epoch_store,adapter,authorize,
            primary,primary,containment.ready,containment.finish,self.clock,
            containment.invalidate_changed_auth)

    def _build_guarded(self,original,frame,budget,authorize):
        if (type(self._smtp_control) is not GuardedSmtpBinding
                or type(original) is not VerifiedGuardedMutation):
            raise Unavailable('native guarded SMTP dependency unavailable')
        coordinator=self._build(original.budget.request.action,budget,authorize)
        return self._smtp_control.compose(coordinator,original,frame,budget)

    def worker(self):
        return MutationWorker(self.bootstrap.mutation_key,self.bootstrap.accounts,
            self.journal,self.epoch_store,self._build,_legacy_authority_unavailable,
            self.clock,session_key=self.bootstrap.session_key,
            guarded_builder=None if self._smtp_control is None else self._build_guarded)
