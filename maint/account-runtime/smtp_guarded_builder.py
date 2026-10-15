"""Fixed guarded startup composition; native qualification remains closed.

New source-owned contract: smtp-control.key under the existing supervisor ROOT
is the broker's distinct MAC purpose key. No existing provision is inferred and
this loader creates no file; the eventual broker factory must use this contract.
"""
import os
import time
from account_guarded_mutation import VerifiedGuardedMutation
from account_mutation_codec import key_valid
from account_mutation_supervisor import _Bootstrap,ROOT,_directory,_private
from account_mutation_budget import wall_millis
from authoritative_password import AuthoritativePasswordAdapter,Refused
from mail_session_containment import MailSessionContainment
from operation_budget import OperationBudget
from prepared_password import PreparedPasswordCoordinator
from smtp_control_authorization import ControlAuthority,derive_authorization
from smtp_mutation_containment import PrivateControlEndpoint,GuardedSmtpContainment

CONTROL_KEY_NAME='smtp-control.key'
STARTUP_SECONDS=5
_FILES=('config.json','mutation.key','session-proof.key',CONTROL_KEY_NAME)

class GuardedSmtpBinding:
    def __init__(self,bootstrap,authority,endpoint,*,clock_millis):
        if (type(bootstrap)is not _Bootstrap or type(authority)is not ControlAuthority
                or type(endpoint)is not PrivateControlEndpoint or not callable(clock_millis)
                or bootstrap.accounts!=authority.accounts
                or authority.key in (bootstrap.mutation_key,bootstrap.session_key)):
            raise Refused('guarded SMTP startup binding unavailable')
        key_valid(bootstrap.mutation_key);key_valid(bootstrap.session_key)
        if bootstrap.mutation_key==bootstrap.session_key:raise Refused('guarded SMTP startup keys unavailable')
        self.bootstrap=bootstrap;self.authority=authority;self.endpoint=endpoint;self._clock=clock_millis
    def compose(self,coordinator,original,frame,budget):
        if (type(coordinator)is not PreparedPasswordCoordinator
                or type(original)is not VerifiedGuardedMutation or type(frame)is not bytes
                or type(budget)is not OperationBudget
                or type(coordinator.adapter)is not AuthoritativePasswordAdapter
                or coordinator.pending_confirmation is not None
                or coordinator.release_containment is not None
                or not budget.inherited_group()):
            raise Refused('guarded SMTP coordinator binding unavailable')
        mail=getattr(coordinator.containment_ready,'__self__',None)
        if (type(mail)is not MailSessionContainment or mail._budget is not budget
                or mail._account!=original.budget.request.action.account
                or coordinator.finish_containment!=mail.finish
                or coordinator.invalidate_changed_auth!=mail.invalidate_changed_auth
                or coordinator.adapter._before_write!=mail.before_write):
            raise Refused('guarded SMTP mail binding unavailable')
        budget.require_original(sent_millis=original.budget.sent_millis,
            deadline_millis=original.budget.deadline_millis,expires_at=original.budget.request.action.expires)
        self.recheck(budget)
        # Independently reverify exact original MACs locally. No password-bearing
        # frame, original keys, SQL authority or issuer Boolean reaches broker.
        minimal=derive_authorization(frame,self.bootstrap.mutation_key,
            self.bootstrap.session_key,self.authority,self._clock())
        bridge=GuardedSmtpContainment(mail,self.endpoint,minimal,self.authority,original,clock_millis=self._clock)
        coordinator.adapter._before_write=bridge.before_write
        coordinator.containment_ready=bridge.ready
        coordinator.finish_containment=bridge.finish
        coordinator.invalidate_changed_auth=bridge.invalidate_changed_auth
        coordinator.pending_confirmation=bridge.capture_pending
        coordinator.release_containment=bridge.abandon
        return coordinator
    @staticmethod
    def _identity(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    @classmethod
    def _read(cls,bootstrap,root,owner,endpoint,budget):
        # Private source/test seam, never a wire-selected path or owner. Native
        # supplies fixed ROOT/owner0 and the fixed endpoint constructor below.
        if (type(bootstrap)is not _Bootstrap or type(endpoint)is not PrivateControlEndpoint
                or type(budget)is not OperationBudget or endpoint.owner!=owner):
            raise Refused('guarded SMTP startup authority unavailable')
        descriptor=None
        try:
            budget.remaining();descriptor=_directory(root,owner)
            root_identity=cls._identity(os.fstat(descriptor))[:5]
            before=tuple(cls._identity(os.stat(name,dir_fd=descriptor,follow_symlinks=False))for name in _FILES)
            # Bootstrap reread independently binds the complete account set and
            # both original purpose keys to this same private directory.
            if _Bootstrap._read(root,owner)!=bootstrap:
                raise Refused('guarded SMTP bootstrap changed')
            budget.remaining()
            control=_private(descriptor,CONTROL_KEY_NAME,owner,1024)
            authority=ControlAuthority(control,bootstrap.accounts)
            value=cls(bootstrap,authority,endpoint,clock_millis=wall_millis)
            after=tuple(cls._identity(os.stat(name,dir_fd=descriptor,follow_symlinks=False))for name in _FILES)
            if (before!=after or cls._identity(os.fstat(descriptor))[:5]!=root_identity
                    or cls._identity(root.lstat())[:5]!=root_identity):
                raise Refused('guarded SMTP startup custody changed')
            endpoint.recheck(budget);budget.remaining()
            value._custody=(root,owner,root_identity,before)
            return value
        except Exception:
            raise Refused('guarded SMTP startup binding unavailable')from None
        finally:
            if descriptor is not None:os.close(descriptor)

    def recheck(self,budget):
        custody=getattr(self,'_custody',None)
        if custody is None:
            # Existing explicitly constructed source fixtures remain unchanged;
            # the native factory always uses the fixed custody loader.
            return
        root,owner,root_identity,files=custody
        current=type(self)._read(self.bootstrap,root,owner,self.endpoint,budget)
        if (current._custody!=(root,owner,root_identity,files)
                or current.authority!=self.authority):
            raise Refused('guarded SMTP startup binding changed')

    @classmethod
    def native(cls,bootstrap=None):
        if type(bootstrap)is not _Bootstrap:
            raise Refused('native guarded SMTP startup unavailable')
        # Endpoint qualification remains closed. No caller or flag here can
        # bypass fixed host/owner/socket admission or create a broker service.
        endpoint=PrivateControlEndpoint.native()
        budget=OperationBudget(int(time.time())+STARTUP_SECONDS,maximum_seconds=STARTUP_SECONDS)
        return cls._read(bootstrap,ROOT,0,endpoint,budget)
