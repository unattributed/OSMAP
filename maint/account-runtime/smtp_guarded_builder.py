"""Trusted disabled worker startup binding; original bytes stay local."""
from account_guarded_mutation import VerifiedGuardedMutation
from account_mutation_codec import key_valid
from account_mutation_supervisor import _Bootstrap
from authoritative_password import AuthoritativePasswordAdapter,Refused
from mail_session_containment import MailSessionContainment
from operation_budget import OperationBudget
from prepared_password import PreparedPasswordCoordinator
from smtp_control_authorization import ControlAuthority,derive_authorization
from smtp_mutation_containment import PrivateControlEndpoint,GuardedSmtpContainment

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
    @classmethod
    def native(cls,*_args):
        # Fixed operator key/endpoint custody and unique worker/issuer bootstrap
        # are not qualified. No flag patch can cause private file access.
        raise Refused('native guarded SMTP startup unavailable')
