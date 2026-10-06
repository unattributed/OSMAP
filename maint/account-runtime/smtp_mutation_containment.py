"""Disabled actual pending-hook -> SASL cutoff -> independent mail termination.

A trusted worker supplies the same authenticated original budget and minimal
control authorization. Source fixtures cannot attest unique worker/flock
ownership, production routing/ingress, TCP absence or enable a native factory.
"""
import os
import hashlib
import json
from pathlib import Path
import socket
import stat
from account_mutation_supervisor import _directory
from account_guarded_mutation import VerifiedGuardedMutation
from account_epoch import EpochStore
from authoritative_password import Refused,Unconfirmed
from mail_session_containment import MailSessionContainment,SmtpTerminationScope
from operation_budget import OperationBudget
from prepared_password import PreparedAction
from smtp_auth_control import LifecycleControlClient,_send
from smtp_auth_lifecycle import _kernel_peer,_socket_identity
from smtp_control_authorization import ControlAuthority,verify_authorization

NATIVE_MUTATION_SMTP_CONTROL_QUALIFIED=False
CONTROL_SOCKET=Path('/var/run/osmap-account-smtp-control/control.sock')

class PrivateControlEndpoint:
    def __init__(self,path,owner):
        if not isinstance(path,Path)or path.name!='control.sock'or type(owner)is not int or owner<0:
            raise Refused('SMTP control endpoint startup unavailable')
        self.path=path;self.owner=owner
        fd=_directory(path.parent,owner)
        try:self._parent=self._identity(os.fstat(fd))
        finally:os.close(fd)
        self._socket=self._current()
    @staticmethod
    def _identity(info):return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink
    def _current(self):
        if self.path.resolve()!=self.path:raise Refused('SMTP control endpoint path unavailable')
        fd=_directory(self.path.parent,self.owner)
        try:
            if self._identity(os.fstat(fd))!=self._parent:raise Refused('SMTP control endpoint namespace changed')
        finally:os.close(fd)
        info=self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode)or info.st_uid!=self.owner or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
            raise Refused('SMTP control endpoint socket unavailable')
        return self._identity(info)
    def recheck(self,budget):
        budget.remaining()
        if self._current()!=self._socket:raise Refused('SMTP control endpoint inode changed')
        budget.remaining()
    def connect(self,budget):
        self.recheck(budget);stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            stream.settimeout(budget.cap_seconds(1));stream.connect(str(self.path))
            identity=_socket_identity(stream)
            if _kernel_peer(stream)[0]!=self.owner:raise Refused('SMTP control endpoint peer refused')
            self.recheck(budget)
            if _socket_identity(stream)!=identity:raise Refused('SMTP control endpoint descriptor changed')
            return stream
        except BaseException:stream.close();raise
    @classmethod
    def native(cls,*_args):raise Refused('native SMTP mutation endpoint unavailable')

class GuardedSmtpContainment:
    """Preserves normal mail readiness; pending hook holds sealed broker cutoff."""
    def __init__(self,mail,endpoint,authorization,authority,original,*,clock_millis):
        if (type(mail)is not MailSessionContainment or type(endpoint)is not PrivateControlEndpoint
                or type(authority)is not ControlAuthority or type(original)is not VerifiedGuardedMutation
                or not callable(clock_millis)
                or mail._smtp_scope is not SmtpTerminationScope.REQUIRED
                or mail._topology is None or mail._topology._certificate_version!=2
                or mail._proxy_control is None or mail._proxy_control._namespace._owner!=endpoint.owner):
            raise Refused('SMTP mutation containment startup unavailable')
        proof=verify_authorization(authorization,authority,clock_millis())
        # This worker already holds original credential-bearing bytes. Compare
        # the MACed commitment locally; those bytes never cross broker control.
        value=json.loads(original.budget.raw,object_pairs_hook=EpochStore._unique)
        local_action=original.budget.request.action
        sealed=json.loads(authorization)
        fields=('account','epoch','intent_reference','session_id','request_id','source','issued','expires','current','new','confirmation')
        if (not original.authorize(local_action,clock_millis()//1000)
                or any(value[k]!=getattr(local_action,k)for k in fields)
                or value['signature']!=original.budget.request.signature
                or sealed['request_signature']!=original.budget.request.signature
                or sealed['request_sha256']!=hashlib.sha256(original.budget.raw).hexdigest()
                or proof.sent_millis!=original.budget.sent_millis
                or proof.deadline_millis!=original.budget.deadline_millis):
            raise Refused('SMTP mutation original request commitment unavailable')
        if (proof.account!=mail._account or type(mail._budget)is not OperationBudget
):
            raise Refused('SMTP mutation original authorization budget unavailable')
        mail._budget.require_original(sent_millis=proof.sent_millis,
            deadline_millis=proof.deadline_millis,expires_at=proof.expires)
        self._mail=mail;self._endpoint=endpoint;self._authorization=authorization
        self._proof=proof;self._action=local_action;self._authority=authority;self._clock_millis=clock_millis
        self._budget=mail._budget;self._client=None;self._state='new'
        endpoint.recheck(self._budget)
    def _current(self,account,*,endpoint=True):
        if account!=self._proof.account:raise Refused('SMTP mutation account refused')
        self._budget.require_original(sent_millis=self._proof.sent_millis,
            deadline_millis=self._proof.deadline_millis,expires_at=self._proof.expires)
        if endpoint:self._endpoint.recheck(self._budget)
        checked=verify_authorization(self._authorization,self._authority,self._clock_millis())
        if checked!=self._proof:raise Refused('SMTP mutation sealed authorization changed')
    def ready(self,account):
        if self._state!='new':raise Refused('SMTP mutation readiness already consumed')
        self._current(account);result=self._mail.ready(account)
        self._current(account);self._state='ready';return result
    def capture_pending(self,action):
        # Invoked ONLY after the same coordinator's durable pending record and
        # original issuer ACK, under the existing account flock, before SQL.
        if (type(action)is not PreparedAction or action is not self._action or self._state!='ready'or action.account!=self._proof.account
                or action.epoch!=self._proof.epoch or action.intent_reference!=self._proof.intent_reference):
            raise Refused('SMTP mutation pending action refused')
        self._state='capture-dispatched';stream=None
        try:
            self._current(action.account);stream=self._endpoint.connect(self._budget)
            _send(stream,len(self._authorization).to_bytes(4,'big')+self._authorization,self._budget)
            self._client=LifecycleControlClient(stream,self._mail._proxy_control._namespace,self._budget)
            self._client.capture(action.account);self._current(action.account)
            self._state='captured';return True
        except BaseException:
            if stream is not None:stream.close()
            self._state='contained';raise Unconfirmed('SMTP mutation pending capture unconfirmed')from None
    def before_write(self,account):
        if self._state!='captured':raise Refused('SMTP mutation pending capture unavailable')
        self._current(account);return self._mail.before_write(account)
    def invalidate_changed_auth(self,account):
        if self._state!='captured':raise Unconfirmed('SMTP mutation auth invalidation unavailable')
        self._current(account);return self._mail.invalidate_changed_auth(account)
    def finish(self,account):
        if self._state!='captured'or self._client is None:raise Unconfirmed('SMTP mutation closure unavailable')
        self._state='cancel-dispatched'
        try:
            self._current(account);self._client.cancel();self._current(account,endpoint=False)
            # CLOSED covers broker SASL ends only; proxy TCP kick/query, IMAP
            # kick/query and topology continuity remain independently required.
            if self._mail.finish(account)is not True:raise ValueError
            self._current(account,endpoint=False);self._state='finished';return True
        except BaseException:
            self._state='contained';raise Unconfirmed('SMTP mutation independent containment unconfirmed')from None
    def abandon(self):
        # Release only this accepted source-owned descriptor. No reconnect,
        # cancel retry, grant reset, fixture process signal or new budget.
        if self._client is not None:self._client._stream.close()
        if self._state!='finished':self._state='contained'
    @classmethod
    def native(cls,*_args):raise Refused('native SMTP mutation containment unavailable')
