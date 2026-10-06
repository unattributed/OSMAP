"""Password-free control delegation from an independently verified supervisor.

A distinct control MAC key is a fixed startup dependency. The broker receives
no password fields, raw request, mutation key or guarded-session signing key.
This has no native provisioning or caller activation path.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
from account_epoch import EpochStore
from account_guarded_mutation import verify_guarded
from account_mutation_codec import encoded,key_valid,lower_hex,uint,Invalid
from authoritative_password import AuthoritativePasswordAdapter
from operation_budget import OperationBudget

SCHEMA='osmap-smtp-control-authorization-v1'
LIMIT=2048
FIELDS=frozenset(('schema','account','epoch','intent_reference','session_id','request_id','source',
                 'request_sha256','guard_sha256','request_signature','issued','expires','sent_millis',
                 'deadline_millis','session_expires','idle_expires','signature'))

def payload(v):
    return encoded([SCHEMA,'capture_cancel_original_cutoff',*[v[k]for k in sorted(FIELDS-{'schema','signature'})]])

@dataclass(frozen=True,repr=False)
class ControlAuthority:
    key:bytes
    accounts:frozenset
    def __post_init__(self):
        key_valid(self.key)
        if type(self.accounts)is not frozenset or not self.accounts:raise Invalid('control authority unavailable')
        for account in self.accounts:AuthoritativePasswordAdapter._account(account)

@dataclass(frozen=True,repr=False)
class VerifiedControlAuthorization:
    account:str
    epoch:int
    intent_reference:str
    expires:int
    sent_millis:int
    deadline_millis:int
    commitment:str

    def budget(self,*,received_mono,received_millis,monotonic,clock_millis):
        return OperationBudget.from_original_deadline(self.expires,received_mono=received_mono,
          received_millis=received_millis,sent_millis=self.sent_millis,deadline_millis=self.deadline_millis,
          monotonic=monotonic,wall_millis=clock_millis)

def derive_authorization(raw,mutation_key,session_key,authority,now_millis):
    """Trusted supervisor only: verify originals locally, emit minimal delegation."""
    if type(authority)is not ControlAuthority or authority.key in (mutation_key,session_key):
        raise Invalid('control purpose key separation unavailable')
    original=verify_guarded(raw,mutation_key,session_key,now_millis)
    action=original.budget.request.action;p=original.proof
    value=dict(schema=SCHEMA,account=action.account,epoch=action.epoch,intent_reference=action.intent_reference,
      session_id=action.session_id,request_id=action.request_id,source=action.source,
      request_sha256=p['request_sha256'],guard_sha256=hashlib.sha256(raw).hexdigest(),
      request_signature=original.budget.request.signature,issued=action.issued,expires=action.expires,
      sent_millis=original.budget.sent_millis,deadline_millis=original.budget.deadline_millis,
      session_expires=p['session_expires'],idle_expires=p['idle_expires'])
    value['signature']=hmac.new(authority.key,payload(value),hashlib.sha256).hexdigest()
    result=encoded(value);verify_authorization(result,authority,now_millis)
    return result

def verify_authorization(raw,authority,now_millis):
    if type(authority)is not ControlAuthority or type(raw)is not bytes or not 0<len(raw)<=LIMIT:
        raise Invalid('control authorization unavailable')
    try:
        v=json.loads(raw.decode('ascii'),object_pairs_hook=EpochStore._unique,
                     parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        if type(v)is not dict or set(v)!=FIELDS or v['schema']!=SCHEMA or not uint(now_millis):raise ValueError
        if v['account']not in authority.accounts:raise ValueError
        for k in ('epoch','issued','expires','sent_millis','deadline_millis','session_expires','idle_expires'):
            if not uint(v[k]):raise ValueError
        for k in ('intent_reference','session_id','request_sha256','guard_sha256','request_signature','signature'):
            if not lower_hex(v[k]):raise ValueError
        # Closed original request identifiers are preserved as signed bindings;
        # they do not grant a unique kernel worker PID or continued flock.
        for k in ('request_id','source'):
            if type(v[k])is not str or not 1<=len(v[k])<=128 or not v[k].isascii()or any(ord(c)<33 or ord(c)>126 for c in v[k]):raise ValueError
        if (v['sent_millis']<=0 or not 0<v['deadline_millis']-v['sent_millis']<=60000
            or now_millis<v['sent_millis']or now_millis>=v['deadline_millis']
            or v['issued']*1000>v['sent_millis']or v['expires']<=v['issued']
            or v['deadline_millis']>v['expires']*1000 or v['idle_expires']>v['session_expires']
            or v['deadline_millis']>v['idle_expires']*1000):raise ValueError
        if not hmac.compare_digest(hmac.new(authority.key,payload(v),hashlib.sha256).hexdigest(),v['signature']):raise ValueError
        return VerifiedControlAuthorization(v['account'],v['epoch'],v['intent_reference'],v['expires'],
                                           v['sent_millis'],v['deadline_millis'],hashlib.sha256(raw).hexdigest())
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        raise Invalid('control authorization unavailable')from None
