"""Guarded-only pending-before-write issuer challenge; native route disabled.

An authenticated ACK is accepted only after durable account pending, bound to
this exact guarded frame/action/nonce/original deadline. It attests the issuer
answered while its actual local stored-session lease was held. Durable pending
contains a later issuer loss; no ACK proves distributed locks remain alive.
"""
import hashlib
import hmac
import json
import secrets
import time

from account_epoch import EpochStore
from account_mutation_codec import Invalid, encoded, key_valid, lower_hex, uint
from operation_budget import OperationBudget

SCHEMA='osmap-account-mutation-continuity-v1'
LIMIT=2048
FIELDS=frozenset(('schema','phase','account','epoch','intent_reference','request_signature',
                  'frame_sha256','nonce','deadline_millis','challenged_millis','signature'))


def payload(v):
    return encoded([SCHEMA,v['phase'],v['account'],v['epoch'],v['intent_reference'],
                    v['request_signature'],v['frame_sha256'],v['nonce'],
                    v['deadline_millis'],v['challenged_millis']])


def signed(value,key):
    value=dict(value)
    value['signature']=hmac.new(key,payload(value),hashlib.sha256).hexdigest()
    return encoded(value)


def verify(raw,key,phase):
    key_valid(key)
    if type(raw) is not bytes or not 0<len(raw)<=LIMIT or phase not in ('challenge','ack'):
        raise Invalid('issuer continuity unavailable')
    try:
        v=json.loads(raw.decode('utf-8'),object_pairs_hook=EpochStore._unique,
                     parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        if (type(v) is not dict or set(v)!=FIELDS or v['schema']!=SCHEMA or v['phase']!=phase
                or not all(lower_hex(v[k]) for k in ('intent_reference','request_signature',
                                                    'frame_sha256','nonce','signature'))
                or not uint(v['epoch']) or not uint(v['deadline_millis'])
                or not uint(v['challenged_millis']) or v['challenged_millis']<=0
                or not v['challenged_millis']<v['deadline_millis']
                or v['deadline_millis']-v['challenged_millis']>60000
                or type(v['account']) is not str):raise ValueError
        if not hmac.compare_digest(v['signature'],hmac.new(key,payload(v),hashlib.sha256).hexdigest()):raise ValueError
        return v
    except (ValueError,TypeError,UnicodeError,KeyError,RecursionError):
        raise Invalid('issuer continuity unavailable') from None


class PendingIssuerConfirmation:
    """Fixed helper-owned actual peer, exact proof/action and same budget.

    Construct only after private peer plus complete guarded frame verification.
    Request fields cannot select a stream, key, callback or durable store.
    """
    def __init__(self,stream,guarded,frame,key,budget,clock_millis):
        from account_guarded_mutation import VerifiedGuardedMutation
        if (type(guarded) is not VerifiedGuardedMutation or type(frame) is not bytes
                or not frame or type(budget) is not OperationBudget or not callable(clock_millis)):
            raise Invalid('issuer continuity dependency unavailable')
        key_valid(key)
        self._stream=stream;self._proof=guarded;self._frame_sha=hashlib.sha256(frame).hexdigest()
        self._key=key;self._budget=budget;self._clock=clock_millis;self._used=False

    def _read(self,n):
        result=bytearray()
        while len(result)<n:
            self._stream.settimeout(self._budget.remaining())
            part=self._stream.recv(n-len(result))
            if not part:raise Invalid('issuer continuity lost')
            result.extend(part)
        self._budget.remaining()
        return bytes(result)

    def __call__(self,action):
        if self._used or action is not self._proof.budget.request.action:
            raise Invalid('issuer continuity action unavailable')
        self._used=True
        self._budget.remaining()
        now=self._clock()
        if not uint(now) or not self._proof.authorize(action,now//1000):
            raise Invalid('issuer continuity expired')
        v=dict(schema=SCHEMA,phase='challenge',account=action.account,epoch=action.epoch,
               intent_reference=action.intent_reference,request_signature=self._proof.budget.request.signature,
               frame_sha256=self._frame_sha,nonce=secrets.token_hex(32),
               deadline_millis=self._proof.budget.deadline_millis,challenged_millis=now)
        raw=signed(v,self._key);verify(raw,self._key,'challenge')
        self._stream.settimeout(self._budget.remaining())
        self._stream.sendall(len(raw).to_bytes(4,'big')+raw)
        n=int.from_bytes(self._read(4),'big')
        if not 0<n<=LIMIT:raise Invalid('issuer continuity frame unavailable')
        ack=verify(self._read(n),self._key,'ack')
        for field in FIELDS-{'phase','signature'}:
            if ack[field]!=v[field]:raise Invalid('issuer continuity binding unavailable')
        # Exactly one ACK plus writer half-close; EOF proves framing only.
        # Pending is already durable, so a subsequent issuer loss cannot reopen
        # the old account epoch or automatically repeat this intent.
        self._stream.settimeout(self._budget.remaining())
        if self._stream.recv(1)!=b'':raise Invalid('issuer continuity trailing frame')
        self._budget.remaining()
        final=self._clock()
        if not uint(final) or final<now or not self._proof.authorize(action,final//1000):
            raise Invalid('issuer continuity expired')
        self._budget.remaining()
        return True
