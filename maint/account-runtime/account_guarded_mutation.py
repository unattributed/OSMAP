"""Separate guarded-session assertion verifier; no listener or activation.

The issuer can mint this assertion only during actual Rust FileSessionStore
exclusive validation. It attests that exact snapshot and original deadline, not
continued distributed lock ownership after issuer failure. A native worker still
requires qualified routing/liveness, confinement and fixed dependency bootstrap.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
from account_epoch import EpochStore
from account_mutation_budget import verify_envelope
from account_mutation_codec import Invalid, encoded, key_valid, lower_hex, uint

SCHEMA = 'osmap-guarded-session-proof-v1'
LIMIT = 12288
FIELDS = frozenset(('schema','account','epoch','session_id','request_id','source',
                   'intent_reference','request_sha256','budget_sha256','checked_millis',
                   'session_expires','idle_expires','issued','expires','deadline_millis','signature'))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',',':')).encode('utf-8')


def payload(p):
    return encoded([SCHEMA,'guarded_file_session',p['account'],p['epoch'],p['session_id'],
                    p['request_id'],p['source'],p['intent_reference'],p['request_sha256'],
                    p['budget_sha256'],p['checked_millis'],p['session_expires'],
                    p['idle_expires'],p['issued'],p['expires'],p['deadline_millis']])


@dataclass(frozen=True, repr=False)
class VerifiedGuardedMutation:
    budget: object
    proof: dict
    key: bytes

    def authorize(self, action, now):
        # No external Boolean substitutes for the independently verified proof.
        # The coordinator must use this same exact decoded immutable action.
        if action is not self.budget.request.action or not uint(now):
            return False
        try:
            _verify_proof(self.proof, self.budget, self.key, now * 1000)
            return True
        except Invalid:
            return False


def _verify_proof(p, budget, key, now_millis):
    a = budget.request.action
    if (type(p) is not dict or set(p) != FIELDS or p['schema'] != SCHEMA
            or not uint(now_millis)
            or not all(uint(p[k]) for k in ('epoch','checked_millis','session_expires',
                                           'idle_expires','issued','expires','deadline_millis'))
            or not all(lower_hex(p[k]) for k in ('session_id','intent_reference',
                                               'request_sha256','budget_sha256','signature'))
            or p['checked_millis'] != budget.sent_millis
            or p['deadline_millis'] != budget.deadline_millis
            or now_millis < p['checked_millis'] // 1000 * 1000
            or now_millis >= p['deadline_millis']
            or p['idle_expires'] > p['session_expires']
            or p['deadline_millis'] > p['idle_expires'] * 1000
            or now_millis >= p['idle_expires'] * 1000
            or p['account'] != a.account or p['epoch'] != a.epoch
            or p['session_id'] != a.session_id or p['request_id'] != a.request_id
            or p['source'] != a.source or p['intent_reference'] != a.intent_reference
            or p['issued'] != a.issued or p['expires'] != a.expires
            or p['request_sha256'] != hashlib.sha256(budget.raw).hexdigest()):
        raise Invalid('guarded session authority unavailable')
    expected = hmac.new(key, payload(p), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,p['signature']):
        raise Invalid('guarded session authority unavailable')


def verify_guarded(raw, mutation_key, session_key, now_millis):
    key_valid(mutation_key);key_valid(session_key)
    if (mutation_key == session_key or type(raw) is not bytes
            or not 0 < len(raw) <= LIMIT):
        raise Invalid('guarded session authority unavailable')
    try:
        value = json.loads(raw.decode('utf-8'),object_pairs_hook=EpochStore._unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(value) is not dict or set(value) != {'budget','session_proof'}:
            raise ValueError
        budget_bytes = canonical(value['budget'])
        budget = verify_envelope(budget_bytes,mutation_key,now_millis)
        proof = value['session_proof']
        _verify_proof(proof,budget,session_key,now_millis)
        if not hmac.compare_digest(proof['budget_sha256'],hashlib.sha256(budget_bytes).hexdigest()):
            raise ValueError
        return VerifiedGuardedMutation(budget,proof,session_key)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        raise Invalid('guarded session authority unavailable') from None
