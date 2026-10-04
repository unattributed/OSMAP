"""Exact Rust account_mutation v1 wire contract; bounded memory, no activation."""
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import re
import unicodedata

from authoritative_password import AuthoritativePasswordAdapter, Refused
from account_epoch import EpochStore, MAX_EPOCH
from prepared_password import PreparedAction

SCHEMA = 'osmap-account-mutation-v1'
ACTION = 'change_password'
LIMIT = 4096
U64_MAX = 2**64 - 1


class Invalid(Refused):
    """Invalid/authentication/expiry is not proof that an earlier write did not occur."""


def encoded(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':')).encode('utf-8')
    except (ValueError, TypeError, UnicodeError):
        raise Invalid('mutation wire unavailable') from None


def uint(value):
    return type(value) is int and 0 <= value <= U64_MAX


def lower_hex(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def bounded(value, limit):
    if type(value) is not str or not value or any(unicodedata.category(c) == 'Cc' for c in value):
        return False
    try:
        return len(value.encode('utf-8')) <= limit
    except UnicodeError:
        return False


def key_valid(key):
    if type(key) is not bytes or not 32 <= len(key) <= 1024:
        raise Invalid('mutation authority unavailable')


@dataclass(frozen=True, repr=False)
class VerifiedRequest:
    action: PreparedAction
    signature: str

    def payload(self):
        a = self.action
        return encoded([SCHEMA, ACTION, 'request', a.account, a.epoch, a.intent_reference,
                        a.session_id, a.request_id, a.source, a.issued, a.expires,
                        a.current, a.new, a.confirmation])

    def verify(self, key, now):
        key_valid(key)
        a = self.action
        if (type(a) is not PreparedAction or not uint(now) or not uint(a.issued) or
                not uint(a.expires) or a.issued == 0 or a.expires != a.issued + 300 or
                now < a.issued or now >= a.expires or not uint(a.epoch) or a.epoch >= MAX_EPOCH or
                not lower_hex(a.intent_reference) or not lower_hex(a.session_id) or
                not bounded(a.request_id, 128) or not a.request_id.strip() or
                not bounded(a.source, 128) or '%' in a.source or not bounded(a.current, 1024) or
                not bounded(a.new, 512) or not 15 <= len(a.new) <= 128 or
                a.new != a.confirmation or a.current == a.new or not lower_hex(self.signature)):
            raise Invalid('mutation action unavailable')
        try:
            AuthoritativePasswordAdapter._account(a.account)
            ipaddress.ip_address(a.source)
        except (Refused, ValueError, TypeError):
            raise Invalid('mutation action unavailable') from None
        expected = hmac.new(key, self.payload(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.signature):
            raise Invalid('mutation authority unavailable')


def verify_request(raw, key, now):
    if type(raw) is not bytes or not raw or len(raw) > LIMIT:
        raise Invalid('mutation wire unavailable')
    try:
        r = json.loads(raw.decode('utf-8'), object_pairs_hook=EpochStore._unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        fields = {'schema', 'action', 'account', 'epoch', 'intent_reference', 'session_id',
                  'request_id', 'source', 'issued', 'expires', 'current', 'new',
                  'confirmation', 'signature'}
        if type(r) is not dict or set(r) != fields or r['schema'] != SCHEMA or r['action'] != ACTION:
            raise ValueError
        result = VerifiedRequest(PreparedAction(r['account'], r['epoch'], r['intent_reference'],
                                 r['session_id'], r['request_id'], r['source'], r['issued'],
                                 r['expires'], r['current'], r['new'], r['confirmation']), r['signature'])
        result.verify(key, now)
        return result
    except (ValueError, TypeError, UnicodeError, Refused, RecursionError):
        raise Invalid('mutation request unavailable') from None


def valid_outcome(outcome, epoch):
    if type(outcome) is not dict:
        raise Invalid('mutation outcome unavailable')
    status = outcome.get('status')
    if status in ('known_refused', 'contained') and set(outcome) == {'status'}:
        return {'status': status}
    if status == 'changed' and set(outcome) == {'status', 'epoch', 'changed_at'}:
        value = outcome['epoch']
        if not uint(value) or value != epoch + 1 or value > MAX_EPOCH:
            raise Invalid('mutation outcome unavailable')
        try:
            stamp = AuthoritativePasswordAdapter._stamp(outcome['changed_at'])
        except (Refused, TypeError):
            raise Invalid('mutation outcome unavailable') from None
        # Fixed Rust enum field order is part of the authenticated tuple.
        return {'status': 'changed', 'epoch': value, 'changed_at': stamp}
    raise Invalid('mutation outcome unavailable')


def response(request, outcome, key, now):
    if type(request) is not VerifiedRequest:
        raise Invalid('mutation action unavailable')
    request.verify(key, now)
    a = request.action
    outcome = valid_outcome(outcome, a.epoch)
    payload = encoded([SCHEMA, ACTION, 'response', a.account, a.intent_reference,
                       a.request_id, request.signature, now, outcome])
    value = {'schema': SCHEMA, 'action': ACTION, 'account': a.account,
             'intent_reference': a.intent_reference, 'request_id': a.request_id,
             'request_signature': request.signature, 'responded_at': now,
             'outcome': outcome, 'signature': hmac.new(key, payload, hashlib.sha256).hexdigest()}
    raw = encoded(value)
    if len(raw) > LIMIT:
        raise Invalid('mutation wire unavailable')
    return raw
