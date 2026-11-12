"""Authenticated original workflow budget envelope around untouched v1 bytes.

No clock-synchronization/native-confinement or credential-effect claim. The
receiver rejects future sender samples and any expired/rolled-back budget with
no grace. Exact native Unix peers share a kernel clock only after qualification.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import time

from account_epoch import EpochStore
from account_mutation_codec import encoded, Invalid, key_valid, lower_hex, uint, verify_request
from operation_budget import OperationBudget

SCHEMA = 'osmap-account-mutation-budget-v1'
LIMIT = 12288
MAXIMUM_MILLIS = 60000


def wall_millis():
    # Rounding up at the receiver never adds fractional-millisecond grace.
    value = time.time()
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise Invalid('mutation budget clock unavailable')
    return math.ceil(value * 1000)


@dataclass(frozen=True, repr=False)
class VerifiedBudget:
    raw: bytes
    request: object
    sent_millis: int
    deadline_millis: int


def payload(value):
    return encoded([SCHEMA, 'remaining_budget', value['raw_sha256'], value['account'],
                    value['intent_reference'], value['request_signature'],
                    value['sent_millis'], value['deadline_millis']])


def envelope(raw, key, sent_millis, deadline_millis):
    """Public synthetic fixture issuer; production Rust emits the same tuple."""
    request = verify_request(raw, key, sent_millis // 1000)
    value = dict(schema=SCHEMA, request_hex=raw.hex(), raw_sha256=hashlib.sha256(raw).hexdigest(),
                 account=request.action.account, intent_reference=request.action.intent_reference,
                 request_signature=request.signature, sent_millis=sent_millis,
                 deadline_millis=deadline_millis)
    value['signature'] = hmac.new(key, payload(value), hashlib.sha256).hexdigest()
    result = encoded(value)
    verify_envelope(result, key, sent_millis)
    return result


def verify_envelope(raw, key, now_millis):
    key_valid(key)
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT or not uint(now_millis):
        raise Invalid('mutation budget unavailable')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=EpochStore._unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {'schema', 'request_hex', 'raw_sha256', 'account', 'intent_reference',
                  'request_signature', 'sent_millis', 'deadline_millis', 'signature'}
        if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA or
                not all(lower_hex(value[k]) for k in
                        ('raw_sha256', 'intent_reference', 'request_signature', 'signature')) or
                not uint(value['sent_millis']) or not uint(value['deadline_millis']) or
                value['sent_millis'] <= 0 or
                not 0 < value['deadline_millis'] - value['sent_millis'] <= MAXIMUM_MILLIS or
                now_millis < value['sent_millis'] or now_millis >= value['deadline_millis'] or
                type(value['request_hex']) is not str or
                not 0 < len(value['request_hex']) <= 8192 or
                len(value['request_hex']) % 2 or
                not lower_hex(value['request_hex'], len(value['request_hex']))):
            raise ValueError
        expected = hmac.new(key, payload(value), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, value['signature']):
            raise ValueError
        inner = bytes.fromhex(value['request_hex'])
        if not hmac.compare_digest(hashlib.sha256(inner).hexdigest(), value['raw_sha256']):
            raise ValueError
        request = verify_request(inner, key, now_millis // 1000)
        if (request.action.account != value['account'] or
                request.action.intent_reference != value['intent_reference'] or
                request.signature != value['request_signature'] or
                value['deadline_millis'] > request.action.expires * 1000):
            raise ValueError
        return VerifiedBudget(inner, request, value['sent_millis'], value['deadline_millis'])
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise Invalid('mutation budget unavailable') from None


def operation_budget(proof, *, received_mono, received_millis,
                     monotonic=time.monotonic, clock_millis=wall_millis):
    if type(proof) is not VerifiedBudget:
        raise Invalid('mutation budget unavailable')
    return OperationBudget.from_original_deadline(
        proof.request.action.expires, received_mono=received_mono,
        received_millis=received_millis, sent_millis=proof.sent_millis,
        deadline_millis=proof.deadline_millis, monotonic=monotonic,
        wall_millis=clock_millis)
