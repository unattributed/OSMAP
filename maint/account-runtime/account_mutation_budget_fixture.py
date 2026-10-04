"""Reserved public synthetic compatibility fixture only; no worker dispatch."""
import hashlib,json,sys
from account_mutation_budget import verify_envelope,envelope
from account_mutation_codec import Invalid
raw=sys.stdin.buffer.read(32769)
try:
    if len(raw)>32768:raise ValueError
    value=json.loads(raw)
    if set(value)!={'raw_hex','now_millis'}:raise ValueError
    original=bytes.fromhex(value['raw_hex'])
    proof=verify_envelope(original,bytes([17])*32,value['now_millis'])
    if proof.request.action.account!='alice@example.test':raise ValueError
    output={'accepted':True,'inner_sha256':hashlib.sha256(proof.raw).hexdigest(),
            'reencoded_hex':envelope(proof.raw,bytes([17])*32,proof.sent_millis,proof.deadline_millis).hex(),
            'remaining_millis':proof.deadline_millis-value['now_millis']}
except (Invalid,ValueError,TypeError,KeyError):output={'accepted':False}
sys.stdout.buffer.write(json.dumps(output,separators=(',',':')).encode())
