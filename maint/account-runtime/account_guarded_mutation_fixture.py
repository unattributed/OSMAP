"""Reserved public Rust/Python authority compatibility fixture; no writer."""
import dataclasses,json,sys
from account_guarded_mutation import verify_guarded,Invalid
try:
    raw=sys.stdin.buffer.read(32769)
    if len(raw)>32768:raise ValueError
    value=json.loads(raw)
    if set(value)!={'raw_hex','now_millis'}:raise ValueError
    proof=verify_guarded(bytes.fromhex(value['raw_hex']),bytes([17])*32,bytes([19])*32,value['now_millis'])
    action=proof.budget.request.action
    if action.account!='alice@example.test':raise ValueError
    output={'accepted':True,'current_action':proof.authorize(action,value['now_millis']//1000),
            'copied_action':proof.authorize(dataclasses.replace(action),value['now_millis']//1000),
            'account':action.account,'epoch':action.epoch}
except (Invalid,ValueError,TypeError,KeyError):output={'accepted':False}
sys.stdout.buffer.write(json.dumps(output,separators=(',',':')).encode())
