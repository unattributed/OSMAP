"""Public synthetic exact-byte challenge compatibility, no writer or listener."""
import hashlib,json,sys
from account_mutation_codec import verify_request
from account_mutation_continuity import signed,verify,SCHEMA,FIELDS
try:
 value=json.loads(sys.stdin.buffer.read(32769));key=bytes([17])*32
 frame=bytes.fromhex(value['frame_hex']);at=value['now_millis'];mode=value['mode']
 if mode=='challenge':
  guarded=json.loads(frame);raw=bytes.fromhex(guarded['budget']['request_hex'])
  request=verify_request(raw,key,at//1000);a=request.action
  p=dict(schema=SCHEMA,phase='challenge',account=a.account,epoch=a.epoch,
    intent_reference=a.intent_reference,request_signature=request.signature,
    frame_sha256=hashlib.sha256(frame).hexdigest(),nonce='c'*64,
    deadline_millis=guarded['budget']['deadline_millis'],challenged_millis=at)
  out={'accepted':True,'challenge_hex':signed(p,key).hex()}
 elif mode=='ack':
  challenge=verify(bytes.fromhex(value['challenge_hex']),key,'challenge')
  ack=verify(bytes.fromhex(value['ack_hex']),key,'ack')
  out={'accepted':all(ack[k]==challenge[k] for k in FIELDS-{'phase','signature'})}
 else:raise ValueError
except Exception:out={'accepted':False}
sys.stdout.buffer.write(json.dumps(out,separators=(',',':')).encode())
