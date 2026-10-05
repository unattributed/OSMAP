"""Fixed public pipe peer; real MAC wire bytes, no native SSH/SQL/provider."""
from pathlib import Path
import hashlib,os,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'account-runtime'))
from account_guarded_mutation import verify_guarded
from account_mutation_budget import wall_millis
from account_mutation_codec import response
from account_mutation_continuity import signed,verify,FIELDS,SCHEMA
KEY=bytes([17])*32;SESSION=bytes([19])*32
mode=sys.argv[1]
def exact(n):
 out=bytearray()
 while len(out)<n:
  p=sys.stdin.buffer.read(n-len(out))
  if not p:raise EOFError
  out.extend(p)
 return bytes(out)
def framed(limit):
 n=int.from_bytes(exact(4),'big')
 if not 0<n<=limit:raise ValueError
 return exact(n)
def send(raw):
 sys.stdout.buffer.write(len(raw).to_bytes(4,'big')+raw);sys.stdout.buffer.flush()
raw=framed(12288);proof=verify_guarded(raw,KEY,SESSION,wall_millis())
a=proof.budget.request.action
if mode=='wait':time.sleep(5)
elif mode=='oversize':sys.stdout.buffer.write((4097).to_bytes(4,'big'));sys.stdout.buffer.flush()
else:
 p=dict(schema=SCHEMA,phase='challenge',account=a.account,epoch=a.epoch,
  intent_reference=a.intent_reference,request_signature=proof.budget.request.signature,
  frame_sha256=hashlib.sha256(raw).hexdigest(),nonce='c'*64,
  deadline_millis=proof.budget.deadline_millis,challenged_millis=wall_millis())
 challenge=signed(p,KEY);send(challenge)
 ack=verify(framed(2048),KEY,'ack')
 if not all(ack[k]==p[k] for k in FIELDS-{'phase','signature'}):raise ValueError
 if sys.stdin.buffer.read(1)!=b'':raise ValueError
 out=response(proof.budget.request,{'status':'changed','epoch':a.epoch+1,'changed_at':'20261004170000'},KEY,int(time.time()))
 if mode=='badmac':out=out.replace(b'"changed"',b'"altered"')
 send(out)
 if mode=='trailing':sys.stdout.buffer.write(b'X');sys.stdout.buffer.flush()
if mode=='badexit':raise SystemExit(7)
