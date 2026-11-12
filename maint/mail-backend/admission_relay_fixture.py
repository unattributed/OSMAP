"""Public Rust-compatible admission HMAC pipe peer; no native SSH/mail/SQL."""
import hashlib,hmac,json,os,sys,time
KEY=bytes([23])*32
SCHEMA='osmap-account-admission-v1'
def encoded(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def exact(n):
 raw=sys.stdin.buffer.read(n)
 if len(raw)!=n:raise ValueError
 return raw
mode=sys.argv[1];expected=sys.argv[2]
size=int.from_bytes(exact(4),'big')
if not 0<size<=4096:raise ValueError
raw=exact(size)
if sys.stdin.buffer.read(1)!=b''or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError
value=json.loads(raw);now=int(time.time())
payload=encoded([SCHEMA,'request',value['account'],value['operation'],value['issued'],value['expires'],value['nonce']])
if(not hmac.compare_digest(value['signature'],hmac.new(KEY,payload,hashlib.sha256).hexdigest())or not value['issued']<=now<value['expires']):raise ValueError
if mode=='wait':time.sleep(5)
elif mode=='oversize':sys.stdout.buffer.write((4097).to_bytes(4,'big'));sys.stdout.buffer.flush()
else:
 operation=value['operation'];epoch=4
 if operation['operation']=='admit'and operation['epoch']!=epoch:raise ValueError
 response=dict(schema=SCHEMA,account=value['account'],nonce=value['nonce'],status='active',epoch=epoch)
 response['signature']=hmac.new(KEY,encoded([SCHEMA,'response',response['account'],response['nonce'],'active',epoch]),hashlib.sha256).hexdigest()
 reply=encoded(response);sys.stdout.buffer.write(len(reply).to_bytes(4,'big')+reply);sys.stdout.buffer.flush()
 if mode=='trailing':sys.stdout.buffer.write(b'X');sys.stdout.buffer.flush()
 if mode=='lateexit':os.close(1);time.sleep(.08);os._exit(0)
 if mode=='badexit':raise SystemExit(7)
