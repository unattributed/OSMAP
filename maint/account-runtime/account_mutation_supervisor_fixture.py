"""Fixed public synthetic child, no native adapter/auth/SQL/provider effects."""
import os
from pathlib import Path
import socket
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_mutation_supervisor import COMPLETE

mode=sys.argv[1] if len(sys.argv)==2 else 'reply'
n=int.from_bytes(sys.stdin.buffer.read(4),'big')
raw=sys.stdin.buffer.read(n+1)
if len(raw)!=n:raise SystemExit(1)
stream=socket.socket(fileno=os.dup(1))
if mode=='coordinator':
 import test_account_mutation_worker as f
 import test_guarded_mutation_worker as g
 from account_mutation_entry import _dispatch
 from account_mutation_supervisor import _Bootstrap
 from account_mutation_worker import MutationWorker
 from io import BytesIO
 case=f.WorkerTests();case.setUp()
 try:
  case.now=int(time.time());case.clock=lambda:int(time.time());case.monotonic=time.monotonic
  worker=MutationWorker(f.KEY,frozenset([f.ACCOUNT]),case.journal,case.store,
   case.build,lambda *args:(_ for _ in ()).throw(AssertionError('legacy authority forbidden')),
   case.clock,case.monotonic,session_key=g.SESSION_KEY)
  bootstrap=_Bootstrap(f.KEY,g.SESSION_KEY,frozenset([f.ACCOUNT]),os.getuid())
  _dispatch(worker,bootstrap,BytesIO(n.to_bytes(4,'big')+raw),stream)
 finally:case.tearDown()
elif mode=='wait':time.sleep(5)
elif mode=='trailing':
 stream.sendall(b'\x00\x00\x00\x02{}X');stream.shutdown(socket.SHUT_WR);os.write(2,COMPLETE)
elif mode=='badmarker':
 stream.sendall(b'\x00\x00\x00\x02{}');stream.shutdown(socket.SHUT_WR);os.write(2,b'bad')
else:
 stream.sendall(b'\x00\x00\x00\x02{}');stream.shutdown(socket.SHUT_WR);os.write(2,COMPLETE)
stream.close()
if mode=='badexit':raise SystemExit(7)
