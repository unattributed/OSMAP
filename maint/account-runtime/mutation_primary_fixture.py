"""Public synthetic verifier program, never native auth, SQL or provider."""
import os,sys,time
mode=sys.argv[1];password=sys.stdin.buffer.read(1026)
if mode=='wait':time.sleep(5)
elif mode=='huge':os.write(1,b'x'*4097)
elif mode=='foreign':os.write(1,b'auth succeeded\nuser=bob@example.test\n')
elif mode=='conflict':os.write(1,b'auth succeeded\nauth failed\nuser=alice@example.test\n')
elif mode=='failed':os.write(1,b'auth failed\n');raise SystemExit(77)
else:
 if mode=='ownership' and os.getpgrp()!=os.getppid():raise SystemExit(1)
 if password!=b'public synthetic password\n':raise SystemExit(1)
 os.write(1,b'auth succeeded\nuser=alice@example.test\n')
