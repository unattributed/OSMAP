"""Fixed root service entry; native qualification gates remain false."""
import signal
import resource
import sys
import threading

if __name__=='__main__':
    sys.path.insert(0,'/usr/local/libexec/osmap/account-runtime')

from account_mutation_supervisor import serve_native


def main():
    # Signals remove future admission; an in-flight operation retains its same
    # bounded original deadline. Forced termination/remote worker stop still
    # require separate native supervisor/watchdog qualification.
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    stop=threading.Event()
    previous={}
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):
            previous[sig]=signal.signal(sig,lambda *_args:stop.set())
        serve_native(stop.is_set)
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1) from None
