"""Fixed child entry for future native helper; unavailable before qualification.

No command-line configuration or credentials. The supervisor authenticates its
peer and frame, holds terminal publication, and supervises this process group.
Native dependency construction (SQL grant/auth/complete SMTP containment) is
still unqualified; ordinary profiles never import or launch this entry.
"""
import os
import socket
import sys

# -I deliberately excludes the caller's cwd and Python environment. The fixed
# root-owned library directory must be independently checked by native startup.
if __name__ == '__main__':
    sys.path.insert(0, '/usr/local/libexec/osmap/account-runtime')

from account_mutation_supervisor import _Bootstrap, COMPLETE, _peer
from account_mutation_worker import MutationWorker, Unavailable
from account_guarded_mutation import LIMIT


def _dispatch(worker, bootstrap, source, stream):
    """Only the fixed supervised child calls this exact owned dependency seam."""
    if (type(worker) is not MutationWorker or type(bootstrap) is not _Bootstrap
            or os.getpid() != os.getpgrp() or _peer(stream) != os.geteuid()
            or worker._key != bootstrap.mutation_key
            or worker._session_key != bootstrap.session_key
            or worker._accounts != bootstrap.accounts):
        raise Unavailable('guarded child authority unavailable')
    size = source.read(4)
    if len(size) != 4 or not 0 < int.from_bytes(size,'big') <= LIMIT:
        raise Unavailable('guarded child frame unavailable')
    raw = source.read(int.from_bytes(size,'big')+1)
    if len(raw) != int.from_bytes(size,'big'):
        raise Unavailable('guarded child frame unavailable')
    reply,budget = worker.execute_guarded(raw,_continuity_stream=stream,_reply_budget=True)
    stream.settimeout(budget.remaining())
    stream.sendall(len(reply).to_bytes(4,'big')+reply)
    budget.remaining()
    stream.shutdown(socket.SHUT_WR)
    # Metadata-only private completion pipe. The supervisor withholds the reply
    # until this exact marker, group termination/absence and direct reap agree.
    os.write(2,COMPLETE)


def main():
    # Refuse BEFORE parsing stdin/operator files or constructing native adapters.
    from account_mutation_native import NativeDependencies
    dependencies=NativeDependencies.native()
    worker=dependencies.worker()
    # stdout is the supervisor-private socketpair, never the browser socket.
    stream=socket.socket(fileno=os.dup(1))
    with stream:
        _dispatch(worker,dependencies.bootstrap,sys.stdin.buffer,stream)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Fixed generic refusal contains no exception text or request material.
        raise SystemExit(1) from None
