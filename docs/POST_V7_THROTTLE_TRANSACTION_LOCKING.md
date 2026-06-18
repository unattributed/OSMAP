# Post-V7 Throttle Transaction Locking

Date: 2026-06-19
Status: Implemented and locally verified

## Objective

Close the V7 residual risk where overlapping OSMAP processes could load the
same throttle record, increment independently, and atomically replace each
other's result. Atomic file replacement prevented corruption but did not
prevent lost updates.

## Design

Each file-backed throttle directory now has one store-local advisory lock:

```text
.throttle-store.lock
```

The lock file is created with mode `0600`. Lock acquisition failure fails
closed. An RAII guard releases the lock on normal return and unwind.

The transaction boundary covers both related buckets for:

- login checks, failed-attempt recording, and successful-login clearing;
- submission checks and accepted-submission recording;
- message-move checks and accepted-move recording.

The lock is not held across external authentication, mailbox, or send
operations. It protects only the bounded file-state transaction and therefore
does not widen the browser or helper trust boundaries.

## Verification

Regression coverage proves:

- independent file-store handles block on the same advisory lock;
- the lock file has mode `0600`;
- lock-open failure fails closed;
- every login, submission, and message-move throttle operation executes inside
  the transaction boundary;
- existing threshold, remote-bucket, clear, temporary-file, and permission
  behavior remains unchanged.

## Residual Boundary

This is cooperating-process serialization on one host and one throttle
directory. It does not claim distributed locking across multiple hosts.
