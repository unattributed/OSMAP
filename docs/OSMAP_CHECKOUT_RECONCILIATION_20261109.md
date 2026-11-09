# Checkout reconciliation — 2026-11-09

## Scope and preservation

The owner authorizes implementing the investigated reconciliation in GitHub and
the local filesystem with traceability. The subsequent explicit correction
excludes all ongoing S08 code, documentation and acceptance: that work belongs
to the separate active Codex chat. No file in its
`Documents/ChatGPT/OSMAP/source` worktree is changed by this reconciliation.

The older `Workspace/OSMAP` checkout was at
`6c509a542dfc30129e23b838b1faf7cd01608f4e`, with seven tracked modifications and
one untracked S05 specification. Its source/history is the same repository as
the newer linked worktree, not an independent clone.

Before restoring any path, preserve and read back:

- [preservation manifest](reconciliation/20261109/preservation.json): original
  base, file SHA-256 values, permission modes and patch hashes;
- [superseded S05 patch](reconciliation/20261109/superseded-s05.patch.gz): six
  tracked-file deltas and the complete untracked S05 specification;
- [original installed startup-repair patch](reconciliation/20261109/original-startup-repair.patch.gz).

The deterministic gzip archives were decoded and both patches applied to the original committed file blobs in disposable
local storage. All eight reconstructed files matched the pending working files
byte-for-byte. The recorded permission modes also reconstruct the original
filesystem metadata. The initial staged whitespace check rejected raw patch context whitespace; lossless gzip storage corrects that packaging issue without modifying source bytes or weakening the check. The archives are historical, non-executable evidence;
they must not be applied to the current source tree wholesale.

After preservation, only those eight named paths were restored/removed in the
older checkout. Its existing `feat/ux-completion-20260929` branch was advanced
by a fast-forward to published commit
`501f6430a5ec2eda95e8d6a942fee2268ab4e6a6`. No branch was renamed, rewritten or
force-updated. Other local branches, including the private publication-refused
branch, are outside this bounded change and remain untouched.

## Why the old S05 changes are retired

The originating `Review OSMAP S04-03 status` chat
(`01a178e9-53b0-7871-8cca-00a32ac11dbe`, turn
`01a18668-7885-7f70-8c50-d3381a3d3860`) records interruption during acceptance
testing, not a completed source delivery or a rejection of the feature.

Later `Complete credential freshness loop` work
(`01a17137-7b89-72e2-8c29-c667ae4ae179`) reused and expanded that UI work. On
October 31 the owner requested visible imported identities and applied policies,
with encryption off by default. On November 1 the owner explicitly requested
certificate-derived email identities instead of the separate ordinary binding
operation. Published commits `fa26102d5c2603cc5c298c845910a01ae072766c` and
`6c799d920a56de0c6d6a6d20f6a0058dbfd505fe` implement that later direction.

The current renderer retains exact-fingerprint identity matching, escaping and
unbound/foreign-state tests, and adds direct account validation, policy display
and effective certificate-recipient projections. The old UI file would regress
those changes. Its old specification/index/work order and V10 line/hash refreshes
describe the earlier snapshot; they are preserved as provenance, not reinstated
as active source, audit results or acceptance.

## Account-service startup correction

The `Fix failed OSMAP services on obsd1` chat
(`01a1afaf-eb03-7c41-a43d-92d10c457354`, repair turn
`01a1afaf-ed44-7da1-a47c-bc487894d2e6`) records a November 6 boot-persistence
failure: volatile admission/mutation directories were absent after reboot and
the service correctly refused startup. The rc script prepared its log but did
not recreate the required directories. The dependent web service then lacked
its admission socket.

The repair was installed and tested separately, but deliberately left uncommitted
in the older dirty checkout. Its local SHA-256 matched the recorded installed
script:

`437c333c019fa18620d5a8a5a03bd3054ec035beba92547d672dc257873a81c7`.

The live GitHub UX-branch script still lacked the correction; none of the other
five current remote branch tips contained it. Integrate the directory preparation
before log preparation and daemon launch. Create only genuinely absent fixed
paths as `root:osmapgpg` mode `0750`; refuse symlinks, non-directories or different
custody without adopting/chmodding existing objects.

The amended source compares numeric UID0, symbolic group `osmapgpg` and exact
directory type/mode `40750`. OpenBSD [stat(1)](https://man.openbsd.org/stat.1)
documents `%Sg` for the group name. This matches the named group passed to
`install` and removes the original host-specific GID1003 assumption. Unknown or
different group output refuses; no fallback numeric GID is introduced.

## Validation and delivery boundary

Expected source result: safe directory creation or unchanged valid custody;
unsafe/unresolved custody refuses before daemon launch. The focused regression
extracts the actual `rc_prepare_runtime` and `rc_start` functions and executes
them with ksh, projecting only the OpenBSD external utilities locally. It covers
missing and existing directories, preservation, wrong owner/group/mode,
unresolved group names, regular files, valid/dangling symlinks and nonroot calls.
The existing account-runtime unittest discovery includes this regression.

The November 6 directory-loss/restart evidence remains historical native evidence
for the original numeric-GID patch. Local checks for the amended symbolic-group
source do not claim a new native installation, boot test or product UAT. No live
service, mailbox, credential, account or public mail configuration is changed.

Normal commit/push hooks, Shopkeeper signing, signature verification and a fresh
origin fetch are required before reporting this source delivery synchronized.
The final commit and fresh local/remote equality receipt establish publication;
they do not close or reconcile S08 or imply production release acceptance.

## Preserved publication-gate failure and changed environment

The first ordinary push of signed source commit
`1e8bbef355f30987eb640fd4eac6f683a0005b3c` stopped in the Rust suite:
**2,203 passed, 147 failed, 90 ignored**. No publication is claimed for that
attempt. Its task-specific temporary directory was under the chat workspace,
with group-writable ancestors and a 69-character base pathname.

Independent reassessment confirmed actual ancestor-custody refusals and Unix
socket path-length failures in the retained log. The crypto lifecycle fixture
also explicitly requires a scratch root under `/tmp`. These observations support
correcting the test environment; they do not individually prove the cause of
every failed test.

Use a short task-owned mode0700 directory under `/tmp` for the unchanged normal
hook. Before another full push attempt, both distinguishing original failures
passed under that directory:

- `account_access_config::tests::private_regular_config_and_genuine_leaf_absence_use_actual_reader`
- `account_admission_runtime::tests::listener_rejects_wrong_peer_before_read_and_refuses_foreign_socket_cleanup`

The implementation, security profile, assertions and hooks remain unchanged.
The next full hook result and fresh remote equality must establish delivery;
the passing discriminators alone do not turn the first failed gate into PASS.

The next pipe-launched ordinary push at signed documentation descendant
`623e503b080e6ead223f131b3ec4994abb3e1b43` was **INTERRUPTED, exit143** before
the Rust suite produced a terminal result. The log contained no reported
assertion failure before termination. The signal sender and full-suite outcome
remain UNKNOWN; the adjacent successful helper test is not causal proof.

Combined independent reassessment then inspected owned-child signal handling.
One exact crypto helper-SIGTERM lifecycle test passed under the same pipe launch
with restricted signal tracing: the intended helper group received TERM, the
worker was absent afterward, and traced processes exited successfully. This
does not retrospectively establish the source of the interrupted gate's signal.

One further ordinary full push is reviewed as a terminal-runner isolation
observation, using a PTY and the same short private temporary directory,
implementation, profile and hooks. It is not described as a proven causal fix.
Stop on another failure/interruption, retain that result and reassess; no repeated
unchanged retries or full-suite tracing is authorized by this record.

The reviewed terminal launch completed the Rust suite with **2,350 passed,
zero failed and 90 ignored**. Clippy, supply-chain, rendering, V8 aggregate and
publication checks passed before the documentation governance guard refused the
new index entry: it required the literal backticked report filename, whereas
the new entry supplied a Markdown link only. Preserve this as a documentation
delivery failure. Correct that index format without changing the guard or any
product source; run the actual documentation guard before the next ordinary
publication attempt. The earlier signal sender remains UNKNOWN.
