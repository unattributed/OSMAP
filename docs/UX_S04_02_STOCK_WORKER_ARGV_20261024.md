# S04-02-T03: StockWorkerArgv metadata denial

Source work from signed `a7ad3116a58fb37682a51742caf5f2a9e30ed1fd`.
Target for a separately authorized native operation: obsd1 only. Production
`mail.blackbagsecurity.com` is out of scope. No host action is authorized or
performed by this source work order.

## Findings and correction

The path is `stock_socket_probe` → `stock_query` → `query_with_stage` →
`MetadataExecutor::run_with_stdin_bytes_timeout_and_output_limit` →
`metadata_command` → `auth::password_metadata_command` →
`run_with_cap_labeled` → `run_with_group`. During `StockRuntime::new`, this is
before `ParentPrepare`, `ParentSeal` and the operational accept loop.

The fixed policy already accepts `/bin/ps -p <canonical observed PID> -o args=`.
The service changes its own working directory to `/` before initial StockPeer
observation. Its later revalidation does not intentionally change that directory.
No missing allowlist entry or incorrect starting directory has been demonstrated.

The old trace retained operation57 (`StockWorkerArgv`) but reduced each exact
metadata tag to its category suffix. Thus distinct observed denials became the
same `Denied`. Probe165 cannot recover the discarded subphase or errno.

| Possible boundary | Existing fixed observation | What source establishes |
| --- | --- | --- |
| Command builder | `metadata_builder_denied` | May reject shape/cwd, or propagate a real cwd syscall error; the required shape is admitted. |
| Native launch | `metadata_spawn_denied` | A real `spawn` error classified from EACCES/EPERM or PermissionDenied; no launch-policy correction is established. |
| Child descriptors/I/O | `metadata_child_io_denied` | A real setup/read/wait error classified without private exception text. |
| Sealed kernel argv observation | `metadata_ps_argv_denied` | Available on the existing sealed PS path; this startup revalidation precedes the parent seal. |
| Completion/query | `metadata_query_exit`, `metadata_query_stderr`, `metadata_query_output` | Fixed query contract refuses nonzero exit, stderr, empty/oversize/non-ASCII/NUL output. These do not establish a permission denial. |
| Deadline/disposition | Existing budget/deadline/cleanup tags | Original deadlines and custody remain. Cleanup uncertainty is separate from the first execution error. |

Three demonstrated Rust defects are corrected: the exact whitelisted metadata
detail was discarded; ErrorKind-only PermissionDenied was classified unknown
when no raw errno existed; and uncertain child cleanup replaced an earlier
metadata failure. Child read errors now retain their fixed I/O category too.
An already expired stock query records its existing deadline tag before returning.
No numeric errno is invented, reconstructed or newly exported.

`StartupTrace` retains the first exact closed metadata detail, operation/category
and query error. Later trace changes cannot replace that first observation.
The existing process quarantine and unreaped-child retention still apply when
cleanup is uncertain; successful I/O followed by failed cleanup still fails.

The ordinary no-argument helper keeps the existing legacy diagnostic format.
The explicit fixed `--startup-metadata-diagnostic` argument invokes the identical
signal setup and service lifecycle, adding one bounded line on the same stderr
channel: `metadata=<closed tag> error=<closed error> cleanup=<fixed state>`.
Absent detail is reported as `unobserved`. This is an emission choice, not an
authority, confinement or readiness flag. No dynamic reason, argv, ps output,
private path, credential or arbitrary stderr is printed.

The unchanged Python helper-trace consumer accepts exactly the legacy two-line
record. It deliberately cannot consume the opt-in extra line. The next native
operation must explicitly capture and consume the Rust diagnostic invocation;
running the old default probe would still lose that detail. The legacy four-byte
worker bootstrap also carries only operation/category; this correction does not
claim to recover untransported worker detail. Python infrastructure is unchanged.

## Identity and functional limit

The held real socket/root binder, same live master, protected executable/config,
expected nonroot worker UID/GID and parent, unique candidate, exact argv rule,
birth/command recheck, socket/file continuity and original deadline are preserved.
Argv alone is not executable identity. Neither argv removal nor replacement with
the existing sealed kernel observer is justified by probe165's generic denial.
No functional command, permission, UID, pledge/unveil, allowlist or deadline
change is made. The exact native cause remains UNKNOWN pending measurement.

Local tests exercise the real Rust builder, labeled runner, I/O drain, query and
trace formatter, including their negative paths. They establish source behavior;
they do not establish native launch permission or working OpenBSD startup.
Actual test/review/delivery results are recorded in the execution ledger.

## Probe165 retained-resource disposition: separate operation

Preserve probe165's original FAIL/UNCERTAIN and submission/authority uncertainty.
The later unchanged full17 account rows, zero epochs and empty intent sets are
separate authoritative no-write evidence, not cleanup clearance.

The retained inventory is33 runtime paths, two fixture rows, one SQL principal,
two locked users and two groups, plus protected diagnostic/recovery stages.
Exact names, identities and evidence hashes remain in the private sprint record;
they must be freshly reconciled before any disposition. Historical160 stages
remain preserved. No deletion is authorized by this directive.

Disposition requires independently reviewed current recovery/stage/source/binary
custody, durable diagnostic readback/hash, full17 rows/epochs/intents, exact SQL
principal definition/grants, locked users/groups and exact file/directory owners.
Preserve the installed OSMAP service baseline; shared UID1001 is not ownership.
After separate authorization, use conditional compare-delete for owned rows,
then exact principal/files/roles and empty child-first directories. Preserve
evidence stages, never signal historical PIDs, and record each effect and final
absence/public-service preservation separately. Do not replay163's cleanup
against165 or silently adopt its resources.

## Prepared next operation: one-shot R1/R2, NOT AUTHORIZED

1. After separate authorization and exact-owned isolation/disposition, admit
   the current signed affected helper and libtest artifacts against their real
   compiler-input receipts. Verify concrete OpenBSD command/schema/confinement
   capabilities; observed release numbers are evidence only. There is no fixed
   RAM floor, version predicate or full optimized-library-test prerequisite.
2. Run the actual fixed helper once as its existing protected service identity:
   `/usr/local/libexec/osmap/account-passwd --startup-metadata-diagnostic`.
   Keep its existing five-second startup deadline. Preserve its exact binary,
   born-process identity, socket custody and fixed diagnostic output; socket
   publication alone is not R1 readiness. No HTTP driver or password operation.
3. As the configured dedicated nonroot client, invoke the matching libtest once:
   `--exact account_admission_runtime::tests::native_rust_stock_epoch_admission --ignored --nocapture --test-threads=1`.
   Private stdin is exactly a version1 JSON bootstrap containing `client_root`,
   bound to a fresh owned `/var/run/osmap-service-admission-client-<16hex>` root.
   No password or command selector is accepted. The Rust test checks root0750
   custody, constructs the existing paired client against the fixed admission
   socket/helperUID0 and purpose key, and calls `admit_before` once for the fixed
   controlled Alice account at epoch0 within its original35-second client bound.
4. R2 requires a real authenticated MAC request/reply and validated epoch result,
   not EOF or mere socket connection. Bind it to the same helper birth/artifact.
   Since that service handles the request only after `StockRuntime::new`,
   `ParentPlan::prepare_stock`, parent sealing/activation and entry to its accept
   loop, this exchange plus lifecycle/custody evidence establishes R1 for that
   invocation. It does not establish primary-password authentication or Serve.
5. Use one technical envelope of60 seconds plus15 seconds for bounded owned
   stop/disposition, with no retry. Before removing sources, retain private output
   with readback/hash and pass the actual producer output through the actual
   fixed-field consumer, including failure/cleanup refusal. Export only closed
   Rust tags/error categories and bounded process/stream outcomes. The existing
   Python default helper-trace parser is unsuitable for this opt-in record;
   do not dispatch through it and claim diagnostic continuity.
6. Stop after this one operation. Independently compare full17 rows, epochs and
   intents and preserve public/installed baselines. Cleanup disposition remains
   independent. Missing custody/evidence or ambiguous effects retain resources
   for separately reviewed exact-owned recovery. No provisioning/disposal or
   native build/start is performed under the present source-only authority.

The ignored Rust entry is prepared and compiled locally, not executed natively.
Its execution requires fresh explicit authorization and current concrete fixture,
artifact and capture/consumer bindings. R1, R2, Serve confinement, HTTP READY,
guarded password change and T03 qualification remain unclaimed.
