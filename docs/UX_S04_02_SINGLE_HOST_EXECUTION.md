# S04.02 single-host execution correction

## Operator decision, 2026-10-21

**OSMAP production is single-host only.** Development and functional
qualification use the same local service architecture on `obsd1`.
`mail.blackbagsecurity.com` is a separate production environment and is not
a dependency for S04.02 feature development. The historical two-host SSH
relay fixture is not a required production mode or a S04.02 completion gate.
Preserve its signed evidence and implementation history without promoting it
into a product requirement.

This is an execution-topology correction. The frozen 20 obligations, four
outcomes, D04 policy, T01 through T09 requirements, independently measured
results and prior failures remain unchanged. All production qualification
flags remain CLOSED until their original functional/security evidence exists.

## Operator ruling on build memory, 2026-10-21

The operator abandoned the team-added 6 GiB free-RAM gate and the assumption
that a full optimized library-test build is a blanket completion prerequisite.
Neither is an OSMAP runtime memory requirement. No measured peak-memory study
established that floor, and the113 refusal is not evidence of inadequate host
capacity. Do not replace the withdrawn requirement with another unsupported
fixed memory floor. Scope builds and tests to the actual acceptance outcome;
retain the intended production artifact configuration where that claim depends
on it, required functional/security evidence and normal delivery hooks.

Keep original109/113 failures, source pins and private carriers unchanged as
historical evidence. The113 carrier/recipe is retired and must not be replayed.
Removing the requirement does not manufacture matching native/installed passes
or change qualification flags, execution leases or mail-service boundaries.

## Existing implementation to reuse

OSMAP already has paired Unix-domain socket clients in
`src/account_admission_runtime.rs` and `src/account_mutation_client.rs`,
constructed by `src/http_gateway_account.rs`. The Rust `account-passwd`
server binds exactly these native local sockets:

- `/var/run/osmap-account-admission/admission.sock`
- `/var/run/osmap-account-mutation/mutation.sock`

`src/config.rs` enforces these two endpoints for configured production
account-runtime clients. When account-runtime configuration is absent, it
remains absent. A configured but unqualified or unavailable pair MUST remain
unavailable; the parser does not activate password change or relax either
client's native qualification gate.

The account clients retain distinct purpose keys and a separate session-proof
key, runtime peer UID checks, current epoch, durable rate limits, per-operation
budget and uncertain-write containment. The web process receives no direct
MariaDB credential-mutation grant or arbitrary command capability. A same-host
socket does not justify removing process isolation, filesystem custody or
peer-authentication checks.

## Development and installation boundaries

- `obsd1` is the isolated source/build/test target. Use disposable Alice/Bob
  data and purpose-specific service namespaces. Inspect local Dovecot/MariaDB
  readiness only when necessary for a concrete test failure.
- Never change, stop, reload or restart public Dovecot, Postfix or MariaDB
  services, nor use real operator passwords, to qualify this slice.
- Never require SSH account-admission/mutation relays or remote Toronto
  fixtures for the normal S04.02 functional journey.
- `mail` remains the later single-host installation target after source,
  native and installed qualification and explicit operator authorization.
- The old paired-SSH fixture/results are historical only. Do not delete their
  code, evidence or original failure records as part of this correction.

## Immediate coding sequence

1. Verify the local native account service can start and bind both fixed
   sockets in a disposable development configuration, without public-service
   changes or qualification-bypass flags.
2. Complete the existing `BrowserGateway::change_own_password` path through
   local paired clients and the shared account authority. Address actual
   `primary_backend_unavailable` failures from precise traces, not guesses.
3. Reuse existing T01/T02 source PASS. Validate T03/T04/T05 against disposable
   local service and T06/T07/T08 against the matching installed local pair.
4. Run changed-boundary checks, the normal signed-source gate, independent
   review and finally T09 owner usability. Do not reinterpret a source test
   as an installed scenario PASS.

This change does not provision a database, start a service, activate the
password form, mutate credentials or authorize production deployment.
