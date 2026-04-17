# Version 2 Pilot Rehearsal SOP

## Purpose

This document records the standard operator procedure for rehearsing the
authoritative Version 2 readiness gate on the validated host before or during
pilot preparation.

It exists to keep one short operational answer in-repo for:

- the standard host-side checkout and wrapper path
- the SSH-triggered path used from a reachable workstation
- the expected first local report artifact for the current host snapshot

`docs/V2_ACCEPTANCE_CRITERIA.md` remains the authoritative Version 2 gate.
This document does not redefine that gate. It only captures the repo-owned
operator flow for rerunning it consistently.

## Standard Paths

The standard host-side checkout is:

- `~/OSMAP` on `mail.blackbagsecurity.com`

The routine operator access path is:

- `ssh mail`

The authoritative host-side Version 2 wrapper is:

- `ksh ./maint/live/osmap-live-validate-v2-readiness.ksh`

The standard host-side helper for rehearsals that include `login-send` is:

- `sh ./maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh`

The standard off-host trigger for the same host-side wrapper is:

- `./maint/live/osmap-run-v2-readiness-over-ssh.sh --host mail`

The standard host-side summary report path is:

- `~/osmap-v2-readiness-report.txt`

The standard repo-archived local report path is:

- `./maint/live/latest-host-v2-readiness-report.txt`

Before either a host-local rehearsal or an off-host SSH-triggered rehearsal,
make sure the standard `~/OSMAP` checkout is synced to the current pushed
`origin/main` tip so the host-side wrapper set matches the repo state being
validated.

## Standard Host Rehearsal

When the validating operator is already on the host, use the standard checkout
and the repo-owned helper:

```sh
ssh mail
cd ~/OSMAP
sh ./maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh \
  --report "$HOME/osmap-v2-readiness-report.txt" \
  security-check \
  login-send \
  login-failure-normalization \
  all-mailbox-search \
  archive-shortcut \
  session-surface \
  send-throttle \
  move-throttle \
  helper-peer-auth \
  request-guardrails \
  mailbox-backend-unavailable
```

That helper performs the guarded sequence automatically:

1. Read and preserve the current mailbox password hash for
   `osmap-helper-validation@blackbagsecurity.com`.
2. Generate one temporary password and one temporary `BLF-CRYPT` hash.
3. Update the validation mailbox record to that temporary hash.
4. Export `OSMAP_VALIDATION_PASSWORD` only for the wrapped Version 2 command.
5. Restore the original mailbox password hash on exit, even if the rehearsal
   run fails.

For narrower host-side reruns that do not include `login-send`, use the
Version 2 wrapper directly. For example:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v2-readiness.ksh \
  --report "$HOME/osmap-v2-readiness-report.txt" \
  security-check helper-peer-auth request-guardrails
```

To print the current authoritative Version 2 step set without running it:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v2-readiness.ksh --list
```

## Standard Off-Host Rehearsal

When the operator is on a workstation that can reach the validated host, use:

```sh
cd /home/foo/Workspace/OSMAP
./maint/live/osmap-run-v2-readiness-over-ssh.sh \
  --host mail \
  --local-report ./maint/live/latest-host-v2-readiness-report.txt
```

That wrapper SSHes into the standard `~/OSMAP` checkout on `mail`, runs the
same host-side Version 2 wrapper there, and fetches the resulting report back
to the local machine.

When the selected step set includes `login-send`, the SSH wrapper routes the
run through the same Version 2 host-side helper, so the temporary password
override and restoration still happen
entirely on the validated OpenBSD host.

## Host Privilege Note

The current validating operator account is `foo` on `mail`, and that account
currently has passwordless `doas` on the host. That operator privilege is
useful for host validation and for the guarded temporary validation-password
flow, but it must remain an operator property rather than an OSMAP runtime
dependency.

## Expected Report Artifact

The Version 2 wrapper writes a small summary report. For a full successful
rehearsal from the standard checkout, operators should expect the report to
look like this shape:

```text
osmap_v2_readiness_result=passed
project_root=/home/foo/OSMAP
step_count=11
steps=
security-check=passed
login-send=passed
login-failure-normalization=passed
all-mailbox-search=passed
archive-shortcut=passed
session-surface=passed
send-throttle=passed
move-throttle=passed
helper-peer-auth=passed
request-guardrails=passed
mailbox-backend-unavailable=passed
```

For a narrower rerun, `step_count` and the listed `...=passed` lines should
match exactly the subset the operator selected.

## When To Rehearse

Rerun the Version 2 readiness wrapper when:

- Version 2 gate-facing behavior changes
- migration or pilot guidance needs fresh proof against the current snapshot
- the public-exposure, rollback, or hostile-path story may have drifted
- the operator wants a fresh pre-pilot readiness snapshot from
  `mail.blackbagsecurity.com`

Do not widen the proof set casually. Use the exact authoritative wrapper steps
named in `docs/V2_ACCEPTANCE_CRITERIA.md`.
