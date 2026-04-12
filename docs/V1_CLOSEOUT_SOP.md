# Version 1 Closeout SOP

## Purpose

This document records the standard operator procedure for rerunning the
authoritative Version 1 closeout gate on the validated host.

It exists to keep one short operational answer in-repo for:

- the standard host-side checkout and wrapper path
- the temporary validation-password override used by the real `login-send`
  step
- the small closeout report artifact operators should expect afterward

`docs/ACCEPTANCE_CRITERIA.md` remains the authoritative Version 1 gate. This
document does not redefine the gate. It only captures the now-proven operator
flow for rerunning it.

## Standard Paths

The standard host-side checkout is:

- `~/OSMAP` on `mail.blackbagsecurity.com`

The authoritative host-side closeout wrapper is:

- `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh`

The standard host-side helper for reruns that include `login-send` is:

- `sh ./maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh`

The off-host trigger for the same host-side wrapper is:

- `./maint/live/osmap-run-v1-closeout-over-ssh.sh`

The standard host-side summary report path is:

- `~/osmap-v1-closeout-report.txt`

For routine off-host invocation from a reachable workstation, the standard
local report path is whatever the operator passes with `--local-report`, or the
wrapper default in the current working directory if none is supplied.

## Standard Host Rerun

When the validating operator is already on the host and the rerun includes the
real `login-send` step, use the standard checkout and the repo-owned helper:

```sh
cd ~/OSMAP
sh ./maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh --report "$HOME/osmap-v1-closeout-report.txt"
```

To rerun only a narrower affected subset after a targeted closeout-facing
change that still includes `login-send`, pass the exact step names after the
helper options. For example:

```sh
cd ~/OSMAP
sh ./maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh --report "$HOME/osmap-v1-closeout-report.txt" login-send
```

For narrower reruns that do not include `login-send`, use the closeout wrapper
directly and avoid touching the validation mailbox password hash at all. For
example:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report "$HOME/osmap-v1-closeout-report.txt" security-check session-surface
```

To print the authoritative current step set without running it, use the
closeout wrapper directly:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --list
```

## Off-Host Rerun

When the operator is on a workstation that can reach the validated host, use:

```sh
./maint/live/osmap-run-v1-closeout-over-ssh.sh --host mail --local-report ./maint/live/latest-host-v1-closeout-report.txt
```

That wrapper SSHes into the standard `~/OSMAP` checkout, runs the same
host-side closeout wrapper there, and fetches the resulting report back to the
local machine.

For the standard full rerun that includes the real `login-send` step, prefer
SSHing to the host and using the helper there so the temporary password
override and restoration stay entirely on the validated OpenBSD host.

## Real `login-send` Secret Handling

The `login-send` step uses the real validation mailbox, so the standard
repo-owned answer is the helper
`maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh` to
handle the real `login-send` secret flow on the host.

That helper now performs the validated guarded sequence automatically:

1. Read and preserve the current mailbox password hash for
   `osmap-helper-validation@blackbagsecurity.com`.
2. Generate one temporary password and one temporary `BLF-CRYPT` hash.
3. Update the validation mailbox record to that temporary hash.
4. Export `OSMAP_VALIDATION_PASSWORD` only for the wrapped closeout command.
5. Restore the original mailbox password hash on exit, even if the closeout run
   fails.

This keeps the real `login-send` step reproducible without storing mailbox
credentials in the repository, without asking operators to assemble the hash
swap by hand, and without leaving the validation mailbox on a temporary secret
after the run.

## Expected Report Artifact

The closeout wrapper writes a small summary report. For a full successful
host-side closeout run from the standard checkout, operators should expect the
report to look like this shape:

```text
osmap_v1_closeout_result=passed
project_root=/home/foo/OSMAP
step_count=7
steps=
security-check=passed
login-send=passed
all-mailbox-search=passed
archive-shortcut=passed
session-surface=passed
send-throttle=passed
move-throttle=passed
```

For a narrower rerun, `step_count` and the listed `...=passed` lines should
match exactly the subset the operator chose to execute.

## When To Rerun

Rerun the closeout wrapper when:

- closeout-facing behavior changes
- the release-facing docs need fresh proof against the current snapshot
- a repo inconsistency or failing proof suggests the closeout boundary may have
  drifted

Do not widen the proof set casually. Use the exact authoritative wrapper steps
named in `docs/ACCEPTANCE_CRITERIA.md`.
