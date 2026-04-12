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

The off-host trigger for the same host-side wrapper is:

- `./maint/live/osmap-run-v1-closeout-over-ssh.sh`

The standard host-side summary report path is:

- `~/osmap-v1-closeout-report.txt`

For routine off-host invocation from a reachable workstation, the standard
local report path is whatever the operator passes with `--local-report`, or the
wrapper default in the current working directory if none is supplied.

## Standard Host Rerun

When the validating operator is already on the host, use the standard checkout
and run:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report "$HOME/osmap-v1-closeout-report.txt"
```

To rerun only a narrower affected subset after a targeted closeout-facing
change, pass the exact step names after the wrapper options. For example:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report "$HOME/osmap-v1-closeout-report.txt" security-check session-surface
```

To print the authoritative current step set without running it:

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

## Real `login-send` Secret Handling

The `login-send` step uses the real validation mailbox, so the repository still
requires an operator-supplied `OSMAP_VALIDATION_PASSWORD` at runtime when that
step is included.

The current validated answer is a controlled temporary password override:

1. Read and preserve the current mailbox password hash for
   `osmap-helper-validation@blackbagsecurity.com`.
2. Generate one temporary `BLF-CRYPT` hash with `doveadm pw -s BLF-CRYPT`.
3. Update the validation mailbox record to that temporary hash.
4. Run the authoritative closeout wrapper in the same guarded shell session.
5. Restore the original mailbox password hash on exit, even if the closeout run
   fails.

This keeps the real `login-send` step reproducible without storing mailbox
credentials in the repository or leaving the validation mailbox on a temporary
secret after the run.

## Example Guarded Host Session

The following pattern captures the validated choreography. It should be run in
one shell session on the host so the original mailbox hash is restored on exit:

```sh
set -eu

validation_user='osmap-helper-validation@blackbagsecurity.com'
temp_password="$(openssl rand -hex 16)"
orig_hash="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='${validation_user}' AND active='1';")"

restore_password() {
  doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${orig_hash}'
WHERE username='${validation_user}' AND active='1';
SQL
}

trap restore_password EXIT INT TERM

temp_hash="$(doas doveadm pw -s BLF-CRYPT -p "${temp_password}")"

doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${temp_hash}'
WHERE username='${validation_user}' AND active='1';
SQL

cd ~/OSMAP
OSMAP_VALIDATION_PASSWORD="${temp_password}" \
  ksh ./maint/live/osmap-live-validate-v1-closeout.ksh \
  --report "$HOME/osmap-v1-closeout-report.txt"
```

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
