# Duncan-only native storage profile

This is the bounded obsd1 S08 deployment profile, not a general storage service.
It preserves vmail UID/GID2000 and gives Duncan an account-exclusive FFS
filesystem with a 512000000-byte hard quota. Other accounts retain their current
storage. No production mail host, password, private-key or continuous mailbox
replication operation is part of this recipe.

The source `rc.d/osmap_duncan_storage` never creates an image, formats a device,
sets a quota limit, migrates mail, changes SQL or stops Dovecot. Its `check` is a
read-only mounted-image/kernel-quota check. Initial provisioning and migration
are separately bounded root operations; do not run them from a boot hook.

## Layout and fixed operator inputs

Use root-owned non-writable-to-vmail ancestors:

```text
/var/osmap-storage/                       root:wheel 0755
/var/osmap-storage/images/                root:wheel 0700
/var/osmap-storage/images/duncan.img      root:wheel 0600, one link
/var/osmap-storage/accounts/              root:wheel 0755
/var/osmap-storage/accounts/duncan/       root:wheel 0555 when unmounted, empty
```

The mounted filesystem root stays root:wheel0755. Its `quota.user` must be a
regular nonsymlink root:wheel0600 file with one link. Duncan's home/Maildir root
is the child `/var/osmap-storage/accounts/duncan/Maildir`, vmail:vmail0700.
Do not chown the filesystem root to vmail: that would permit removing the quota
file. The unmounted placeholder has no Maildir child, and its root-owned parent
prevents vmail replacing it with unmetered storage. Do not change ownership of
the existing shared `/var/vmail/blackbagsecurity.com` directory.

Native mail metadata belongs outside the quota filesystem:

```text
/var/osmap-mail-state/duncan/index/       vmail:vmail, private
/var/osmap-mail-state/duncan/control/     vmail:vmail, private
```

The native quota worker validates ownership, canonical paths, exact configured
FFS mount, device separation and the actual kernel hard limit. It is installed
root-owned, mode0555 or0755, one link; the existing root:bin0555 libexec convention
is supported. Its real and effective caller UID must be2000. It does not become
a privileged broker.
The root rc action invokes this read through the observed native
`/usr/bin/su -m vmail -c` contract, with a fixed `cd / && exec` command and only
validated restricted-character paths. It does not add a doas permission rule.

Install the rc script root-owned mode0555 or0755. Create exactly five newline-
terminated unquoted `key=value` lines in `/etc/osmap/duncan-storage.conf`,
root:wheel0600, one link. No comments, extra keys, duplicate keys, shell expansion
or caller-supplied configuration path is supported; every value must be nonempty.
The script checks the entire absolute ancestor chain of the image, configuration,
mountpoint and native executable parents: canonical nonsymlink directories,
UID0 and no group/other write permission. The host fstab must also be a regular
nonsymlink root-owned file with one link and no group/other write permission:

```text
image=/var/osmap-storage/images/duncan.img
vnd=vnd1
index=/var/osmap-mail-state/duncan/index
control=/var/osmap-mail-state/duncan/control
worker_sha=REPLACE_WITH_ACTUAL_64_LOWERCASE_HEX_DIGEST
```

Select an observed unused vnd slot; `vnd1` is an example, not permission to reuse
an occupied device. The script admits only the host's reviewed vnd0–vnd3 range.
Verify the actual `vnconfig -l` producer includes the exact image path and inode
in the spelling consumed by `associated()` before first dispatch. The script
refuses a different association and never detaches it automatically.

The corresponding two fstab rows for the example slot are:

```fstab
/var/osmap-storage/images/duncan.img /dev/vnd1c vnd rw,noauto 0 0
/dev/vnd1a /var/osmap-storage/accounts/duncan ffs rw,nodev,nosuid,noexec,noauto 0 0
```

Keep exactly that option ordering for this deployment profile's narrow admission
check. Preserve all unrelated fstab entries. `mount_vnd(8)` requires the FFS row
to use noauto/pass0 because its backing image cannot be attached during the
initial filesystem check. Do not use the whole-disk c partition as the FFS
filesystem; use the prepared a partition.

The host row deliberately omits `userquota`: the base boot-time `quotaon -a`
must not act on this unmounted late account filesystem. Explicit native
`quotaon -u /var/osmap-storage/accounts/duncan` selects its default quota.user
without that option. Qualify that actual native contract before rollout.
Do not temporarily change the host row to pass2: interruption could leave the
next initial fsck trying to check an unattached vnd device.

## One-time preparation and migration

1. Record the current source home/mail location, all real mailbox names,
   GUIDs/UIDVALIDITY/UIDNEXT, per-message UIDs/GUIDs, persistent flags/keywords,
   INTERNALDATE and raw message hashes, subscriptions, Sieve/non-mail inventory,
   ownership/modes and relevant userdb/configuration. Store private metadata
   privately. Current475 messages and two INBOX messages are observations to
   reconcile against the fresh inventory, not permanent expected counts.
2. Run the isolated Rust migration sample first. It qualifies native `doveadm
   backup` into a new FFS Maildir with off-filesystem INDEX/CONTROL, then a source
   delta and second backup. Match the actual compiler/test input and preserve
   failed diagnostics. This is not owner-data migration or a boot/reboot test.
3. Root creates a new fully allocated image sized for the agreed data cap plus
   FFS overhead and operating headroom, using measured backing-store space.
   Attach an unused exact vnd association, prepare its disklabel/a partition and
   format only that verified new device. This step is never repeated at boot.
4. Provision user quota for UID2000 on this one filesystem. The raw hard limit
   is1000000 DEV_BSIZE512 blocks; soft limit0 (or exactly the hard limit).
   Use the installed native edquota/quotacheck/quotaon contract, inspecting its
   actual formatter and units first. Edquota text units must not be guessed
   from raw kernel block units. Require readback through the actual self-UID
   worker: `limit_bytes=512000000`, finite measured usage, exact mount and
   metadata-device separation. Do not invoke quotaon/quotacheck with `-a`.
   The host pass0 row is insufficient for quotacheck even with an explicit
   target: it may exit0 after skipping the filesystem. Use the private native
   recount described below; admission needs the actual checking marker and
   the known allocated-usage result, not the exit status alone.
5. While the original account remains the source, perform the initial native
   backup to a fresh unexposed destination. For the Maildir location use the
   candidate data root plus explicit INDEX and CONTROL paths. Do not query or
   initialize the target through Dovecot before its first backup. Accept only
   exit0 and matching inventory; retain exit2 as incomplete, not PASS.
6. Dsync covers mailbox state, not the rest of the home. Copy only the observed
   non-mail/Sieve paths with native `pax -rw -pe`, without `-H`/`-L`/`-l`, and
   compare contents, ownership, modes and link targets. Preserve the relative
   `.dovecot.sieve -> sieve/managesieve.sieve` link, the observed sieve directory
   and compiled cache. Never overwrite the destination's dsync-generated
   uidlist/keywords/index/control metadata with copied old control files. Unknown
   non-mail paths need an explicit disposition; do not silently omit them.
7. Quiesce only necessary OSMAP writer admission, kick Duncan's IMAP sessions and
   drain current account operations. `doveadm backup -l` serializes dsync, not
   ordinary IMAP/LMTP writes. Do not deactivate the SQL mailbox or permanently
   bounce deliveries. The observed Postfix path uses LMTP and the existing
   `hash:/etc/postfix/backup_transport` transport map. First inspect the native
   retry transport service. Preserve the exact map and database, atomically add
   only Duncan's `retry:4.3.2 maintenance` entry, run native postmap, and verify
   its exact lookup. Keep other recipients' rows intact. Drain in-flight Duncan
   delivery operations before the final backup; a map lookup or IMAP kick alone
   does not establish quiescence. After cutover restore the exact original map
   and database and flush only the observed Duncan queue IDs. If that native
   contract is unavailable, retain/reconcile old-source deltas rather than
   inventing a successful writer barrier.
8. Apply the final source delta while the destination still has no independent
   writes. Recopy changed non-mail files, compare all inventory again, then
   quiescently unmount staging. Install the protected empty final mountpoint,
   fstab/profile and the exact account-specific home/mail/quota_mount mapping.
   The startup action mounts/activates/verifies the prepared filesystem; it
   never resets the quota. The new home is the Maildir child. Other account
   rows and credential/active fields remain unchanged. Current auth cache is
   observed disabled; flush only Duncan if a later actual configuration enables
   cached userdb results.
9. Check the new userdb result and native helper/worker path, all message and
   non-mail facts, quota and relevant services before restoring OSMAP admission.
   Inspect the retained source again after old writers settle. Any late source
   mail or uncertain outcome blocks no-loss closure and requires bounded native
   reconciliation. A destructive backup must never overwrite a destination that
   has begun accepting independent new mail.

## Qualify the unused final profile before account cutover

The actual final mount can be provisioned and tested while Duncan's SQL home
still points to the old Maildir. That gives the rc script its real UID2000,
mount, metadata and512000000-byte policy without copying live mail into it.
It is not evidence of account migration. Freshly verify the chosen unused vnd
slot, available physical backing space and absence of every new path first.
A1GiB fully allocated image provides room above the data cap; do not use a
sparse allocation or overwrite an existing image. A shell-created exclusive
output descriptor can feed native dd (`dd ... > image` with noclobber); do not
assume dd's `of=` respects shell noclobber. Record the created file's identity
before attaching, labelling or formatting only that exact new association.

For the one-time native edquota operation, preserve the host fstab and change
only this new FFS row to add `userquota`, keeping pass0. Never add pass2 to the
host file. Mount the newly prepared filesystem root-only and create its empty
root:wheel0600 quota.user. Capture the actual installed edquota formatter
before using a fixed private editor. The native formatter's `KBytes` are1024
bytes: hard500000 means512000000 bytes, or1000000 raw512-byte blocks. Preserve
the existing usage fields; edquota changes limits rather than current usage.

The following is a private execution-artifact editor, not an installed service.
It intentionally accepts only a three-line native file for this one new
filesystem, with initially zero limits. If edquota also lists other filesystems,
stop and preserve that observation; do not remove their rows, because omitted
rows cause edquota to clear their limits. Use only after matching the actual
formatter, and set both VISUAL and EDITOR to its root-owned private pathname:

```ksh
#!/bin/ksh
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
umask 077
[[ $(id -u) = 0 && $# = 1 ]] || exit 1
case "$1" in /tmp/edquota.*) ;; *) exit 1;; esac
[[ -f $1 && ! -L $1 && $(stat -f '%u:%Lp:%l' "$1") = 0:600:1 ]] || exit 1
before=$(sha256 -q "$1")
identity=$(stat -f '%d:%i' "$1")
candidate=$(mktemp /tmp/osmap-duncan-edquota.XXXXXXXX)
trap 'rm -f "$candidate"' EXIT
awk '
    NR==1 {if ($0!="Quotas for user 2000:") bad=1}
    NR==2 {
        prefix="/var/osmap-storage/accounts/duncan: KBytes in use: "
        if (index($0,prefix)!=1 || substr($0,length(prefix)+1)!~/^[0-9]+, limits \(soft = 0, hard = 0\)$/) bad=1
        sub(/limits \(soft = 0, hard = 0\)$/, "limits (soft = 0, hard = 500000)")
    }
    NR==3 {if ($0!~/^\tinodes in use: [0-9]+, limits \(soft = 0, hard = 0\)$/) bad=1}
    {print}
    END {if (NR!=3 || bad) exit 1}
' "$1" > "$candidate"
[[ $(stat -f '%d:%i' "$1") = "$identity" && $(sha256 -q "$1") = "$before" ]] || exit 1
# edquota retains this inode's open descriptor: do not rename the candidate.
cat "$candidate" > "$1"
cmp -s "$candidate" "$1"
```

Run the editor-driven native edquota under a finite outer deadline and retain
its actual output. Its exit status alone is not acceptance: inspect all eight
u32 fields at UID2000's32-byte quota record and require hard1000000/soft0.
Native od may zero-pad these decimal fields; validate digits and normalize
explicitly in base10 before comparing limits or calculating bytes.
Restore the exact permanent host fstab without `userquota` before rc startup.
An interruption during this pass0-only provisioning window affects this unused
profile; it does not redirect Duncan or create a boot-time unattached pass2
check. Retain the original/candidate fstab identities for bounded recovery.

Create the private UID2000 Maildir child and the separate-FS index/control
directories without changing active userdb. A small known file owned by UID2000
can establish nonzero allocated usage for recount qualification; retain its
identity and remove only that exact test file before migration. Qualify actual
startup, counter recomputation, kernel limit, ready read-only check, safe stop
refusal and root700 failure protection on this unused profile. A failed check
does not authorize automatic reformatting, a different device, quota disabling
or a live SQL cutover. Snapshot old Duncan mapping/mail and current service
state again before the separately qualified two-pass migration.

## Boot, failure and stop semantics

Enable and order this one-shot rc.d action before Postfix, Dovecot and OSMAP
package services, preserving their other ordering. Use `rcctl order` with any
actual prerequisites followed by this service; do not replace the entire list.
`rc.local` is too late: the native boot script starts package services first.
The usual quota pass also precedes these late-mounted images, so this action
explicitly checks/activates this filesystem's quota.

The custom startup action reserves160 seconds for admission and20 seconds for
failure protection; individual native commands are clamped to the remaining
time and60 seconds. The surrounding rcctl dispatcher must also have its own
finite bound covering rc.subr checks before and after that action. It verifies
profile/image/device custody and performs offline fsck only after checking that
the device is unmounted. It then mounts under the root0700 guard
`/root/osmap-duncan-check/mount` and makes the FFS root root0700. The guard is on
the root filesystem because the observed /var nodev setting prevents using
private device nodes there.

Recount uses the unchanged native `/sbin/quotacheck` in that private chroot. The
observed native executable is static; qualify that actual producer before
rollout. The script copies and hashes that root-owned executable, creates only
the exact block/raw vnd device pair with major/minor values read from their
native device nodes, and writes a private `/etc/fstab` containing one
`/dev/vndNa /mount ffs rw,userquota 0 2` row. The host `/etc/fstab` is never
rewritten for recount. No account/password database or dynamic loader is copied.
Missing runtime requirements fail before exposure. `quotacheck -uv /mount`
must produce its exact native checking marker; a skipped filesystem's exit0 is
refused. Native qualification must demonstrate recomputation of known nonzero
allocated usage as well as preservation of the hard limit.

The script reads only UID2000's32-byte quota record and checks the actual
1000000-block hard/soft policy before and after recount. It unmounts the guard,
removes its known files, and mounts at the final location with root-only mode
preserved. It checks the quota record again before native quotaon. Only after
quotaon succeeds does it expose root0755 and verify the kernel record as vmail.
It does not repair a mounted unhealthy live store while Dovecot/OSMAP writer
services are running, and never calls fsck while the filesystem is mounted.

An already-ready startup performs the read-only check and changes nothing.
A failed startup keeps an identified mount root-only or the underlying empty
root0555 placeholder. If native identity/permission checks themselves fail, it
reports ACCESS=UNCONFIRMED rather than claiming protection. Per-attempt root-
private logs are retained under `/var/log/osmap-duncan-storage.*`; preserve/hash
them before finite recovery. Partial staging is retained; never run fsck on a
mounted image or detach an unknown device to make a retry pass.

Stop refuses while Dovecot or OSMAP mail writer services are running. With them
stopped, it also requires no open descriptors on this filesystem before closing
access, turning off this quota, unmounting and detaching the exact association.
It does not kill processes. A native isolated stop-refusal test does not require
a broad live Dovecot outage; positive maintenance stop remains separate unless
actually executed. No reboot is invented as a prerequisite to this rollout.

This is a one-shot mount action, not a daemon matching the quota reader's argv.
The script sets its rc.subr timeout to240 seconds after sourcing the library,
covering the initial bounded readiness check plus the180-second custom action.
It uses an inert process expression and suppresses generic daemon signals.
Stop is dispatched directly to the bounded maintenance function after rc.subr
option parsing, preserving an immediate refusal status; the generic daemon
fallback must not wait for or signal an unrelated storage-quota process.

## Rollback and proof limits

Retain the original source home and old userdb/configuration bytes intact until
the migrated account is qualified. Before new-side writes, a failed cutover can
quiesce the same account, restore its exact old mapping and admission, and retain
the candidate image for diagnosis. After new-side writes, first preserve both
sides and reconcile the delta with native tools; a blind mapping rollback or
reverse destructive backup can lose new mail. Root must inspect exact mount,
association and open-FD state before any unmount/detach. Other accounts and public
mail daemons stay available during the account migration.

Native contracts to qualify before deployment: vnconfig association spelling;
host fstab noauto/pass0 without userquota; copied static quotacheck, exact
private device nodes and private pass2 recount with nonzero usage; explicit
per-filesystem quotaon without a host userquota option; exact edquota units and
limit readback; successful and unavailable-quota startup/access states; ready
read-only startup; safe stop refusal; matching isolated migration proof. These
source instructions are not evidence that the operations have run or that all
475 messages have been preserved.

Primary contracts: [mount_vnd](https://man.openbsd.org/mount_vnd.8),
[rc.d ordering](https://man.openbsd.org/rc.d.8),
[quotacheck](https://man.openbsd.org/quotacheck.8),
[quotaon](https://man.openbsd.org/quotaon.8),
[edquota](https://man.openbsd.org/edquota.8),
[Dovecot migration](https://doc.dovecot.org/2.3/admin_manual/migrating_mailboxes/),
[Dovecot filesystem quota/metadata locations](https://doc.dovecot.org/2.3/configuration_manual/quota/quota_fs/),
and [pax physical copy semantics](https://man.openbsd.org/pax.1).
