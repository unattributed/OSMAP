# Dedicated authoritative mutation connector grant (disabled)

This source increment supplies a separate, fixed-purpose endpoint grant. It does
not create a user/group, install an authorized key, change permissions, read an
operator credential or activate a password form. `NATIVE_CONNECTOR_GRANT_QUALIFIED`
remains false before users/groups, private config and namespace access.

The authoritative helper keeps `/etc/osmap/account-runtime` owner-private and
all MAC keys/config0600. A separate `/var/run/osmap-account-mutation` namespace
is root-owned, mode0710, with dedicated `_osmapmutation` group. Its exact socket
is root:that-group0660. Connectors have search/connect but no directory write,
key custody or authority to choose a socket/account/action. The fixed native
loader resolves the group by name instead of inventing a GID; it checks the
configured `_osmap` UID against the existing bootstrap trusted-relay UID and
checks dedicated supplementary/primary membership internally without emitting
account inventories. More than4096 local passwd entries is unavailable.

A private, bounded `connector-grant.json` record contains exactly version1,
authority `mail.blackbagsecurity.com`, purpose `osmap-account-mutation`, connector
`_osmap`, group `_osmapmutation` and trusted_relay_uid. This grant is not a
credential, request-MAC, live-session or mutation authorization. Bootstrap
account/action proofs and exact peer authentication remain mandatory.

The native listener requires this grant; private existing test listeners retain
mode600. The grant verifies immutable ancestry, exact owner/group/mode and held
namespace inode. Socket ownership/mode are published and rechecked before listen
and before authenticating the accepted frame. Symlinks, hardlinks, namespace or
socket replacement, broad directory modes and caller-selected paths refuse.

`osmap_account_mutation_connector` is a source restricted-key entry command: it
requires the literal SSH original command and execs `/usr/bin/nc -N -U` with only
the exact purpose socket. Future installation must keep this executable/root
entry immutable, install a purpose-exclusive restricted authorized key and prove
no shell/forwarding/general command grant. Endpoint access does not bypass the
supervisor's independent MAC, current guarded-session, epoch and action checks.

Actual strict-SSH read-only metadata from the authoritative Vultr host confirmed
hostname/OpenBSD and `_osmap` UID1001, primaryGID1003, groups1003/1004. The current
auth socket is UID1001/GID1003 mode660. New account private bootstrap, mutation
namespace and fixed-purpose group are absent. No groups, sockets, keys, rows,
config or services were modified. The first metadata query rejected Python's
actual platform `openbsd7` before metadata because it expected exact `openbsd`;
that refusal is retained separately and the narrowly corrected query succeeded.

The real earlier listener rejected an owned mode0710 namespace before publication
(actual one-case RED retained). The corrected source executes eight discriminating
local tests: actual socket mode/group publication; reachable endpoint with forged
frame still refuses before child spawn; broad/symlink/foreign namespace/path;
held-inode replacement/hardlink refusal; private config exact binding; membership
refusals; default-off before files; literal forced-purpose refusal. Eighteen
preserved supervisor/native-factory cases pass. These are current-user local
source fixtures, not root/foreign-principal DAC or SSH/native qualification.

The next controlled native proposal must use isolated public synthetic keys and
purpose grant, no operator passwords/provider traffic: verify actual distinct
connector/group DAC, fixed-key forced command and peer refusals, original duplex
challenge/ACK/deadline and remote watchdog/issuer death. Native routing, actual
confinement, SQL/current authentication, SMTP termination and whole password UAT
remain open. Root owns activation and qualification after independent review.
