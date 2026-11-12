# Guarded account-mutation relay (disabled prerequisite)

`mutation_relay.py` is a purpose-exclusive, key-free transport between the
web peer on obsd1 and the authoritative helper on mail.blackbagsecurity.com.
The fixed address 216.128.179.75, local web UID 1001, `_osmapbridge` local
principal and `_osmap` remote connector follow the existing source conventions;
these literals are not a new native identity or permission qualification.

The bridge authenticates the local Unix peer and uses a dedicated mutation SSH
identity, pinned host key, and fixed `osmap-account-mutation` purpose. The remote
identity must have one root-controlled restricted forced-command entry leading
to the exact mutation helper socket. No auth/mailbox SSH master is reused and no
mutation master is created. Password, TOTP, request-MAC and session-proof-MAC
keys are not read by the bridge. The helper independently verifies the original
opaque signed action, budget and live guarded-session proof.

Full duplex challenge/ACK bytes are preserved exactly. Unsigned deadline parsing
can only shorten the bridge's initial 60-second cap; it never supplies authority.
Framing, SSH I/O, cleanup and terminal reply share that shortened original cap.
The terminal reply is withheld until zero SSH exit, direct-child reap and owned
process-group absence are confirmed. Unconfirmed cleanup latches the instance
unavailable, with no reconnect or automatic retry. Confirming local SSH cleanup
does not confirm remote helper termination or distributed issuer continuity.

The local listener follows the existing bridge group's traverse/socket model.
The authoritative helper currently uses a private parent and owner-only socket;
its connector grant remains a separate implemented-and-qualified prerequisite.
The relay must not weaken those permissions or infer authorization from endpoint
access. A separate purpose grant must preserve private key/config custody and
actual peer checks as well as the end-to-end session/action proofs.

`NATIVE_RELAY_QUALIFIED` remains false before principal, SSH material or listener
access. The rc.d file is source only: no service installation, identity creation,
permission change, SSH connection, operator credential change or mail submission
was performed. Native host-key routing, forced-command/grant, OpenBSD confinement,
clock behaviour and remote stop/issuer-failure handling remain unqualified.

Actual local verification used public synthetic fixtures: 10 new focused cases
pass, and 17 combined new/preserved cases execute and pass; the existing OpenBSD
peer case is explicitly skipped on Linux. These discriminate exact Unicode
bytes, real challenge/ACK MACs, account/source/action/epoch tampering, peer and
budget refusals, deadline kill/reap, malformed/oversized/late output, nonzero exit
and cleanup uncertainty. The public remote fixture has no SQL or mail effects;
it proves transport and compatibility, not complete password workflow or UAT.
