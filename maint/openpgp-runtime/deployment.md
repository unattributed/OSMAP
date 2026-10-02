# OpenPGP development service preparation on obsd1

This bundle prepares `obsd1.blackbagsecurity.com` (`192.168.1.44`). It does not
contact the production mail host, replace the running web binary, change its
environment, start/enable services, or import/export private keys. The separate
native principal qualification is recorded in the S05 execution evidence.

## Prepare the public inventory and helper boundary

Run the repository script as root on obsd1, using the reviewed native source,
helper build directory, and the operator-approved **public** certificates:

```sh
doas /usr/local/bin/python3 deployment_prepare.py --prepare \
  --source /absolute/reviewed/native/source \
  --binaries /absolute/reviewed/native/target/debug \
  --duncan-public /absolute/public-duncan.asc \
  --proton-public /absolute/public-proton.asc \
  --account mailbox@example.test \
  --test-account test@obsd1.example.test \
  --correspondent correspondent@example.test
```

The script creates `_osmapgpg`, the `osmapgpg` socket group, and
`/var/lib/osmap-gpg`. It preserves `_osmap`'s existing groups and adds the socket
group. Existing web processes retain their current groups until the separately
coordinated web restart. It refuses to overwrite an existing helper deployment.

The helper account owns executable workers/shim, configuration, private grant
copies, and the account homes. Each home is `0700`; public keybox/trust database
files are `0600`. The socket directory is helper-owned `0750`; the production
services create sockets `0660` and independently authenticate peer UIDs and
signed account grants. Separate random inventory/crypto HMAC keys have `0600`
copies for the helper and `_osmap`. The keys are never printed.

The prepared services are `osmap_crypto` and `osmap_public_inventory`; both stay
disabled. `/var/lib/osmap-gpg/preparation.json` records non-secret provenance and
binary hashes. The current web executable/environment remain unchanged.

Prepared account mappings:

- the operator-supplied mailbox account: primary
  `E401B0FDCA3A712DE8E15BB23DAB198EA2E96BBE`, exact signing subkey
  `83A5689C7C52CE43DB88C8A5322909FC05BF68BB`, and recipient Proton primary
  `C384498B2CC97D8D9EB7B20162C21B767540D006`.
- the operator-supplied test account: public inventory and recipient bindings
  only. No account signing/decryption key is invented or selected. Those
  capabilities remain unavailable until its dedicated test key is provisioned.

Public material alone does not make signing/decryption operational. The crypto
worker uses a pre-existing account agent and refuses unattended prompts or
agent autostart. Recipient discovery is not automatic trust.

## Prepare the PAGE21 public-key administration service

Once the reviewed `osmap_public_admin_helper` binary has passed the authenticated
RPC and native confinement tests, add it to the existing obsd1 custody setup:

```sh
doas /usr/local/bin/python3 deployment_admin_prepare.py --prepare \
  --binary /absolute/reviewed/native/target/debug/osmap_public_admin_helper \
  --inventory-worker /absolute/reviewed/native/qualified-inventory-worker \
  --crypto-engine /absolute/reviewed/native/qualified-crypto-engine \
  --inventory-worker-sha256 QUALIFIED_INVENTORY_WORKER_SHA256 \
  --crypto-engine-sha256 QUALIFIED_CRYPTO_ENGINE_SHA256
```

The additive script reads the already approved account mappings, creates a
separate service grant and owner-private replay state, and installs a disabled
`osmap_public_admin` rc service. It appends the complete public-admin client
triple to the pending web environment; it does not restart webmail or alter
account key homes. Supply the actual hashes from the same obsd1 native
qualification that exercised public import, removal and the secret-key guard;
preparation installs separate admin-only copies and preserves the previously
prepared inventory/crypto workers. Its receipt records only binary hashes and
state booleans.
The helper authenticates the web peer and each bounded request before touching
the actual public keybox. Browser import/remove additionally requires fresh
password/TOTP, session and CSRF validation, an unchanged binding revision and
an unchanged keybox hash. A bound key must first be explicitly unbound; an
import alone never establishes account or recipient trust.

## Apply operator-approved public bindings after the gated build

After the reviewed helper binaries and binding CLI are installed, start the
inventory service independently of the web deployment:

```sh
doas rcctl start osmap_public_inventory
```

Invoke the operator CLI as `_osmap` so persisted settings retain the correct
ownership. The CLI reads authenticated current inventory through the actual
helper Client, validates the proposed bindings, and uses an expected revision.
For the first record, expected revision is `0`; a stale revision fails without
replacement. Read the helper UID from `preparation.json`, not from an example.

```sh
doas -u _osmap /absolute/reviewed/osmap_openpgp_bindings \
  /var/lib/osmap/settings/openpgp-bindings \
  mailbox@example.test 0 \
  /var/lib/osmap/settings/openpgp-pending/duncan.json \
  /var/lib/osmap-gpg/run/inventory.sock \
  /var/lib/osmap/secrets/openpgp-inventory.key HELPER_UID
```

Repeat for the operator-supplied test account using its pending JSON. This
trusted operator operation is not a substitute for the future HTTP key-management
workflow's fresh password/TOTP confirmation. It does not silently enable signing,
encryption, or encrypt-to-self in the composer.

## Mail key custody and interactive unlock

The mailbox private key is separate from the workstation's Shopkeeper Git
signing key and its agent. Do not export, transfer, or unlock Shopkeeper for this
mail operation. The prepared public mapping expects the Duncan mailbox primary
and exact signing subkey listed above.

The operator must supply the matching **passphrase-protected mailbox secret
key** through an encrypted SSH transfer and import it in the helper-owned
`/var/lib/osmap-gpg/accounts/duncan` home. Do not put private material in the
repository, delivery/evidence archive, command arguments, logs, environment
variables, or chat. The application never performs private-key export. Preserve
its encrypted source backup under operator control.

A concrete private-key import should run as `_osmapgpg`, using a helper-readable
owner-only protected import file supplied by the operator:

Stop the crypto helper, public inventory helper, and any separately installed
public administration helper before importing or modifying mailbox private
custody. Confirm the processes have exited before running GnuPG. Keep them
stopped throughout the import; start them only after it completes. The public
administration store's account lock does not serialize a direct operator GnuPG
command. Running that command concurrently with a public-key removal can add
secret capability between its last guard and public-keybox commit. An eventual
operator import launcher may instead hold that exact account lock throughout.

```sh
doas rcctl stop osmap_crypto osmap_public_inventory
# If the public administration service has been installed:
doas rcctl stop osmap_public_admin
# Stop the public administration service too, if installed, and verify all
# relevant helper processes have exited before continuing.
```

```sh
doas -u _osmapgpg /bin/ksh -c 'ulimit -c 0; exec /usr/local/bin/gpg \
  --no-options --homedir /var/lib/osmap-gpg/accounts/duncan \
  --batch --import /absolute/operator-protected-mailbox-key.asc'
```

Do not place `gpg.conf`, `common.conf`, or `gpg-agent.conf` in that account home;
the worker intentionally refuses such configuration overrides. Agent/pinentry
settings belong to the explicit operator launcher. The agent must already be
running and the signing/decryption key cached before the web worker uses it.
An expired cache or locked key produces a typed refusal rather than a prompt in
an HTTP request. Complete the interactive mailbox unlock in the operator's SSH terminal:

```sh
doas /usr/local/bin/python3 /absolute/reviewed/deployment_unlock.py
```

The launcher grants only that terminal to the helper while real pinentry-tty
prompts run, then restores its original owner/group/mode in `finally`. The
plain terminal Pinentry also works when an SSH terminal has tiny dimensions or
no `TERM` value. It warms
the exact signing key and verifies decryption with a disposable self-encrypted
challenge. No passphrase is read by the launcher or sent to Codex. Signing and
decryption can require separate pinentry prompts because their keygrips differ.
All OpenPGP helpers must be stopped while the launcher replaces the mailbox
agent. It stops any existing account agent and starts a new one with both
default and maximum passphrase-cache lifetime set to 300 seconds, with external
Pinentry caching disabled. Existing agent sockets are never accepted as proof
of this policy. Restart the helpers after successful warming; after cache
expiry, operations fail closed and the operator repeats the terminal unlock.

## Coordinated activation and rollback

Only after the common gates and the reader/composer integration pass should the
coordinator install the reviewed web build, add the pending inventory/crypto
client environment entries, and restart the web service with its new socket-group
membership. The pending environment is
`/var/lib/osmap-gpg/config/web-environment.pending`; it contains paths/UIDs, no
secret values. The environment entries must be added together as complete
socket/key-file/helper-UID triples.

For service rollback, stop and disable the prepared OpenPGP services:

```sh
doas rcctl stop osmap_crypto osmap_public_inventory osmap_public_admin
doas rcctl disable osmap_crypto osmap_public_inventory osmap_public_admin
```

The installed wrappers remove their own sockets after stopping. If a hard crash
left a socket, confirm that its service is stopped before removing that exact
helper-owned socket. Preserve the account homes/private keys, grant copies,
public bindings, preparation receipt, and existing web rollback build. Do not
rerun preparation over existing custody state or remove unrelated mail services.
A future update replaces only stopped helper binaries from a reviewed build and
refreshes their non-secret hashes; it preserves homes and grants.
