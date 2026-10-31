#!/bin/ksh
# Existing Rust application/helper tests with disposable native keys, no live mail.
set -eu
# Bound this exact fixture and its process group. This does not supervise live services.
if [[ ${OSMAP_S05_NATIVE_BOUND:-no} != yes ]]; then
    exec /usr/local/bin/python3 - "$0" "$@" <<'PY'
import os, signal, subprocess, sys
env = dict(os.environ, OSMAP_S05_NATIVE_BOUND="yes")
child = subprocess.Popen(["/bin/ksh", *sys.argv[1:]], env=env, start_new_session=True)
try:
    result = child.wait(timeout=240)
except subprocess.TimeoutExpired:
    # A timed-out, unreaped direct child still reserves this process-group ID.
    os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    print("NATIVE_OUTER_DEADLINE=EXPIRED; RETAINED_FIXTURE_REQUIRES_RECONCILIATION", flush=True)
    result = 124
sys.exit(result if result >= 0 else 128 - result)
PY
fi
umask 077
ulimit -c 0
export PATH=/usr/local/bin:/usr/bin:/bin
export LC_ALL=C

[[ $# -eq 2 && $(uname -s) = OpenBSD ]] || exit 64
source_root=$(cd "$1" && pwd -P)
test_binary=$2
[[ "$source_root" = "$1" && -x "$test_binary" && "$test_binary" = /* ]] || exit 64
fixture=$(mktemp -d /tmp/osmap-crypto-fixture-XXXXXXXX)
stage=prepare
complete=no
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    stopped=yes
    for account in alice bob; do
        home_dir=$fixture/$account
        if [[ -d "$home_dir" ]]; then
            agent_socket=$(/usr/local/bin/gpgconf --homedir "$home_dir" --list-dirs agent-socket \
                2>>"$fixture/commands.log") || stopped=no
            /usr/local/bin/gpgconf --homedir "$home_dir" --kill gpg-agent \
                >>"$fixture/commands.log" 2>&1 || stopped=no
            attempts=0
            while [[ -n "$agent_socket" && -S "$agent_socket" && "$attempts" -lt 20 ]]; do
                sleep 0.1
                attempts=$((attempts + 1))
            done
            [[ -n "$agent_socket" && ! -S "$agent_socket" ]] || stopped=no
        fi
    done
    if [[ "$complete" = yes && "$result" -eq 0 && "$stopped" = yes ]]; then
        rm -r -- "$fixture"
        print 'DISPOSABLE_CLEANUP=PASS'
    else
        print "NATIVE_FAILURE_STAGE=$stage"
        print "NATIVE_PROCESS_EXIT=$result"
        print "OWNED_AGENT_STOP=$stopped"
        print "RETAINED_PRIVATE_FIXTURE=$fixture"
        [[ "$result" -ne 0 ]] || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for unit in crypto crypto_engine inventory; do
    stage=compile_$unit
    if [[ "$unit" = crypto_engine ]]; then
        cc -std=c99 -Wall -Wextra -Werror \
            "$source_root/maint/openpgp-runtime/$unit.c" -o "$fixture/$unit" \
            >"$fixture/commands.log" 2>&1
    else
        cc -std=c99 -Wall -Wextra -Werror -I/usr/local/include \
            "$source_root/maint/openpgp-runtime/$unit.c" \
            -L/usr/local/lib -lgpgme -lgpg-error -o "$fixture/$unit" \
            >>"$fixture/commands.log" 2>&1
    fi
done
print 'NATIVE_C_WORKER_BUILD=PASS'

gpg_fixture() {
    key_home=$1
    shift
    /usr/local/bin/gpg --no-options --homedir "$key_home" --batch \
        --pinentry-mode loopback --passphrase-fd 0 "$@"
}
for account in alice bob; do
    stage=disposable_key_$account
    home_dir=$fixture/$account
    mkdir "$home_dir"
    print '' | gpg_fixture "$home_dir" --quick-generate-key \
        "Synthetic $account <$account@example.test>" ed25519 cert,sign 0 \
        >>"$fixture/commands.log" 2>&1
    gpg_fixture "$home_dir" --with-colons --list-keys </dev/null \
        >"$fixture/$account.list" 2>>"$fixture/commands.log"
    fingerprint=$(awk -F: '$1 == "fpr" {print $10; exit}' "$fixture/$account.list")
    [[ ${#fingerprint} -eq 40 && "$fingerprint" != *[!A-F0-9]* ]]
    print '' | gpg_fixture "$home_dir" --quick-add-key "$fingerprint" cv25519 encrypt 0 \
        >>"$fixture/commands.log" 2>&1
    print -r -- "$fingerprint" >"$fixture/$account.fingerprint"
    gpg_fixture "$home_dir" --export "$fingerprint" </dev/null \
        >"$fixture/$account.public" 2>>"$fixture/commands.log"
done
stage=disposable_public_exchange
/usr/local/bin/gpg --no-options --homedir "$fixture/alice" --batch --import \
    "$fixture/bob.public" >>"$fixture/commands.log" 2>&1
/usr/local/bin/gpg --no-options --homedir "$fixture/bob" --batch --import \
    "$fixture/alice.public" >>"$fixture/commands.log" 2>&1

export OSMAP_CRYPTO_NATIVE_WORKER=$fixture/crypto
export OSMAP_CRYPTO_NATIVE_ENGINE=$fixture/crypto_engine
export OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER=$fixture/inventory
export OSMAP_CRYPTO_NATIVE_ALICE_HOME=$fixture/alice
export OSMAP_CRYPTO_NATIVE_BOB_HOME=$fixture/bob
export OSMAP_CRYPTO_NATIVE_ALICE_FP=$(cat "$fixture/alice.fingerprint")
export OSMAP_CRYPTO_NATIVE_BOB_FP=$(cat "$fixture/bob.fingerprint")

run_native() {
    stage=$1
    "$test_binary" --list --exact "$2" >"$fixture/listing" 2>>"$fixture/commands.log"
    # Refuse a zero-test selection before interpreting libtest exit status.
    /usr/bin/grep -Fx "$2: test" "$fixture/listing" >/dev/null
    "$test_binary" --exact "$2" --ignored >"$fixture/$stage.log" 2>&1
    print "$stage=PASS"
}
run_native AUTHENTICATED_RUST_ROUNDTRIP \
    openpgp_crypto_runtime::tests::native_crypto_authenticated_service_client
run_native PRODUCTION_GATEWAY_ROUNDTRIP \
    http::http_gateway::http_gateway_mail::tests::protected_send_native::native_crypto_gateway_protected_send_roundtrip
complete=yes
print 'S05_01_NATIVE_FUNCTIONAL=PASS'
