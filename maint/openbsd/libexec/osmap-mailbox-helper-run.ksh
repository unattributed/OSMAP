#!/bin/ksh
#
# Minimal launcher for the local mailbox-helper runtime on OpenBSD.
# Intended install target: /usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh

set -eu

: "${OSMAP_BIN:=/usr/local/bin/osmap}"
: "${OSMAP_ENV_FILE:=/etc/osmap/osmap-mailbox-helper.env}"

mode="${1:-mailbox-helper}"

case "$mode" in
bootstrap|mailbox-helper)
	;;
*)
	printf '%s\n' "unsupported OSMAP run mode for mailbox-helper launcher: $mode" >&2
	exit 1
	;;
esac

[ -x "$OSMAP_BIN" ] || {
	printf '%s\n' "OSMAP binary is not executable: $OSMAP_BIN" >&2
	exit 1
}

[ -r "$OSMAP_ENV_FILE" ] || {
	printf '%s\n' "OSMAP env file is not readable: $OSMAP_ENV_FILE" >&2
	exit 1
}

set -a
. "$OSMAP_ENV_FILE"
set +a

exec "$OSMAP_BIN" "$mode"
