#!/bin/ksh
#
# Minimal launcher for the browser-facing OSMAP runtime on OpenBSD.
# Intended install target: /usr/local/libexec/osmap/osmap-serve-run.ksh

set -eu

: "${OSMAP_BIN:=/usr/local/bin/osmap}"
: "${OSMAP_ENV_FILE:=/etc/osmap/osmap-serve.env}"

mode="${1:-serve}"

case "$mode" in
bootstrap|serve)
	;;
*)
	printf '%s\n' "unsupported OSMAP run mode for serve launcher: $mode" >&2
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

: "${OSMAP_AUDIT_DIR:=/var/lib/osmap/audit}"
: "${OSMAP_STDERR_LOG_PATH:=${OSMAP_AUDIT_DIR%/}/serve.log}"

umask 027
: >> "$OSMAP_STDERR_LOG_PATH" || {
	printf '%s\n' "OSMAP serve log file is not writable: $OSMAP_STDERR_LOG_PATH" >&2
	exit 1
}

exec >>"$OSMAP_STDERR_LOG_PATH" 2>&1
exec "$OSMAP_BIN" "$mode"
