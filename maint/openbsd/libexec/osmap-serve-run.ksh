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

: "${OSMAP_LOG_DIR:=/var/log/osmap}"
: "${OSMAP_STDERR_LOG_PATH:=${OSMAP_LOG_DIR%/}/serve.log}"

umask 027
: >> "$OSMAP_STDERR_LOG_PATH" || {
	printf '%s\n' "OSMAP serve log file is not writable: $OSMAP_STDERR_LOG_PATH" >&2
	exit 1
}

exec >>"$OSMAP_STDERR_LOG_PATH" 2>&1

child_pid=
stop_requested=0

forward_shutdown() {
	stop_requested=1
	[ -n "$child_pid" ] && kill -TERM "$child_pid" 2>/dev/null || true
}

trap forward_shutdown HUP INT TERM

"$OSMAP_BIN" "$mode" &
child_pid=$!

set +e
wait "$child_pid"
status=$?
set -e

if [ "$stop_requested" -eq 1 ] || [ "$status" -eq 143 ]; then
	printf 'ts="%s" level=info category=bootstrap action=process_stopped msg="OSMAP serve process stopped by supervisor" exit_status="%s"\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status"
elif [ "$status" -gt 128 ]; then
	signal=$((status - 128))
	printf 'ts="%s" level=error category=bootstrap action=process_exited msg="OSMAP serve process terminated by signal" exit_status="%s" signal="%s"\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" "$signal"
elif [ "$status" -ne 0 ]; then
	printf 'ts="%s" level=error category=bootstrap action=process_exited msg="OSMAP serve process exited unsuccessfully" exit_status="%s"\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status"
else
	printf 'ts="%s" level=info category=bootstrap action=process_exited msg="OSMAP serve process exited normally" exit_status="0"\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

exit "$status"
