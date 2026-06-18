#!/bin/ksh
#
# Enforce the production browser-entry invariant without handling credentials.
# Intended install target: /usr/local/libexec/osmap/osmap-login-availability.ksh

set -eu

: "${OSMAP_LOGIN_HOST:=mail.blackbagsecurity.com}"
: "${OSMAP_LOGIN_ADDR:=127.0.0.1}"
: "${OSMAP_LOGIN_PORT:=8080}"
: "${OSMAP_LOGIN_NC:=/usr/bin/nc}"
: "${OSMAP_LOGIN_RCCTL:=/usr/sbin/rcctl}"
: "${OSMAP_LOGIN_SLEEP:=/bin/sleep}"

mode="${1:---recover}"
case "$mode" in
--check-only|--recover)
	;;
*)
	printf '%s\n' "usage: $0 [--check-only|--recover]" >&2
	exit 2
	;;
esac

request_path() {
	path=$1
	printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
		"$path" "$OSMAP_LOGIN_HOST" |
		"$OSMAP_LOGIN_NC" -w 5 "$OSMAP_LOGIN_ADDR" "$OSMAP_LOGIN_PORT"
}

browser_entry_is_healthy() {
	root_response="$(request_path / 2>/dev/null || true)"
	login_response="$(request_path /login 2>/dev/null || true)"
	root_response="$(printf '%s\n' "$root_response" | tr -d '\r')"
	login_response="$(printf '%s\n' "$login_response" | tr -d '\r')"

	printf '%s\n' "$root_response" | grep -Fq 'HTTP/1.1 303 ' &&
		printf '%s\n' "$root_response" | grep -Fxq 'Location: /login' &&
		printf '%s\n' "$login_response" | grep -Fq 'HTTP/1.1 200 ' &&
		printf '%s\n' "$login_response" | grep -Fq '<title>OSMAP Login</title>'
}

if browser_entry_is_healthy; then
	printf '%s\n' "OSMAP browser entry invariant passed"
	exit 0
fi

printf '%s\n' "OSMAP browser entry invariant failed" >&2
[ "$mode" = "--recover" ] || exit 1

printf '%s\n' "restarting osmap_serve after browser entry failure" >&2
"$OSMAP_LOGIN_RCCTL" restart osmap_serve
"$OSMAP_LOGIN_SLEEP" 2

if browser_entry_is_healthy; then
	printf '%s\n' "OSMAP browser entry invariant recovered"
	exit 0
fi

printf '%s\n' "OSMAP browser entry invariant still failed after restart" >&2
exit 1
