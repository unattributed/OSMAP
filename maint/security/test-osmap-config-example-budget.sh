#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

assert_contains_file() {
	file_path=$1
	needle=$2

	grep -Fq "${needle}" "${file_path}" || {
		printf 'expected to find "%s" in %s\n' "${needle}" "${file_path}" >&2
		exit 1
	}
}

for env_file in \
	"${repo_root}/config/osmap.env.example" \
	"${repo_root}/maint/openbsd/osmap-serve.env.example" \
	"${repo_root}/maint/openbsd/osmap-mailbox-helper.env.example" \
	"${repo_root}/maint/openbsd/mail.blackbagsecurity.com/etc/osmap/osmap-serve.env" \
	"${repo_root}/maint/openbsd/mail.blackbagsecurity.com/etc/osmap/osmap-mailbox-helper.env"
do
	[ -f "${env_file}" ] || {
		printf 'missing env example: %s\n' "${env_file}" >&2
		exit 1
	}

	assert_contains_file "${env_file}" "OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS=16"
	assert_contains_file "${env_file}" "OSMAP_MAILBOX_WORKER_BUDGET=8"
	assert_contains_file "${env_file}" "OSMAP_SEARCH_WORKER_BUDGET=4"
	assert_contains_file "${env_file}" "OSMAP_SEND_WORKER_BUDGET=2"
	assert_contains_file "${env_file}" "OSMAP_AUTH_WORKER_BUDGET=4"
	assert_contains_file "${env_file}" "OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS=5"
done

printf '%s\n' "OSMAP budget env example regression checks passed"
