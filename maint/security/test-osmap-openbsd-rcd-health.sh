#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
serve_rc="${repo_root}/maint/openbsd/rc.d/osmap_serve"
helper_rc="${repo_root}/maint/openbsd/rc.d/osmap_mailbox_helper"

assert_pexp_follows_rc_subr() {
  file_path=$1
  expected=$2

  rc_subr_line=$(grep -nF '. /etc/rc.d/rc.subr' "${file_path}" | cut -d: -f1)
  pexp_line=$(grep -nF "${expected}" "${file_path}" | cut -d: -f1)

  [ -n "${rc_subr_line}" ] || {
    printf 'missing rc.subr include in %s\n' "${file_path}" >&2
    exit 1
  }

  [ -n "${pexp_line}" ] || {
    printf 'missing expected pexp in %s\n' "${file_path}" >&2
    exit 1
  }

  [ "${pexp_line}" -gt "${rc_subr_line}" ] || {
    printf 'expected pexp to be set after rc.subr in %s\n' "${file_path}" >&2
    exit 1
  }
}

assert_pexp_follows_rc_subr "${serve_rc}" 'pexp="/usr/local/bin/osmap serve"'
assert_pexp_follows_rc_subr "${helper_rc}" 'pexp="/usr/local/bin/osmap mailbox-helper"'

printf '%s\n' "openbsd rc.d health regression checks passed"
