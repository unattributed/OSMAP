#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
script="${repo_root}/maint/live/osmap-live-validate-session-surface.ksh"

line_number() {
  pattern="$1"
  awk -v pattern="$pattern" 'index($0, pattern) { print NR; exit }' "$script"
}

build_line=$(line_number 'cargo build --quiet')
now_line=$(line_number 'NOW="$(date +%s)"')

if [ -z "$build_line" ] || [ -z "$now_line" ]; then
  echo "missing expected build or timestamp assignment in session-surface validator"
  exit 1
fi

if [ "$now_line" -le "$build_line" ]; then
  echo "session-surface validator must timestamp synthetic sessions after cargo build"
  exit 1
fi

grep -Fq 'OTHER_LAST_SEEN_AT="${NOW}"' "$script" || {
  echo "single-revoke synthetic session must remain active after build"
  exit 1
}

grep -Fq 'BULK_OTHER_LAST_SEEN_AT="${NOW}"' "$script" || {
  echo "bulk-revoke synthetic session must remain active after build"
  exit 1
}

grep -Fq 'IDLE_LAST_SEEN_AT="$((NOW - 120))"' "$script" || {
  echo "idle synthetic session must remain stale enough to prove idle revocation"
  exit 1
}

echo "session-surface timestamp regression checks passed"
