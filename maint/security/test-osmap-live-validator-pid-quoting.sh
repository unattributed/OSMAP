#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "${repo_root}"

bad_pid_echoes=$(grep -RInF 'echo \$$' maint/live/*.ksh 2>/dev/null || true)
if [ -n "${bad_pid_echoes}" ]; then
  printf '%s\n' "live validators must pass literal child-shell PID expansion as echo \\\$\\\$"
  printf '%s\n' "${bad_pid_echoes}"
  exit 1
fi

fixed_pid_echo_count=$(grep -RInF 'echo \$\$' maint/live/*.ksh 2>/dev/null | wc -l | tr -d ' ')
if [ "${fixed_pid_echo_count}" -lt 1 ]; then
  printf '%s\n' "expected live validators to record child-shell PIDs with echo \\\$\\\$"
  exit 1
fi

direct_pid_kills=$(grep -RIn 'doas kill "$(.*cat ".*PID_PATH' maint/live/*.ksh 2>/dev/null || true)
if [ -n "${direct_pid_kills}" ]; then
  printf '%s\n' "live validators must terminate recorded PIDs through the verified cleanup helper"
  printf '%s\n' "${direct_pid_kills}"
  exit 1
fi

unprivileged_pid_tests=$(grep -RIn '\[ -f ".*PID_PATH.*" \]' maint/live/*.ksh 2>/dev/null || true)
if [ -n "${unprivileged_pid_tests}" ]; then
  printf '%s\n' "live validator PID checks must use doas test for protected runtime directories"
  printf '%s\n' "${unprivileged_pid_tests}"
  exit 1
fi

kill_fallbacks=$(grep -RInF 'doas kill -KILL "${target_pid}"' maint/live/*.ksh 2>/dev/null | wc -l | tr -d ' ')
if [ "${kill_fallbacks}" -lt 1 ]; then
  printf '%s\n' "expected live validators to keep a KILL fallback for isolated runtime cleanup"
  exit 1
fi

printf '%s\n' "live validator pid quoting regression checks passed"
