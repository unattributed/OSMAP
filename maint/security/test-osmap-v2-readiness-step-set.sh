#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v2-readiness-step-set-test.XXXXXX")
bin_dir="${tmp_root}/bin"
expected_steps="security-check
login-send
safe-html-attachment-download
login-failure-normalization
all-mailbox-search
archive-shortcut
session-surface
send-throttle
move-throttle
helper-peer-auth
request-guardrails
mailbox-backend-unavailable"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${bin_dir}"

cat > "${bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF
chmod +x "${bin_dir}/ksh"

assert_equals() {
  left=$1
  right=$2
  label=$3

  [ "${left}" = "${right}" ] || {
    printf '%s\nexpected:\n%s\nactual:\n%s\n' "${label}" "${right}" "${left}" >&2
    exit 1
  }
}

extract_acceptance_steps() {
  awk '
    /^The current authoritative readiness step set is:/ {
      in_steps = 1
      next
    }
    in_steps && /^$/ {
      if (seen_step) {
        exit
      }
      next
    }
    in_steps {
      seen_step = 1
      print
    }
  ' "${repo_root}/docs/V2_ACCEPTANCE_CRITERIA.md" |
    sed -n 's/^- `\([^`][^`]*\)`$/\1/p'
}

extract_ssh_default_steps() {
  awk '
    /^set_default_steps\(\) \{/ {
      in_func = 1
      next
    }
    in_func && /^}/ {
      exit
    }
    in_func && /STEP_NAMES="/ {
      sub(/^.*STEP_NAMES="/, "")
      sub(/"$/, "")
      print
      next
    }
    in_func {
      gsub(/^[[:space:]]*/, "")
      sub(/"$/, "")
      if ($0 != "") {
        print
      }
    }
  ' "${repo_root}/maint/live/osmap-run-v2-readiness-over-ssh.sh"
}

extract_sop_command_steps() {
  awk '
    /osmap-run-v2-readiness-with-temporary-validation-password\.sh \\/ {
      in_command = 1
      next
    }
    in_command && /^```/ {
      exit
    }
    in_command {
      gsub(/^[[:space:]]*/, "")
      gsub(/[[:space:]]*\\$/, "")
      gsub(/[[:space:]]*$/, "")
      if ($0 ~ /^[a-z0-9][a-z0-9-]*$/) {
        print
      }
    }
  ' "${repo_root}/docs/V2_PILOT_REHEARSAL_SOP.md"
}

extract_sop_report_steps() {
  awk '
    /^steps=$/ {
      in_report = 1
      next
    }
    in_report && /^```/ {
      exit
    }
    in_report {
      print
    }
  ' "${repo_root}/docs/V2_PILOT_REHEARSAL_SOP.md" |
    sed -n 's/^\([a-z0-9][a-z0-9-]*\)=passed$/\1/p'
}

wrapper_steps=$(PATH="${bin_dir}:${PATH}" sh "${repo_root}/maint/live/osmap-live-validate-v2-readiness.ksh" --list)
acceptance_steps=$(extract_acceptance_steps)
ssh_default_steps=$(extract_ssh_default_steps)
sop_command_steps=$(extract_sop_command_steps)
sop_report_steps=$(extract_sop_report_steps)

assert_equals "${wrapper_steps}" "${expected_steps}" "host-side V2 readiness wrapper step set drifted"
assert_equals "${acceptance_steps}" "${expected_steps}" "V2 acceptance criteria step set drifted"
assert_equals "${ssh_default_steps}" "${expected_steps}" "off-host V2 readiness SSH wrapper step set drifted"
assert_equals "${sop_command_steps}" "${expected_steps}" "V2 pilot rehearsal command step set drifted"
assert_equals "${sop_report_steps}" "${expected_steps}" "V2 pilot rehearsal report step set drifted"

printf '%s\n' "v2 readiness step-set consistency checks passed"
