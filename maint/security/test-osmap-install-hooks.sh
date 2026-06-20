#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_makefile="${repo_root}/Makefile"
source_pre_commit="${repo_root}/.githooks/pre-commit"
source_pre_push="${repo_root}/.githooks/pre-push"
source_security_check="${repo_root}/maint/security/osmap-security-check.sh"
source_supply_chain_check="${repo_root}/maint/security/osmap-supply-chain-check.sh"
source_release_check="${repo_root}/maint/security/osmap-release-check.sh"
source_v4_assurance_gate="${repo_root}/maint/security/osmap-v4-hostile-assurance-gate.sh"
source_v4_tuple_gate="${repo_root}/maint/security/osmap-v4-release-tuple-gate.sh"
source_v4_claim_matrix_gate="${repo_root}/maint/security/osmap-v4-security-claim-matrix-gate.sh"
source_v5_boundary_gate="${repo_root}/maint/security/osmap-v5-boundary-gate.sh"
source_v6_readiness_gate="${repo_root}/maint/security/osmap-v6-retirement-readiness-gate.sh"
source_v7_boundary_gate="${repo_root}/maint/security/osmap-v7-boundary-hardening-gate.sh"
source_v7_rendering_gate="${repo_root}/maint/security/osmap-v7-rendering-regression-gate.sh"
source_v7_rendering_gate_test="${repo_root}/maint/security/test-osmap-v7-rendering-regression-gate.sh"
source_v6_evidence_archive="${repo_root}/maint/security/osmap-v6-evidence-archive.sh"
source_evidence_metadata="${repo_root}/maint/security/osmap-evidence-metadata.sh"
source_cwe_guard="${repo_root}/maint/security/osmap-cwe-top25-guard.sh"
source_cwe_guard_py="${repo_root}/maint/security/osmap-cwe-top25-guard.py"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-hook-install-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_hooks_dir="${fake_repo}/.githooks"
fake_security_dir="${fake_repo}/maint/security"
hook_workdir="${fake_repo}/maint/security"
bin_dir="${tmp_root}/bin"
real_make=$(command -v make)

cleanup() {
	rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${fake_hooks_dir}" "${fake_security_dir}" "${hook_workdir}" "${bin_dir}"
cp "${source_makefile}" "${fake_repo}/Makefile"
cp "${source_pre_commit}" "${fake_hooks_dir}/pre-commit"
cp "${source_pre_push}" "${fake_hooks_dir}/pre-push"
cp "${source_security_check}" "${fake_security_dir}/osmap-security-check.sh"
cp "${source_supply_chain_check}" "${fake_security_dir}/osmap-supply-chain-check.sh"
cp "${source_release_check}" "${fake_security_dir}/osmap-release-check.sh"
cp "${source_v4_assurance_gate}" "${fake_security_dir}/osmap-v4-hostile-assurance-gate.sh"
cp "${source_v4_tuple_gate}" "${fake_security_dir}/osmap-v4-release-tuple-gate.sh"
cp "${source_v4_claim_matrix_gate}" "${fake_security_dir}/osmap-v4-security-claim-matrix-gate.sh"
cp "${source_v5_boundary_gate}" "${fake_security_dir}/osmap-v5-boundary-gate.sh"
cp "${source_v6_readiness_gate}" "${fake_security_dir}/osmap-v6-retirement-readiness-gate.sh"
cp "${source_v7_boundary_gate}" "${fake_security_dir}/osmap-v7-boundary-hardening-gate.sh"
cp "${source_v7_rendering_gate}" "${fake_security_dir}/osmap-v7-rendering-regression-gate.sh"
cp "${source_v7_rendering_gate_test}" "${fake_security_dir}/test-osmap-v7-rendering-regression-gate.sh"
cp "${source_v6_evidence_archive}" "${fake_security_dir}/osmap-v6-evidence-archive.sh"
cp "${source_evidence_metadata}" "${fake_security_dir}/osmap-evidence-metadata.sh"
cp "${source_cwe_guard}" "${fake_security_dir}/osmap-cwe-top25-guard.sh"
cp "${source_cwe_guard_py}" "${fake_security_dir}/osmap-cwe-top25-guard.py"

git init -q "${fake_repo}"

assert_contains() {
	haystack=$1
	needle=$2

	printf '%s' "${haystack}" | grep -Fq "${needle}" || {
		printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
		exit 1
	}
}

assert_equals() {
	left=$1
	right=$2

	[ "${left}" = "${right}" ] || {
		printf 'expected:\n%s\nactual:\n%s\n' "${right}" "${left}" >&2
		exit 1
	}
}

"${real_make}" -C "${fake_repo}" install-hooks >/dev/null

assert_equals "$(git -C "${fake_repo}" config --local core.hooksPath)" ".githooks"
[ -x "${fake_hooks_dir}/pre-commit" ] || {
	printf '%s\n' "expected pre-commit hook to be executable" >&2
	exit 1
}
[ -x "${fake_hooks_dir}/pre-push" ] || {
	printf '%s\n' "expected pre-push hook to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-security-check.sh" ] || {
	printf '%s\n' "expected security-check script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-supply-chain-check.sh" ] || {
	printf '%s\n' "expected supply-chain-check script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-release-check.sh" ] || {
	printf '%s\n' "expected release-check script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v4-hostile-assurance-gate.sh" ] || {
	printf '%s\n' "expected V4 hostile assurance gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v4-release-tuple-gate.sh" ] || {
	printf '%s\n' "expected V4 release tuple gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v4-security-claim-matrix-gate.sh" ] || {
	printf '%s\n' "expected V4 security claim matrix gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v5-boundary-gate.sh" ] || {
	printf '%s\n' "expected V5 boundary gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v6-retirement-readiness-gate.sh" ] || {
	printf '%s\n' "expected V6 retirement readiness gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v7-boundary-hardening-gate.sh" ] || {
	printf '%s\n' "expected V7 boundary hardening gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v7-rendering-regression-gate.sh" ] || {
	printf '%s\n' "expected V7 rendering regression gate script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/test-osmap-v7-rendering-regression-gate.sh" ] || {
	printf '%s\n' "expected V7 rendering regression gate wrapper test to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-v6-evidence-archive.sh" ] || {
	printf '%s\n' "expected V6 evidence archive script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-evidence-metadata.sh" ] || {
	printf '%s\n' "expected evidence metadata script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-cwe-top25-guard.sh" ] || {
	printf '%s\n' "expected CWE Top 25 guard script to be executable" >&2
	exit 1
}
[ -x "${fake_security_dir}/osmap-cwe-top25-guard.py" ] || {
	printf '%s\n' "expected CWE Top 25 guard Python entrypoint to be executable" >&2
	exit 1
}

cat > "${bin_dir}/make" <<'EOF'
#!/bin/sh

set -eu

log_file=${OSMAP_TEST_HOOK_LOG_FILE:?}

[ "$#" -eq 1 ] && [ "$1" = "security-check" ] || {
	printf 'unexpected make invocation: %s\n' "$*" >&2
	exit 1
}

printf 'pwd=%s args=%s\n' "$PWD" "$*" >> "${log_file}"
EOF
chmod +x "${bin_dir}/make"

pre_commit_log="${tmp_root}/pre-commit.log"
pre_commit_output=$(
	cd "${hook_workdir}" && \
		env \
			PATH="${bin_dir}:$PATH" \
			OSMAP_TEST_HOOK_LOG_FILE="${pre_commit_log}" \
			sh "${fake_hooks_dir}/pre-commit"
)

assert_contains "${pre_commit_output}" "Running OSMAP pre-commit security check"
assert_equals "$(cat "${pre_commit_log}")" "pwd=${fake_repo} args=security-check"

pre_push_log="${tmp_root}/pre-push.log"
pre_push_output=$(
	cd "${hook_workdir}" && \
		printf '%s\n' "refs/heads/main HEAD refs/heads/main HEAD" | \
		env \
			PATH="${bin_dir}:$PATH" \
			OSMAP_TEST_HOOK_LOG_FILE="${pre_push_log}" \
			sh "${fake_hooks_dir}/pre-push" origin git@github.com:unattributed/OSMAP.git
)

assert_contains "${pre_push_output}" "Running OSMAP pre-push security check"
assert_equals "$(cat "${pre_push_log}")" "pwd=${fake_repo} args=security-check"

printf '%s\n' "hook installation and invocation regression checks passed"
