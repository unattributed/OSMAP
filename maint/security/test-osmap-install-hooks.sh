#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_makefile="${repo_root}/Makefile"
source_pre_commit="${repo_root}/.githooks/pre-commit"
source_pre_push="${repo_root}/.githooks/pre-push"
source_security_check="${repo_root}/maint/security/osmap-security-check.sh"
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
