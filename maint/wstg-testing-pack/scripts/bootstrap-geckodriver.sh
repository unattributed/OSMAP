#!/bin/sh

set -eu

version="0.37.0"
expected_sha256="90d4e33bd9816684400c160d1309aaffec23a3f65103511d5a62d8501062e548"
install_root="${OSMAP_WSTG_DRIVER_ROOT:-${HOME}/.cache/osmap-wstg}"
archive="${install_root}/geckodriver-${version}-linux64.tar.gz"
driver="${install_root}/geckodriver"
url="https://github.com/mozilla/geckodriver/releases/download/v${version}/geckodriver-v${version}-linux64.tar.gz"

mkdir -p "${install_root}"
if [ ! -x "${driver}" ]; then
	curl -fsSL "${url}" -o "${archive}"
	actual_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
	if [ "${actual_sha256}" != "${expected_sha256}" ]; then
		echo "error: geckodriver archive checksum mismatch" >&2
		exit 1
	fi
	tar -xzf "${archive}" -C "${install_root}" geckodriver
	chmod 0755 "${driver}"
fi

"${driver}" --version
printf 'driver_path=%s\n' "${driver}"
