#!/bin/sh
set -eu

python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py --self-test >/dev/null

workdir="$(mktemp -d /tmp/osmap-v12-helper-compile-scaffold-test.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

cp maint/security/v12-openpgp-helper-compile-scaffold.example.json "$workdir/good.json"
python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py \
  --config "$workdir/good.json" \
  --skip-compile \
  --source maint/security/openpgp-helper/osmap-openpgp-helper-compile-only.c >/dev/null

python3 - "$workdir/good.json" "$workdir/bad.json" <<'PY'
import json
import sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src, encoding="utf-8"))
data["safety_invariants"]["runtime_crypto_enabled"] = True
json.dump(data, open(dst, "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
if python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py --config "$workdir/bad.json" --skip-compile --source maint/security/openpgp-helper/osmap-openpgp-helper-compile-only.c >/dev/null 2>&1; then
  echo "expected runtime_crypto_enabled=true config to fail" >&2
  exit 1
fi

{
  printf '%s\n' '#include <gpgme.h>'
  printf '%s' 'int main(void) { gpgme_op_'
  printf '%s\n' 'decrypt(0, 0, 0); return 0; }'
} > "$workdir/bad.c"
if python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py --config "$workdir/good.json" --skip-compile --source "$workdir/bad.c" >/dev/null 2>&1; then
  echo "expected forbidden GPGME operation source to fail" >&2
  exit 1
fi

echo "V12 OpenPGP helper compile scaffold gate regression test passed"
