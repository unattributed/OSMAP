#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed file python3
setup_run_dir "47-weak-crypto-primitives-check"

perform_login cookies.txt login.headers login.body.html
curl -sS -o login-page.html -D login-page.headers "${TARGET_BASE_URL}${LOGIN_PATH}"
fetch_get "${MAILBOXES_PATH}" mailboxes.html mailboxes.headers cookies.txt
fetch_get "${SESSIONS_PATH}" sessions.html sessions.headers cookies.txt
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message.html message.headers cookies.txt
fetch_get "${ATTACHMENT_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}&part=${DEFAULT_ATTACHMENT_PART}" attachment.bin attachment.headers cookies.txt
SESSION_COOKIE="$(session_cookie_value cookies.txt)"
printf '===== session cookie stats =====\nvalue=%s\nlength=%s\nhex_only=%s\n' "$SESSION_COOKIE" "${#SESSION_COOKIE}" "$(printf '%s' "$SESSION_COOKIE" | grep -Eq '^[0-9a-f]+$' && echo yes || echo no )"
printf '\n===== response headers overview =====\n'
for f in login.headers login-page.headers mailboxes.headers sessions.headers message.headers attachment.headers; do
  printf '\n--- %s ---\n' "$f"
  sed -n '1,40p' "$f"
done
printf '\n===== crypto token scan in HTML =====\n'
grep -Ein 'md5|sha1|sha-1|des|3des|rc4|blowfish|ecb|cbc|rsa|dsa|ecdsa|ed25519|aes|gcm|chacha|argon2|bcrypt|pbkdf2|scrypt|hkdf|nonce|salt|iv|hmac|jwt|jwe|jws|pgp|gpg|encrypt|decrypt|signature|signed|cipher' login-page.html mailboxes.html sessions.html message.html | sed -n '1,200p'
printf '\n===== attachment type and prefix =====\n'
file attachment.bin
print_body_prefix attachment.bin

printf '\nSaved in %s\n' "$RUN_DIR"
