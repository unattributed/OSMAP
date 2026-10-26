#!/usr/bin/node
'use strict';
// One fixed, controlled local-delivery journey. --check-tools makes no requests.
// Root must first register S04-03-INSTALLED-recovery03 and install the normal
// source-bound Web with OSMAP_RECOVERY_CONTACT_LOCAL_DOMAIN set to this domain.
// No password, cookie, factor or proof body is printed or written by this driver.
const fs = require('node:fs');
const https = require('node:https');
const crypto = require('node:crypto');
const {spawn, spawnSync} = require('node:child_process');
const DOMAIN = 'obsd1.blackbagsecurity.com';
const PRIMARY = `s04-03-primary-20261026-01@${DOMAIN}`;
const A = `s04-03-proof-a-20261026-01@${DOMAIN}`;
const B = `s04-03-proof-b-20261026-01@${DOMAIN}`;
const USERS = [PRIMARY, A, B];
const STAGE = '/var/backups/osmap-recovery-contact-20261026-03';
const OUT = '/home/foo/Downloads/osmap-ux-s04/recovery-contact-20261026/native03';
const TOTP_SOURCE = '/home/foo/Workspace/OSMAP/maint/ux/s04_02_startup_candidate/sources/frontend/native_http_front_driver.py';
const TOTP_SHA = 'eebdbe26269e35bffe43beb83ef84b08712fc67676663b66110cbd32876a7ec3';
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const epoch = account => hash(Buffer.concat([Buffer.from('osmap-account-epoch-v1\0'), Buffer.from(account)]));
const contactStem = hash(Buffer.concat([Buffer.from('osmap-recovery-contact-v1\0'), Buffer.from(PRIMARY)]));
class Refused extends Error { constructor(code) { super(code); this.code = code; } }
function requireThat(value, code) { if (!value) throw new Refused(code); }
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let phase = 'preflight', cookie = '', requests = 0, lastCounter = -1;
let prepared = false, provisioned = false, complete = false;
let webHash = '', helperHash = '', password = '';
let began = 0, bodyEnd = 0, totalEnd = 0;
const observed = [];
function remaining(end = bodyEnd) { const n = end - performance.now(); requireThat(n > 0, 'ORIGINAL_DEADLINE'); return Math.ceil(n); }
function emit(code, extra = {}) { observed.push({phase, code, ...extra}); process.stdout.write(JSON.stringify({phase, code, ...extra}) + '\n'); }

// The already-maintained RFC6238 fixture function supplies the controlled test
// factor. Its public seed is never used for an existing or human account.
function fixtureCode(counter) {
  const script = 'import importlib.util,sys\np=' + JSON.stringify(TOTP_SOURCE) + '\ns=importlib.util.spec_from_file_location("fixed_totp",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);sys.stdout.write(m.code(int(sys.argv[1])))';
  const r = spawnSync('/usr/bin/python3', ['-I', '-c', script, String(counter)], {cwd:'/',env:{PATH:'/usr/bin:/bin',LC_ALL:'C'},timeout:3000,maxBuffer:4096});
  requireThat(r.status === 0 && /^[0-9]{6}$/.test(String(r.stdout)), 'MAINTAINED_TOTP_UNAVAILABLE');
  return String(r.stdout);
}
async function freshCode() {
  while (Math.floor(Date.now()/30000) <= lastCounter) await pause(Math.min(200,remaining()));
  lastCounter = Math.floor(Date.now()/30000); return fixtureCode(lastCounter);
}

function child(program, args, input, end, maximum = 1048576) {
  return new Promise((resolve, reject) => {
    const budget=remaining(end);
    const p = spawn(program,args,{env:{PATH:'/usr/bin:/bin',LC_ALL:'C'},stdio:['pipe','pipe','pipe']});
    let stdout = [], stderr = [], stderrBytes = 0, size = 0, failed = false, closed = false;
    const timer = setTimeout(() => { failed = true; p.kill('SIGTERM'); }, budget);
    const killer = setTimeout(() => { if (!closed) p.kill('SIGKILL'); }, budget+2000);
    p.stdout.on('data', data => { size += data.length; if (size > maximum) { failed = true; p.kill('SIGTERM'); } else stdout.push(data); });
    // Private child diagnostics are not copied into transcripts or result JSON.
    p.stderr.on('data', data => { stderrBytes += data.length; if (stderrBytes > 65536) { failed=true; p.kill('SIGTERM'); } else stderr.push(data); });
    p.on('error', () => { failed=true; });
    p.on('close',(status,signal) => {
      closed=true; clearTimeout(timer); clearTimeout(killer);
      const errorBytes=Buffer.concat(stderr), wire=errorBytes.toString('utf8');
      const match=wire.match(/(?:^|\n)RECOVERY_NATIVE_REFUSED:([A-Z_]{1,48})(?:\n|$)/);
        const known=new Set(['IDENTITY','WEB_BINDING','HELPER_BINDING','OLD_ROWS_READ','OLD_ROWS_SHAPE','OLD_ROWS_BOUND','PENDING_OPERATION','HTTPS_READINESS','WEB_STOP','HELPER_STOP','HELPER_START','HELPER_SOCKETS','WEB_START','STAGE_EXISTS','STAGE_CREATE','PROTECTED_DIRECTORY','FRESH_ROWS_OR_TRIGGER','FRESH_MAILDIR','FRESH_EPOCH','FRESH_FACTOR','FRESH_CONTACT','STAGE_CUSTODY','BIRTH_ALREADY_DISPATCHED','POLICY_DRIFT','INITIAL_HASH','INITIAL_HASH_SCHEME','INITIAL_HASH_COUNT','INITIAL_ROWS_UNCONFIRMED','MAIL_ROOT','MAIL_DOMAIN','MAILDIR_EXISTS','CONTACT_CUSTODY','CONTACT_BOUND','MAIL_SYMLINK','MAIL_BOUND','AMBIGUOUS_MAIL','STAGE_ABSENT','OLD_ROWS_CHANGED','OLD_FILES_CHANGED','POLICY_UNEXPECTED','POLICY_RESTORE','SESSION_BOUND','SESSION_CUSTODY','SESSION_SHAPE','SESSION_CHANGED','MTA_ROUTE','MTA_ALIAS','MTA_BCC','MTA_TRANSPORT','MTA_SIEVE','LOADED_IDENTITY','FRAME_ENCODING','FRAME_DECODING','ACTION']);
      const code=match&&known.has(match[1])?match[1]:'CHILD_REFUSED';
      if (failed || status !== 0) {
        emit('CHILD_REFUSED',{status,signal:signal || null,stdout_bytes:size,stderr_bytes:stderrBytes,stderr_sha256:hash(errorBytes),eof:true,category:code});reject(new Refused(code));
      }
      else {emit('CHILD_COMPLETED',{status,signal:signal||null,stdout_bytes:size,stderr_bytes:stderrBytes,stderr_sha256:hash(errorBytes),eof:true,category:stderrBytes?(code==='CHILD_REFUSED'?'UNRECOGNIZED_CHILD_STDERR':code):'NONE'});resolve(Buffer.concat(stdout));}
    });
    p.stdin.on('error',()=>{}); p.stdin.end(input);
  });
}

// Root shell contains only fixed operations. Dynamic secrets are hex-generated
// assignments supplied in this process's private SSH stdin, never command args.
function remoteScript(action, secretLines = '', policyLines = '') {
  const row = "SHA2(CONCAT_WS(CHAR(0),HEX(username),HEX(password),HEX(name),HEX(maildir),HEX(quota),HEX(local_part),HEX(domain),HEX(created),HEX(modified),HEX(active),HEX(phone),HEX(email_other),HEX(token),HEX(token_validity),HEX(password_expiry),IF(totp_secret IS NULL,'NULL',CONCAT('VALUE',HEX(totp_secret))),HEX(smtp_active)),256)";
  const exclusions = USERS.map(v=>`'${v}'`).join(',');
  return `set +x
set +v
set +a
set -eu
umask 077
ulimit -c 0
stage='${STAGE}'
action='${action}'
fail() { print -u2 -- "RECOVERY_NATIVE_REFUSED:$1"; exit 1; }
test "$(id -u)" = 0 && test "$(hostname)" = '${DOMAIN}' || fail IDENTITY
test "$(sha256 -q /usr/local/bin/osmap)" = '${webHash}' || fail WEB_BINDING
test "$(sha256 -q /usr/local/libexec/osmap/account-passwd)" = '${helperHash}' || fail HELPER_BINDING
sql() { printf '%s\\n' "$query" | /usr/local/bin/mariadb --protocol=SOCKET --socket=/var/run/mysql/mysql.sock -N -B --raw --database=postfixadmin; }
rows() {
 query="SET SESSION group_concat_max_len=65536; SELECT CONCAT(COUNT(*),'|',COALESCE(GROUP_CONCAT(${row} ORDER BY BINARY username SEPARATOR ''),'')) FROM mailbox WHERE BINARY username NOT IN (${exclusions});"
 value=$(sql) || fail OLD_ROWS_READ
 count=\${value%%'|'*}; digests=\${value#*'|'}
 case "$count:$digests" in (*[!0-9a-f:]*|'') fail OLD_ROWS_SHAPE;; esac
 test "$count" -le 128 && test "\${#digests}" -eq "$((count*64))" || fail OLD_ROWS_BOUND
 printf '%s' "$value" | sha256 -q
}
pending_absent() {
 for record in /var/db/osmap-account/epoch/*.json; do
  test -f "$record" || continue
  if grep -Eq '"state"[[:space:]]*:[[:space:]]*"pending"' "$record"; then fail PENDING_OPERATION; fi
 done
}
ready() {
 tick=0
 while test "$tick" -lt 20; do
  code=$(/usr/local/bin/curl --max-time 2 -s -o /dev/null -w '%{http_code}' https://${DOMAIN}/login || :)
  test "$code" != 200 || return 0
  tick=$((tick+1)); sleep 1
 done
 fail HTTPS_READINESS
}
stop_services() {
 : > "$stage/services-stopping"
 /usr/bin/timeout -k 2 25 /usr/sbin/rcctl stop osmap_serve >/dev/null || fail WEB_STOP
 pending_absent
 /usr/bin/timeout -k 2 25 /usr/sbin/rcctl stop osmap_account_password >/dev/null || fail HELPER_STOP
}
start_services() {
 /usr/bin/timeout -k 2 25 /usr/sbin/rcctl start osmap_account_password >/dev/null || fail HELPER_START
 tick=0
 while test "$tick" -lt 10; do
  if test -S /var/run/osmap-account-admission/admission.sock && test -S /var/run/osmap-account-mutation/mutation.sock; then break; fi
  tick=$((tick+1)); sleep 1
 done
 test "$tick" -lt 10 || fail HELPER_SOCKETS
 /usr/bin/timeout -k 2 25 /usr/sbin/rcctl start osmap_serve >/dev/null || fail WEB_START
 ready
 helper_pid=$(pgrep -U0 -u0 -xf '^/usr/local/libexec/osmap/account-passwd$') || fail LOADED_IDENTITY
 web_pid=$(pgrep -U1001 -u1001 -xf '^/usr/local/bin/osmap serve$') || fail LOADED_IDENTITY
 case "$helper_pid:$web_pid" in (*[!0-9:]*|'') fail LOADED_IDENTITY;; esac
 for pair in "$helper_pid /usr/local/libexec/osmap/account-passwd" "$web_pid /usr/local/bin/osmap"; do
  set -- $pair
  /usr/bin/fstat -p "$1" "$2" > "$stage/loaded-text.current" || fail LOADED_IDENTITY
  awk -v p="$1" -v i="$(stat -f '%i' "$2")" 'NR>1 && $3==p && $4=="text" && $6==i {ok=1} END {exit(!ok)}' "$stage/loaded-text.current" || fail LOADED_IDENTITY
 done
 /usr/bin/fstat -p "$helper_pid" > "$stage/loaded-sockets.current" || fail LOADED_IDENTITY
 for socket in /var/run/osmap-account-admission/admission.sock /var/run/osmap-account-mutation/mutation.sock; do
  grep -Fq "$socket" "$stage/loaded-sockets.current" || fail LOADED_IDENTITY
 done
 rm "$stage/services-stopping" || fail LOADED_IDENTITY
}
local_route() {
 test "$(/usr/local/sbin/postconf -h mydestination)" = localhost && test "$(/usr/local/sbin/postconf -h virtual_mailbox_domains)" = '${DOMAIN}' && test "$(/usr/local/sbin/postconf -h virtual_transport)" = lmtp:unix:private/dovecot-lmtp || fail MTA_ROUTE
 test "$(/usr/local/sbin/postconf -h virtual_mailbox_maps)" = mysql:/etc/postfix/mysql_virtual_mailbox_maps.cf && test "$(/usr/local/sbin/postconf -h virtual_mailbox_base)" = /var/vmail && test "$(/usr/local/sbin/postconf -h virtual_uid_maps)" = static:2000 && test "$(/usr/local/sbin/postconf -h virtual_gid_maps)" = static:2000 || fail MTA_ROUTE
 for option in virtual_alias_maps virtual_alias_domains; do value=$(/usr/local/sbin/postconf -h "$option") || fail MTA_ALIAS; test -z "$value" || fail MTA_ALIAS; done
 for option in always_bcc recipient_bcc_maps sender_bcc_maps content_filter lmtp_generic_maps canonical_maps recipient_canonical_maps; do value=$(/usr/local/sbin/postconf -h "$option") || fail MTA_BCC; test -z "$value" || fail MTA_BCC; done
 test "$(/usr/local/sbin/postconf -h transport_maps)" = hash:/etc/postfix/backup_transport || fail MTA_TRANSPORT
 # Match transport(5): bare parents apply only in its configured legacy mode.
 parent_tokens=$(/usr/local/sbin/postconf -h parent_domain_matches_subdomains) || fail MTA_TRANSPORT
 parent_tokens=$(printf '%s' "$parent_tokens" | tr ',\\t\\n' '   ')
 route_absent() {
  # postmap -q returns1 for no result; a diagnostic is a lookup refusal.
  if value=$(/usr/local/sbin/postmap -q "$1" hash:/etc/postfix/backup_transport 2>&1); then fail MTA_TRANSPORT; else status=$?; fi
  test "$status" = 1 && test -z "$value" || fail MTA_TRANSPORT
 }
 for key in '${PRIMARY}' '${A}' '${B}' '${DOMAIN}' '.${DOMAIN}' '.blackbagsecurity.com' '.com' '*'; do route_absent "$key"; done
 case " $parent_tokens " in (*" transport_maps "*) for key in blackbagsecurity.com com; do route_absent "$key"; done;; esac
 test "$(/usr/local/bin/doveconf -h -f protocol=lmtp mail_plugins | tr -d ' \t')" = sieve || fail MTA_SIEVE
 test "$(/usr/local/bin/doveconf -h plugin/sieve)" = 'file:~/sieve;active=~/.dovecot.sieve' && test "$(/usr/local/bin/doveconf -h plugin/sieve_before)" = /etc/dovecot/sieve-before || fail MTA_SIEVE
 for option in plugin/sieve_after plugin/sieve_default plugin/sieve_global_path; do value=$(/usr/local/bin/doveconf -h "$option") || fail MTA_SIEVE; test -z "$value" || fail MTA_SIEVE; done
 test ! -L /etc/dovecot/sieve-before && test -d /etc/dovecot/sieve-before || fail MTA_SIEVE
 entries=0
 for entry in /etc/dovecot/sieve-before/* /etc/dovecot/sieve-before/.[!.]* /etc/dovecot/sieve-before/..?*; do
  test ! -L "$entry" || fail MTA_SIEVE
  test -e "$entry" || continue
  test -f "$entry" || fail MTA_SIEVE
  case "$entry" in (/etc/dovecot/sieve-before/10-rspamd-quarantine.sieve|/etc/dovecot/sieve-before/10-rspamd-quarantine.svbin) ;; (*) fail MTA_SIEVE;; esac
  entries=$((entries+1))
 done
 test "$entries" = 2 || fail MTA_SIEVE
 test "$(sha256 -q /etc/dovecot/sieve-before/10-rspamd-quarantine.sieve)" = fbf04d54c65c5b9c595e9650c852d9c59f71fbd812d0d9f0f5e63b8bf91c138f && test "$(sha256 -q /etc/dovecot/sieve-before/10-rspamd-quarantine.svbin)" = 582170ab145d46c66ede6995ddb3838210ea067957b6225e7984834d5864a571 || fail MTA_SIEVE
 for local in s04-03-primary-20261026-01 s04-03-proof-a-20261026-01 s04-03-proof-b-20261026-01; do
  account="$local@${DOMAIN}"; home="/var/vmail/${DOMAIN}/$local/"
  actual_home=$(/usr/local/bin/doveadm user -f home "$account") || fail MTA_ROUTE
  actual_mail=$(/usr/local/bin/doveadm user -f mail "$account") || fail MTA_ROUTE
  test "\${actual_home%/}/" = "$home" && test "\${actual_mail%/}/" = "maildir:$home" && test "$(/usr/local/bin/doveadm user -f uid "$account")" = 2000 && test "$(/usr/local/bin/doveadm user -f gid "$account")" = 2000 || fail MTA_ROUTE
  test ! -L "$home" && test "$(stat -f '%u:%g:%p' "$home")" = 2000:2000:40700 || fail MTA_ROUTE
  for leaf in .forward .dovecot.sieve sieve; do test ! -e "$home$leaf" && test ! -L "$home$leaf" || fail MTA_SIEVE; done
 done
}
session_hashes() {
 count=0
 for file in /var/lib/osmap-s04-02/state/sessions/*.session; do
  test -f "$file" || continue
  test ! -L "$file" || fail SESSION_CUSTODY
  name=\${file##*/}; count=$((count+1)); test "$count" -le 256 || fail SESSION_BOUND
  leaf=\${name%.session}; test "$name" = "$leaf.session" && test "\${#leaf}" = 64 || fail SESSION_SHAPE
  case "$leaf" in (*[!0-9a-f]*|'') fail SESSION_SHAPE;; esac
  { exec 8< "$file"; } 2>/dev/null || fail SESSION_CUSTODY
  sum=$(awk '!/^last_seen_at=/' <&8 | sha256 -q) || fail SESSION_CUSTODY
  printf '%s %s\\n' "$name" "$sum"
 done
}
session_check() {
 while read -r name expected; do
  leaf=\${name%.session}; test "$name" = "$leaf.session" && test "\${#leaf}" = 64 && test "\${#expected}" = 64 || return 1
  case "$leaf:$expected" in (*[!0-9a-f:]*|'') return 1;; esac
  file="/var/lib/osmap-s04-02/state/sessions/$name"
  test ! -L "$file" && test -f "$file" || return 1
  { exec 8< "$file"; } 2>/dev/null || return 1
  test "$(awk '!/^last_seen_at=/' <&8 | sha256 -q)" = "$expected" || return 1
 done < "$stage/session-authority.before"
}
${secretLines}
${policyLines}
case "$action" in
prepare)
 pending_absent
 test ! -e "$stage" && test ! -L "$stage" || fail STAGE_EXISTS
 mkdir -m 700 "$stage" || fail STAGE_CREATE
 cp -p /etc/osmap/account-admission.json "$stage/admission.before"
 cp -p /etc/osmap/account-runtime/config.json "$stage/mutation.before"
 rows > "$stage/rows.before"
 : > "$stage/protected.before"
 for directory in /var/db/osmap-account/epoch /var/lib/osmap-s04-02/keys /var/lib/osmap-s04-02/state/secrets/totp /var/lib/osmap-s04-02/state/settings/recovery-contact-v1; do
  test ! -L "$directory" || fail PROTECTED_DIRECTORY
  if test -d "$directory"; then find "$directory" -type f -exec sha256 {} \\; >> "$stage/protected.before"; fi
 done
 session_hashes > "$stage/session-authority.before"
 query="SELECT COUNT(*) FROM mailbox WHERE BINARY username IN (${exclusions}); SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA='postfixadmin' AND EVENT_OBJECT_TABLE='mailbox';"
 test "$(sql)" = '0
0' || fail FRESH_ROWS_OR_TRIGGER
 for local in s04-03-primary-20261026-01 s04-03-proof-a-20261026-01 s04-03-proof-b-20261026-01; do
  test ! -e "/var/vmail/${DOMAIN}/$local" && test ! -L "/var/vmail/${DOMAIN}/$local" || fail FRESH_MAILDIR
 done
 for file in /var/db/osmap-account/epoch/${epoch(PRIMARY)}.json /var/db/osmap-account/epoch/${epoch(PRIMARY)}.lock /var/db/osmap-account/epoch/${epoch(PRIMARY)}.uncertain; do test ! -e "$file" && test ! -L "$file" || fail FRESH_EPOCH; done
 for file in /var/lib/osmap-s04-02/state/secrets/totp/${Buffer.from(PRIMARY).toString('hex')}.totp /var/lib/osmap-s04-02/state/cache/totp-replay/${Buffer.from(PRIMARY).toString('hex')}.counter; do test ! -e "$file" && test ! -L "$file" || fail FRESH_FACTOR; done
 for file in /var/lib/osmap-s04-02/state/settings/recovery-contact-v1/${contactStem}.json /var/lib/osmap-s04-02/state/settings/recovery-contact-v1/${contactStem}.lock; do test ! -e "$file" && test ! -L "$file" || fail FRESH_CONTACT; done
 encoded=$(/usr/bin/openssl base64 -A -in "$stage/admission.before") || fail FRAME_ENCODING
 printf 'POLICY_A %s\\n' "$encoded"
 encoded=$(/usr/bin/openssl base64 -A -in "$stage/mutation.before") || fail FRAME_ENCODING
 printf 'POLICY_B %s\\n' "$encoded"
 ;;
provision)
 test -d "$stage" && test ! -L "$stage" || fail STAGE_CUSTODY
 test ! -e "$stage/birth-dispatched" || fail BIRTH_ALREADY_DISPATCHED
 cmp -s "$stage/admission.before" /etc/osmap/account-admission.json && cmp -s "$stage/mutation.before" /etc/osmap/account-runtime/config.json || fail POLICY_DRIFT
 hashes=''
 for pw in "$pw1" "$pw2" "$pw3"; do
  h=$(printf '%s\\n%s\\n' "$pw" "$pw" | /usr/local/bin/doveadm -O pw -s ARGON2ID) || fail INITIAL_HASH
  case "$h" in ('{ARGON2ID}$argon2id$'*) ;; (*) fail INITIAL_HASH_SCHEME;; esac
  hashes="$hashes $h"
 done
 set -f; set -- $hashes; test "$#" = 3 || fail INITIAL_HASH_COUNT
 : > "$stage/birth-dispatched"
 query="START TRANSACTION; INSERT INTO mailbox (username,password,name,maildir,local_part,domain,created,modified,active,smtp_active) VALUES ('${PRIMARY}','$1','recovery fixture','${DOMAIN}/s04-03-primary-20261026-01/','s04-03-primary-20261026-01','${DOMAIN}',UTC_TIMESTAMP(),UTC_TIMESTAMP(),1,1),('${A}','$2','recovery fixture','${DOMAIN}/s04-03-proof-a-20261026-01/','s04-03-proof-a-20261026-01','${DOMAIN}',UTC_TIMESTAMP(),UTC_TIMESTAMP(),1,1),('${B}','$3','recovery fixture','${DOMAIN}/s04-03-proof-b-20261026-01/','s04-03-proof-b-20261026-01','${DOMAIN}',UTC_TIMESTAMP(),UTC_TIMESTAMP(),1,1); SELECT ROW_COUNT(); COMMIT;"
 test "$(sql)" = 3 || fail INITIAL_ROWS_UNCONFIRMED
 test -d /var/vmail && test ! -L /var/vmail || fail MAIL_ROOT
 if test ! -e /var/vmail/${DOMAIN}; then mkdir -m 700 /var/vmail/${DOMAIN}; chown 2000:2000 /var/vmail/${DOMAIN}; fi
 test -d /var/vmail/${DOMAIN} && test ! -L /var/vmail/${DOMAIN} || fail MAIL_DOMAIN
 for local in s04-03-primary-20261026-01 s04-03-proof-a-20261026-01 s04-03-proof-b-20261026-01; do
  d="/var/vmail/${DOMAIN}/$local"; mkdir -m 700 "$d" || fail MAILDIR_EXISTS
  mkdir -m 700 "$d/cur" "$d/new" "$d/tmp"
  chown 2000:2000 "$d/cur" "$d/new" "$d/tmp"; chown 2000:2000 "$d"
 done
 (set -C; printf '%s\\n' '{"epoch":0,"state":"active","changed_at":null,"intent":null,"used_intents":[]}' > /var/db/osmap-account/epoch/${epoch(PRIMARY)}.json; : > /var/db/osmap-account/epoch/${epoch(PRIMARY)}.lock; printf '%s\\n' 'secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' > /var/lib/osmap-s04-02/state/secrets/totp/${Buffer.from(PRIMARY).toString('hex')}.totp)
 chown 1001:1001 /var/lib/osmap-s04-02/state/secrets/totp/${Buffer.from(PRIMARY).toString('hex')}.totp
 printf '%s' "$policy_a" | /usr/bin/openssl base64 -d -A > "$stage/admission.published" || fail FRAME_DECODING
 printf '%s' "$policy_b" | /usr/bin/openssl base64 -d -A > "$stage/mutation.published" || fail FRAME_DECODING
 stop_services
 cp -p "$stage/admission.published" /etc/osmap/account-admission.json
 cp -p "$stage/mutation.published" /etc/osmap/account-runtime/config.json
 start_services
 local_route
 print PROVISIONED
 ;;
clock)
 date +%s
 ;;
state)
 file=/var/lib/osmap-s04-02/state/settings/recovery-contact-v1/${contactStem}.json
 test ! -L "$file" && test "$(stat -f '%u:%p:%l' "$file")" = 1001:100600:1 || fail CONTACT_CUSTODY
 test "$(wc -c < "$file")" -le 16384 || fail CONTACT_BOUND
 cat "$file"
 ;;
proof-a|proof-b|notice-a|notice-b)
 case "$action" in (proof-a|notice-a) local=s04-03-proof-a-20261026-01;; (*) local=s04-03-proof-b-20261026-01;; esac
 case "$action" in (proof-*) subject='Verify your OSMAP recovery contact';; (notice-a) subject='OSMAP recovery contact replaced';; (*) subject='OSMAP recovery contact removed';; esac
 count=0; scanned=0; digests=''
 for directory in /var/vmail/${DOMAIN}/"$local" /var/vmail/${DOMAIN}/"$local"/new /var/vmail/${DOMAIN}/"$local"/cur /var/vmail/${DOMAIN}/"$local"/.Junk /var/vmail/${DOMAIN}/"$local"/.Junk/new /var/vmail/${DOMAIN}/"$local"/.Junk/cur; do test ! -L "$directory" || fail MAIL_SYMLINK; done
 for file in /var/vmail/${DOMAIN}/"$local"/new/* /var/vmail/${DOMAIN}/"$local"/cur/* /var/vmail/${DOMAIN}/"$local"/.Junk/new/* /var/vmail/${DOMAIN}/"$local"/.Junk/cur/*; do
  test -f "$file" || continue
  test ! -L "$file" || fail MAIL_SYMLINK
  scanned=$((scanned+1)); test "$scanned" -le 16 && test "$(wc -c < "$file")" -le 65536 || fail MAIL_BOUND
  digests="$digests$(sha256 -q "$file")"
  if grep -Fq "Subject: $subject" "$file"; then count=$((count+1)); test "$(wc -c < "$file")" -le 65536 || fail MAIL_BOUND; encoded=$(/usr/bin/openssl base64 -A -in "$file") || fail FRAME_ENCODING; printf 'MESSAGE %s\\n' "$encoded"; fi
 done
 max=1; test "$action" != proof-a || max=2
 test "$count" -le "$max" || fail AMBIGUOUS_MAIL
 printf 'OBSERVATION %s %s %s\\n' "$scanned" "$count" "$(printf '%s' "$digests" | sha256 -q)"
 ;;
final|restore)
 test -d "$stage" && test ! -L "$stage" || fail STAGE_ABSENT
 if test "$action" = restore; then
  changed=0
  for pair in 'admission /etc/osmap/account-admission.json' 'mutation /etc/osmap/account-runtime/config.json'; do
   set -- $pair
   if cmp -s "$stage/$1.before" "$2"; then continue; fi
   test -f "$stage/$1.published" && cmp -s "$stage/$1.published" "$2" || fail POLICY_UNEXPECTED
   changed=1
  done
  if test "$changed" = 1 || test -e "$stage/services-stopping"; then
   stop_services
   cp -p "$stage/admission.before" /etc/osmap/account-admission.json
   cp -p "$stage/mutation.before" /etc/osmap/account-runtime/config.json
   start_services
  fi
  cmp -s "$stage/admission.before" /etc/osmap/account-admission.json && cmp -s "$stage/mutation.before" /etc/osmap/account-runtime/config.json || fail POLICY_RESTORE
  print RESTORATION_PASS
 fi
 preservation=PASS
 test "$(rows)" = "$(cat "$stage/rows.before")" || preservation=OLD_ROWS_CHANGED
 if ! sha256 -q -c "$stage/protected.before" >/dev/null; then preservation=OLD_FILES_CHANGED; fi
 if ! session_check; then preservation=SESSION_CHANGED; fi
 if test "$preservation" = PASS; then print PRESERVATION_PASS; else print "PRESERVATION_FAIL:$preservation"; fi
 ;;
*) fail ACTION;;
esac
`;
}

async function root(action, extra = '', policies = '', end = bodyEnd) {
  const seconds = Math.max(1, Math.floor(remaining(end)/1000));
  return child('/usr/bin/ssh',['-S','none','-i','/home/foo/.ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',`foo@192.168.1.44`,`doas -n /usr/bin/timeout -k 2 ${seconds} /bin/ksh -s`],remoteScript(action,extra,policies),end);
}
async function request(method, body = '', path = '/settings/recovery') {
  const value = await new Promise((resolve,reject)=>{
    // Ordinary recovery actions retain their native sixty-second deadline.
    const budget=Math.min(65000,remaining());
    let timer;
    const req=https.request({hostname:DOMAIN,path,method,headers:{'User-Agent':'OSMAP-fixed-recovery-native-01','Origin':`https://${DOMAIN}`,...(cookie?{Cookie:cookie}:{}),...(method==='POST'?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}:{})}},res=>{
      let data=[],size=0;res.on('data',b=>{size+=b.length;if(size>1048576)req.destroy();else data.push(b);});
      res.on('end',()=>{clearTimeout(timer);resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(data).toString('utf8')});});res.on('error',()=>{clearTimeout(timer);reject(new Refused('HTTP_RESPONSE'));});
    });
    timer=setTimeout(()=>req.destroy(),budget);req.on('error',()=>{clearTimeout(timer);reject(new Refused('HTTP_REQUEST'));});req.end(body);
  });
  requests++; requireThat(!password || !value.body.includes(password),'PASSWORD_ECHO'); emit('HTTP',{method,status:value.status}); return value;
}
function fields(body) {
  const all=name=>[...body.matchAll(new RegExp(`name="${name}" value="([^"]*)"`,'g'))].map(m=>m[1]);
  const csrf=[...new Set(all('csrf_token'))],revision=[...new Set(all('revision'))];
  requireThat(csrf.length===1 && /^[a-f0-9]{64}$/.test(csrf[0]) && revision.length===1 && /^\d+$/.test(revision[0]),'FORM_FIELDS');
  return {csrf_token:csrf[0],revision:revision[0]};
}
async function post(page, action, extras) {
  const next=await request('POST',new URLSearchParams({...fields(page.body),action,...extras}).toString());
  requireThat(next.status===200,'ACTION_REFUSED');requireThat(Number(fields(next.body).revision)===Number(fields(page.body).revision)+1,'REVISION_NOT_ADVANCED');return next;
}
async function stored(end=bodyEnd) { return JSON.parse(String(await root('state','','',end))); }
async function nativeNow() {const value=String(await root('clock'));requireThat(/^[0-9]{1,12}\n$/.test(value),'CLOCK_OBSERVATION');return Number(value.trim());}
function verifiedTime(state,page,lower,upper) {const stamp=state.verified?.verified_at;requireThat(Number.isSafeInteger(stamp)&&stamp>=lower&&stamp<=upper&&page.body.includes(new Date(stamp*1000).toISOString().replace('.000Z','Z')),'VERIFIED_TIME');}
async function mail(kind, expectedDigest, expectedExpiry, expectedCount = 1) {
  let observation;
  const end=Math.min(bodyEnd,performance.now()+20000);
  while(performance.now()<end) {
    const wire=String(await root(kind));
    const lines=wire.trim().split('\n');
    const metadata=lines.pop()?.match(/^OBSERVATION ([0-9]{1,2}) ([0-9]) ([a-f0-9]{64})$/);requireThat(metadata && Number(metadata[1])<=16 && Number(metadata[2])===lines.length,'MAIL_OBSERVATION');
    observation={candidate_files:Number(metadata[1]),subject_matches:Number(metadata[2]),mailbox_sha256:metadata[3]};
    if(lines.length) {
      const recipient=(kind.endsWith('a')?A:B);
      const frames=lines;requireThat(frames.length===expectedCount,'MAIL_COUNT');
      let selected=[];
      for(const frame of frames) {
        const encoded=frame.match(/^MESSAGE ([A-Za-z0-9+/=]+)$/);requireThat(encoded,'MAIL_FRAME');
        const message=Buffer.from(encoded[1],'base64').toString('utf8').replaceAll('\r\n','\n');
        requireThat(message.includes(`From: ${PRIMARY}\n`) && message.includes(`To: ${recipient}\n`) && /^Return-Path: <>$/m.test(message) && /^Auto-Submitted: auto-generated$/m.test(message) && /^X-Auto-Response-Suppress: All$/m.test(message),'MAIL_IDENTITY');
        const body=message.split('\n\n').slice(1).join('\n\n');
        if(expectedDigest) {
          const match=body.match(/\n\n([a-f0-9]{64})\n\nExpires at Unix time ([0-9]+)\./);requireThat(match,'MAIL_PROOF_SHAPE');
          if(hash(Buffer.from('osmap-recovery-contact-proof-v1\0'+PRIMARY+'\0'+match[1]))===expectedDigest){requireThat(match[2]===String(expectedExpiry),'MAIL_EXPIRY');selected.push(match[1]);}
        } else {requireThat(!/[a-f0-9]{64}/.test(body) && !body.includes(password),'NOTICE_PRIVATE');selected.push('');}
      }
      requireThat(selected.length===1,'MAIL_CURRENT_PROOF');return selected[0];
    }
    await pause(Math.min(500,remaining()));
  }
  emit('MAIL_NOT_OBSERVED',observation || {});throw new Refused('MAIL_DELIVERY_NOT_OBSERVED');
}
async function main() {
  requireThat(hash(fs.readFileSync(TOTP_SOURCE))===TOTP_SHA && fixtureCode(1)==='287082','MAINTAINED_TOTP_BINDING');
  if(process.argv[2]==='--check-tools' && process.argv.length===3) { emit('TOOLS_PASS_NO_TRAFFIC');return; }
  requireThat(process.argv.length===5 && process.argv[2]==='--run' && /^[a-f0-9]{64}$/.test(process.argv[3]) && /^[a-f0-9]{64}$/.test(process.argv[4]),'PUBLIC_ARTIFACT_ARGUMENTS');
  [webHash,helperHash]=process.argv.slice(3);began=performance.now();bodyEnd=began+420000;totalEnd=began+600000;
  const declaration=JSON.parse(String(await child('/usr/bin/python3',['-B','/home/foo/Workspace/OSMAP/maint/ux/validate_acceptance.py','--repo','/home/foo/Workspace/OSMAP','--work-order-only'],'',bodyEnd,8192)));
  requireThat(declaration.active_slice==='S04-03'&&declaration.state==='IN_PROGRESS','ACTIVE_WORK_ORDER');
  fs.mkdirSync(OUT,{mode:0o700}); // Exclusive: never adopt a previous operation.
  let cleanup='NOT_STARTED',cleanupFailure='NONE',failure='NONE',preservation='NOT_CONFIRMED',persistence='NOT_CONFIRMED',removedRevision;
  try {
    phase='prepare';const policies=String(await root('prepare'));requireThat(/^POLICY_A [A-Za-z0-9+/=]+\nPOLICY_B [A-Za-z0-9+/=]+\n$/.test(policies),'ACCOUNT_POLICY_FRAME');
    const parse=label=>JSON.parse(Buffer.from(policies.match(new RegExp(`^${label} ([A-Za-z0-9+/=]+)$`,'m'))?.[1]||'','base64').toString('utf8'));
    const admission=parse('POLICY_A'),mutation=parse('POLICY_B');
    requireThat(Array.isArray(admission.accounts)&&Array.isArray(mutation.accounts)&&JSON.stringify([...admission.accounts].sort())===JSON.stringify([...mutation.accounts].sort())&&!admission.accounts.includes(PRIMARY)&&admission.accounts.length<64,'ACCOUNT_POLICY');
    prepared=true;
    admission.accounts.push(PRIMARY);mutation.accounts.push(PRIMARY);
    const ps=[0,1,2].map(()=>crypto.randomBytes(32).toString('hex'));password=ps[0];
    const secret=ps.map((v,i)=>`pw${i+1}='${v}'`).join('\n');
    const policy=`policy_a='${Buffer.from(JSON.stringify(admission)).toString('base64')}'\npolicy_b='${Buffer.from(JSON.stringify(mutation)).toString('base64')}'`;
    phase='provision';await root('provision',secret,policy);provisioned=true;emit('THREE_FRESH_ROWS_PRIMARY_ENROLLED');
    phase='login';requireThat((await request('GET','','/login')).status===200,'LOGIN_PAGE');
    const login=await request('POST',new URLSearchParams({username:PRIMARY,password,totp_code:await freshCode()}).toString(),'/login');
    requireThat(login.status===303,'MFA_LOGIN');const cookies=login.headers['set-cookie']||[];const session=cookies.filter(v=>v.startsWith('osmap_session='));
    requireThat(session.length===1 && /;\s*Secure/i.test(session[0]) && /;\s*HttpOnly/i.test(session[0]),'SESSION_COOKIE');cookie=session[0].split(';')[0];
    let page=await request('GET');requireThat(page.status===200 && page.body.includes('No verified recovery contact'),'INITIAL_EMPTY');
    phase='begin_a';page=await post(page,'begin',{email:A,current_password:password,totp_code:await freshCode()});let sent=performance.now();
    let state=await stored();requireThat(!state.verified&&state.pending.email===A&&state.pending.delivery==='Accepted','PENDING_A');
    const firstToken=await mail('proof-a',state.pending.token_digest,state.pending.token_expires_at);
    while(performance.now()<sent+61000) await pause(Math.min(250,remaining()));
    phase='resend_a';page=await post(page,'resend',{current_password:password,totp_code:await freshCode()});sent=performance.now();state=await stored();
    requireThat(state.pending?.email===A&&state.pending.delivery==='Accepted','PENDING_RESEND_A');const tokenA=await mail('proof-a',state.pending.token_digest,state.pending.token_expires_at,2);requireThat(tokenA!==firstToken,'RESEND_NOT_ROTATED');
    phase='verify_a';const beforeA=await nativeNow();page=await post(page,'verify',{token:tokenA});const afterA=await nativeNow();requireThat(!page.body.includes(tokenA),'PROOF_ECHO');state=await stored();requireThat(state.verified.email===A&&!state.pending,'VERIFIED_A');verifiedTime(state,page,beforeA,afterA);
    while(performance.now()<sent+61000) await pause(Math.min(250,remaining()));
    phase='begin_b';page=await post(page,'begin',{email:B,current_password:password,totp_code:await freshCode()});
    state=await stored();requireThat(state.verified.email===A&&state.pending.email===B&&state.pending.delivery==='Accepted','OLD_VERIFIED_RETAINED');
    const tokenB=await mail('proof-b',state.pending.token_digest,state.pending.token_expires_at);
    phase='verify_b';const beforeB=await nativeNow();page=await post(page,'verify',{token:tokenB});const afterB=await nativeNow();requireThat(!page.body.includes(tokenB),'PROOF_ECHO');state=await stored();requireThat(state.verified.email===B&&!state.pending&&state.notice.delivery==='Accepted','VERIFIED_B');verifiedTime(state,page,beforeB,afterB);await mail('notice-a',false);
    phase='remove';page=await post(page,'remove',{current_password:password,totp_code:await freshCode()});state=await stored();requireThat(!state.verified&&!state.pending&&state.notice.kind==='Removed'&&state.notice.delivery==='Accepted','REMOVED');removedRevision=state.revision;await mail('notice-b',false);
    phase='final';requireThat(String(await root('final')).trim()==='PRESERVATION_PASS','PRESERVATION');preservation='PASS';complete=true;emit('FUNCTIONAL_PASS',{requests,proof_messages:3,old_notices:2});
  } catch(error) { failure=error instanceof Refused?error.code:'UNEXPECTED_REFUSAL';emit('FUNCTIONAL_REFUSED',{failure}); }
  finally {
    password='';cookie='';phase='restore';
    if(prepared) { try { const final=String(await root('restore','','',totalEnd));requireThat(/^(?:RESTORATION_PASS\n)(?:PRESERVATION_PASS|PRESERVATION_FAIL:(?:OLD_ROWS_CHANGED|OLD_FILES_CHANGED|SESSION_CHANGED))\n$/.test(final),'RESTORATION');cleanup='PASS';preservation=final.includes('PRESERVATION_PASS')?'PASS':'FAIL';if(preservation==='FAIL')emit('PRESERVATION_REFUSED',{category:final.match(/PRESERVATION_FAIL:([A-Z_]+)/)[1]}); } catch(error) {cleanup='UNCERTAIN';cleanupFailure=error instanceof Refused?error.code:'UNEXPECTED_REFUSAL';} }
    if(cleanup==='PASS'&&removedRevision!==undefined){try{const state=await stored(totalEnd);requireThat(state.version===1&&state.account===PRIMARY&&state.revision===removedRevision&&!state.verified&&!state.pending&&state.notice.kind==='Removed'&&state.notice.delivery==='Accepted','PERSISTENCE');persistence='PASS';}catch(error){persistence='FAIL';if(failure==='NONE')failure=error instanceof Refused?error.code:'UNEXPECTED_REFUSAL';emit('PERSISTENCE_REFUSED',{category:failure});}}
    const result={persistence,functional:complete?'PASS':'NOT_CONFIRMED',restoration:cleanup,preservation,failure,cleanup_failure:cleanupFailure,requests,fixture_rows:provisioned?'RETAINED':'INITIALIZATION_UNCERTAIN',password_changes:0,actual_mail_observations:complete?5:0,requested_external_recipients:0,elapsed_ms:Math.ceil(performance.now()-began),observed};
    fs.writeFileSync(`${OUT}/result.json`,JSON.stringify(result,null,2)+'\n',{mode:0o600,flag:'wx'});process.stdout.write(JSON.stringify(result)+'\n');if(!complete||cleanup!=='PASS'||preservation!=='PASS'||persistence!=='PASS')process.exitCode=1;
  }
}
if(require.main===module)main().catch(error=>{process.stdout.write(JSON.stringify({code:'RECOVERY_NATIVE_PREFLIGHT_REFUSED',failure:error instanceof Refused?error.code:'UNEXPECTED_REFUSAL'})+'\n');process.exitCode=1;});
module.exports={remoteScript,fields,main,PRIMARY,A,B,STAGE};
