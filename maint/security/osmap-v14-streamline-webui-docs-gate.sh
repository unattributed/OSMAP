#!/bin/sh
set -eu

failures=0

fail() {
    printf '%s\n' "FAIL: $1" >&2
    failures=$((failures + 1))
}

require_file() {
    if [ ! -f "$1" ]; then
        fail "missing file: $1"
    fi
}

require_pattern() {
    pattern="$1"
    file="$2"
    if ! grep -Eq "$pattern" "$file"; then
        fail "missing pattern '$pattern' in $file"
    fi
}

reject_pattern() {
    pattern="$1"
    file="$2"
    if grep -Eq "$pattern" "$file"; then
        fail "rejected pattern '$pattern' in $file"
    fi
}

V14_DOC="docs/V14_STREAMLINE_WEBUI_OPENPGP_UX.md"
REF_DIR="docs/design/v14-approved-ui-reference"
REF_README="$REF_DIR/README.md"

require_file "$V14_DOC"
require_file "$REF_README"
require_file "$REF_DIR/SHA256SUMS"
require_file "$REF_DIR/main-page-annotated.png"
require_file "$REF_DIR/compose-page-annotated.png"
require_file "$REF_DIR/secure-acct-admin-page-annotated.png"
require_file "docs/README.md"
require_file "docs/DECISION_LOG.md"

if [ -f "$V14_DOC" ]; then
    require_pattern "Protected by Default" "$V14_DOC"
    require_pattern "JavaScript-free" "$V14_DOC"
    require_pattern "server-rendered Rust HTML" "$V14_DOC"
    require_pattern "No JavaScript" "$V14_DOC"
    require_pattern "No Node, npm, Vite, Webpack, React, Vue, Svelte, Alpine, htmx" "$V14_DOC"
    require_pattern "No external icon CDN" "$V14_DOC"
    require_pattern "V12 remains the OpenPGP foundation" "$V14_DOC"
    require_pattern "does not enable decrypt, verify, sign, encrypt" "$V14_DOC"
    require_pattern "Verification does not make content safe" "$V14_DOC"
    require_pattern "Source view remains explicit, escaped, authorized, and bounded" "$V14_DOC"
    require_pattern "docs/design/v14-approved-ui-reference" "$V14_DOC"
    reject_pattern "Safe Mode" "$V14_DOC"
    reject_pattern "cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|<script" "$V14_DOC"
fi

if [ -f "$REF_README" ]; then
    require_pattern "design references only" "$REF_README"
    require_pattern "not loaded by the runtime browser UI" "$REF_README"
    require_pattern "Protected by Default" "$REF_README"
    reject_pattern "Safe Mode" "$REF_README"
    reject_pattern "cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|<script" "$REF_README"
fi

if [ -f "docs/README.md" ]; then
    require_pattern "V14_STREAMLINE_WEBUI_OPENPGP_UX.md" "docs/README.md"
fi

if [ -f "docs/DECISION_LOG.md" ]; then
    require_pattern "V14 Streamline WebUI and OpenPGP UX integration" "docs/DECISION_LOG.md"
fi

if [ -d "$REF_DIR" ]; then
    (cd "$REF_DIR" && sha256sum -c SHA256SUMS) >/dev/null || fail "approved UI reference image checksum verification failed"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "v14 streamline webui docs gate failed: $failures failure(s)" >&2
    exit 1
fi

printf '%s\n' "v14 streamline webui docs gate passed"
