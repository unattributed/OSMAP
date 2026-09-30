#!/bin/sh
set -eu

require_file() {
  file="$1"
  if [ ! -f "$file" ]; then
    echo "error: missing required file: ${file}" >&2
    exit 2
  fi
}

require_pattern() {
  file="$1"
  pattern="$2"
  description="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "error: missing ${description} in ${file}" >&2
    echo "pattern: ${pattern}" >&2
    exit 2
  fi
}

reject_pattern() {
  file="$1"
  pattern="$2"
  description="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "error: unexpected ${description} in ${file}" >&2
    echo "pattern: ${pattern}" >&2
    exit 2
  fi
}

require_file "docs/V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md"
require_file "maint/security/osmap-v14-no-js-low-sbom-gate.sh"
require_file "Cargo.toml"
require_file "src/http_support.rs"
require_file "src/http_ui.rs"

require_pattern "docs/V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md" "no runtime JavaScript" "no JavaScript boundary"
require_pattern "docs/V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md" "low-SBOM" "low-SBOM boundary"
require_pattern "docs/V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md" "source-aware" "source-aware scan boundary"
require_pattern "docs/V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md" "No OpenPGP runtime capability change" "OpenPGP no-claim boundary"
require_pattern "docs/README.md" "V14_SLICE_9_NO_JAVASCRIPT_LOW_SBOM_GATES.md" "Slice 9 documentation index entry"
require_pattern "Makefile" "osmap-v14-no-js-low-sbom-gate.sh" "Slice 9 v14-check gate registration"
require_pattern "src/http_support.rs" "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" "restrictive browser CSP"

reject_pattern "src/http_support.rs" "script-src" "CSP script allowance"

frontend_paths="$(git ls-files | grep -E '(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|deno\.json|vite\.config\.|webpack\.config\.|rollup\.config\.|gulpfile\.|Gruntfile\.|tsconfig\.json|node_modules/|bower_components/|web_modules/|dist/)' || true)"
if [ -n "$frontend_paths" ]; then
  echo "error: frontend build or package-manager artifacts are tracked" >&2
  printf '%s\n' "$frontend_paths" >&2
  exit 2
fi

js_paths="$(git ls-files --cached --others --exclude-standard | grep -E '\.(js|mjs|cjs|jsx|ts|tsx|wasm)$' | grep -Fvx 'src/http/compose_local.js' || true)"
if [ -n "$js_paths" ]; then
  echo "error: script artifacts outside the exact R2 composer allowance" >&2
  printf '%s\n' "$js_paths" >&2
  exit 2
fi

python3 - <<'PY'
from pathlib import Path
import sys
import tomllib
import base64
import hashlib
import re

# R2 / S03-02: exact compose-only hash plus two literal first-party saves.
script = Path("src/http/compose_local.js").read_bytes()
boundary = Path("src/http/compose_enhancement.rs").read_text()

def validate_compose(script, boundary):
    expected = "sha256-" + base64.b64encode(hashlib.sha256(script).digest()).decode()
    assert re.search(r'const SCRIPT_HASH: &str =\s*"([^"]+)";', boundary).group(1) == expected, "composer script hash drift"
    assert 'include_str!("compose_local.js")' in boundary, "composer source boundary drift"
    assert '"{}; connect-src \'self\'; script-src \'{}\'; script-src-attr \'none\'"' in boundary, "composer CSP drift"
    assert boundary.count("connect-src") == 1, "extra connection directive"
    for forbidden in ["unsafe-eval", "strict-dynamic", "script-src 'self'", "script-src 'unsafe-inline'"]:
        assert forbidden not in boundary, "broad composer CSP allowance"
    text = script.decode()
    for forbidden in ["innerHTML", "outerHTML", "insertAdjacentHTML", "setHTMLUnsafe", "createContextualFragment", "parseFromString", "srcdoc", "document.write", "eval(", "Function(",
                      "XMLHttpRequest", "WebSocket", "EventSource", "WebTransport", "RTCPeerConnection", "sendBeacon", "localStorage", "sessionStorage", "indexedDB",
                      "document.cookie", "import(", "import ", "Worker(", "serviceWorker", "</script"]:
        assert forbidden not in text, f"unexpected composer API: {forbidden}"
    # A capability test grants no alias or call authority. Exactly one probe.
    probe = 'typeof fetch === "function"'
    assert text.count(probe) == 1, "missing or altered exact fetch capability probe"
    text = text.replace(probe, "")
    calls = [
        'fetch("/drafts/autosave", { method: "POST", body: fields, credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store", signal: controller.signal })',
        'fetch("/drafts/autosave/config", { credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store" })',
    ]
    for call in calls:
        pattern = r"\s+".join(re.escape(part) for part in call.split())
        text, count = re.subn(pattern, "", text)
        assert count == 1, "missing or altered exact autosave request"
    assert not re.search(r"\bfetch\b", text), "additional or dynamic fetch API"

validate_compose(script, boundary)
# Negative controls run through the same validator with a valid replacement hash,
# so rejection proves the source boundary rather than merely hash mismatch.
mutations = [
    (script.replace(b'typeof fetch === "function"', b'fetch("/third", {})'), boundary),
    (script.replace(b'typeof fetch === "function"', b'(alias = fetch)'), boundary),
    (script + b'\nconst alias = fetch;', boundary),
    (script + b'\ntypeof fetch === "function";', boundary),
    (script + b'\nfetch("/third", {});', boundary),
    (script.replace(b'"/drafts/autosave/config"', b'destination'), boundary),
    (script, boundary.replace("connect-src 'self'", "connect-src https://example.invalid")),
    (script + b'\nnode.innerHTML = returned;', boundary),
    (script.replace(b'credentials: "same-origin"', b'credentials: "include"'), boundary),
    (script.replace(b'mode: "same-origin"', b'mode: "cors"'), boundary),
    (script.replace(b'redirect: "error"', b'redirect: "follow"'), boundary),
    (script.replace(b'cache: "no-store"', b'cache: "default"'), boundary),
]
for altered, policy in mutations:
    digest = "sha256-" + base64.b64encode(hashlib.sha256(altered).digest()).decode()
    policy = re.sub(r'(const SCRIPT_HASH: &str =\s*")[^"]+(";)', lambda m: m[1] + digest + m[2], policy)
    try:
        validate_compose(altered, policy)
    except AssertionError:
        continue
    raise AssertionError("negative composer source control unexpectedly accepted")
print(f"composer source/CSP negative controls passed: {len(mutations)}")
allowed_callers = {"src/http/routes_compose.rs", "src/http/routes_draft.rs"}
for path in Path("src").rglob("*.rs"):
    production = path.read_text().split("\n#[cfg(test)]", 1)[0]
    if "compose_enhancement::response(" in production:
        assert str(path) in allowed_callers, f"scripted response escaped composer: {path}"

runtime_files = [Path("src/http_ui.rs"), Path("src/http_support.rs")]
patterns = [
    ("<script", "script tag"),
    ("</script", "script closing tag"),
    ("javascript:", "javascript URL"),
    (" onload=", "inline onload handler"),
    (" onclick=", "inline onclick handler"),
    (" onerror=", "inline onerror handler"),
    (" onmouseover=", "inline onmouseover handler"),
    (" onfocus=", "inline onfocus handler"),
    (" onchange=", "inline onchange handler"),
    (" oninput=", "inline oninput handler"),
    (" onsubmit=", "inline onsubmit handler"),
    ("<link", "HTML link tag"),
    ("src=\\\"http", "remote asset source"),
    ("href=\\\"http", "remote runtime link"),
]

for path in runtime_files:
    text = path.read_text(encoding="utf-8")
    # Keep the scan focused on production source. Test modules and doctests in this
    # project deliberately contain hostile examples such as javascript: and <script>.
    production = text.split("\n#[cfg(test)]", 1)[0]
    lower = production.lower()
    for needle, description in patterns:
        if needle in lower:
            print(f"error: {description} found in production UI source: {path}: {needle}", file=sys.stderr)
            sys.exit(2)

data = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))
deps = data.get("dependencies", {})
max_dependencies = 9
if len(deps) > max_dependencies:
    print(
        f"error: Cargo.toml dependency count {len(deps)} exceeds low-SBOM threshold {max_dependencies}",
        file=sys.stderr,
    )
    sys.exit(2)

frontend_crates = {
    "wasm-bindgen",
    "web-sys",
    "js-sys",
    "yew",
    "leptos",
    "dioxus",
    "gloo",
    "seed",
    "sycamore",
}
found = sorted(frontend_crates.intersection(deps.keys()))
if found:
    print("error: frontend/browser framework crates are present: " + ", ".join(found), file=sys.stderr)
    sys.exit(2)
PY

echo "v14 no-JavaScript and low-SBOM gate passed"
