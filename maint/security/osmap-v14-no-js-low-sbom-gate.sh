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

js_paths="$(git ls-files | grep -E '\.(js|mjs|cjs|jsx|ts|tsx|wasm)$' || true)"
if [ -n "$js_paths" ]; then
  echo "error: JavaScript, TypeScript, or WASM artifacts are tracked" >&2
  printf '%s\n' "$js_paths" >&2
  exit 2
fi

python3 - <<'PY'
from pathlib import Path
import sys
import tomllib

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
