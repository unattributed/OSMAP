#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "15-search-reflected-xss"

perform_login cookies.txt login.headers login.body.html
cat > payloads.txt <<'EOF'
WSTGQ1-basic
"><WSTGQ2>
<WSTGQ3 attr="a&b'c">
EOF

i=0
while IFS= read -r payload; do
  i=$((i+1))
  curl -sS -G -o "search-${i}.html" -D "search-${i}.headers" -b cookies.txt -c cookies.txt \
    --data-urlencode "q=${payload}" "${TARGET_BASE_URL}${SEARCH_PATH}"
  printf '\n===== payload %s =====\n%s\n' "$i" "$payload"
  sed -n '1,40p' "search-${i}.headers"
  python3 - "$i" <<'PY'
import sys, pathlib, re
i = sys.argv[1]
html = pathlib.Path(f"search-{i}.html").read_text(errors="ignore")
tokens = ["WSTGQ1", "WSTGQ2", "WSTGQ3"]
for token in tokens:
    pos = html.find(token)
    if pos != -1:
        start = max(0, pos - 220)
        end = min(len(html), pos + 260)
        print(f"\n--- context around {token} ---")
        print(html[start:end])
entities = sorted(set(re.findall(r'&(lt|gt|quot|#39|amp);', html)))
print("\nentities_seen=", entities)
PY
done < payloads.txt

printf '\nSaved in %s\n' "$RUN_DIR"
