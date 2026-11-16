#!/usr/bin/env bash
# Pull an age-encrypted ~/.config/jev/env drop from the private archive, decrypt, install, verify.
# Default drop: bitskc/jev-agent-kit-archive drops/cachy-jev-env.age (see honest-jev#20).
#
#   ./scripts/recv-jev-env.sh
#   ./scripts/recv-jev-env.sh --keep-drop --no-doctor
set -euo pipefail
repo="${JEV_DROP_REPO:-bitskc/jev-agent-kit-archive}"
path="${JEV_DROP_PATH:-drops/cachy-jev-env.age}"
identity="${JEV_AGE_IDENTITY:-$HOME/.config/jev/age-identity}"
envfile="${JEV_ENV_FILE:-$HOME/.config/jev/env}"
url_expect="${JEV_MCP_URL_EXPECT:-https://jev-mcp.andy-e3e.workers.dev/mcp}"
delete=1
doctor=1
while [ $# -gt 0 ]; do case "$1" in
  --keep-drop) delete=0;;
  --no-doctor) doctor=0;;
  --identity) identity="$2"; shift;;
  --repo) repo="$2"; shift;;
  --path) path="$2"; shift;;
  -h|--help) sed -n '2,10p' "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;;
esac; shift; done
command -v age >/dev/null || { echo "age not on PATH (install FiloSottile/age)" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh not on PATH" >&2; exit 2; }
[ -f "$identity" ] || { echo "missing age identity: $identity (create with: age-keygen -o $identity)" >&2; exit 2; }
umask 077
mkdir -p "$(dirname "$envfile")"
meta=$(mktemp); cipher=$(mktemp); plain=$(mktemp)
trap 'rm -f "$meta" "$cipher" "$plain"' EXIT
gh api "repos/$repo/contents/$path" >"$meta"
sha=$(python3 - "$meta" "$cipher" <<'PY'
import base64, json, sys
meta, out = sys.argv[1:3]
d = json.load(open(meta))
open(out, "wb").write(base64.b64decode(d["content"]))
print(d["sha"])
PY
)
age -d -i "$identity" -o "$plain" "$cipher"
python3 - "$plain" "$url_expect" <<'PY'
import re, sys
path, url = sys.argv[1:3]
text = open(path).read()
if "JEV_MCP_TOKEN=" not in text or "JEV_MCP_URL=" not in text:
    sys.exit("refusing: decrypted drop missing JEV_MCP_URL/JEV_MCP_TOKEN keys")
if url not in text:
    sys.exit(f"refusing: decrypted drop does not contain expected URL {url}")
if re.search(r"JEV_MCP_TOKEN=''\s*$", text, re.M) or "JEV_MCP_TOKEN=''\n" in text:
    sys.exit("refusing: empty token")
print("shape ok")
PY
cp "$plain" "$envfile"
chmod 0600 "$envfile"
echo "wrote $envfile (0600); contents not printed"
if [ "$delete" = 1 ]; then
  gh api --method DELETE "repos/$repo/contents/$path" \
    -f message="drop: consumed by recv-jev-env.sh on $(hostname -s)" \
    -f sha="$sha" >/dev/null
  echo "deleted $repo:$path"
fi
if [ "$doctor" = 1 ]; then
  set -a
  # shellcheck disable=SC1090
  . "$envfile"
  set +a
  here=$(cd "$(dirname "$0")/.." && pwd)
  if [ -x "$here/install.sh" ]; then
    "$here/install.sh" --doctor
  else
    echo "install.sh not beside this script; run ./install.sh --doctor yourself with the env loaded" >&2
  fi
fi
