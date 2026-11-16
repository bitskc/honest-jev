#!/usr/bin/env bash
# Encrypt a jev env file to cachy's age recipient and upload ciphertext to the private archive.
# For senders that cannot SSH to the target host (honest-jev#20).
#
#   # from an existing env file (preferred; never prints values):
#   ./scripts/send-jev-env-drop.sh --from ~/.config/jev/env
#
#   # or pipe the two lines on stdin:
#   printf "JEV_MCP_URL='...'\nJEV_MCP_TOKEN='...'\n" | ./scripts/send-jev-env-drop.sh --stdin
set -euo pipefail
repo="${JEV_DROP_REPO:-bitskc/jev-agent-kit-archive}"
path="${JEV_DROP_PATH:-drops/cachy-jev-env.age}"
recipient="${JEV_AGE_RECIPIENT:-age156c39ax0qa7et0ts6hhj6r28t7du3lxj0r4rfpm2v67wy06s5cfsjpy44k}"
url_expect="${JEV_MCP_URL_EXPECT:-https://jev-mcp.andy-e3e.workers.dev/mcp}"
from=""; stdin=0
while [ $# -gt 0 ]; do case "$1" in
  --from) from="$2"; shift;;
  --stdin) stdin=1;;
  --recipient) recipient="$2"; shift;;
  --repo) repo="$2"; shift;;
  --path) path="$2"; shift;;
  -h|--help) sed -n '2,12p' "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;;
esac; shift; done
command -v age >/dev/null || { echo "age not on PATH" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh not on PATH" >&2; exit 2; }
umask 077
plain=$(mktemp); cipher=$(mktemp); trap 'rm -f "$plain" "$cipher"' EXIT
if [ "$stdin" = 1 ]; then
  cat >"$plain"
elif [ -n "$from" ]; then
  cp "$from" "$plain"
else
  echo "need --from FILE or --stdin" >&2; exit 2
fi
python3 - "$plain" "$url_expect" <<'PY'
import re, sys
path, url = sys.argv[1:3]
text = open(path).read()
if "JEV_MCP_TOKEN=" not in text or "JEV_MCP_URL=" not in text:
    sys.exit("refusing: input missing JEV_MCP_URL/JEV_MCP_TOKEN keys")
if url not in text:
    sys.exit(f"refusing: input does not contain expected URL {url}")
if re.search(r"JEV_MCP_TOKEN=''\s*$", text, re.M):
    sys.exit("refusing: empty token")
print("shape ok")
PY
age -r "$recipient" -o "$cipher" "$plain"
# IMPORTANT: upload via JSON body. `gh api -f content=...` can corrupt the base64 payload.
python3 - "$cipher" "$repo" "$path" <<'PY'
import base64, json, pathlib, subprocess, sys
cipher, repo, path = sys.argv[1:4]
content = base64.b64encode(pathlib.Path(cipher).read_bytes()).decode("ascii")
sha = None
probe = subprocess.run(["gh", "api", f"repos/{repo}/contents/{path}"], capture_output=True, text=True)
if probe.returncode == 0:
    sha = json.loads(probe.stdout)["sha"]
body = {"message": f"drop: age-encrypted jev env ({path})", "content": content}
if sha:
    body["sha"] = sha
p = subprocess.run(
    ["gh", "api", "--method", "PUT", f"repos/{repo}/contents/{path}", "--input", "-"],
    input=json.dumps(body), text=True, capture_output=True,
)
if p.returncode != 0:
    sys.stderr.write(p.stderr or p.stdout)
    sys.exit(p.returncode)
info = json.loads(p.stdout)
print(f"uploaded {repo}:{path} size={info['content']['size']} sha={info['content']['sha'][:12]}…")
print("plaintext not printed; receiver runs scripts/recv-jev-env.sh")
PY
