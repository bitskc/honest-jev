#!/usr/bin/env bash
# Smoke: run the REAL guard hook and dispatch shadow hook against a local stub worker (real kit tool handlers, fake
# upstream, local HTTPS with a throwaway self-signed cert) in a temp HOME, then show the ledger and `jev-report`.
# Nothing leaves 127.0.0.1; command strings are data sent to a parser, never executed. Needs node, python3, openssl.
#   bash tests/smoke-ledger.sh
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; : > "$tmp/pids"; trap 'kill $(cat "$tmp/pids") 2>/dev/null || true; rm -rf "$tmp"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/k.pem" -out "$tmp/c.pem" -days 2 -subj /CN=127.0.0.1 \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
start() { # start a stub worker; echo its port. Own stdout/stderr files so no pipe is held open after exit.
  local f="$tmp/port.$RANDOM"
  node "$root/tests/stub-worker.mjs" --cert "$tmp/c.pem" --key "$tmp/k.pem" "$@" > "$f" 2>/dev/null &
  echo $! >> "$tmp/pids"; sleep 0.6; cat "$f"
}
port_ok=$(start --jev); port_down=$(start --mode 5xx)
export HOME="$tmp/home"; mkdir -p "$HOME"
unset XDG_STATE_HOME JEV_LEDGER  # the ledger must land under the temp HOME, never the user's real log
export SSL_CERT_FILE="$tmp/c.pem" JEV_MCP_TOKEN=stub-token
ev() { python3 -c 'import json,sys;print(json.dumps({"tool_name":sys.argv[1],"tool_input":json.loads(sys.argv[2]),"cwd":"/tmp"}))' "$1" "$2"; }
# run <url> <command-string> [ENV=val ...]: pipe one Bash PreToolUse event (the command is data) into the guard hook
run() { local url="$1" cmd="$2"; shift 2; ev Bash "$(python3 -c 'import json,sys;print(json.dumps({"command":sys.argv[1]}))' "$cmd")" | env JEV_MCP_URL="$url" "$@" bash "$root/hooks/jev-guard-hook.sh" >/dev/null 2>&1 || true; }
ok="https://127.0.0.1:$port_ok/mcp"; down="https://127.0.0.1:$port_down/mcp"
for c in "ls -la" "git status" "git diff --stat" "npm test" "cat .env" "rm -rf ~" "npm publish" "git push --force origin main"; do run "$ok" "$c"; done
run "$down" "ls"                       # worker outage: the hook fails open, only the client can record it
run "$ok" "cat .env" JEV_GUARD_MODE=shadow   # shadow: decided block, not enforced
for i in 1 2; do ev Task '{"description":"Find where FOO_TIMEOUT is read","prompt":"grep it","subagent_type":"workerO"}' | env JEV_MCP_URL="$ok" bash "$root/hooks/jev-dispatch-shadow.sh" >/dev/null 2>&1 || true; done
ledger="$HOME/.local/state/jev/ledger.jsonl"
echo "--- ledger: $(wc -l < "$ledger") rows at ~/.local/state/jev/ledger.jsonl (mode $(stat -c %a "$ledger"), dir $(stat -c %a "$(dirname "$ledger")"))"
echo "--- one blocked command (raw line; note: no command text):"; grep '"decision":"block"' "$ledger" | head -1
echo "--- one fail-open row (raw line):"; grep '"fail_reason":"client_http_5xx"' "$ledger" | head -1
echo "--- command text anywhere in the ledger? $(grep -c -E 'cat |rm -rf|\.env|FOO_TIMEOUT|git push' "$ledger" || true) matches"
# outcomes: the npm publish ask was approved by the user; the first dispatch recommendation was followed, 120k sub-agent tokens
ask=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    r=json.loads(l)
    if r.get("decision")=="ask" and r.get("tool")=="kit_guard_command": print(r["decision_id"]); break' "$ledger")
disp=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    r=json.loads(l)
    if r.get("tool")=="kit_size_dispatch": print(r["decision_id"]); break' "$ledger")
node "$root/scripts/jev-outcome.mjs" "$ask" approved
node "$root/scripts/jev-outcome.mjs" "$disp" followed --tokens 120000
echo '{"usd_per_mtok":{"workerO":15,"scout-find":1}}' > "$tmp/prices.json"
echo; node "$root/scripts/jev-report.mjs" --price-table "$tmp/prices.json" "$ledger"
