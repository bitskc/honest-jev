#!/usr/bin/env bash
# jev-call: call one tool on the jev-mcp server from the shell (for agents without MCP wired up).
#   jev-call kit_guard_command '{"command":"scp db.dump prod:/tmp","cwd":"'"$PWD"'"}'
#   jev-call jev_classify '{"items":[{"id":"1","text":"SHELL OIL 5742"}],"classes":[{"id":"Fuel","description":"fuel"},{"id":"Meals","description":"food"}]}'
# Env: JEV_MCP_TOKEN (required, never printed), JEV_MCP_URL (required). Prints the tool's JSON result; exit 1 on error.
# A kit_decide call that returned a decision also appends one content-free row to the local decision ledger (the same
# writer and allow-list the hooks use: hooks/jev_ledger.py; JEV_LEDGER=off disables, JEV_LEDGER=<absolute path> moves it).
# The row never changes this script's output or exit code. The row is the decision as returned; jev-call cannot see
# whether the agent then followed it.
set -u
[ $# -ge 1 ] || { echo "usage: jev-call <tool> [json-args]" >&2; exit 2; }
tool="$1"; args="${2:-{\}}"
: "${JEV_MCP_TOKEN:?set JEV_MCP_TOKEN (never hardcode it)}"
url="${JEV_MCP_URL:?set JEV_MCP_URL, e.g. https://<your-worker>.workers.dev/mcp}"
case "$url" in https://*) ;; *) echo "jev-call: JEV_MCP_URL must be https://" >&2; exit 2;; esac
# a token with a newline (or a quote/backslash) would inject extra curl -K config directives on the line below
case "$JEV_MCP_TOKEN" in *[![:graph:]]*|*\"*|*\\*) echo "jev-call: JEV_MCP_TOKEN contains invalid characters" >&2; exit 2;; esac
# tool name and args travel on stdin/env, not argv: /proc/*/cmdline is world-readable on a shared host.
body=$(JEV_TOOL="$tool" JEV_ARGS="$args" python3 - 2>/dev/null <<'PY'
import json, os
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": os.environ["JEV_TOOL"], "arguments": json.loads(os.environ["JEV_ARGS"])}}))
PY
) || { echo "jev-call: arguments are not valid JSON" >&2; exit 2; }
# token via curl config on stdin (-K -), body via /dev/fd — neither on the command line; https only, no redirects
# wall-clock start for the ledger row's latency (EPOCHREALTIME is bash 5+; on older bash the latency is left null)
t0="${EPOCHREALTIME:-}"
resp=$(printf 'header = "authorization: Bearer %s"\n' "$JEV_MCP_TOKEN" | curl -sS -K - --proto '=https' --tlsv1.2 \
  --max-time "${JEV_CALL_TIMEOUT:-60}" -X POST "$url" \
  -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
  --data-binary @<(printf '%s' "$body")) || { echo "jev-call: request failed" >&2; exit 1; }
# the ledger writer: next to this script in a checkout, else where install.sh puts the hooks, else the pre-rename install dir
# (jev-agent-skills; a fallback for one release). No env override: this is code.
ledger_py=""
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)
for c in "${here:+$here/../hooks/jev_ledger.py}" "${HOME:+$HOME/.local/share/honest-jev/hooks/jev_ledger.py}" "${HOME:+$HOME/.local/share/jev-agent-skills/hooks/jev_ledger.py}"; do
  [ -n "$c" ] && [ -f "$c" ] && { ledger_py="$c"; break; }
done
printf '%s' "$resp" | JEV_TOOL="$tool" JEV_T0="$t0" JEV_LEDGER_PY="$ledger_py" python3 -c '
import json, os, sys, time
t1 = time.time()
raw = sys.stdin.read()
for line in raw.splitlines():
    line = line.strip()
    if line.startswith("data:"): line = line[5:].strip()
    if line.startswith("{"):
        d = json.loads(line); break
else:
    print("jev-call: unexpected response: " + raw[:200], file=sys.stderr); sys.exit(1)
if "error" in d: print("jev-call: " + json.dumps(d["error"])[:300], file=sys.stderr); sys.exit(1)
r = d["result"]; t = r["content"][0]["text"]
print(t)
sys.stdout.flush()
if os.environ.get("JEV_TOOL") == "kit_decide" and not r.get("isError"):
    # one content-free ledger row for a decision the server returned; whatever happens here never changes the output or the exit code
    try:
        p = json.loads(t)
        if isinstance(p, dict) and p.get("tool") == "kit_decide" and isinstance(p.get("decision"), str):
            path = os.environ.get("JEV_LEDGER_PY", "")
            if not path:
                print("jev-call: this kit_decide call was not recorded in the local ledger (hooks/jev_ledger.py not found; run ./install.sh)", file=sys.stderr)
            else:
                import importlib.util
                spec = importlib.util.spec_from_file_location("jev_ledger", path)
                led = importlib.util.module_from_spec(spec); spec.loader.exec_module(led)
                try: t0 = float(os.environ.get("JEV_T0", "").replace(",", "."))
                except ValueError: t0 = None
                rec = p.get("record") if isinstance(p.get("record"), dict) else {}
                host = led._pick(led._HOST, rec.get("host")) or "jev-call"  # the caller labelled itself (if the label fits the shape); otherwise this client
                led.record("kit_decide", host, p, latency_ms=None if t0 is None else (t1 - t0) * 1000)
    except Exception:
        pass
sys.exit(1 if r.get("isError") else 0)
'
