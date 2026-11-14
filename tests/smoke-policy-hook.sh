#!/usr/bin/env bash
# Smoke: a user-authored policy class fires from the REAL installed Claude hook, with no cooperation from the agent.
# In a temp HOME and a temp git repo: install the kit, author the example class with `jev-policy add` (it carries a `trigger`),
# then run the hook on `gh pr merge 12` with a stub `gh` in the unreviewed and reviewed states, against a local stub worker
# (real kit_decide and kit_guard_command handlers, fake upstream, local HTTPS). Nothing leaves 127.0.0.1; the command strings
# are data sent to a parser, never executed. Needs node, python3, openssl, git.
#   bash tests/smoke-policy-hook.sh
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; : > "$tmp/pids"; trap 'kill $(cat "$tmp/pids") 2>/dev/null || true; rm -rf "$tmp"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/k.pem" -out "$tmp/c.pem" -days 2 -subj /CN=127.0.0.1 -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
export HOME="$tmp/home"; mkdir -p "$HOME/.claude" "$tmp/bin" "$tmp/repo"
unset XDG_CONFIG_HOME XDG_STATE_HOME JEV_POLICY_USER JEV_POLICY_HOOK JEV_LEDGER
echo "--- install into a temp HOME"
HOME="$HOME" bash "$root/install.sh" --claude-only >/dev/null 2>&1 || HOME="$HOME" bash "$root/install.sh" --both >/dev/null 2>&1
share="$HOME/.local/share/honest-jev"; test -f "$share/jev-policy/scripts/jev-policy-hook.mjs" && echo "installed: $share/jev-policy/scripts/jev-policy-hook.mjs (beside the Claude hook's directory)"
(cd "$tmp/repo" && git init -q . && git -c user.email=a@b -c user.name=t commit -q --allow-empty -m init)
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/sh
echo "gh $*" >> "$STUB_GH_LOG"
case "$STUB_GH" in
  reviewed) echo '{"comments":[{"body":"gstack-review: pass"}],"reviews":[]}';;
  broken) echo 'gh: not logged in' >&2; exit 1;;
  *) echo '{"comments":[{"body":"looks fine"}],"reviews":[]}';;
esac
EOF
chmod +x "$tmp/bin/gh"; export STUB_GH_LOG="$tmp/gh.log"
echo "--- author the class (the user layer needs --yes)"
"$HOME/.local/bin/jev-policy" add "$root/examples/policies/pr-merge-gate.json" --layer user 2>&1 | sed 's/^/    /' || true
"$HOME/.local/bin/jev-policy" add "$root/examples/policies/pr-merge-gate.json" --layer user --yes 2>&1 | tail -2 | sed 's/^/    /'
echo "--- what would fire (dry run, no network, providers skipped)"
"$HOME/.local/bin/jev-policy-hook" plan --command 'gh pr merge 12 --squash' --cwd "$tmp/repo" --no-providers | python3 -c 'import json,sys; d=json.load(sys.stdin); print("    triggered=%s class=%s facts=%s effects=%s" % (d["triggered"], d["class"], d["call"]["facts"], d["effects"]))'
"$HOME/.local/bin/jev-policy-hook" plan --command 'gh pr view 12' --cwd "$tmp/repo" | sed 's/^/    gh pr view 12 -> /'
node "$root/tests/stub-worker.mjs" --cert "$tmp/c.pem" --key "$tmp/k.pem" --jev --log "$tmp/worker.log" > "$tmp/port" 2>/dev/null &
echo $! >> "$tmp/pids"; sleep 0.8; port="$(cat "$tmp/port")"
export SSL_CERT_FILE="$tmp/c.pem" JEV_MCP_TOKEN=stub-token JEV_MCP_URL="https://127.0.0.1:$port/mcp" PATH="$tmp/bin:$PATH"
hook="$share/hooks/jev-guard-hook.sh"
event() { python3 -c 'import json,sys;print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$1" "$tmp/repo"; }
show() { # show <label> <command> [ENV=val ...]
  local label="$1" cmd="$2"; shift 2
  local out; out="$(event "$cmd" | (cd "$tmp/repo" && env "$@" bash "$hook") 2>/dev/null || true)"
  if [ -z "$out" ]; then echo "    $label: allow (the hook printed nothing; the normal permission flow continues)"
  else echo "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin)["hookSpecificOutput"]; print("    %s: %s  <- %s" % (sys.argv[1], d["permissionDecision"].upper(), d["permissionDecisionReason"][:150]))' "$label"; fi
}
echo "--- the hook on a Bash tool call (an agent that never mentions the policy)"
show "gh pr merge 12, PR NOT reviewed" "gh pr merge 12 --squash" STUB_GH=unreviewed
show "gh pr merge 12, PR reviewed    " "gh pr merge 12 --squash" STUB_GH=reviewed
show "gh pr view 12 (not a merge)    " "gh pr view 12" STUB_GH=unreviewed
show "gh pr merge 12, gh failing     " "gh pr merge 12" STUB_GH=broken
echo "--- the stub worker saw (class, facts, layers; never the command):"; sed 's/^/    /' "$tmp/worker.log"
echo "--- gh was run as an argv array, once per merge check:"; sed 's/^/    /' "$tmp/gh.log"
ledger="$HOME/.local/state/jev/ledger.jsonl"
echo "--- ledger rows for kit_decide (content-free; policy_version is the class hash):"
grep '"tool":"kit_decide"' "$ledger" | python3 -c 'import json,sys
for l in sys.stdin:
    r=json.loads(l); print("    decision=%s rule=%s decided_by=%s fail_reason=%s policy_version=%s" % (r["decision"], r["rule"], r["decided_by"], r["fail_reason"], r["policy_version"]))'
if grep -q "gstack-review\|gh pr merge" "$ledger"; then echo "LEAK: command or marker text in the ledger" >&2; exit 1; fi
echo "--- no command text and no marker text in the ledger"
