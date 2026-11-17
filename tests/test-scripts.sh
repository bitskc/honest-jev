#!/usr/bin/env bash
# Offline tests for the shell pieces: install.sh, update.sh --timer, the statusline badge, jev-call exit codes, and the
# guard hook's local decisions (oversized input, non-https URL). No network: curl is stubbed on PATH.
#   bash tests/test-scripts.sh
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
ok() { if [ "$1" = "$2" ]; then pass=$((pass+1)); printf 'PASS %s\n' "$3"; else fail=$((fail+1)); printf 'FAIL %s\n     expected: %s\n     got:      %s\n' "$3" "$2" "$1"; fi; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# the guard hook tests below run the real hook: its decision log and its once-per-session notice marker go to a private state dir, never the real one
export XDG_STATE_HOME="$tmp/xdg-state"

# ── statusline badge ────────────────────────────────────────────────────────────
sl="$root/hooks/jev-honest-statusline.sh"
cfg="$tmp/cfg"; mkdir -p "$cfg" "$tmp/sl-home"
ok "$(HOME=$tmp/sl-home CLAUDE_CONFIG_DIR=$cfg bash "$sl")" "" "statusline: no flag -> empty"
for m in off soft standard strict; do printf '%s\n' "$m" > "$cfg/.jev-honest-active"; eval "got_$m=\$(HOME=$tmp/sl-home CLAUDE_CONFIG_DIR=$cfg bash \"$sl\")"; done
ok "$got_off" "" "statusline: off -> empty"
ok "$got_soft" $'\033[38;5;130m[HONEST:SOFT]\033[0m' "statusline: soft badge"
ok "$got_standard" $'\033[38;5;130m[HONEST]\033[0m' "statusline: standard badge"
ok "$got_strict" $'\033[38;5;130m[HONEST:STRICT]\033[0m' "statusline: strict badge"
printf 'BOGUS\n' > "$cfg/.jev-honest-active"; ok "$(HOME=$tmp/sl-home CLAUDE_CONFIG_DIR=$cfg bash "$sl")" "" "statusline: unrecognised level -> empty, not a bogus badge"
mkdir -p "$tmp/sl-home/.omp/agent"; printf 'soft\n' > "$tmp/sl-home/.omp/agent/.jev-honest-active"
ok "$(HOME=$tmp/sl-home CLAUDE_CONFIG_DIR=$tmp/sl-nocfg bash "$sl")" $'\033[38;5;130m[HONEST:SOFT]\033[0m' "statusline: omp flag (~/.omp/agent) badges when no Claude flag"
mkdir -p "$tmp/pi-agent"; printf 'strict\n' > "$tmp/pi-agent/.jev-honest-active"
ok "$(HOME=$tmp/sl-home PI_CODING_AGENT_DIR=$tmp/pi-agent CLAUDE_CONFIG_DIR=$tmp/sl-nocfg bash "$sl")" $'\033[38;5;130m[HONEST:STRICT]\033[0m' "statusline: PI_CODING_AGENT_DIR overrides the omp flag dir (not ~/.omp/agent)"

# ── install.sh: both targets, project scope with spaces, hooks + helpers landed ──
H="$tmp/home"; mkdir -p "$H/.omp/agent" "$H/.claude"
HOME=$H bash "$root/install.sh" --both >/dev/null
ok "$(ls "$H/.claude/skills" | tr '\n' ' ')" "$(ls "$H/.omp/agent/skills" | tr '\n' ' ')" "install: same skills in both agent dirs"
ok "$([ -d "$H/.claude/skills/jev-honest" ] && echo yes)" yes "install: jev-honest skill present"
ok "$([ -x "$H/.local/bin/jev-call" ] && [ -x "$H/.local/bin/jev-update" ] && echo yes)" yes "install: jev-call + jev-update executable"
ok "$([ -x "$H/.local/share/honest-jev/hooks/honest/jev-honest-activate.js" ] && [ -f "$H/.local/share/honest-jev/hooks/omp/jev-honest.ts" ] && echo yes)" yes "install: honest hooks shipped"
ok "$([ -f "$H/.local/share/honest-jev/hooks/honest/rules.default.json" ] && echo yes)" yes "install: rules.default.json shipped alongside the honest hooks"
ok "$(node -e "const rt=require('$H/.local/share/honest-jev/hooks/honest/jev-honest-runtime.js'); console.log(rt.rules()[0] && rt.rules()[0].id)")" "pr-gstack-reviewed" "install: default rule resolves from the installed location"
jp="$H/.local/bin/jev-policy"; jpu="$tmp/installed-user-policy.json"
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$tmp/no-such-policy.json" "$jp" list 2>&1)" "no policy classes (run: jev-policy init --layer repo)" "install: jev-policy launcher runs from the installed tree"
(cd "$tmp" && HOME=$H JEV_POLICY_USER="$jpu" "$jp" add "$root/examples/policies/pr-merge-gate.json" --layer user --yes >/dev/null 2>&1)
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$jpu" "$jp" test pr-merge-gate 2>&1 | tail -1)" "7/7 examples pass (offline, no model call)" "install: installed jev-policy adds and tests the example class offline"
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$jpu" "$jp" list 2>&1 | head -1 | grep -o 'trigger: Bash gh pr merge')" "trigger: Bash gh pr merge" "install: the example class carries its trigger and jev-policy list shows it"
jph="$H/.local/bin/jev-policy-hook"
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$tmp/no-such-policy.json" "$jph" plan --command 'gh pr merge 12' --cwd "$tmp" 2>&1)" '{"ok":true,"triggered":false}' "install: jev-policy-hook launcher runs from the installed tree (no layer, nothing fires)"
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$jpu" "$jph" plan --command 'gh pr view 12' --cwd "$tmp" 2>&1)" '{"ok":true,"triggered":false}' "install: installed plan helper: a different gh command does not fire the trigger"
ok "$(cd "$tmp" && HOME=$H JEV_POLICY_USER="$jpu" "$jph" plan --command 'gh pr merge 12' --cwd "$tmp" --no-providers 2>&1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["triggered"], d["class"], d["call"]["facts"], d["effects"]["ask_user"])')" "True pr-merge-gate {} ask" "install: installed plan helper fires on gh pr merge (providers skipped, no network)"
P="$tmp/My Project"; mkdir -p "$P"
HOME=$H bash "$root/install.sh" --project "$P" >/dev/null
ok "$([ -f "$P/.claude/skills/jev-honest/SKILL.md" ] && [ -f "$P/.omp/skills/jev-honest/SKILL.md" ] && echo yes)" yes "install: --project path with spaces"
ok "$([ -f "$H/.local/share/honest-jev/skills/jev-honest/SKILL.md" ] && echo yes)" yes "install: --project also populates \$share/skills for the honest hook's own lookup"
actcfg="$tmp/actcfg"; mkdir -p "$actcfg"; printf 'standard\n' > "$actcfg/.jev-honest-active"
actlen=$(CLAUDE_CONFIG_DIR="$actcfg" node "$H/.local/share/honest-jev/hooks/honest/jev-honest-activate.js" | wc -c)
ok "$([ "$actlen" -gt 3000 ] && echo yes)" yes "install: --project activate output is the real SKILL.md (len=$actlen), not the ~700-char fallback"

# ── guard differential: no un-allowlisted block/ask -> allow transition against main ──
# (evals/diff-guard.mjs decides every evals/guard.jsonl row under main and under this tree; data only, nothing is executed.)
if command -v node >/dev/null 2>&1 && { git -C "$root" rev-parse --verify --quiet 'origin/main^{commit}' >/dev/null || git -C "$root" rev-parse --verify --quiet 'main^{commit}' >/dev/null; }; then
  # with an authenticated gh, every closure exemption's issue is also checked to exist and be OPEN; offline only its `#N` shape is
  dg_args=""; if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then dg_args="--check-issues"; fi
  dg_out=$(node "$root/evals/diff-guard.mjs" $dg_args 2>&1); dg_rc=$?
  ok "$dg_rc" 0 "evals/diff-guard.mjs: no un-allowlisted block/ask -> allow vs main, and the wrapper-closure invariant holds (every block stays block in every wrapper)$([ "$dg_rc" -ne 0 ] && printf '\n%s' "$(printf '%s' "$dg_out" | tail -5)")"
else
  printf 'SKIP evals/diff-guard.mjs (needs node and an origin/main or main ref in this checkout)\n'
fi

# ── update.sh --timer: ExecStart quoting; --check on a missing release ─────────
stub="$tmp/bin"; mkdir -p "$stub"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
# offline stub: GitHub API lookups answer like a repo with no releases; archive fetch copies the local tree
for a in "$@"; do case "$a" in
  *api.github.com/*releases/latest) echo '{"message":"Not Found"}'; exit 22;;
  *api.github.com/*commits/*) echo '{"sha":"0000000000000000000000000000000000000000"}'; exit 0;;
  *github.com/*/archive/*.tar.gz) out=""; for b in "$@"; do [ "$prev" = -o ] && out="$b"; prev="$b"; done
     tar -czf "$out" -C "$(dirname "$REPO_ROOT")" --transform "s|^$(basename "$REPO_ROOT")|honest-jev-0000|" --exclude=.git --exclude=node_modules "$(basename "$REPO_ROOT")"; exit 0;;
esac; done; exit 1
EOF
chmod +x "$stub/curl"
cat > "$stub/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$stub/systemctl"
U="$tmp/uhome"; mkdir -p "$U/.omp/agent" "$U/.claude" "$U/.config/systemd/user"
got=$(HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" bash "$root/update.sh" --check 2>&1); ok "$?" 1 "update: no release -> exit 1"
ok "$got" "no release found for bitskc/honest-jev; set JEV_REF to install an unpinned ref" "update: no release -> one clean line"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer >/dev/null 2>&1
ok "$(grep ExecStart "$U/.config/systemd/user/jev-skill-sync.service")" "ExecStart=$U/.local/bin/jev-update" "update: --timer with no args -> bare ExecStart"
ok "$(cat "$U/.local/share/honest-jev/installed-ref")" "0000000000000000000000000000000000000000" "update: installed-ref stamp written"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer --project "$tmp/a\"b c" >/dev/null 2>&1
ok "$(grep ExecStart "$U/.config/systemd/user/jev-skill-sync.service")" "ExecStart=$U/.local/bin/jev-update \"--project\" \"$tmp/a\\\"b c\"" "update: --timer quotes args systemd-style"
ok "$(HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check 2>&1 | tail -1)" "up to date" "update: --check after install -> up to date"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check >/dev/null 2>&1; ok "$?" 0 "update: --check up to date -> exit 0"
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n' > "$U/.local/share/honest-jev/installed-ref"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --check >/dev/null 2>&1; ok "$?" 1 "update: --check update available -> exit 1"
printf '0000000000000000000000000000000000000000\n' > "$U/.local/share/honest-jev/installed-ref"
bash "$root/update.sh" --check --timer >/dev/null 2>&1; ok "$?" 2 "update: --check --timer -> rejected"
bash "$root/update.sh" --project >/dev/null 2>&1; ok "$?" 2 "update: --project with no DIR -> usage error, exit 2"

# ── statusline sourcing; update.sh --timer: relative --project, % escaping, persisted env, enable failure ──
printf 'soft\n' > "$cfg/.jev-honest-active"
ok "$(HOME=$tmp/sl-home CLAUDE_CONFIG_DIR=$cfg bash -c 'source "$1"; jev_honest_badge; echo -n after' _ "$sl")" $'\033[38;5;130m[HONEST:SOFT]\033[0m'"after" "statusline: sourced -> badge returned, parent shell keeps running"
mkdir -p "$tmp/rel/proj" "$tmp/pct%x"
(cd "$tmp/rel" && HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer --project proj >/dev/null 2>&1)
ok "$(grep ExecStart "$U/.config/systemd/user/jev-skill-sync.service")" "ExecStart=$U/.local/bin/jev-update \"--project\" \"$tmp/rel/proj\"" "update: --timer resolves a relative --project to an absolute path"
HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer --project "$tmp/pct%x" >/dev/null 2>&1
ok "$(grep -c 'pct%%x' "$U/.config/systemd/user/jev-skill-sync.service")" 1 "update: % in an arg is escaped as %% for systemd"
ok "$(grep -c '^Environment="JEV_REF=main"$' "$U/.config/systemd/user/jev-skill-sync.service")" 1 "update: --timer persists JEV_REF"
mkdir -p "$tmp/bin-fail"; printf '#!/usr/bin/env bash\n[ "$2" = enable ] && exit 1\nexit 0\n' > "$tmp/bin-fail/systemctl"; chmod +x "$tmp/bin-fail/systemctl"
HOME=$U PATH="$tmp/bin-fail:$stub:$PATH" REPO_ROOT="$root" JEV_REF=main bash "$root/update.sh" --timer >/dev/null 2>&1; ok "$?" 1 "update: --timer with a failing systemctl enable -> exit 1, not silent"
ok "$(HOME=$U PATH="$stub:$PATH" REPO_ROOT="$root" bash "$root/update.sh" --check --ref main 2>&1 | tail -1)" "up to date" "update: --ref REF parsed and used"

# jev-report: invisible format characters are stripped from a printed ledger path
for ch in $'\u200e' $'\u061c' $'\u00ad' $'\ufeff' $'\U000e0041'; do
  msg=$(JEV_LEDGER="rel${ch}x" node "$root/scripts/jev-report.mjs" 2>&1 || true)
  ok "$(if [[ "$msg" == *'(got "relx")'* ]]; then echo clean; else echo "bad:$msg"; fi)" clean "jev-report: U+$(printf '%X' "'$ch") stripped from output"
done
# the sweep is the whole Unicode format category (Cf), not a list: word joiner and invisible operators, deprecated format
# controls, interlinear annotation, Mongolian vowel separator, and a few Cf from other blocks; a letter and an emoji stay
for cp in 2060 2061 2062 2063 2064 206A 206B 206C 206D 206E 206F FFF9 FFFA FFFB 180E 0600 110BD 1D173 E0001; do
  ch=$(node -e 'process.stdout.write(String.fromCodePoint(parseInt(process.argv[1], 16)))' "$cp")
  msg=$(JEV_LEDGER="rel${ch}x" node "$root/scripts/jev-report.mjs" 2>&1 || true)
  ok "$(if [[ "$msg" == *'(got "relx")'* ]]; then echo clean; else echo "bad:$msg"; fi)" clean "jev-report: U+$cp (format character) stripped from output"
done
msg=$(JEV_LEDGER="rel$(node -e 'process.stdout.write("\u00e9\u{1f600}")')x" node "$root/scripts/jev-report.mjs" 2>&1 || true)
ok "$(if [[ "$msg" == *"(got \"rel$(node -e 'process.stdout.write("\u00e9\u{1f600}")')x\")"* ]]; then echo kept; else echo "bad:$msg"; fi)" kept "jev-report: ordinary letters and emoji are not stripped"

# ── jev-call exit codes (offline) ───────────────────────────────────────────────
jc="$root/scripts/jev-call.sh"
JEV_MCP_TOKEN=t JEV_MCP_URL=https://x/mcp bash "$jc" x '{' 2>/dev/null; ok "$?" 2 "jev-call: bad args JSON -> exit 2"
JEV_MCP_TOKEN=t JEV_MCP_URL=http://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: http:// URL -> exit 2"
JEV_MCP_TOKEN=$'abc\ninsecure' JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: token with embedded newline -> exit 2, no curl config injection"
JEV_MCP_TOKEN='abc"def' JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 2 "jev-call: token with embedded quote -> exit 2"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null; echo 'data: {"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"boom"}]}}'
EOF
PATH="$stub:$PATH" JEV_MCP_TOKEN=t JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null; ok "$?" 1 "jev-call: isError -> exit 1"
cat > "$stub/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null; echo '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"decision\":\"allow\"}"}]}}'
EOF
ok "$(PATH="$stub:$PATH" JEV_MCP_TOKEN=secret-token-value JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null | tr -d ' \n')" '{"decision":"allow"}' "jev-call: result printed"
ok "$(cd "$tmp" && PATH="$stub:$PATH" JEV_MCP_TOKEN=t JEV_MCP_URL=https://x/mcp bash "$jc" x '{}' 2>/dev/null | tr -d ' \n')" '{"decision":"allow"}' "jev-call: runs from a bare checkout path, outside the repo cwd"
jcH="$tmp/jchome"; mkdir -p "$jcH/.config/jev"; printf "JEV_MCP_URL='https://file.example/mcp'\nJEV_MCP_TOKEN='file-token'\n" > "$jcH/.config/jev/env"
ok "$(HOME=$jcH PATH="$stub:$PATH" env -u JEV_MCP_URL -u JEV_MCP_TOKEN bash "$jc" x '{}' 2>/dev/null | tr -d ' \n')" '{"decision":"allow"}' "jev-call: URL and token from the env file when the process has neither"
touchf="$tmp/jev-call-ran"; printf "JEV_MCP_URL='https://file.example/mcp'\nJEV_MCP_TOKEN=\$(touch %s)\n" "$touchf" > "$jcH/.config/jev/env"
HOME=$jcH PATH="$stub:$PATH" env -u JEV_MCP_URL -u JEV_MCP_TOKEN bash "$jc" x '{}' >/dev/null 2>&1 || true
ok "$([ -e "$touchf" ] && echo yes || echo no)" no "jev-call: unquoted \$(...) in the env file is never executed"

# ── guard hook local decisions (no network needed) ──────────────────────────────
hook="$root/hooks/jev-guard-hook.sh"
ev() { python3 -c 'import json,sys;print(json.dumps({"tool_name":sys.argv[1],"tool_input":json.loads(sys.argv[2]),"cwd":"/tmp"}))' "$1" "$2"; }
dec() { python3 -c 'import json,sys;d=sys.stdin.read();print(json.loads(d).get("hookSpecificOutput", {}).get("permissionDecision", "none") if d.strip() else "none")'; }
big=$(python3 -c 'import json;print(json.dumps({"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa #"+"x"*20001},"cwd":"/tmp"}))')
ok "$(printf '%s' "$big" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" ask "guard: oversized command -> ask, no call"
ok "$(ev Bash '{"command":"curl -X POST https://example.com/api -d x"}' | JEV_MCP_TOKEN=t JEV_MCP_URL=http://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: http:// URL -> fail open, token never sent"
ok "$(ev Bash '{"command":"ls"}' | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp JEV_GUARD_TIMEOUT=0.3 bash "$hook" 2>/dev/null | dec)" none "guard: unreachable server -> fail open"
bigpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001,"output_mode":"content"},"cwd":"/tmp"}))')
ok "$(printf '%s' "$bigpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" ask "guard: Grep output_mode=content -> judged (oversized pattern asks)"
fwmpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001,"output_mode":"files_with_matches"},"cwd":"/tmp"}))')
ok "$(printf '%s' "$fwmpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: Grep output_mode=files_with_matches -> skipped, no secret-content exposure to judge"
defpattern=$(python3 -c 'import json;print(json.dumps({"tool_name":"Grep","tool_input":{"pattern":"x"*20001},"cwd":"/tmp"}))')
ok "$(printf '%s' "$defpattern" | JEV_MCP_TOKEN=t JEV_MCP_URL=https://127.0.0.1:9/mcp bash "$hook" 2>/dev/null | dec)" none "guard: Grep with no output_mode (defaults to files_with_matches) -> skipped"
redirect_test=$(python3 - "$root" <<'PYEOF'
import sys, io, json, importlib.util, os
root = sys.argv[1]
os.environ["JEV_MCP_URL"] = "https://example.invalid/mcp"
os.environ["JEV_MCP_TOKEN"] = "t"
spec = importlib.util.spec_from_file_location("jev_guard_hook", os.path.join(root, "hooks/jev_guard_hook.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# The redirect handler must raise a distinguishable exception, not a bare network-class error.
exc = None
try:
    [h for h in mod._http()[2].handlers if type(h).__name__ == "_NoRedirect"][0].redirect_request(None, None, 302, "Found", {}, "http://evil.example/steal")
except Exception as e:
    exc = e
assert exc is not None, "redirect_request did not raise"
assert isinstance(exc, mod.RedirectRefused), "redirect must raise RedirectRefused, got %s" % type(exc).__name__

# main()'s exception routing must treat a redirect refusal as ask, never a silent fail-open allow.
mod.call_guard = lambda args: (_ for _ in ()).throw(mod.RedirectRefused("redirect refused (302 -> http://evil.example/steal)"))
os.environ["JEV_GUARD_LOCAL"] = "off"  # this case is about the server path: with the local rules on, `rm -rf /` would never reach call_guard
sys.stdin = io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": "/tmp"}))
out = io.StringIO()
sys.stdout = out
try:
    mod.main()
except SystemExit:
    pass
sys.stdout = sys.__stdout__
printed = out.getvalue().strip()
assert printed, "redirect refusal produced no output (fail-open regression)"
decision = json.loads(printed)["hookSpecificOutput"]["permissionDecision"]
assert decision == "ask", "redirect refusal must ask, got %r" % decision
print("PASS")
PYEOF
)
ok "$redirect_test" "PASS" "guard: redirect refusal -> ask, never silent allow"
http_status_test=$(python3 - "$root" <<'PYEOF'
import sys, io, urllib.error, importlib.util, os
root = sys.argv[1]

os.environ["JEV_MCP_URL"] = "https://example.invalid/mcp"
os.environ["JEV_MCP_TOKEN"] = "t"
spec = importlib.util.spec_from_file_location("jev_guard_hook", os.path.join(root, "hooks/jev_guard_hook.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Exercise call_guard()'s real HTTPError handling: no live server needed, _opener.open is replaced with a
# function that raises the exact exception urllib raises for a non-2xx response, so the rest of call_guard
# (the try/except around _opener.open, inside the actual hook file) runs unmodified.
def classify(status):
    def fake_open(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(b""))
    mod._http()[2].open = fake_open  # the opener the hook builds on first use
    try:
        mod.call_guard({"tool": "Bash", "command": "x"})
        return "no-error"
    except mod.ServerRejected:
        return "ServerRejected"
    except urllib.error.HTTPError:
        return "re-raised (fail-open path)"

assert classify(401) == "ServerRejected", "401 must classify as ServerRejected (ask)"
assert classify(503) == "re-raised (fail-open path)", "503 must not be ServerRejected"
print("PASS")
PYEOF
)
ok "$http_status_test" "PASS" "guard: HTTP 4xx -> ServerRejected (ask); 5xx stays fail-open"

# ── PreToolUse matcher must cover every tool jev_guard_hook.py branches on ──────
matcher_has_grep() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("Grep" in d["hooks"]["PreToolUse"][0]["matcher"])' "$1"; }
ok "$(matcher_has_grep "$root/hooks/claude-plugin-hooks.json")" True "hooks/claude-plugin-hooks.json: PreToolUse matcher includes Grep"
ok "$(matcher_has_grep "$root/config/claude-settings-hook.json")" True "config/claude-settings-hook.json: PreToolUse matcher includes Grep"
readme_matches=$(python3 -c '
import json, sys
root = sys.argv[1]
matcher = json.load(open(root + "/hooks/claude-plugin-hooks.json"))["hooks"]["PreToolUse"][0]["matcher"]
claim = matcher.replace("|", "/")
readme = open(root + "/README.md").read()
n = readme.count(claim)
# exactly two places state the full claim (install section + Guard hook section); any other "Bash/Read" is a stale partial claim
print("True" if n == 2 and readme.count("Bash/Read") == n else "False (claim count=%d, Bash/Read count=%d, claim=%r)" % (n, readme.count("Bash/Read"), claim))
' "$root")
ok "$readme_matches" "True" "README: guard-coverage claim appears exactly twice; no stale partial matcher claim"

# ── --save-env / --doctor: env file is data, never executed ─────────────────────
envH="$tmp/envhome"; mkdir -p "$envH"; pwn="$tmp/pwned-env"
tok='tok$(touch PWN)`touch PWN` "q" it'"'"'s   sp ace\n$HOME'; tok=${tok//PWN/$pwn}
url='https://x.workers.dev/mcp?a=1&b=2'
HOME=$envH JEV_MCP_URL="$url" JEV_MCP_TOKEN="$tok" bash "$root/install.sh" --save-env >/dev/null
ok "$(stat -c %a "$envH/.config/jev/env")" 600 "save-env: mode 0600"
ok "$([ -e "$pwn" ] && echo yes || echo no)" no "save-env: \$(...) and backticks in token not executed"
ok "$(HOME=$envH bash -c 'set -a; . "$HOME/.config/jev/env"; set +a; printf %s "$JEV_MCP_TOKEN"')" "$tok" "save-env: documented source workflow yields literal token"
ok "$([ -e "$pwn" ] && echo yes || echo no)" no "save-env: sourcing the env file does not execute the token"
ok "$(HOME=$envH bash -c 'set -a; . "$HOME/.config/jev/env"; set +a; printf %s "$JEV_MCP_URL"')" "$url" "save-env: URL round-trips"
ok "$(HOME=$envH JEV_MCP_URL=$'https://x/mcp\nevil' JEV_MCP_TOKEN=t bash "$root/install.sh" --save-env >/dev/null 2>&1; echo $?)" 2 "save-env: newline in value -> exit 2"
d=$(HOME=$envH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null | sed -n 2,3p)
ef="$envH/.config/jev/env"
ok "$d" "$(printf 'ok   JEV_MCP_URL set (from %s only)\nok   JEV_MCP_TOKEN set (from %s only)' "$ef" "$ef")" "doctor: reads both keys from env file and says they came from the file only"
pwn2="$tmp/pwned-doc"; printf 'JEV_MCP_URL=$(touch %s)\nJEV_MCP_TOKEN=x\n' "$pwn2" > "$envH/.config/jev/env"
d2=$(HOME=$envH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null | sed -n 2p)
ok "$([ -e "$pwn2" ] && echo yes || echo no)" no "doctor: unquoted \$(...) in env file never executed"
ok "$d2" "FAIL JEV_MCP_URL not set" "doctor: unquoted env value rejected as data"
# the local-rules line leads the doctor output (it is the part of the guard that needs no server), and the no-server note appears only when URL or token is missing
doc_full=$(HOME=$envH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(printf '%s\n' "$doc_full" | head -1)" "ok   guard rules load locally ($root/server/src/kit/guard.mjs)" "doctor: first line says the guard rules load locally, and from where"
ok "$(printf '%s\n' "$doc_full" | grep -c '^note guard runs on local rules only, not checked against any server; unclear commands are allowed without a model check$')" 1 "doctor: no server configured -> the local-rules-only note, which says the rules are not checked against a server"
printf 'JEV_MCP_URL='"'"'https://x.example/mcp'"'"'\nJEV_MCP_TOKEN='"'"'t'"'"'\n' > "$envH/.config/jev/env"
doc_set=$(HOME=$envH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(printf '%s\n' "$doc_set" | grep -c '^note guard runs on local rules only' || true)" 0 "doctor: URL and token only in the env file -> the hooks read that file, so not local-rules-only"
doc_set_env=$(HOME=$envH JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=t PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(printf '%s\n' "$doc_set_env" | grep -c '^note guard runs on local rules only' || true)" 0 "doctor: URL and token in the environment -> no local-rules-only note"
# a runner that cannot load the rules is a FAIL line and exit 1; a missing runtime too
brokenH="$tmp/brokenhome"; mkdir -p "$brokenH/.local/share/honest-jev/hooks"; printf 'process.exit(3)\n' > "$brokenH/.local/share/honest-jev/hooks/jev-guard-local.mjs"
doc_broken=$(HOME=$brokenH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null); rc=$?
ok "$(printf '%s\n' "$doc_broken" | head -1)" "FAIL guard rules do not load locally (runner: $brokenH/.local/share/honest-jev/hooks/jev-guard-local.mjs)" "doctor: an installed runner that fails -> FAIL line"
ok "$rc" 1 "doctor: the local rules not loading -> exit 1"
nonode="$tmp/nonode"; mkdir -p "$nonode"; for t in bash env dirname cat head sed grep tr mktemp rm mkdir python3 curl; do p=$(command -v "$t") && ln -sf "$p" "$nonode/$t"; done
doc_nonode_full=$(HOME=$envH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$nonode" "$nonode/bash" "$root/install.sh" --doctor 2>/dev/null)
doc_nonode=$(printf '%s\n' "$doc_nonode_full" | head -1)
ok "$doc_nonode" "FAIL guard rules do not load locally: no node or bun on PATH" "doctor: no node or bun -> FAIL line"
# the `note` line says what the guard is doing right now, so it depends on BOTH the rules check and whether a server is configured
# (the doctor's separate note about a Worker that reports no rules fingerprint is another line, tested on its own below)
notes_of() { printf '%s\n' "$1" | grep '^note ' | grep -v '^note the server did not report its rules fingerprint' || true; }
n_local="note guard runs on local rules only, not checked against any server; unclear commands are allowed without a model check"
n_none="note the guard is not checking commands: the local rules do not load and no server is configured"
n_srv="note the local rules do not load; every command is sent to the server"
n_file="note the guard hooks and jev-call read $envH/.config/jev/env themselves. An MCP entry that uses \${JEV_MCP_URL} / \${JEV_MCP_TOKEN} still needs those variables in the agent process"
ok "$(notes_of "$doc_full")" "$n_local" "doctor: rules load + no server -> the local-rules-only note, and no other note"
ok "$(notes_of "$doc_broken")" "$n_none" "doctor: rules do not load + no server -> says the guard is not checking commands (not 'local rules only')"
doc_broken_srv=$(HOME=$brokenH JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=t PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(notes_of "$doc_broken_srv")" "$n_srv" "doctor: rules do not load + server configured -> every command is sent to the server"
ok "$(notes_of "$doc_set")" "$n_file" "doctor: rules load + server only in the env file -> the MCP-process note, and the hooks do see that server"
ok "$(printf '%s\n' "$doc_set" | grep -c '^ok   JEV_MCP_URL set (from .* only)$')" 1 "doctor: both from the file -> URL line has the suffix"
ok "$(printf '%s\n' "$doc_set" | grep -c '^ok   JEV_MCP_TOKEN set (from .* only)$')" 1 "doctor: both from the file -> token line has the suffix"
ok "$(printf '%s\n' "$doc_set" | grep -c 'jev-call read')" 1 "doctor: both from the file -> the note appears once"
secH="$tmp/sechome"; mkdir -p "$secH/.config/jev"; printf "JEV_MCP_URL='https://sec.example/mcp'\nJEV_MCP_TOKEN='s3cr3t-T0K-9f1x'\n" > "$secH/.config/jev/env"
doc_sec=$(HOME=$secH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>&1)
ok "$(printf '%s\n' "$doc_sec" | grep -c 's3cr3t-T0K-9f1x\|sec.example')" 0 "doctor: neither value from the file is printed"
# the process environment wins over the file, with no suffix and no note
doc_env=$(HOME=$envH JEV_MCP_URL=https://env.example/mcp JEV_MCP_TOKEN=envtok PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(printf '%s\n' "$doc_env" | grep '^ok   JEV_MCP_' | head -2)" "$(printf 'ok   JEV_MCP_URL set\nok   JEV_MCP_TOKEN set')" "doctor: both from the environment -> lines unchanged, no suffix"
ok "$(notes_of "$doc_env")" "" "doctor: both from the environment -> no note"
# one from each: only the file-sourced one is marked, and the note appears once
doc_urlenv=$(HOME=$envH env -u JEV_MCP_TOKEN JEV_MCP_URL=https://env.example/mcp PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
n_mix="note a value in the process and a value in $ef are not combined, so the hooks do not use the file"
ok "$(printf '%s\n' "$doc_urlenv" | grep -E '^(ok   JEV_MCP_|FAIL JEV_MCP_)' | head -2)" "$(printf 'ok   JEV_MCP_URL set\nFAIL JEV_MCP_TOKEN not set')" "doctor: URL from the environment, token only in the file -> the token is not taken from the file"
ok "$(notes_of "$doc_urlenv")" "$(printf '%s\n%s' "$n_mix" "$n_local")" "doctor: URL in the process, token in the file -> not combined, local rules only"
doc_tokenv=$(HOME=$envH env -u JEV_MCP_URL JEV_MCP_TOKEN=envtok PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
ok "$(printf '%s\n' "$doc_tokenv" | grep -E '^(ok   JEV_MCP_|FAIL JEV_MCP_)' | head -2)" "$(printf 'FAIL JEV_MCP_URL not set\nok   JEV_MCP_TOKEN set')" "doctor: token from the environment, URL only in the file -> the URL is not taken from the file"
ok "$(notes_of "$doc_tokenv")" "$(printf '%s\n%s' "$n_mix" "$n_local")" "doctor: token in the process, URL in the file -> not combined, local rules only"
ok "$(notes_of "$doc_nonode_full")" "$(printf '%s\n%s' "$n_file" "$n_srv")" "doctor: no node or bun + a server only in the env file -> the file note, and every command is sent to the server"
fbH="$tmp/filebroken"; mkdir -p "$fbH/.local/share/honest-jev/hooks" "$fbH/.config/jev"; cp "$envH/.config/jev/env" "$fbH/.config/jev/env"
printf 'process.exit(3)\n' > "$fbH/.local/share/honest-jev/hooks/jev-guard-local.mjs"
doc_file_broken=$(HOME=$fbH env -u JEV_MCP_URL -u JEV_MCP_TOKEN PATH="$stub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null)
n_file_fb="note the guard hooks and jev-call read $fbH/.config/jev/env themselves. An MCP entry that uses \${JEV_MCP_URL} / \${JEV_MCP_TOKEN} still needs those variables in the agent process"
ok "$(notes_of "$doc_file_broken")" "$(printf '%s\n%s' "$n_file_fb" "$n_srv")" "doctor: rules do not load + server only in the env file -> the file note, then every command is sent to the server"
ok "$(printf '%s\n' "$doc_file_broken" | grep -c 'every command is sent to the server')" 1 "doctor: rules do not load + server only in the env file -> the hooks see that server"
ok "$(notes_of "$doc_set")" "$n_file" "doctor: rules load + server only in the env file -> the file note, and no local-rules-only note"
doc_http_log="$tmp/doc-http.log"; httpstub="$tmp/httpstub"; mkdir -p "$httpstub"
printf '#!/bin/sh\necho called >> "$HTTP_LOG"\n' > "$httpstub/curl"; chmod +x "$httpstub/curl"
doc_http=$(HOME=$envH HTTP_LOG="$doc_http_log" JEV_MCP_URL=http://plain-host.example/mcp JEV_MCP_TOKEN=t PATH="$httpstub:$PATH" bash "$root/install.sh" --doctor 2>/dev/null); rc=$?
ok "$(printf '%s\n' "$doc_http" | grep '^FAIL JEV_MCP_URL')" "FAIL JEV_MCP_URL is not an https:// URL; the hooks refuse any other scheme, so they never reach the server" "doctor: a non-https URL is named as that, not as unset"
ok "$(printf '%s\n' "$doc_http" | grep -c 'JEV_MCP_URL not set')" 0 "doctor: a non-https URL is not reported as unset"
ok "$rc" 1 "doctor: a non-https URL -> exit 1"
ok "$(printf '%s\n' "$doc_http" | grep -c 'plain-host.example')" 0 "doctor: the rejected URL is not printed"
ok "$([ -e "$doc_http_log" ] && echo called || echo none)" none "doctor: a non-https URL is never contacted"
ok "$(notes_of "$doc_http")" "$n_local" "doctor: a non-https URL in the environment is no server to the hooks -> local rules only"

# ── merge_json: first backup kept, atomic write, non-JSON left alone ─────────────
mj="$tmp/mjhome"; mkdir -p "$mj/.claude"; printf '{"keep":1}\n' > "$mj/.claude.json"
HOME=$mj bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$(cat "$mj/.claude.json.jev-bak")" '{"keep":1}' "merge_json: first run backs up original"
printf '{"keep":2}\n' > "$mj/.claude.json"
HOME=$mj bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$(cat "$mj/.claude.json.jev-bak")" '{"keep":1}' "merge_json: rerun does not clobber first backup"
ok "$(cat "$mj/.claude.json.jev-bak".* | tr -d '\n')" '{"keep":2}' "merge_json: rerun backup kept under timestamped name"
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["keep"], "jev" in d["mcpServers"])' "$mj/.claude.json")" "2 True" "merge_json: existing keys kept, jev MCP entry merged"
printf '{ broken' > "$mj/.claude/settings.json"
HOME=$mj bash "$root/install.sh" --claude --wire >/dev/null 2>&1; rc=$?
ok "$(cat "$mj/.claude/settings.json")" '{ broken' "merge_json: non-JSON file left untouched"
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: non-JSON refused with nonzero exit"
ok "$(ls -A "$mj" "$mj/.claude" | grep -c 'jev-tmp')" 0 "merge_json: no temp files left behind"

# ── --doctor: bearer token never in curl argv ───────────────────────────────────
argvd="$tmp/argvstub"; mkdir -p "$argvd"; argLog="$tmp/argv.log"; argH="$tmp/argvhome"; mkdir -p "$argH"
cat > "$argvd/curl" <<'SH'
#!/bin/sh
printf '%s\n' "$@" >> "$ARGV_LOG"
exit 0
SH
chmod +x "$argvd/curl"
argTok='SECRET-argv-7f3a9c'
HOME=$argH ARGV_LOG="$argLog" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN="$argTok" PATH="$argvd:$PATH" bash "$root/install.sh" --doctor >/dev/null 2>&1 || true
ok "$([ -s "$argLog" ] && echo called)" called "doctor: curl stub invoked (test is not vacuous)"
ok "$(grep -c "$argTok" "$argLog" || true)" 0 "doctor: bearer token never appears in curl argv"

# ── --wire (claude): full hook set from the shipped template; dedupe; --no-hook ─
gH="$tmp/guardhome"; mkdir -p "$gH"
HOME=$gH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
HOME=$gH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
gs="$gH/.claude/settings.json"
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));p=d["hooks"]["PreToolUse"];print(len(p), p[0]["matcher"], p[0]["hooks"][0]["command"], p[1]["matcher"], "jev-classify-redact.js" in p[1]["hooks"][0]["command"])' "$gs")" "2 Bash|Read|NotebookRead|Grep $gH/.local/share/honest-jev/hooks/jev-guard-hook.sh mcp__.*__jev_classify|jev_classify True" "claude --wire: guard + redact PreToolUse after two runs; \$HOME resolved; no duplicate"
ok "$(python3 -c 'import json,sys;print(sorted(json.load(open(sys.argv[1]))["hooks"]))' "$gs")" "['PreToolUse', 'SessionStart', 'Stop', 'SubagentStart', 'UserPromptSubmit']" "claude --wire: full Honest Jev hook set (levels + guard + redact + Stop)"
# \$HOME form already present must not duplicate when --wire expands to absolute
dupH="$tmp/duphome"; mkdir -p "$dupH/.claude"
python3 -c 'import json,os,sys; h=sys.argv[1]; t=json.load(open("config/claude-settings-hook.json")); json.dump(t, open(os.path.join(h,".claude/settings.json"),"w"), indent=2); open(os.path.join(h,".claude/settings.json"),"a").write("\n")' "$dupH"
HOME=$dupH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));p=d["hooks"]["PreToolUse"];print(len(p), sum(1 for e in p for h in e["hooks"] if "jev-guard-hook.sh" in h["command"]), all("$HOME" not in h["command"] for e in p for h in e["hooks"]))' "$dupH/.claude/settings.json")" "2 1 True" "claude --wire: \$HOME template form deduped against expanded path; commands expanded"
nH="$tmp/nohookhome"; mkdir -p "$nH"
HOME=$nH bash "$root/install.sh" --claude --wire --no-hook >/dev/null 2>&1
ok "$([ -e "$nH/.claude/settings.json" ] && echo yes || echo no)" no "--no-hook: all hooks skipped (settings.json not written)"

# ── --wire: stale guard matcher refreshed in place; user hooks untouched; no duplicate ─
mH="$tmp/matcherhome"; mkdir -p "$mH/.claude"
cat > "$mH/.claude/settings.json" <<JSON
{"hooks": {
  "PreToolUse": [
    {"matcher": "Write", "hooks": [{"type": "command", "command": "/usr/local/bin/my-write-hook.sh", "timeout": 3}]},
    {"matcher": "Bash|Read", "hooks": [{"type": "command", "command": "$mH/.local/share/honest-jev/hooks/jev-guard-hook.sh", "timeout": 5}]}
  ],
  "SessionStart": [{"hooks": [{"type": "command", "command": "/usr/local/bin/my-start.sh"}]}]
}}
JSON
HOME=$mH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
HOME=$mH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ms="$mH/.claude/settings.json"
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));p=d["hooks"]["PreToolUse"];w={"matcher":"Write","hooks":[{"type":"command","command":"/usr/local/bin/my-write-hook.sh","timeout":3}]};ss=d["hooks"]["SessionStart"];print(len(p), [e.get("matcher") for e in p], p[0]==w, ss[0]=={"hooks":[{"type":"command","command":"/usr/local/bin/my-start.sh"}]}, any("jev-honest-activate.js" in h.get("command","") for e in ss for h in e.get("hooks",[])), len([e for e in p if any("jev-guard-hook.sh" in h.get("command","") for h in e.get("hooks",[]))]))' "$ms")" "3 ['Write', 'Bash|Read|NotebookRead|Grep', 'mcp__.*__jev_classify|jev_classify'] True True True 1" "claude --wire: stale guard matcher refreshed, redact added, user hooks untouched, no duplicate"

# ── install-dir rename: old ~/.local/share/jev-agent-skills -> honest-jev ───────
# Seeds an old-layout install + Claude settings that still point at the old path; asserts the
# move, the symlink left behind, rewritten hook commands, an idempotent second run, and that a
# user hook that never used the old path is left alone.
migH="$tmp/mighome"; mkdir -p "$migH/.local/share/jev-agent-skills/hooks" "$migH/.claude" "$migH/.local/bin"
printf 'old-stamp\n' > "$migH/.local/share/jev-agent-skills/installed-ref"
printf '#!/bin/sh\necho old-guard\n' > "$migH/.local/share/jev-agent-skills/hooks/jev-guard-hook.sh"
chmod +x "$migH/.local/share/jev-agent-skills/hooks/jev-guard-hook.sh"
cat > "$migH/.claude/settings.json" <<JSON
{"hooks": {
  "PreToolUse": [
    {"matcher": "Write", "hooks": [{"type": "command", "command": "/usr/local/bin/my-write-hook.sh", "timeout": 3}]},
    {"matcher": "Bash|Read", "hooks": [{"type": "command", "command": "$migH/.local/share/jev-agent-skills/hooks/jev-guard-hook.sh", "timeout": 5}]}
  ],
  "SessionStart": [{"hooks": [{"type": "command", "command": "/usr/local/bin/my-start.sh"}]}]
}}
JSON
HOME=$migH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$([ -d "$migH/.local/share/honest-jev/hooks" ] && [ -f "$migH/.local/share/honest-jev/installed-ref" ] && echo yes)" yes "migrate: old share dir moved to honest-jev (stamp survived)"
ok "$([ -L "$migH/.local/share/jev-agent-skills" ] && readlink "$migH/.local/share/jev-agent-skills")" "honest-jev" "migrate: symlink left at old path"
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));p=d["hooks"]["PreToolUse"];print(p[1]["hooks"][0]["command"])' "$migH/.claude/settings.json")" "$migH/.local/share/honest-jev/hooks/jev-guard-hook.sh" "migrate --wire: old-path guard command rewritten"
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["hooks"]["PreToolUse"][0]["hooks"][0]["command"], d["hooks"]["SessionStart"][0]["hooks"][0]["command"])' "$migH/.claude/settings.json")" "/usr/local/bin/my-write-hook.sh /usr/local/bin/my-start.sh" "migrate --wire: user hooks untouched"
HOME=$migH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));p=d["hooks"]["PreToolUse"];g=[e for e in p if any("jev-guard-hook.sh" in h.get("command","") for h in e.get("hooks",[]))];print(len(p), len(g), g[0]["hooks"][0]["command"])' "$migH/.claude/settings.json")" "3 1 $migH/.local/share/honest-jev/hooks/jev-guard-hook.sh" "migrate: second --wire is idempotent (Write+guard+redact, path stays new)"
# both dirs already exist: leave old alone, keep using new
bothH="$tmp/bothhome"; mkdir -p "$bothH/.local/share/jev-agent-skills/hooks" "$bothH/.local/share/honest-jev/hooks" "$bothH/.claude"
printf 'old-only\n' > "$bothH/.local/share/jev-agent-skills/installed-ref"
printf 'new-wins\n' > "$bothH/.local/share/honest-jev/installed-ref"
HOME=$bothH bash "$root/install.sh" --claude >/dev/null 2>&1
ok "$(cat "$bothH/.local/share/jev-agent-skills/installed-ref")" "old-only" "migrate: when both dirs exist, old is left untouched"
ok "$([ -d "$bothH/.local/share/honest-jev/hooks" ] && echo yes)" yes "migrate: when both dirs exist, new one is still populated"

# ── merge_json: validate before backup; refused files get no backup ──────────────
mv="$tmp/mvhome"; mkdir -p "$mv"; printf '{"mcpServers": null}\n' > "$mv/.claude.json"
HOME=$mv bash "$root/install.sh" --claude --wire --no-hook >/dev/null 2>"$tmp/mv.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: null mcpServers refused with nonzero exit"
ok "$(grep -c 'mcpServers is not a JSON object' "$tmp/mv.err")" 1 "merge_json: null mcpServers gives a message, not a traceback"
ok "$(ls -A "$mv" | grep -c 'jev-bak' || true)" 0 "merge_json: refused file gets no backup"
printf '[1,2]\n' > "$mv/.claude.json"
HOME=$mv bash "$root/install.sh" --claude --wire --no-hook >/dev/null 2>"$tmp/mv.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: top-level array refused with nonzero exit"
ok "$(grep -c 'top level is not a JSON object' "$tmp/mv.err")" 1 "merge_json: top-level array gives a message"

# ── merge_json: claude hooks of the wrong shape refused before any backup ───────
hk="$tmp/hookhome"; mkdir -p "$hk/.claude"
printf '{"hooks": []}\n' > "$hk/.claude/settings.json"
HOME=$hk bash "$root/install.sh" --claude --wire >/dev/null 2>"$tmp/hk.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: non-object hooks refused with nonzero exit"
ok "$(grep -c 'hooks is not a JSON object' "$tmp/hk.err")" 1 "merge_json: non-object hooks gives a message"
ok "$(grep -c 'Traceback' "$tmp/hk.err" || true)" 0 "merge_json: non-object hooks gives no traceback"
ok "$(ls -A "$hk/.claude" | grep -c 'jev-bak' || true)" 0 "merge_json: refused hooks file gets no backup"
printf '{"hooks": {"PreToolUse": {}}}\n' > "$hk/.claude/settings.json"
HOME=$hk bash "$root/install.sh" --claude --wire >/dev/null 2>"$tmp/hk.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: non-array PreToolUse refused with nonzero exit"
ok "$(grep -c 'PreToolUse is not a JSON array' "$tmp/hk.err")" 1 "merge_json: non-array PreToolUse gives a message"
ok "$(grep -c 'Traceback' "$tmp/hk.err" || true)" 0 "merge_json: non-array PreToolUse gives no traceback"
printf '{"hooks": {"PreToolUse": [1]}}\n' > "$hk/.claude/settings.json"
HOME=$hk bash "$root/install.sh" --claude --wire >/dev/null 2>"$tmp/hk.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: non-object PreToolUse entry refused with nonzero exit"
ok "$(grep -c 'PreToolUse entries must be objects' "$tmp/hk.err")" 1 "merge_json: non-object PreToolUse entry gives a message"
ok "$(grep -c 'Traceback' "$tmp/hk.err" || true)" 0 "merge_json: non-object PreToolUse entry gives no traceback"
ok "$(cat "$hk/.claude/settings.json")" '{"hooks": {"PreToolUse": [1]}}' "merge_json: refused hooks file left untouched"
printf '{"hooks": {"SessionStart": {}}}\n' > "$hk/.claude/settings.json"
HOME=$hk bash "$root/install.sh" --claude --wire >/dev/null 2>"$tmp/hk.err"; rc=$?
ok "$([ "$rc" -ne 0 ] && echo nonzero)" nonzero "merge_json: non-array SessionStart refused with nonzero exit"
ok "$(grep -c 'SessionStart is not a JSON array' "$tmp/hk.err")" 1 "merge_json: non-array SessionStart gives a message"
ok "$(ls -A "$hk/.claude" | grep -c 'jev-bak' || true)" 0 "merge_json: refused SessionStart file gets no backup"

# ── no-op rerun: unchanged files get no backup and no rewrite ───────────────────
nH="$tmp/noophome"; mkdir -p "$nH"
HOME=$nH bash "$root/install.sh" --claude --wire >/dev/null 2>&1
cp "$nH/.claude.json" "$tmp/noop-mcp1"; cp "$nH/.claude/settings.json" "$tmp/noop-set1"
HOME=$nH bash "$root/install.sh" --claude --wire >"$tmp/noop.out" 2>&1
ok "$(grep -c '^unchanged ->' "$tmp/noop.out")" 2 "rerun: MCP and hook files reported as unchanged"
ok "$(find "$nH" -name '*jev-bak*' | wc -l | tr -d ' ')" 0 "rerun: no backup when nothing changed"
ok "$(cmp -s "$nH/.claude.json" "$tmp/noop-mcp1" && cmp -s "$nH/.claude/settings.json" "$tmp/noop-set1" && echo same)" same "rerun: files byte-identical"

# ── config dirs: CLAUDE_CONFIG_DIR and PI_CODING_AGENT_DIR move every user-scope path ─
cH="$tmp/cfghome"; cC="$tmp/cfgdir-claude"; mkdir -p "$cH"
HOME=$cH CLAUDE_CONFIG_DIR=$cC bash "$root/install.sh" --claude --wire >/dev/null 2>&1
ok "$(python3 -c 'import json,sys; print("jev" in json.load(open(sys.argv[1]))["mcpServers"])' "$cC/.claude.json")" True "CLAUDE_CONFIG_DIR: MCP entry in \$CLAUDE_CONFIG_DIR/.claude.json"
ok "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["hooks"]["PreToolUse"]))' "$cC/settings.json")" 2 "CLAUDE_CONFIG_DIR: guard + redact hooks in \$CLAUDE_CONFIG_DIR/settings.json"
ok "$([ -d "$cC/skills/jev-classify" ] && echo yes)" yes "CLAUDE_CONFIG_DIR: skills copied to \$CLAUDE_CONFIG_DIR/skills"
ok "$(if [ -e "$cH/.claude.json" ] || [ -e "$cH/.claude" ]; then echo leaked; else echo clean; fi)" clean "CLAUDE_CONFIG_DIR: nothing written to the default ~/.claude"
pH="$tmp/ompdhome"; pP="$tmp/omp-agent"; mkdir -p "$pH"
HOME=$pH PI_CODING_AGENT_DIR=$pP bash "$root/install.sh" --omp --wire >/dev/null 2>&1
ok "$([ -f "$pP/mcp.json" ] && [ -f "$pP/hooks/pre/jev-guard.ts" ] && [ -f "$pP/hooks/pre/jev-honest.ts" ] && [ -d "$pP/skills/jev-classify" ] && echo yes)" yes "PI_CODING_AGENT_DIR: mcp.json, guard+honest hooks and skills in the override dir"
ok "$(if [ -e "$pH/.omp/agent/mcp.json" ] || [ -e "$pH/.omp/agent/skills" ]; then echo leaked; else echo clean; fi)" clean "PI_CODING_AGENT_DIR: nothing written to the default ~/.omp/agent"

# ── --doctor: MCP handshake order, tool count, exit codes; flags that must run alone ─
dH="$tmp/doctorhome"; mkdir -p "$dH/.local/bin"; printf '#!/bin/sh\n' > "$dH/.local/bin/jev-call"; chmod +x "$dH/.local/bin/jev-call"
dstub="$tmp/doctorstub"; mkdir -p "$dstub"; dlog="$tmp/doctor.log"
cat > "$dstub/curl" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "${DOCTOR_ARGV_LOG:-/dev/null}"
prev=""; hf=""; for a in "$@"; do [ "$prev" = -D ] && hf=$a; prev=$a; done; [ -n "$hf" ] && [ "$hf" != - ] && : > "$hf"
case " $* " in
  *" -D - "*) cat > /dev/null; printf 'HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n'; [ -n "${STUB_FP:-}" ] && printf 'X-Jev-Rules-Fingerprint: %s\r\n' "$STUB_FP"; printf '\r\n';;
  *" --config "*) cfg=$(cat); printf '%s\n' "$cfg" >> "${DOCTOR_CFG_LOG:-/dev/null}"; body=$(printf '%s\n' "$@" | grep -F '{"jsonrpc"' || true)
    case "$body" in
      *'"method":"initialize"'*) echo initialize >> "$DOCTOR_LOG"; [ -n "$hf" ] && printf 'HTTP/1.1 200 OK\r\nMcp-Session-Id: sess-123\r\n\r\n' > "$hf"; echo '{"jsonrpc":"2.0","id":1,"result":{}}';;
      *'"notifications/initialized"'*) echo notifications/initialized >> "$DOCTOR_LOG";;
      *'"tools/list"'*) echo tools/list >> "$DOCTOR_LOG"; python3 -c 'import json,os; print("data: "+json.dumps({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":str(i)} for i in range(int(os.environ.get("STUB_TOOLS","15")))]}}))';;
    esac;;
  *" -w "*) echo 401;;
  *"/health"*) echo ok;;
esac
SH
chmod +x "$dstub/curl"
run_doctor() { HOME=$dH DOCTOR_LOG="$dlog" DOCTOR_CFG_LOG="$tmp/doctor-cfg.log" DOCTOR_ARGV_LOG="$tmp/doctor-argv.log" PATH="$dstub:$PATH" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=tok STUB_TOOLS="$1" bash "$root/install.sh" --doctor; }
want=$(sed -n 's/^EXPECTED_TOOLS=\([0-9][0-9]*\)$/\1/p' "$root/install.sh") # the count install.sh --doctor demands: derived, so adding a tool cannot silently break these cases
ok "$([ -n "$want" ] && echo found)" found "doctor: EXPECTED_TOOLS is readable from install.sh"
: > "$dlog"; run_doctor "$want" >"$tmp/doc.out" 2>&1; rc=$?
ok "$rc" 0 "doctor: all checks pass -> exit 0"
ok "$(tr '\n' ' ' < "$dlog")" "initialize notifications/initialized tools/list " "doctor: MCP handshake order is initialize, notifications/initialized, tools/list"
ok "$(grep -c "tools/list = $want tools" "$tmp/doc.out")" 1 "doctor: reports the expected tool count"
: > "$dlog"; run_doctor "$((want - 1))" >/dev/null 2>&1; ok "$?" 1 "doctor: wrong tool count -> exit 1"
HOME=$dH bash "$root/install.sh" --save-env --doctor >/dev/null 2>&1; ok "$?" 2 "flags: --save-env with --doctor -> exit 2 (run alone)"
HOME=$dH bash "$root/install.sh" --doctor --wire >/dev/null 2>&1; ok "$?" 2 "flags: --doctor with --wire -> exit 2"
: > "$dlog"; HOME=$dH DOCTOR_LOG="$dlog" PATH="$dstub:$PATH" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=tok STUB_TOOLS="$want" bash "$root/install.sh" --doctor --yes >/dev/null 2>&1; ok "$?" 0 "flags: --doctor --yes accepted (--yes is a no-op) -> exit 0"
: > "$tmp/doctor-cfg.log"; : > "$tmp/doctor-argv.log"; run_doctor "$want" >/dev/null 2>&1
ok "$(grep -c 'Mcp-Session-Id: sess-123' "$tmp/doctor-cfg.log")" 2 "doctor: session id from initialize sent on notifications and tools/list"
ok "$(grep -c 'sess-123' "$tmp/doctor-argv.log" || true)" 0 "doctor: session id never in curl argv"
# the rules fingerprint check: the Worker's value comes from the X-Jev-Rules-Fingerprint header of an authenticated GET /health (the stub answers it for `-D -`)
real_fp=$(node "$root/hooks/jev-guard-local.mjs" --fingerprint)
ok "$(printf '%s' "$real_fp" | grep -c '^[0-9a-f]\{64\}$')" 1 "doctor: the runner reports a 64-hex rules fingerprint"
: > "$tmp/doctor-argv.log"
STUB_FP="$real_fp" run_doctor "$want" >"$tmp/doc-fp.out" 2>&1; rc=$?
ok "$rc" 0 "doctor: the server's fingerprint equals the local one -> exit 0"
ok "$(grep -c "^ok   guard rules match the server's (fingerprint ${real_fp:0:12})$" "$tmp/doc-fp.out")" 1 "doctor: ... and says the rules match"
ok "$(grep -c 'Bearer' "$tmp/doctor-argv.log" || true)" 0 "doctor: the fingerprint request keeps the token out of argv"
other_fp=$(printf 'b%.0s' $(seq 1 64))
STUB_FP="$other_fp" run_doctor "$want" >"$tmp/doc-fp.out" 2>&1; rc=$?
ok "$rc" 1 "doctor: the server's fingerprint differs -> exit 1"
ok "$(grep '^FAIL guard rules differ' "$tmp/doc-fp.out")" "FAIL guard rules differ from the server's (here ${real_fp:0:12}, server bbbbbbbbbbbb); commands the local rules would allow are sent to the server to decide. Run jev-update if the server is newer, or deploy the Worker if this machine is" "doctor: ... and says both fingerprints and what to do"
STUB_FP="" run_doctor "$want" >"$tmp/doc-fp.out" 2>&1; rc=$?
ok "$rc" 0 "doctor: a Worker that reports no fingerprint (an older one) -> a note, not a failure"
ok "$(grep -c '^note the server did not report its rules fingerprint (an older Worker, or it refused the token); commands the local rules would allow are sent to the server to decide$' "$tmp/doc-fp.out")" 1 "doctor: ... and says what that means"
# a rule file that is a symlink cannot be fingerprinted (Node would load the siblings from the link's target): the installed rules still load, the doctor says why they are unverifiable
lnH="$tmp/linkhome"; mkdir -p "$lnH"; HOME=$lnH bash "$root/install.sh" --claude >/dev/null 2>&1
lnK="$lnH/.local/share/honest-jev/jev-policy/server/src/kit"; mkdir -p "$tmp/linkelsewhere"; cp "$lnK/shell.mjs" "$tmp/linkelsewhere/shell.mjs"; rm "$lnK/shell.mjs"; ln -s "$tmp/linkelsewhere/shell.mjs" "$lnK/shell.mjs"
doc_ln=$(HOME=$lnH DOCTOR_LOG="$dlog" DOCTOR_CFG_LOG="$tmp/doctor-cfg.log" DOCTOR_ARGV_LOG="$tmp/doctor-argv.log" STUB_FP="$real_fp" PATH="$dstub:$PATH" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=tok STUB_TOOLS="$want" bash "$root/install.sh" --doctor 2>&1); rc=$?
ok "$(printf '%s\n' "$doc_ln" | grep -c '^FAIL guard rules cannot be fingerprinted (the rule files are incomplete, or one of them is a symlink)')" 1 "doctor: a symlinked rule file -> FAIL, cannot be fingerprinted"
ok "$rc" 1 "doctor: a symlinked rule file -> exit 1"
# the header dump is created once and removed on exit: no file may survive a run, pass or fail
dtd=$(mktemp -d)
HOME=$dH TMPDIR="$dtd" DOCTOR_LOG="$dlog" DOCTOR_CFG_LOG="$tmp/doctor-cfg.log" DOCTOR_ARGV_LOG="$tmp/doctor-argv.log" PATH="$dstub:$PATH" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=tok STUB_TOOLS=15 bash "$root/install.sh" --doctor >/dev/null 2>&1
ok "$(ls -A "$dtd" | wc -l | tr -d ' ')" 0 "doctor: no temp file left in TMPDIR after a passing run"
HOME=$dH TMPDIR="$dtd" DOCTOR_LOG="$dlog" DOCTOR_CFG_LOG="$tmp/doctor-cfg.log" DOCTOR_ARGV_LOG="$tmp/doctor-argv.log" PATH="$dstub:$PATH" JEV_MCP_URL=https://x.example/mcp JEV_MCP_TOKEN=tok STUB_TOOLS=14 bash "$root/install.sh" --doctor >/dev/null 2>&1
ok "$(ls -A "$dtd" | wc -l | tr -d ' ')" 0 "doctor: no temp file left in TMPDIR after a failing run"
rm -rf "$dtd"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
