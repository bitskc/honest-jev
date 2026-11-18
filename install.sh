#!/usr/bin/env bash
# Install the jev skills pack for omp and/or Claude Code on this machine (user scope). Idempotent.
#   ./install.sh                # install for every agent whose config dir exists, else both
#   ./install.sh --omp | --claude | --both
#   ./install.sh --project DIR  # project scope: DIR/.omp/skills and DIR/.claude/skills instead of ~
#   ./install.sh --wire         # ALSO merge the MCP entry + full hook set (Honest Jev + guard + redact + Stop) into the
#                               # agent config. Backs up first. Token-free (writes ${JEV_MCP_URL}/${JEV_MCP_TOKEN} references only).
#   ./install.sh --no-hook      # with --wire: skip all hooks
#   ./install.sh --save-env     # write JEV_MCP_URL/JEV_MCP_TOKEN from the CURRENT environment to ~/.config/jev/env (0600)
#   ./install.sh --doctor       # check env, /health, auth and tool count (EXPECTED_TOOLS below). Never prints the token.
#   ./install.sh --yes          # accepted for scripted use; the installer never prompts
# Default (no --wire): copies files only; never edits your MCP or settings files and never touches a token.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target=auto; project=""; wire=0; hook=1; doctor=0; saveenv=0; argc=0
for a in "$@"; do case "$a" in -y|--yes|--non-interactive) ;; *) argc=$((argc+1));; esac; done
while [ $# -gt 0 ]; do case "$1" in
  --omp) target=omp;; --claude) target=claude;; --both) target=both;;
  --project) [ $# -ge 2 ] || { echo "--project needs DIR" >&2; exit 2; }; project="$2"; shift;;
  --wire) wire=1;; --no-hook) hook=0;; --doctor) doctor=1;; --save-env) saveenv=1;; -y|--yes|--non-interactive) :;;
  -h|--help) sed -n 2,14p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
if { [ "$saveenv" = 1 ] || [ "$doctor" = 1 ]; } && [ "$argc" -gt 1 ]; then echo "--save-env and --doctor run alone; do not combine them with other flags" >&2; exit 2; fi
envfile="$HOME/.config/jev/env"; bin="$HOME/.local/bin"
# config dirs, same overrides the runtime honours: CLAUDE_CONFIG_DIR (default ~/.claude), PI_CODING_AGENT_DIR (default ~/.omp/agent).
# Claude Code keeps the user MCP file at $CLAUDE_CONFIG_DIR/.claude.json when that is set, else ~/.claude.json.
claude_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then claude_json="$CLAUDE_CONFIG_DIR/.claude.json"; else claude_json="$HOME/.claude.json"; fi
omp_dir="${PI_CODING_AGENT_DIR:-$HOME/.omp/agent}"
# env file: KEY='value' lines (' escaped as '\''), so `. file` yields the literal text. This installer never
# evaluates the file: --doctor reads the two known keys as data.
envq() { local v=$1 q="'\\''"; v=${v//\'/$q}; printf "'%s'" "$v"; }
env_get() {
  local f=$1 k=$2 line="" v l
  [ -f "$f" ] || return 1
  while IFS= read -r l || [ -n "$l" ]; do case "$l" in "$k="*) line=$l;; esac; done < "$f"
  [ -n "$line" ] || return 1
  v=${line#"$k="}
  case "$v" in \'*\') v=${v:1:${#v}-2};; *) return 1;; esac
  printf '%s' "${v//"'\''"/"'"}"
}
if [ "$saveenv" = 1 ]; then
  : "${JEV_MCP_URL:?export JEV_MCP_URL first}"; : "${JEV_MCP_TOKEN:?export JEV_MCP_TOKEN first}"
  case "$JEV_MCP_URL$JEV_MCP_TOKEN" in *$'\n'*|*$'\r'*) echo "JEV_MCP_URL/JEV_MCP_TOKEN must be single-line" >&2; exit 2;; esac
  mkdir -p "$(dirname "$envfile")"; tmp=$(mktemp "$(dirname "$envfile")/.env.XXXXXX")
  { printf 'JEV_MCP_URL=%s\n' "$(envq "$JEV_MCP_URL")"; printf 'JEV_MCP_TOKEN=%s\n' "$(envq "$JEV_MCP_TOKEN")"; } > "$tmp" || { rm -f "$tmp"; exit 1; }
  chmod 600 "$tmp"; mv -f "$tmp" "$envfile"; echo "saved -> $envfile (0600)"; exit 0
fi
# MCP tools the server must expose (checked by --doctor). Source: 12 upstream jev_* tools (jkudish/jev-mcp, pinned in
# server/build-vendor.sh; registerTool count at that commit) + 3 fixed kit_* tools (KIT_TOOL_NAMES in server/src/kit/tools.mjs) + kit_decide (server/src/decide/tool.mjs).
EXPECTED_TOOLS=16
if [ "$doctor" = 1 ]; then
  # The hooks and jev-call read this same file, so a file-only https URL and token is a server they can call.
  url_file_only=0; tok_file_only=0
  # Fill from the file only when the process has neither value. One process value plus the other from the file
  # would send a process token to a URL the file names (#61).
  if [ -z "${JEV_MCP_URL:-}" ] && [ -z "${JEV_MCP_TOKEN:-}" ]; then
    JEV_MCP_URL=$(env_get "$envfile" JEV_MCP_URL || true); if [ -n "$JEV_MCP_URL" ]; then url_file_only=1; fi
    JEV_MCP_TOKEN=$(env_get "$envfile" JEV_MCP_TOKEN || true); if [ -n "$JEV_MCP_TOKEN" ]; then tok_file_only=1; fi
  fi
  url_https=0
  case "${JEV_MCP_URL:-}" in https://*) url_https=1;; esac
  # shellcheck disable=SC2015
  fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
  # the guard's local rules (hooks/jev-guard-local.mjs): the installed copy first, else this checkout. First line on purpose: it is the part
  # of the guard that needs no server.
  runner="$HOME/.local/share/honest-jev/hooks/jev-guard-local.mjs"; [ -f "$runner" ] || runner="$here/hooks/jev-guard-local.mjs"
  rt=$(command -v node || command -v bun || true)
  rules_ok=0
  if [ -z "$rt" ]; then bad "guard rules do not load locally: no node or bun on PATH"
  elif rp=$("$rt" "$runner" --check 2>/dev/null); then ok "guard rules load locally ($rp)"; rules_ok=1
  else bad "guard rules do not load locally (runner: $runner)"; fi
  if [ -z "${JEV_MCP_URL:-}" ]; then bad "JEV_MCP_URL not set"
  elif [ "$url_https" = 0 ]; then bad "JEV_MCP_URL is not an https:// URL; the hooks refuse any other scheme, so they never reach the server"
  elif [ "$url_file_only" = 1 ]; then ok "JEV_MCP_URL set (from $envfile only)"
  else ok "JEV_MCP_URL set"; fi
  if [ -z "${JEV_MCP_TOKEN:-}" ]; then bad "JEV_MCP_TOKEN not set"
  elif [ "$tok_file_only" = 1 ]; then ok "JEV_MCP_TOKEN set (from $envfile only)"
  else ok "JEV_MCP_TOKEN set"; fi
  if [ "$url_file_only" = 1 ] || [ "$tok_file_only" = 1 ]; then
    echo "note the guard hooks and jev-call read $envfile themselves. An MCP entry that uses \${JEV_MCP_URL} / \${JEV_MCP_TOKEN} still needs those variables in the agent process"
  fi
  if { [ -n "${JEV_MCP_URL:-}" ] && [ -z "${JEV_MCP_TOKEN:-}" ]; } || { [ -z "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ]; }; then
    [ -f "$envfile" ] && echo "note a value in the process and a value in $envfile are not combined, so the hooks do not use the file"
  fi
  # Both from the process, or both from the file. A mix is not a server the hooks will call.
  hooks_see_server=0
  if [ "$url_file_only" = "$tok_file_only" ] && [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then hooks_see_server=1; fi
  if [ "$hooks_see_server" = 1 ]; then
    [ "$rules_ok" = 1 ] || echo "note the local rules do not load; every command is sent to the server"
  elif [ "$rules_ok" = 1 ]; then echo "note guard runs on local rules only, not checked against any server; unclear commands are allowed without a model check"
  else echo "note the guard is not checking commands: the local rules do not load and no server is configured"; fi
  if [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then
    base="${JEV_MCP_URL%/mcp}"
    [ "$(curl -s -m 10 "$base/health" || true)" = ok ] && ok "/health" || bad "/health did not return ok"
    code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$JEV_MCP_URL" || true)
    [ "$code" = 401 ] && ok "unauthenticated call rejected (401)" || bad "unauthenticated call returned $code (want 401)"
    # the token reaches curl through a config on stdin, never argv (argv is visible in ps and /proc)
    tokcfg=${JEV_MCP_TOKEN//\\/\\\\}; tokcfg=${tokcfg//\"/\\\"}
    # the rules on this machine against the rules the Worker runs: the guard trusts a local allow only when their fingerprints are identical
    # (the Worker reports its own in a header of an authenticated GET /health; the token travels in the curl config on stdin, never argv)
    if [ "$rules_ok" = 1 ]; then
      lfp=$("$rt" "$runner" --fingerprint 2>/dev/null || true)
      sfp=$(curl -s -m 10 -D - -o /dev/null --config - "$base/health" <<<"header = \"authorization: Bearer $tokcfg\"" 2>/dev/null \
        | tr -d '\r' | awk -F': *' 'tolower($1)=="x-jev-rules-fingerprint"{print tolower($2); exit}' || true)
      if [ -z "$lfp" ]; then bad "guard rules cannot be fingerprinted (the rule files are incomplete, or one of them is a symlink); re-run ./install.sh"
      elif [ -z "$sfp" ]; then echo "note the server did not report its rules fingerprint (an older Worker, or it refused the token); commands the local rules would allow are sent to the server to decide"
      elif [ "$sfp" = "$lfp" ]; then ok "guard rules match the server's (fingerprint ${lfp:0:12})"
      else bad "guard rules differ from the server's (here ${lfp:0:12}, server ${sfp:0:12}); commands the local rules would allow are sent to the server to decide. Run jev-update if the server is newer, or deploy the Worker if this machine is"; fi
    fi
    # MCP handshake (initialize, then notifications/initialized) before tools/list. If initialize returns an
    # Mcp-Session-Id header, every later call sends it back. It travels in the curl config too, never argv.
    sidcfg=""; hdr=$(mktemp); trap 'rm -f "$hdr"' EXIT
    mcp() { curl -s -m 20 -D "$hdr" -X POST "$JEV_MCP_URL" --config - -H 'content-type: application/json' \
      -H 'accept: application/json, text/event-stream' -d "$1" \
      <<<"header = \"authorization: Bearer $tokcfg\"$sidcfg"; }
    mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"jev-doctor","version":"1"}}}' >/dev/null || true
    sid=$(tr -d '\r' < "$hdr" | awk -F': *' 'tolower($1)=="mcp-session-id"{print $2; exit}' || true)
    if [ -n "$sid" ]; then sid=${sid//\\/\\\\}; sid=${sid//\"/\\\"}; sidcfg=$'\n'"header = \"Mcp-Session-Id: $sid\""; fi
    mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
    n=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
      | python3 -c 'import sys,json
for l in sys.stdin.read().splitlines():
    l=l.strip()
    l=l[5:].strip() if l.startswith("data:") else l
    if l.startswith("{"): print(len(json.loads(l)["result"]["tools"])); break' 2>/dev/null || true)
    [ "$n" = "$EXPECTED_TOOLS" ] && ok "tools/list = $EXPECTED_TOOLS tools" || bad "tools/list returned '${n:-nothing}' (want $EXPECTED_TOOLS; bad token?)"
  fi
  for d in "$omp_dir/skills" "$claude_dir/skills"; do [ -d "$d/jev-classify" ] && ok "skills in $d"; done
  [ -x "$bin/jev-call" ] && ok "jev-call installed" || bad "jev-call not installed (run ./install.sh)"
  exit "$fail"
fi
if [ "$target" = auto ]; then
  if [ -d "$HOME/.omp" ] && [ -d "$HOME/.claude" ]; then target=both
  elif [ -d "$HOME/.omp" ]; then target=omp
  elif [ -d "$HOME/.claude" ]; then target=claude
  else target=both; fi
fi
share="$HOME/.local/share/honest-jev"; bin="$HOME/.local/bin"
# The install dir was ~/.local/share/jev-agent-skills before the rename. An existing one is MOVED (one rename, same directory),
# so its installed-ref stamp and anything else in it comes along. A symlink at the old path keeps hook commands that were never
# re-wired working; --wire rewrites them. If both exist the new one wins and the old one is left alone.
old_share="$HOME/.local/share/jev-agent-skills"
if [ -d "$old_share" ] && [ ! -L "$old_share" ]; then
  if [ ! -e "$share" ] && [ ! -L "$share" ]; then
    mkdir -p "$HOME/.local/share" && mv "$old_share" "$share" && ln -s honest-jev "$old_share" \
      && echo "moved $old_share -> $share (a symlink stays at the old path for hook commands that are not re-wired yet; --wire rewrites them)"
  else
    echo "note: both $old_share and $share exist; using $share and leaving $old_share untouched (delete it once nothing references it)"
  fi
fi
mkdir -p "$share" "$bin"
rm -rf "$share/hooks.new" && cp -r "$here/hooks" "$share/hooks.new" && chmod +x "$share"/hooks.new/*.sh "$share"/hooks.new/*.py "$share"/hooks.new/*.js "$share"/hooks.new/honest/*.js && rm -rf "$share/hooks" && mv "$share/hooks.new" "$share/hooks"
# jev-honest-runtime.js resolves SKILL.md relative to its own install location ($share/hooks/honest/.. -> $share/skills)
# first, falling back to ~/.claude/skills only if that's absent. Without this, --omp-only and --project installs
# never populate $share/skills, so the honest hook silently falls back to a ~700-char hardcoded summary instead
# of the real, level-filtered skill body.
rm -rf "$share/skills" && cp -r "$here/skills" "$share/skills"
install -m 755 "$here/scripts/jev-call.sh" "$bin/jev-call"
install -m 755 "$here/update.sh" "$bin/jev-update"
install -m 755 "$here/scripts/jev-report.mjs" "$bin/jev-report"
install -m 755 "$here/scripts/jev-outcome.mjs" "$bin/jev-outcome"
# jev-policy imports the policy and decide modules by relative path, so it installs as a small tree plus a launcher.
rm -rf "$share/jev-policy" && mkdir -p "$share/jev-policy/scripts" "$share/jev-policy/server"
cp -r "$here/server/src" "$share/jev-policy/server/src" && install -m 644 "$here/scripts/jev-policy.mjs" "$share/jev-policy/scripts/jev-policy.mjs"
printf '#!/bin/sh\nexec node "%s" "$@"\n' "$share/jev-policy/scripts/jev-policy.mjs" > "$bin/jev-policy" && chmod 755 "$bin/jev-policy"
# the policy hook's plan helper (add-policy-hook-adapter): both PreToolUse hooks run it; it sits beside jev-policy.mjs and shares its tree
install -m 644 "$here/scripts/jev-policy-hook.mjs" "$share/jev-policy/scripts/jev-policy-hook.mjs"
printf '#!/bin/sh\nexec node "%s" "$@"\n' "$share/jev-policy/scripts/jev-policy-hook.mjs" > "$bin/jev-policy-hook" && chmod 755 "$bin/jev-policy-hook"
# shellcheck disable=SC2115
copy_skills() { mkdir -p "$1"; for d in "$here"/skills/*/; do n=$(basename "$d"); rm -rf "$1/$n"; cp -r "$d" "$1/$n"; done; echo "skills -> $1"; }
if [ "$target" = omp ] || [ "$target" = both ]; then
  if [ -n "$project" ]; then copy_skills "$project/.omp/skills"; else copy_skills "$omp_dir/skills"; fi
fi
if [ "$target" = claude ] || [ "$target" = both ]; then
  if [ -n "$project" ]; then copy_skills "$project/.claude/skills"; else copy_skills "$claude_dir/skills"; fi
fi
merge_json() { # merge_json FILE KIND  (kind: mcp | claude-hook | paths-claude | paths-any). Merges, keeps everything else; no-op when nothing changes.
  # paths-claude / paths-any only move hook and config paths from the pre-rename install dir to the current one (never create a file).
  python3 - "$1" "$2" "$HOME" "$here/config/claude-settings-hook.json" <<'PY'
import json, os, re, shutil, sys, tempfile, time
path, kind, home, tpl_path = sys.argv[1:5]
if kind in ("paths-claude", "paths-any") and not os.path.exists(path): sys.exit(0)
# every spelling a hook command or config value uses for the old install dir; the next character must end the path, so
# jev-agent-skills-extra is not ours
OLD_DIR = re.compile(r"(\$HOME|\$\{HOME\}|~|" + re.escape(home) + r")/\.local/share/jev-agent-skills(?![A-Za-z0-9_.-])")
def moved(s): return OLD_DIR.sub(lambda m: m.group(1) + "/.local/share/honest-jev", s)
def migrate_hooks(d):
    """Rewrite old-dir paths in the commands of EVERY hook event (honest, guard, stop, dispatch-shadow, the policy path that rides
    on the guard...), then drop the entries and hook objects that became duplicates of one already there. Nothing else is touched."""
    hk = d.get("hooks")
    if not isinstance(hk, dict): return
    for arr in hk.values():
        if not isinstance(arr, list): continue
        touched = set()
        for e in arr:
            if not isinstance(e, dict) or not isinstance(e.get("hooks"), list): continue
            for h in e["hooks"]:
                if isinstance(h, dict) and isinstance(h.get("command"), str) and moved(h["command"]) != h["command"]:
                    h["command"] = moved(h["command"]); touched.add(id(e))
        if not touched: continue
        have = {}  # matcher -> commands already present in entries that were not rewritten
        for e in arr:
            if isinstance(e, dict) and id(e) not in touched and isinstance(e.get("hooks"), list):
                have.setdefault(json.dumps(e.get("matcher")), set()).update(h.get("command") for h in e["hooks"] if isinstance(h, dict))
        out = []
        for e in arr:
            if id(e) in touched:
                seen = have.setdefault(json.dumps(e.get("matcher")), set())
                keep = []
                for h in e["hooks"]:
                    c = h.get("command") if isinstance(h, dict) else None
                    if c is not None and c in seen: continue
                    if c is not None: seen.add(c)
                    keep.append(h)
                if not keep: continue
                e["hooks"] = keep
            out.append(e)
        arr[:] = out
def migrate_any(v):
    if isinstance(v, str): return moved(v)
    if isinstance(v, list): return [migrate_any(x) for x in v]
    if isinstance(v, dict): return {k: migrate_any(x) for k, x in v.items()}
    return v
d = {}
if os.path.exists(path):
    try: d = json.load(open(path))
    except Exception as e: sys.exit(f"refusing to edit {path}: not plain JSON ({e}); merge by hand")
    if not isinstance(d, dict): sys.exit(f"refusing to edit {path}: top level is not a JSON object; merge by hand")
    if kind == "mcp" and not isinstance(d.get("mcpServers", {}), dict): sys.exit(f"refusing to edit {path}: mcpServers is not a JSON object; merge by hand")
    if kind == "claude-hook":
        hk = d.get("hooks", {})
        if not isinstance(hk, dict): sys.exit(f"refusing to edit {path}: hooks is not a JSON object; merge by hand")
        # every event the template will write into must already be a proper list-of-entries if present
        tpl_events = json.load(open(tpl_path)).get("hooks", {})
        if not isinstance(tpl_events, dict): sys.exit(f"{tpl_path}: hooks is not a JSON object")
        for ev in tpl_events:
            arr = hk.get(ev, [])
            if ev in hk and not isinstance(arr, list):
                sys.exit(f"refusing to edit {path}: hooks.{ev} is not a JSON array; merge by hand")
            if not all(isinstance(e, dict) and isinstance(e.get("hooks", []), list) and all(isinstance(h, dict) for h in e.get("hooks", [])) for e in arr):
                sys.exit(f"refusing to edit {path}: hooks.{ev} entries must be objects holding a list of hook objects; merge by hand")
before = json.dumps(d, sort_keys=True)
if kind == "paths-any": d = migrate_any(d)
elif kind == "paths-claude": migrate_hooks(d)
elif kind == "mcp":
    d.setdefault("mcpServers", {})["jev"] = {"type": "http", "url": "${JEV_MCP_URL}",
        "headers": {"Authorization": "Bearer ${JEV_MCP_TOKEN}"}}
else:
    migrate_hooks(d)  # first, so an old-path entry is recognised as ours below and is not added a second time
    # full hook set from the shipped template (Honest Jev levels + guard + classify redact + Stop).
    # Commands are matched after expanding $HOME/${HOME}/~ so a prior settings-file merge that left
    # "$HOME/..." and a prior --wire that wrote the absolute path are the same entry (no duplicate).
    tpl = json.load(open(tpl_path))
    def expand(cmd):
        return cmd.replace("${HOME}", home).replace("$HOME", home)
    def norm(cmd):
        return expand(cmd).replace("~", home) if isinstance(cmd, str) else cmd
    hooks = d.setdefault("hooks", {})
    for ev, entries in tpl.get("hooks", {}).items():
        if not isinstance(entries, list): sys.exit(f"{tpl_path}: hooks.{ev} is not a JSON array")
        arr = hooks.setdefault(ev, [])
        for raw in entries:
            entry = json.loads(json.dumps(raw))  # deep copy so expand does not mutate the template on disk
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                sys.exit(f"{tpl_path}: hooks.{ev} entry is not an object with a hooks list")
            for h in entry["hooks"]:
                if isinstance(h.get("command"), str): h["command"] = expand(h["command"])
            wanted = {norm(h.get("command")) for h in entry["hooks"] if isinstance(h.get("command"), str)}
            mine = [e for e in arr if wanted & {norm(h.get("command")) for h in e.get("hooks", []) if isinstance(h, dict)}]
            if mine:
                for e in mine:
                    if "matcher" in entry: e["matcher"] = entry["matcher"]
                    by = {norm(h["command"]): h for h in entry["hooks"] if isinstance(h.get("command"), str)}
                    for h in e.get("hooks", []):
                        n = norm(h.get("command"))
                        if n in by: h.clear(); h.update(by[n])
            else:
                arr.append(entry)
# unchanged content: leave the file, its formatting and its backups alone.
# paths-* passes are silent when nothing moved (the later mcp/claude-hook pass reports the real status for the same file).
if os.path.exists(path) and json.dumps(d, sort_keys=True) == before:
    if kind not in ("paths-claude", "paths-any"):
        print("unchanged ->", path)
    sys.exit(0)
# keep the first backup; a rerun adds a timestamped one instead of clobbering the original.
# Only when a write follows; validated above first, so a refused file gets no backup.
if os.path.exists(path):
    bak = path + ".jev-bak"
    if os.path.exists(bak): bak = f"{path}.jev-bak.{time.time_ns()}"
    shutil.copy2(path, bak)
# validate the full document before it replaces anything, then write temp-file + rename in the same directory
text = json.dumps(d, indent=2) + "\n"
json.loads(text)
dirn = os.path.dirname(path) or "."
os.makedirs(dirn, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=dirn, prefix=".jev-tmp-")
try:
    with os.fdopen(fd, "w") as f:
        f.write(text); f.flush(); os.fsync(f.fileno())
    if os.path.exists(path): shutil.copymode(path, tmp)
    else: os.chmod(tmp, 0o644)
    os.replace(tmp, path)
except BaseException:
    if os.path.exists(tmp): os.unlink(tmp)
    raise
print(("migrated ->" if kind.startswith("paths-") else "wired ->"), path)
PY
}
if [ "$wire" = 1 ]; then
  if [ "$target" = omp ] || [ "$target" = both ]; then
    if [ -n "$project" ]; then ocfg="$project/.omp"; else ocfg="$omp_dir"; fi
    for f in settings.json config.json; do merge_json "$ocfg/$f" paths-any; done  # old install-dir paths in omp's own JSON config
    merge_json "$ocfg/mcp.json" paths-any
    merge_json "$ocfg/mcp.json" mcp; hd="$ocfg/hooks/pre"
    [ "$hook" = 1 ] && { mkdir -p "$hd"; cp "$share/hooks/omp/jev-guard.ts" "$hd/jev-guard.ts"; cp "$share/hooks/omp/jev-honest.ts" "$hd/jev-honest.ts"; echo "hook  -> $hd/jev-guard.ts + jev-honest.ts"; }
  fi
  if [ "$target" = claude ] || [ "$target" = both ]; then
    # user scope: top-level mcpServers in $claude_json (Claude Code expands ${VAR} there); project scope: DIR/.mcp.json
    if [ -n "$project" ]; then merge_json "$project/.mcp.json" mcp; else merge_json "$claude_json" mcp; fi
    if [ -n "$project" ]; then cdir="$project/.claude"; else cdir="$claude_dir"; fi
    for f in settings.json settings.local.json; do merge_json "$cdir/$f" paths-claude; done  # every hook event, not only the guard
    if [ "$hook" = 1 ]; then merge_json "$cdir/settings.json" claude-hook; fi
  fi
  echo "wired. Config holds only \${JEV_MCP_URL}/\${JEV_MCP_TOKEN} references: export them for the agent process (see --save-env)."
fi
echo "hooks  -> $share/hooks   (Claude: honest/*.js + jev-guard-hook.sh; omp: omp/jev-honest.ts + omp/jev-guard.ts)"
echo "helper -> $bin/jev-call  (make sure $bin is on PATH)"
echo "update -> $bin/jev-update  (re-pull the latest release; --check to compare; --timer for weekly auto-sync)"
if [ "$wire" = 1 ]; then echo; echo "Remaining: set JEV_MCP_URL/JEV_MCP_TOKEN, restart the agent, run ./install.sh --doctor"; exit 0; fi
cat <<MSG

Next (nothing below was done for you; re-run with --wire to do steps 2-3 automatically):
 1. export JEV_MCP_URL=https://<your-worker>.workers.dev/mcp  and  JEV_MCP_TOKEN=...
    (keep them in a 0600 env file, never in git; deploy your own worker from server/ first)
 2. Add the MCP server: see config/omp-mcp.json (-> ~/.omp/agent/mcp.json or .omp/mcp.json)
    or config/claude-mcp.json (-> .mcp.json), or:
      claude mcp add --transport http jev "\$JEV_MCP_URL" --header "Authorization: Bearer \$JEV_MCP_TOKEN"
 3. Hooks (Honest Jev levels + guard + classify redact + Stop): re-run with --wire, or for Claude Code install the plugin
      (/plugin marketplace add bitskc/honest-jev), not both: they would register every hook twice. Statusline badge is still
      manual for settings-file installs; see README.
 4. Restart the agent (omp: restart omp to load the hooks; /reload-plugins does not reload them. Then /mcp list, /mcp test jev), then: /honest-jev standard
MSG
