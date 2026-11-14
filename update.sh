#!/usr/bin/env bash
# Pull honest-jev skills from GitHub and (re)install them. Idempotent. No git checkout needed.
#   ./update.sh                 # latest release tag -> skills for every agent whose dir exists, else both
#   ./update.sh --omp|--claude|--both
#   ./update.sh --project DIR   # install into DIR/.omp/skills + DIR/.claude/skills
#   ./update.sh --ref REF       # install a specific ref (branch, tag or SHA); --timer records it as JEV_REF
#   ./update.sh --check         # print the latest release and whether it differs from the installed one; change nothing
#   ./update.sh --timer         # also install a systemd user timer that runs this weekly
# Pinning: the release tag is resolved to its commit SHA through the GitHub API and the archive is fetched by SHA,
# so a moved tag or a push to main cannot change what gets installed. JEV_REF=main (or any ref) opts out of pinning.
set -euo pipefail
repo="${JEV_REPO:-bitskc/honest-jev}"; ref="${JEV_REF:-}"
args=(); timer=0; check=0
while [ $# -gt 0 ]; do case "$1" in
  --omp|--claude|--both) args+=("$1");;
  --project) [ $# -ge 2 ] || { echo "--project needs DIR" >&2; exit 2; }; p="$2"; case "$p" in /*) ;; *) p="$PWD/$p";; esac; args+=("$1" "$p"); shift;;
  --ref) [ $# -ge 2 ] || { echo "--ref needs REF" >&2; exit 2; }; ref="$2"; shift;;
  --timer) timer=1;; --check) check=1;; -h|--help) sed -n 2,10p "$0"; exit 0;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done
[ "$check" = 1 ] && [ "$timer" = 1 ] && { echo "--check and --timer are mutually exclusive" >&2; exit 2; }

api() { curl -fsSL -H 'accept: application/vnd.github+json' -H 'user-agent: jev-update' "https://api.github.com/repos/$repo/$1"; }
json_field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'; }

if [ -z "$ref" ]; then
  tag="$(api releases/latest 2>/dev/null | json_field '["tag_name"]' 2>/dev/null)" || { echo "no release found for $repo; set JEV_REF to install an unpinned ref" >&2; exit 1; }
  tagref="$(api "git/ref/tags/$tag")"
  sha="$(printf '%s' "$tagref" | json_field '["object"]["sha"]')"
  # annotated tags point at a tag object; dereference to the commit
  if [ "$(printf '%s' "$tagref" | json_field '["object"]["type"]')" = tag ]; then sha="$(api "git/tags/$sha" | json_field '["object"]["sha"]')"; fi
  label="$tag ($sha)"
else
  sha="$(api "commits/$ref" | json_field '["sha"]')"; tag="$ref"; label="$ref ($sha)"
fi

stamp="$HOME/.local/share/honest-jev/installed-ref"
installed="$(cat "$stamp" 2>/dev/null || echo none)"
if [ "$check" = 1 ]; then
  echo "latest:    $label"; echo "installed: $installed"
  if [ "$installed" = "$sha" ]; then echo "up to date"; exit 0; fi
  echo "update available: run jev-update"; exit 1
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/$repo/archive/$sha.tar.gz" -o "$tmp/kit.tar.gz"
tar -xzf "$tmp/kit.tar.gz" -C "$tmp"
kit="$(find "$tmp" -maxdepth 1 -type d -name "$(basename "$repo")-*" | head -1)"
[ -n "$kit" ] || { echo "unpacked tree not found" >&2; exit 1; }
"$kit/install.sh" ${args[@]+"${args[@]}"}
mkdir -p "$(dirname "$stamp")"; printf '%s\n' "$sha" > "$stamp"
echo "installed $label"

if [ "$timer" = 1 ]; then
  unit=jev-skill-sync; d="$HOME/.config/systemd/user"; mkdir -p "$d"
  # systemd.syntax(7) quoting: double-quote each word, escaping \ " $ and %; systemd expands $VAR and %specifiers.
  sd_q() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//\$/\$\$}; s=${s//%/%%}; printf '"%s"' "$s"; }
  sd_args=""; for a in ${args[@]+"${args[@]}"}; do sd_args+=" $(sd_q "$a")"; done
  env_lines="Environment=$(sd_q "JEV_REPO=$repo")"; if [ -n "$ref" ]; then env_lines+=$'\n'"Environment=$(sd_q "JEV_REF=$ref")"; fi
  cat > "$d/$unit.service" <<EOF
[Unit]
Description=Sync honest-jev skills from the latest GitHub release
[Service]
Type=oneshot
$env_lines
ExecStart=$HOME/.local/bin/jev-update$sd_args
EOF
  cat > "$d/$unit.timer" <<EOF
[Unit]
Description=Weekly honest-jev skills sync
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload
  if ! systemctl --user enable --now "$unit.timer" >/dev/null 2>&1; then echo "timer  -> NOT enabled: systemctl --user enable --now $unit.timer failed (needs a user session bus; for logged-out hosts: loginctl enable-linger \"\$USER\")" >&2; exit 1; fi
  echo "timer  -> $d/$unit.timer (weekly; systemctl --user status $unit.timer)"
fi
