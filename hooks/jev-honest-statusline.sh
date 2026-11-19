#!/usr/bin/env bash
# Honest Jev statusline badge. Prints nothing when jev-honest is off or the flag is missing/unrecognised.
# Run directly as a Claude Code statusLine command, or source it and call jev_honest_badge from an existing statusLine script.
# Sourcing never exits the parent shell: the function returns 0 and only the direct run calls it.

jev_honest_badge() {
  local flag mode
  flag="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.jev-honest-active"
  # omp keeps its flag under $PI_CODING_AGENT_DIR (default ~/.omp/agent, see hooks/omp/jev-honest.ts); the Claude flag wins when both exist.
  [ -f "$flag" ] || flag="${PI_CODING_AGENT_DIR:-$HOME/.omp/agent}/.jev-honest-active"
  [ -f "$flag" ] || return 0
  mode=$(head -n 1 "$flag" | tr -cd '[:alnum:]')
  case "$mode" in
    standard) printf '\033[38;5;130m🎩 HONEST\033[0m' ;;
    soft)     printf '\033[38;5;130m🎩 HONEST:SOFT\033[0m' ;;
    strict)   printf '\033[38;5;130m🎩 HONEST:STRICT\033[0m' ;;
  esac
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then jev_honest_badge; fi
