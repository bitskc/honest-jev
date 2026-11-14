#!/usr/bin/env bash
# Decision-ledger tests (openspec add-decision-ledger): server record derivation, hook ledger writes against a stub
# worker over local HTTPS, jev-report / jev-outcome, the omp hook under bun. Offline: no real worker, no real Jev, no
# secrets; guarded command strings are data and are never executed.
#   bash tests/test-ledger.sh            # needs node >= 22 (server deps installed: cd server && npm ci), python3, openssl
#   bash tests/test-ledger.sh --mutation # also run tests/mutation_check_ledger.py (slow)
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 2
rc=0
step() { printf '\n== %s\n' "$1"; shift; "$@" || rc=1; }

[ -d server/node_modules/zod ] || { echo "server deps missing: run (cd server && npm ci)" >&2; exit 2; }
step "server: record derivation, content-free, closed fail_reason, compat" bash -c 'cd server && node --test test/ledger.test.mjs'
step "server: existing suite still passes" bash -c 'cd server && npm test'
step "hooks: ledger writes, shadow, failures, atomicity (python)" python3 -m unittest tests/test_ledger_hook.py
step "guard hook: JEV_GUARD_ASK_AT parsing rejects NaN/Infinity (python)" python3 -m unittest tests/test_guard_ask_at.py
step "scripts: jev-report / jev-outcome" node --test tests/ledger-report.test.mjs
step "jev-call: a kit_decide call appends one content-free ledger row (stub curl)" python3 -W ignore -m unittest tests/test_jev_call_ledger.py
if command -v bun >/dev/null 2>&1; then
  step "omp hook (bun)" bun test tests/ledger-omp.test.ts
  step "omp hook, shadow mode (bun)" bun test tests/ledger-omp-shadow.test.ts
  step "omp hook, stalled ledger write does not delay the verdict (bun)" bun test tests/ledger-omp-stall.test.ts
  step "omp guard sends JEV_GUARD_ASK_AT as ask_at (bun)" bun test tests/guard-omp-ask-at.test.ts
  step "omp honest hook: size cap, rule-text cleaning, legacy notice, FIFO (bun)" bun test tests/honest-omp.test.ts
else
  echo "SKIP omp hook tests (bun not on PATH)"
fi
step "install.sh ships the ledger module, the shadow hook and both scripts, and the installed jev-report runs" bash -c '
  H=$(mktemp -d); trap "rm -rf $H" EXIT
  HOME=$H bash install.sh --claude >/dev/null || exit 1
  s=$H/.local/share/honest-jev/hooks
  [ -f $s/jev_ledger.py ] && [ -x $s/jev-dispatch-shadow.sh ] && [ -x $s/jev_dispatch_shadow.py ] || { echo "hooks not installed"; exit 1; }
  [ -x $H/.local/bin/jev-report ] && [ -x $H/.local/bin/jev-outcome ] || { echo "scripts not installed"; exit 1; }
  printf "%s\n" "{\"v\":1,\"decision_id\":\"00000000-0000-4000-8000-000000000001\",\"tool\":\"kit_guard_command\",\"decision\":\"allow\",\"decided_by\":\"prefilter\",\"jev\":{\"calls\":0}}" > $H/l.jsonl
  HOME=$H $H/.local/bin/jev-report $H/l.jsonl | grep -q "1 decision(s)" || { echo "installed jev-report failed"; exit 1; }
  echo ok'
step "dispatch shadow config is valid JSON and opt-in only" python3 - <<'PY'
import json, sys
c = json.load(open("config/claude-dispatch-shadow-hook.json"))
m = c["hooks"]["PreToolUse"][0]["matcher"]
assert m == "Task|Agent", m
base = json.load(open("config/claude-settings-hook.json"))
assert "jev-dispatch-shadow" not in json.dumps(base), "dispatch shadow hook must stay out of the default hook config"
print("ok")
PY
[ "${1:-}" = "--mutation" ] && { step "mutation check" python3 tests/mutation_check_ledger.py; step "mutation check (jev-call ledger row)" python3 tests/mutation_check_jev_call.py; }
printf '\n'; [ "$rc" -eq 0 ] && echo "test-ledger: ALL PASSED" || echo "test-ledger: FAILURES"
exit "$rc"
