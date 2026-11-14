#!/usr/bin/env bash
# Policy hook adapter tests (openspec add-policy-hook-adapter): trigger grammar and matcher, the plan helper with a stub `gh`,
# the Python hook against a stub worker over local HTTPS, the omp hook under bun, the smoke run. Offline: no real worker, no
# real Jev, no real gh, no secrets; command strings are data and are never executed.
#   bash tests/test-policy-hook.sh            # needs node >= 22 (cd server && npm ci), python3, openssl, git; bun for the omp hook
#   bash tests/test-policy-hook.sh --mutation # also run tests/mutation_check_policy_hook.py (slow, about 11 minutes)
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 2
rc=0
step() { printf '\n== %s\n' "$1"; shift; "$@" || rc=1; }

[ -d server/node_modules/zod ] || { echo "server deps missing: run (cd server && npm ci)" >&2; exit 2; }
step "server: trigger grammar, matcher, merge, plan helper" bash -c 'cd server && node --test test/policy-trigger.test.mjs test/policy-hook-plan.test.mjs test/policy.test.mjs test/policy-cli.test.mjs'
step "hooks: policy path of the Python hook (stub worker, stub gh)" python3 -W ignore -m unittest tests/test_policy_hook.py
step "hooks: ledger writers still pass" python3 -W ignore -m unittest tests/test_ledger_hook.py
if command -v bun >/dev/null 2>&1; then
  step "omp hook: policy path (bun)" bun test tests/policy-hook-omp.test.ts
else
  echo "SKIP omp hook tests (bun not on PATH)"
fi
step "smoke: installed hook, authored class, reviewed vs unreviewed" bash tests/smoke-policy-hook.sh
[ "${1:-}" = "--mutation" ] && step "mutation check" python3 tests/mutation_check_policy_hook.py
[ "$rc" = 0 ] && echo "test-policy-hook: ALL PASSED" || echo "test-policy-hook: FAILURES" >&2
exit "$rc"
