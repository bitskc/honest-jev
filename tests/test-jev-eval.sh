#!/usr/bin/env bash
# jev-eval tests: intervals, suite validation, stable split, harm scoring, calibration discipline, compare, the builtin
# offline path, the mcp target against a loopback stub, corpus safety. Offline; no credentials; corpus strings are data.
#   bash tests/test-jev-eval.sh             # needs node >= 22 (no npm install needed)
#   bash tests/test-jev-eval.sh --mutation  # also run tests/mutation_check_jev_eval.py
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 2
rc=0
step() { printf '\n== %s\n' "$1"; shift; "$@" || rc=1; }
step "jev-eval unit and integration tests" node --test scripts/jev-eval/test/
step "suite manifests in scripts/jev-eval/suites are valid" node --input-type=module -e '
import { loadSuite } from "./scripts/jev-eval/lib/suite.mjs";
import { readdirSync } from "node:fs";
for (const f of readdirSync("scripts/jev-eval/suites")) { const { suite } = loadSuite("scripts/jev-eval/suites/" + f); console.log("ok", f, suite.id, suite.target.tool); }'
[ "${1:-}" = "--mutation" ] && step "mutation check" python3 tests/mutation_check_jev_eval.py
printf '\n'; [ "$rc" -eq 0 ] && echo "test-jev-eval: ALL PASSED" || echo "test-jev-eval: FAILURES"
exit "$rc"
