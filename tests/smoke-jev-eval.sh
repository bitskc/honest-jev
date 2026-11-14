#!/usr/bin/env bash
# Smoke: run jev-eval OFFLINE (no credentials) over the kit's accuracy corpus. The corpus and the kit code come from a
# branch of this repo (default origin/fix/eval-findings, which carries evals/), extracted with `git archive` into a temp
# directory; nothing is checked out and no branch is touched. Corpus strings are data for the guard's parser, never run.
#   bash tests/smoke-jev-eval.sh [git-ref]
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
ref="${1:-origin/fix/eval-findings}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/kit"
git -C "$root" archive "$ref" server/src evals | tar -x -C "$tmp/kit"
env -i PATH="$PATH" HOME="$tmp/home" bash -c '
  set -eu
  root="$1"; kit="$2"; tmp="$3"; ref="$4"
  jev() { node "$root/scripts/jev-eval/run.mjs" "$@"; }
  echo "### dry run (no request sent), then score the guard corpus offline against the code at $ref"
  jev score "$root/scripts/jev-eval/suites/dispatch.json" --corpus "$kit/evals/dispatch.jsonl" --kit "$kit" --dry-run
  jev score "$root/scripts/jev-eval/suites/verify_done.json" --corpus "$kit/evals/verify_done.jsonl" --kit "$kit" --dry-run
  echo
  jev score "$root/scripts/jev-eval/suites/guard.json" --corpus "$kit/evals/guard.jsonl" --kit "$kit" --out "$tmp/out1" || echo "(exit $?)"
  echo; echo "### the same suite again, then an item-level compare of the two runs"
  jev score "$root/scripts/jev-eval/suites/guard.json" --corpus "$kit/evals/guard.jsonl" --kit "$kit" --out "$tmp/out2" > /dev/null
  jev compare --baseline "$tmp"/out1/*.json --current "$tmp"/out2/*.json
  echo; echo "### calibrate: every label in this corpus is derived, so it must refuse"
  jev calibrate "$root/scripts/jev-eval/suites/guard.json" --corpus "$kit/evals/guard.jsonl" --kit "$kit" --out "$tmp/out1" --state "$tmp/holdout.jsonl" || echo "(exit $?)"
' _ "$root" "$tmp/kit" "$tmp" "$ref"
