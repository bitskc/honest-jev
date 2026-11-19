---
name: jev-advisor
description: >-
  Use at three fixed moments, with jev_noul and jev_decide, to get a one-line advisory second opinion from Jev:
  before building anything non-trivial (plan, new file or module, dependency), before another round (review pass,
  retry, refactor, sub-agent), and before showing the user a multiple-choice question. Also for a one-off "is this
  the right decision?". Skip for trivial steps. For a rule table that decides actions use jev-decide; for sorting
  items into buckets use jev-classify.
---

# jev-advisor

A lazy senior developer's reflexes (build less, reuse, stop early) turned into yes/no checks that Jev answers with probabilities. Jev gives numbers, not prose. You weigh them, the user decides.

Tools on the `jev` MCP server (Claude Code: `mcp__jev__jev_noul`, `mcp__jev__jev_decide`). Shell fallback: `jev-call <tool> '<json>'`, shown below. `jev_noul` takes `propositions` (strings) and `context`; `jev_decide` takes `decision`, `evidence`, `priorities`, `candidates`. Inputs: `docs/TOOLS.md`. `jev_noul` replies with `results[]` in proposition order, each with `probability`.

## 1. Before building anything non-trivial

`context` = the user's request quoted VERBATIM, then your plan in 5 lines or fewer, then one FACTS line: what a search of the codebase, the standard library or the platform found that already does this (or "searched X, found nothing"). Without it, proposition 2 is a guess. Use exactly these propositions, in this order, so results compare across sessions:

```bash
jev-call jev_noul '{"context":"USER SAID: \"Add a retry to the upload script.\"\nPLAN: new src/retry.ts with a RetryPolicy class; wrap upload() in it; add p-retry as a dependency.\nFACTS: grep -ri retry src/ found nothing; fetch has no built-in retry.","propositions":["The user'"'"'s messages ask for this.","Something already in this codebase does this.","The standard library or the platform covers this.","This adds an abstraction with only one use.","This adds a dependency that a few lines would replace.","A smaller change would satisfy the request.","The plan touches files the request does not need."]}'
```

Proposition 1 flags when LOW (at or below 0.30); propositions 2 to 7 flag when HIGH (at or above 0.70). Print one line for the strongest flag among 2 to 7 (highest probability): `Jev: likely overbuilt (0.77 "a smaller change would satisfy the request")`. If proposition 1 is the only flag, print its own probability as-is: `Jev: plan goes beyond the request (0.12 "the user's messages ask for this")`. No flags: `Jev: no objection (highest 0.34 "...")`.

## 2. Before another round

Another review pass, retry, refactor pass or sub-agent. `context` = the user's request verbatim plus facts about the LAST round's results (findings, diff stat, test output tail). Do not describe or pitch the next round: naming it inflates the answer.

```bash
jev-call jev_noul '{"context":"USER SAID: \"Fix the flaky login test.\"\nLAST ROUND: test passed 20/20 runs; diff +4 -1 in tests/login.test.ts; reviewer found no issues.","propositions":["The previous round found a problem this round fixes.","The user explicitly asked for more rounds like the last one.","Stopping now leaves requested work undone."]}'
```

Take the highest of the three probabilities; each is a reason to continue. At 0.50 or above: `Jev: round justified (0.78 "the user explicitly asked for more rounds like the last one")`. Below 0.50: `Jev: another round looks unneeded (strongest reason to continue 0.18 "the previous round found a problem this round fixes")`.

## 3. Before a multiple-choice question to the user

`evidence` = the user's own words quoted verbatim plus facts. `priorities` = the user's stated priorities quoted verbatim. `candidates` = the options you are about to show (ids match `^[a-z][a-z0-9_-]*$`, 2 to 6).

```bash
jev-call jev_decide '{"decision":"Which test runner for the new package?","evidence":"USER SAID: \"keep it boring\". FACTS: repo has vitest.config.ts and 214 vitest tests; no jest dependency.","priorities":"USER SAID: \"keep it boring\"","candidates":[{"id":"vitest","description":"Keep vitest."},{"id":"jest","description":"Migrate to jest."}]}'
```

Read `recommendation.selected`, `recommendation.escaped` and `recommendation.probabilities`. Show the options as usual, then one line under them, first match wins:
- `selected` is `ask_user`: `Jev: ask the user (0.84)`. `investigate`: `Jev: investigate first (0.61)`. `none`: `Jev: none of these (0.55)`. The number is that entry's probability.
- The top candidate's probability is under 0.60, or its margin over the next CANDIDATE (ignore `ask_user`, `investigate`, `none`) is under 0.25: `Jev: no clear pick`.
- Otherwise `Jev's pick: vitest (1.00)`.

Still show every option.

## 4. One-off

"Is this the right decision?": `jev_decide` with the real alternatives, or `jev_noul` with one proposition for a single yes/no. Sorting things into buckets: use the `jev-classify` skill. A rule table that picks an action: use `jev-decide`.

## Rules

- Advisory only. Report the numbers; never present Jev's answer as proof or as the user's decision.
- Evidence is the user's own words quoted verbatim plus facts (file names, diff stat, test output). Never your own summary of what the user wants: that lets you grade your own framing.
- One call per unchanged question. Do not re-ask to get a nicer answer. Do not reword or add to the section 1 or 2 propositions.
- No secrets in `context` or `evidence`: neither tool redacts. Redact by hand or leave it out.
- Skip the check for trivial steps (a typo, a rename, a one-line fix the user spelled out).
- Jev unreachable or erroring: one line (`Jev: unreachable, carrying on`) and continue.
- One line per check. Every threshold above (0.30, 0.70, 0.50, 0.60, 0.25) is provisional until measured on real sessions.
