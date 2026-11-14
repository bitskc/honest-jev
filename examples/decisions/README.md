# Decision specs: worked examples for `kit_decide`

Three specs, each with a `*.cases.json` of documented cases (facts, raw upstream-style answers, expected decision). The tests run every case through the pure evaluator, the `jev-eval` module target, and the MCP tool with a stubbed upstream. No case contains real customer or workplace text: answers are vectors, state is not stored.

| Spec | Decides | Shows |
|---|---|---|
| [`route-read-or-full.json`](route-read-or-full.json) | Send an inbound message to a read-only agent or the full agent | One `choice` with `min_confidence`, a fact rule first, `missing_as`, a calibration `knob`; an example routing gate (READ at >= 0.9 routes; 0.9 is an example value, not a recommendation: calibrate your own with `jev-eval`) |
| [`ask-before-migration.json`](ask-before-migration.json) | A coding agent about to run a migration: `proceed`, `ask_user`, `block` | A fact-only block with no model call, `noul` thresholds, `missing_as: 1` on risk questions, `grants` and `restrictive` |
| [`support-reply-auto-send.json`](support-reply-auto-send.json) | Is a drafted support reply safe to auto-send | `any` / `all` composition, a hold rule ahead of review, an always-human fact rule |

All three fail **open** to the host's baseline (`on_unavailable.decision` equals `baseline`). To fail closed, set `on_unavailable.decision` to something else, for example `block`; the result reports `fail_mode_applied`.

## Calibrating a threshold

A condition may carry `"knob": "<name>"` on its numeric threshold (`gte`/`lt`/..., `min_confidence`). The evaluator ignores it in production. `jev-eval` sweeps it: [`route-read-or-full.suite.json`](route-read-or-full.suite.json) points the `module` target at `server/src/decide/eval-target.mjs` (`decide`) with `read_min` as the swept parameter, over [`route-read-or-full.corpus.jsonl`](route-read-or-full.corpus.jsonl), a **synthetic** answer-vector corpus. Its labels are invented to exercise the tooling: they say nothing about any real deployment's accuracy. Calibrate on your own labelled outcomes.

## What the specs do not do

- No regular expressions, expressions, loops or templates: the grammar is closed on purpose (see `server/src/decide/validate.mjs`).
- No retries or second passes: one model call per decision. Multi-pass is the host's job: return an `escalate`-style decision and call again with different state.
- `reason` is static spec text, never model output.
