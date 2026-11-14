---
name: jev-decide
description: Use the jev-mcp kit_decide tool when an agent, in any domain, must pick one of a few actions by rule (route a message, auto-send or hold a reply, proceed or ask a person) and you can write the rules as a small table over yes/no or pick-one questions plus facts you already know. Skip it for open-ended reasoning, for sorting many items (use jev-classify), and when your host code already decides cleanly.
---

# jev-decide (kit_decide)

`kit_decide` runs a **decision spec** you pass in the call: an ordered rule table over (a) **facts** you supply, which rules test deterministically, and (b) **questions** Jev answers about the **state** you supply. First matching rule wins. A rule that needs only facts decides with **no model call**. Otherwise there is **one** Jev call, bounded by `budget_ms`, and the table turns its answers into a decision.

It is for decisions with a handful of named outcomes: `read_only` / `full_agent`, `auto_send` / `human_review` / `hold`, `proceed` / `ask_user` / `block`. It is not a planner, and it never writes or runs anything: it returns a decision and your code acts on it.

Shell fallback: `jev-call kit_decide '<json>'`. Worked specs with documented cases: `examples/decisions/` in the kit repo.

An inline `spec` is for a decision made once. When the user wants a rule they will **reuse** ("always ask me before ...") across calls or projects, do not paste a spec each time: use the `jev-policy-author` skill to store it as a named class with examples, then call `kit_decide` with `class` (the call takes either `spec` or `class`, never both).

## Call

```json
{
  "spec": { "id": "ask-before-migration", "version": 1, "...": "see below" },
  "facts": { "environment": "staging", "has_backup": true },
  "state": { "migration": { "sql": "ALTER TABLE t ADD COLUMN note text" } },
  "budget_ms": 5000,
  "host": "claude-code",
  "correlation_id": "task-42"
}
```

- `facts`: flat scalars (string, number, boolean, null), at most 32, keys like `has_backup`. **Facts are never sent to Jev.** Put everything a deterministic rule needs here.
- `state`: the text Jev reads. Keys must be simple identifiers; at most 12,000 characters serialized. Strings go through the kit's credential redactor before they leave the Worker. It matches credential shapes (API keys, bearer tokens, key blocks, URL passwords, `key=value` secrets). **It is a deny-list, not a guarantee: it does not catch a password written in prose ("my password is ..."), card numbers, national ids or other personal data, so never put secrets or regulated personal data in `state`.** Questions refer to state by backticked path (`message.text`), and Jev reads literally.
- `budget_ms`: hard deadline for the model call (default 5000, max 20000). When it passes, the spec's failure decision applies.

## Spec

```json
{
  "id": "ask-before-migration", "version": 1,
  "questions": {
    "destructive": { "type": "noul", "instructions": "Does `migration.sql` drop or rewrite existing data?",
                     "criteria": { "true": "Removes or rewrites existing schema or data.", "false": "Only adds." } }
  },
  "vocabulary": ["proceed", "ask_user", "block"],
  "grants": ["proceed"],
  "baseline": "ask_user",
  "rules": [
    { "id": "R1-prod-no-backup", "when": { "all": [{ "fact": "environment", "eq": "production" }, { "fact": "has_backup", "eq": false }] },
      "decision": "block", "reason": "Production with no backup." },
    { "id": "R2-additive", "when": { "noul": "destructive", "lt": 0.1, "missing_as": 1 },
      "decision": "proceed", "reason": "Confidently additive." }
  ],
  "default": { "decision": "ask_user", "reason": "Not clearly additive." },
  "on_unavailable": { "decision": "ask_user" }
}
```

- **Questions**: `noul` is a yes/no that answers 0..1 (criteria `true` and `false` required); `choice` picks one of 2 to 12 labels with probabilities. Every question must be used by a rule; every rule must use only declared questions.
- **Conditions** (closed list, no regex, no expressions): `{"noul": q, "gte"|"gt"|"lte"|"lt": 0..1, "missing_as"?: 0..1}`; `{"choice": q, "is": label | "in": [labels], "min_confidence"?: 0..1, "missing_as"?: bool}`; `{"choice": q, "prob_of": [labels], "gte"|...: 0..1}`; `{"fact": k, "eq"|"in"|"gt"|"gte"|"lt"|"lte"|"exists": v}`; `{"all": [...]}`, `{"any": [...]}`, `{"not": c}`. Depth 4, 32 rules, 16 questions. An absent fact makes a fact condition false.
- **`missing_as`** is what the condition sees if Jev returns a malformed answer for that question. Without it, a malformed answer sends the call down the failure path. Choose it so the missing case lands on the cautious side (for example `missing_as: 1` on a "is this risky" noul).
- **`baseline`** is what the host does when nothing decides at all. **`on_unavailable.decision`** is what this call returns when Jev cannot answer. If they are equal the spec **fails open** (to the baseline); otherwise it **fails closed**. The result reports the mode. A decision listed in `grants` (a capability or permission you add) cannot be the failure decision unless it is also the baseline: a spec that fails by granting is rejected.
- Decision words match `[a-z][a-z_]{0,31}`; rule ids `[A-Za-z0-9][A-Za-z0-9._-]{0,47}`. The record is built from these, so no free text reaches the log.

## Read the result

`decision`, `rule_id` (null for the default or a failure), `reason` (static text from your spec), `decided_by`:

| `decided_by` | Meaning |
|---|---|
| `prefilter` | Facts alone decided. No model call. |
| `jev` | Jev's answers decided (`answers` shows what was used). |
| `fail_open` / `fail_closed` | Jev did not answer usefully. `fail_reason` is one of `no_upstream`, `upstream_error`, `timeout`, `invalid_response`. |

`spec` carries `id`, `version` and a `hash` of the exact table, so a decision is reproducible later. `record` is the content-free decision record. **An `isError` result means no decision was made** (invalid spec, facts or state). The tool never turns a caller bug into a decision: apply your own failure policy.

## Keep it in host code when

- the logic is a plain function of values you already have: write the `if`;
- you need arithmetic, string matching, or a loop: the grammar is deliberately too small for that;
- you need more than one model call to decide: make one call, return an `escalate` decision, and let the host make a second call with different `state`;
- latency below roughly a second matters on every call: the fact-only path is instant, but the model path is a network round trip.

## Never

- Treat `jev` or `prefilter` as proof of safety. It is the table you wrote, applied to the answers you got.
- Reuse a spec id and version for a changed table. Bump `version`; the `hash` will differ either way.
- Put customer or workplace text in a spec you commit to a public repository.
