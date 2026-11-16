# Handoff: remaining work on bitskc/honest-jev

This file is for the next coding agent (and for Andy). It covers **only** the honest-jev tool (`https://github.com/bitskc/honest-jev`). Site and game work lives in `bitskc/honestjev-site` (`docs/HANDOFF.md` there).

**Snapshot:** 2026-11-16 morning CT. `main` is **v0.3.2** at `bb35ad951fec7021e33b70f0b0f37ccccece449e` (`release: v0.3.2 (plugin version) (#36)`). Design issue #37 was written against v0.3.1 (`ba75198`); treat current `main` as the base.

**Hard rules**
- Never merge PRs on this repo. Never comment, close, or rebase as if you were Andy unless he asked you to in that message. Open or update a docs/fix PR, then stop for his review.
- Never put secrets in code, issues, PR bodies, chat, or this file (`MCP_BEARER_TOKEN`, `JEV_MCP_TOKEN`, Jev keys, webhook secrets). Pipe secrets on stdin; never echo them.
- Do not contact TypeSafe, Vercel, or anyone else on Andy’s behalf.
- Do not touch the production Worker `jev-mcp` / `jev-mcp.andy-e3e.workers.dev` unless Andy explicitly asked for that deploy.
- Do not start the 5-skill rewrite or the hosted multi-user build from #37 until Andy answers the open questions there (the issue itself says “Design proposal only. No code or PRs from this issue”). Land and rebase the existing fix PRs first if he wants that.
- Keep the self-hosted MIT path working. Hosted paid work must stay privacy-first (below).

---

## 1. Fix PRs #27–#31 and #33 (rebase onto v0.3.2, then owner review)

All six are **open**, not merged, and authored from `bitskc`. GitHub currently reports each as `mergeable=true` / `mergeable_state=clean` against its *recorded* base, but those bases are **behind current `main`**. They need a rebase onto **v0.3.2 / `bb35ad9` (current `main`)** before Andy reviews and merges, so CI runs on the current tree. Several PRs touch the same files (`server/src/kit/guard.mjs`, tests). Merge them **one at a time**, re-rebase the next onto the new `main` after each merge, so they do not collide.

Agents must **not** merge these. After a rebase, push the branch and leave the PR for Andy.

Suggested order (guard first, then redact, then verify): **#27 → #28 → #29 → #30 → #31 → #33**.

### What each PR fixes

| PR | Branch / head | Recorded base (behind `bb35ad9`) | What it fixes |
|---|---|---|---|
| [#27](https://github.com/bitskc/honest-jev/pull/27) | `fix/guard-force-push-variants` @ `056631059` | `ba7519814` | `kit_guard_command` only matched a standalone `--force`/`-f`. Now **ask** on bundled force flags (`-uf`, `-fu`), `+` refspecs, `--force-if-includes`, `--mirror`/`--prune`, bundled delete, and `git branch -D` spellings. Ordinary `-u` / `--tags` / `-o ci.skip` stay allow. Files: `server/src/kit/guard.mjs`, `server/test/git-force-push.test.mjs`. |
| [#28](https://github.com/bitskc/honest-jev/pull/28) | `fix/guard-case-insensitive-secret-paths` @ `a7f9c80ff` | `c859a42b3` | Secret-path rules were case-sensitive, so `cat .ENV` / `ID_RSA` was **allow** on macOS/Windows. Fold path candidates to lowercase (keeping safe exemptions like `.env.example` / `*.pub`). Files: `server/src/kit/guard.mjs`, `server/test/secret-path-case.test.mjs`. |
| [#29](https://github.com/bitskc/honest-jev/pull/29) | `fix/guard-secret-manager-cli` @ `f84769fe9` | `c859a42b3` | R1 covered secret *files* but not CLIs that print stored secrets (`pass show`, `vault kv get`, AWS SM, gcloud/az secrets, macOS `security -w`, `gpg --export-secret-keys`, `kubectl get secret`, etc.). New `secretCliPrint()` → **ask** (soft R1). Listing/writing/clipboard forms stay allow. Files: `server/src/kit/guard.mjs`, `server/test/…` (secret-manager CLI tests). |
| [#30](https://github.com/bitskc/honest-jev/pull/30) | `fix/guard-sql-drop-via-stdin` @ `a61366940` | `c859a42b3` | `DROP TABLE/DATABASE` only asked when SQL was in the client’s argv. Heredoc / here-string / pipe-into `psql`/`mysql`/`sqlite3` was **allow**. New `sqlDropViaStdin()` → **ask** (R7). DROP that never reaches a client stays allow. Out of scope: `psql -f file.sql`, `TRUNCATE`/`DELETE`. Files: `server/src/kit/guard.mjs`, `server/test/sql-drop-stdin.test.mjs`. |
| [#31](https://github.com/bitskc/honest-jev/pull/31) | `fix/redact-vendor-token-prefixes` @ `0c0d41d81` | `c859a42b3` | `redact()` missed bare vendor prefixes (`ASIA`, `glpat-`, `SG.`, `whsec_`, `hf_`, `ya29.`, `pypi-`, `xai-`, `gsk_`, etc.) that can appear in tool output before a Jev call. Keep hook/server copies in parity. Related to #4 (separators/headers still open). Files: `server/src/kit/shell.mjs`, `hooks/jev-redact.js`, tests. |
| [#33](https://github.com/bitskc/honest-jev/pull/33) | `fix/verify-passed-override-vs-failure` @ `aae4d8c4f` | `4444caf51` | `kit_verify_done` treated `checks[].passed: true` as a hard override *before* looking at output/exit, so failing test text still came back **verified**. Compute `runOutcome()` first; `passed: true` cannot outrank recognised failure or a nonzero `exit_code`. Prerequisite for the Prove It skill in #37. Files: `server/src/kit/verify.mjs`, `server/test/verify-passed-override.test.mjs`. |

Each PR body says the production Worker is **not** redeployed by the PR. After Andy merges, a Worker deploy is a separate, explicit step.

### Rebase steps (agent or Andy)

For each PR, after the previous one is on `main`:

```sh
git fetch origin
git checkout <branch>
git rebase origin/main          # v0.3.2 / bb35ad9, or whatever main is after prior merges
# resolve conflicts, keeping the PR’s tests green
cd server && npm test           # expect a clean server suite
# hooks suite if hook files changed:
#   (repo hooks tests — 185 tests were green on the original PRs)
node evals/diff-guard.mjs       # for guard PRs; should stay OK
git push --force-with-lease origin <branch>
```

Do not use a raw `--force`. Do not merge.

### Review and merge steps (owner only — Andy)

1. Confirm the branch is rebased onto current `main` (v0.3.2 or later) and CI is green.
2. Read the PR (tables in the body are the contract). Spot-check the new test file fails on old `main` and passes on the branch.
3. Merge (squash or rebase, your choice) **one PR at a time**, then rebase the next.
4. Decide when to deploy `server/` to `jev-mcp` (`npx wrangler secret` / deploy only if you intend a production rollout). Leave existing secrets alone unless you mean to rotate them.
5. After #33 is in, Prove It work in #37 can depend on it.

---

## 2. README PR #38

[#38](https://github.com/bitskc/honest-jev/pull/38) — `docs(readme): Honest Jev sprite, honestjev.com link, Jev's Honest Run teaser, new tagline`

- **Branch:** `readme-site-game` @ `dfa59ddac`, **already based on v0.3.2 / `bb35ad9`**. GitHub: `mergeable=true`, `mergeable_state=clean`.
- **What:** docs and images only. Adds the site sprite (`docs/honest-jev-sprite-192.png`) linking to https://honestjev.com, header links (site / play / star), a short “Jev’s Honest Run” teaser with a screenshot, and the #37 tagline (“Honest Jev: cheap, calibrated judgment calls for any AI agent…”). Install/tools/skills/hooks text is unchanged. A playable copy of the game is explicitly **later**, in a separate PR, once the game build is final (that work is described in the site repo’s portable-build item).
- **Checks claimed:** `bash tests/test-scripts.sh` — 153 passed, including the README guard-coverage claim check.
- **Before merge (owner):** the teaser currently describes a “Ninja Gaiden-style mode”. That name is a trademark. Please change the wording to **Shadow Jev** or a generic “ninja-action mode” before merging (site/game legal rules: homage only, no third-party trademarks in README or marketing).
- **Agents:** do not merge #38. Andy has historically handled honest-jev README PRs. A one-line link from the README to `docs/HANDOFF.md` can land after this PR, or in a tiny follow-up, to avoid a conflict.

---

## 3. Design issue #37 — 5 skills and hosted multi-user

[#37](https://github.com/bitskc/honest-jev/issues/37) — *Design: 5 core coding-agent skills + hosted multi-user Honest Jev*. **Open.** The issue is a design proposal: **no implementation PRs from this issue until Andy answers the open questions** (headline, default thresholds, what to retire, TypeSafe terms, billing unit, pricing, BYOK, resale rights, domain).

Current inventory: 10 skills, 5 hook families, 16 MCP tools (12 upstream `jev_*` + 4 `kit_*`). Upstream pin documented in the issue: `jkudish/jev-mcp` `4a9b331` (v0.14.6) via `server/build-vendor.sh`.

Phased plan from the issue (do not skip ahead of Andy’s call):

1. **Phase 0:** land audit fixes (#27–#31, #33), resolve #14/#16 (redact at construction), README repositioning + count fixes (#10). PR #38 is a partial README refresh, not the full #37 rewrite.
2. **Phase 1:** ship the 5-skill layout (below). Shape Check and Safe Read start shadow-only; Right-Size stays advisory until ledger data; Prove It merges existing gates.
3. **Phase 2:** multi-tenant core (per-request tenant, hashed API keys in D1, mandatory scrubbing on all 16 tools, content-free logging audit, rate limits).
4. **Phase 3:** Stripe billing, metered usage, Customer Portal, BYOK with envelope encryption.
5. **Phase 4:** encrypted per-tenant `kit_decide` policies and rule layers, team sharing.
6. **Phase 5:** packaged self-host, support terms, DPA, sub-processor list.

### Privacy (non-negotiable for any hosted work)

- **Do not store judgment content.** Process requests in memory and drop them when the response is sent. The decision ledger must stay content-free (scalars only: decision, rule, decided_by, latency, tiers, id-shaped correlation ids — never command, path, prompt, or message text).
- **Workers Logs must not receive payloads.** Audit `console.*`. Default `JEV_DECISION_LOG` off or to a per-tenant, content-free sink.
- **Persist only:** account (id, email, Stripe customer id), a **hashed** API key (shown once, never retrievable), and usage counters per key per day.
- **Encrypt anything that must be kept** (policies, rule layers, custom ladders, BYOK upstream keys) with a per-tenant data key wrapped by a platform KEK (envelope encryption). Deleting an account crypto-shreds its data key.
- **Scrub before upstream** with `redact()` on every string leaf for all 16 tools (the 12 `jev_*` tools take raw input today).
- TypeSafe retention/training terms are **unknown**; they must be in writing before a hosted launch. Do not contact TypeSafe unless Andy asks you to. Vercel AI Gateway ZDR is not an end-to-end guarantee; the kit client does not pass a ZDR flag today.

### Build plan for each of the 5 skills

Work in `skills/`, `hooks/`, `hooks/claude-plugin-hooks.json`, `hooks/omp/`, and the existing `kit_*` / `jev_*` server tools. Keep hooks deterministic so behaviour does not depend on the agent remembering a skill. Budget and false-positive rules are in #37; do not invent looser defaults.

**1. Shape Check (new)** — “is this the right shape for what was asked?”

- Goal: a cheap advisor at decision points (a plan is written; a new file appears outside the dirs the task names; a new dependency; a dubious fix approach). Score 0–1 and a one-line reason. Interrupt only below `interrupt_at` (default 0.35); otherwise silent + ledger. Never blocks. At most one upstream call per decision point (p50 &lt; 800 ms, p95 &lt; 2 s). Skip fact-only cases.
- Tools: `jev_decide` for alternatives, `jev_review` once a diff exists, optionally `kit_decide` with a shipped `shape-check` spec so thresholds live in a policy file.
- Fold in blast radius and scope creep as inputs to the same score, not separate skills.
- Record advisories as `enforced:false, would_have:ask` so the threshold can be tuned. User can say “shape ok” for the rest of the turn.
- Replaces: nothing directly (new). Absorbs some “is this the right fix” uses of `jev-decide`.
- Tests: unit tests for skip/interrupt/record; no block path; hook wiring for Claude Code and omp; ledger shape.

**2. Guard** — existing `kit_guard_command`

- Goal: unchanged core. Deterministic prefilter R1–R11; Jev only on the grey area. Rename skill `jev-command-guard` → **Guard**. Shrink skill text to “the hook does this; call the tool yourself only in hosts without hooks.”
- Triggers: keep H1 (`jev-guard-hook.sh` / `jev_guard_hook.py`; omp `jev-guard.ts`). Fold `fast-file-search` (plocate tip, R8) into Guard’s suggestion text if Andy agrees to retire that skill.
- Land #27–#30 here. #34 and #35 wait on Andy (see below). Document timeout fail-open (#3) in the skill.
- Tests: existing guard suite + the new files from those PRs; hook suites.

**3. Right-Size** — existing `kit_size_dispatch`

- Goal: unchanged. Before a sub-agent spawn, check whether the model/tier is bigger than the task needs. Rename `jev-dispatch-sizing` → **Right-Size**. Absorb H5.
- Triggers: promote H5 from shadow-only to **advisory** PreToolUse on `Task|Agent`, but **default to shadow until the ledger shows a low false-positive rate** (Andy’s open question #4). omp has no H5 today — add a dispatch pre-hook.
- Budget: 1 upstream call per spawn; skip already-cheapest-rung. Confidence ≥ 0.8 and margin ≥ 0.4 as today. Under-tiering is flagged, never blocked.
- Tests: existing dispatch tests; new omp hook test; shadow vs advisory mode flags.

**4. Prove It** — merge `kit_verify_done`, Honest Jev claims, and `jev_gate`

- Goal: one “done” gate, cheapest first: (1) Evidence — `kit_verify_done` deterministic check (passing runner after last change is a hard veto, never blocks); (2) Claims — classify claims in the final message with `jev_verify` and the evidence attached (not `jev_classify`); (3) optional Patch at `strict` — `jev_gate` on diff + claims.
- Triggers: Claude Code Stop gate (H4) + level hooks (H2) for off/soft/standard/strict and the statusline. omp: `jev-honest.ts` plus a stop/final-message hook if omp exposes one.
- Budget: stage 1 = 0 calls; stage 2 = 1 call only when there are changes and no fresh passing check; stage 3 = 1 call only at `strict`. p95 under 2 s for stages 1–2. Stop hook timeout stays 10 s.
- `#33` is a prerequisite (`passed: true` must not outrank failure). Block only at `standard`+ on “claims done” with no evidence; `soft` warns only.
- Replaces: `jev-honest` + `jev-verify-before-done` → Prove It. Retire H3 once claims leave `jev_classify`; redact at construction (#14, #16). Keep H2 and H4, relabelled.
- Tests: existing verify/honest tests + #33 cases; stage ordering; soft vs standard vs strict; no-block on fresh passing checks.

**5. Safe Read** — `jev_screen` on untrusted content

- Goal: fill the current gap. Before the agent acts on fetched text (web, issue/PR bodies, emails, third-party READMEs, other MCP tool output), screen with `jev_screen` → `pass | review | block | skip`. Skip local repo files the user owns.
- Triggers: Claude Code PostToolUse on `WebFetch|WebSearch` and configurable external MCP readers; omp post-hook on fetch tools. If the hook cannot suppress the result, inject a warning line.
- Budget: 1 call per document, text capped (e.g. first 32 KB + last 8 KB, after scrub). Cache by content hash for the session.
- False positives: `review` is a caution, not a block. Only `block` (injection ≥ `block_at`, default 0.75) suppresses content; the agent may re-fetch with explicit user consent. Start **shadow-only** if Andy confirms question #3.
- Tests: fixture documents for pass/review/block/skip; cache; no screening of local files; ledger records for tuning.

**Mapping leftovers:** `jev-decide` / `jev-policy-author` / `jev-classify` move to general-server docs. `jev-pr-merge-triage` and `jev-issue-triage` move to `examples/` if Andy agrees (questions #5–#6).

### Hosted multi-user — build plan (after Phase 0–1, and after the open questions)

Today each user deploys their own Worker with one shared `MCP_BEARER_TOKEN` (constant-time compare in `server/src/index.mjs`) and their own upstream key.

- **API keys:** per-user and per-project keys, scopes (which tools), rotation and revocation, constant-time hash compare. Shown once at creation.
- **Usage limits:** per-key token bucket (Durable Objects or Workers Rate Limiting). Daily counters in D1 or Analytics Engine (calls by tool, upstream tokens, decisions by `decided_by`). `jev.usage` and `pricesFrom()` already exist.
- **Paid tiers:** issue lists Free / Pro / Team / BYOK / Enterprise as open pricing questions. Do not invent prices. Stripe products, metered usage, Customer Portal in Phase 3. Check jev-mcp license and TypeSafe terms before charging (question #12).
- **BYOK:** customer TypeSafe or AI Gateway key, envelope-encrypted, decrypted in memory per request, never logged or returned; maps to `resolveUpstream()` / `JEV_UPSTREAM_API_KEY` per tenant.
- **Self-host stays the enterprise / “air-gapped-ish” path:** deploy `server/` to the customer’s Cloudflare account; MIT license remains. Paid part is support, hardened config, optional SSO, update cadence.
- **Files to touch (when work starts):** `server/src/index.mjs` (auth), `server/src/ledger/record.mjs`, `server/src/kit/jev.mjs` (`resolveUpstream`, ZDR flag), `server/src/kit/shell.mjs` (`redact` on all tools), `server/src/policy/*`, new D1 migrations for accounts/keys/usage, privacy/DPA copy that names sub-processors (Cloudflare, TypeSafe, Vercel if used, Stripe).
- **Tests:** auth hash/revocation, no content in ledger or logs (a lint or audit test), redact-on-all-tools, rate-limit behaviour, encryption/crypto-shred on account delete. No live charges in tests.

---

## 4. Issues #34 and #35 — waiting on the owner

Do **not** open fix PRs until Andy picks a tier. Both are open, P2, checked on `ba75198` with `jevAvailable: false` (data only).

**[#34](https://github.com/bitskc/honest-jev/issues/34)** — *guard: secret laundering across tool calls (cp/mv of .env) and shell-history reads*

- Same-command laundering (`cp .env x && cat x`) already blocks; splitting across two tool calls (`cp .env /tmp/x` then `cat /tmp/x`) is **allow**, by design (“lexical only”).
- `cat ~/.bash_history` / `~/.zsh_history` / `history` is **allow**, but history often holds pasted tokens.
- Options for Andy: (1) **ask** when a secret store is the *source* of `cp`/`mv`/`ln`/`install`/`rsync` to a non-secret-shaped destination; (2) treat shell-history files and `history`/`fc -l` as a bare-word **ask** (or a Jev grey-area read).
- `cp .env .env.backup` is already secret-shaped and would be unaffected.

**[#35](https://github.com/bitskc/honest-jev/issues/35)** — *guard: pkexec / run0 / su escalate without R5 (sudo and doas block)*

- R5 blocks `sudo`/`doas` outside a named package install, but `pkexec`, `run0`, `su root` / `su -` / `su -c '…'` are peeled like harmless prefixes and come back **allow**.
- Andy needs to decide: same named-install-or-block treatment as sudo/doas, or **ask** (no package-install exception)? And whether `su <non-root-user>` counts.
- The code change is small (`ELEVATED_PROGS` / `ruleSudo` + corpus) but it changes which commands block, so it waits.

---

## 5. Issue #20 — env file on cachy, `--doctor`, redacted comment

**[#20](https://github.com/bitskc/honest-jev/issues/20)** — *Provide JEV_MCP_TOKEN for cachy: reuse or rotate MCP_BEARER_TOKEN, write ~/.config/jev/env*. **Open.** This is an **owner / machine** task on Andy’s computer **cachy**, not a code PR.

When cachy is online:

1. **Prefer reuse.** If the current Worker `MCP_BEARER_TOKEN` is in a password manager or an old env file, reuse it. Rotating breaks every client still on the old value.
2. **Rotate only if step 1 finds nothing**, on cachy, without printing the value:

```sh
umask 077
tok="$(openssl rand -hex 32)"
cd <honest-jev clone>/server
printf '%s' "$tok" | npx wrangler secret put MCP_BEARER_TOKEN   # stdin, not argv; this deploys a new Worker version
```

Leave `AI_GATEWAY_API_KEY` and every other var alone.

3. Write `~/.config/jev/env` on **cachy**, mode `0600`, exact format (`install.sh --save-env` / hooks source this):

```
JEV_MCP_URL='https://jev-mcp.andy-e3e.workers.dev/mcp'
JEV_MCP_TOKEN='<token>'
```

Never paste the token into the issue, a commit, a log, or chat.

4. Verify on cachy:

```sh
set -a; . ~/.config/jev/env; set +a
cd ~/Documents/GitHub/honest-jev 2>/dev/null || git clone -q https://github.com/bitskc/honest-jev /tmp/hj && cd /tmp/hj
./install.sh --doctor        # expect: tools/list = 16 tools
```

5. **Comment on #20** (Andy or an agent he sent to cachy): which path (reused vs rotated), the new Cloudflare version ID if rotated, and the `--doctor` output with the **token redacted**. If rotated, list any other machines still on the old token.

The Worker is `https://jev-mcp.andy-e3e.workers.dev` (version `163a09c4…` was cited in the issue when it was opened). Agents must not put a new secret in this repo.

---

## Related issues (do not lose)

- **#3** — document guard timeout fail-open in the Guard skill.
- **#4** — further redact work (separators / header forms); #31 covers bare vendor prefixes only.
- **#10** — stale counts in the README; fold into the #37 repositioning (PR #38 does not fix counts).
- **#14 / #16** — redact at construction; retire H3 once Prove It stops using `jev_classify` for claims.

