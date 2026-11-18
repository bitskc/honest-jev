<!-- GENERATED FILE - do not edit by hand.
     Source: jkudish/jev-mcp@4a9b331509752b1f23b3a73c4f274521d4a16020 (v0.14.6), vendored by server/build-vendor.sh, plus the kit_* tools of server/src/kit/tools.mjs and the spec-driven kit_decide.
     Regenerate: cd server && npm run gen:tools
     Checked by: server/test/tools-doc.test.mjs -->

# Tool reference

All 16 tools the Worker serves, verbatim from `tools/list`. The descriptions are the upstream text; the inputs come from each tool's JSON schema (required first).

## `jev_verify` - Verify claims against evidence

Check each claim against provided evidence text with TypeSafe Jev. Returns per claim: verdict (verified | contradicted | unsupported), full probability distribution, confidence, and whether the verdict stands on its own (auto) or needs human review. Pattern: docs.typesafe.ai/cookbooks/citation_check. Pass reports, PR descriptions, or agent briefs as claims and their cited sources, diffs, or documents as evidence.

**Required inputs:** `claims`, `evidence`
**Optional inputs:** `auto_accept`, `subject_at`
**Annotations:** none

## `jev_screen` - Screen content before it enters agent context

Judge fetched or external text with TypeSafe Jev before an agent reads it: probability it contains instructions aimed at an AI agent (prompt injection), whether it has substantive content, and (when a purpose is given) whether it is relevant to the task. Returns a recommendation: pass | review | block | skip. Pattern: docs.typesafe.ai/cookbooks/llm_guardrails.

**Required inputs:** `text`
**Optional inputs:** `purpose`, `block_at`, `review_at`
**Annotations:** none

## `jev_noul` - Calibrated probability for propositions

Return a calibrated probability for each stated proposition with TypeSafe Jev, in one batched request: high means likely, low means unlikely, middling means genuinely uncertain. Supplied context informs the judgment but is not a proof guarantee; to test claims strictly against evidence, including whether the evidence is merely silent, use jev_verify instead.

**Required inputs:** `propositions`
**Optional inputs:** `context`, `auto_accept`
**Annotations:** none

## `jev_find` - Semantic search over candidates

Rank candidates against a plain-language query with TypeSafe Jev — no embeddings needed. One Choice scores every candidate id by how well it answers the query, plus a Noul checks whether any candidate addresses the query at all (so a confident 'top hit' cannot masquerade as an answer). Pattern: docs.typesafe.ai/cookbooks/semantic_find. Use for 'which file/note/line covers X' across up to 250 candidates.

**Required inputs:** `query`, `candidates`
**Optional inputs:** `top_k`
**Annotations:** none

## `jev_classify` - Classify items against a shared label set

Assign each item to one class from a shared catalog with TypeSafe Jev, in one batched request: the class catalog is sent once and every item becomes an independent Choice question. Returns per item: the chosen class, the full distribution, confidence, winner-to-runner-up margin, and an auto-versus-review decision. Auto requires both a high top probability (default 0.85) and a clear margin (default 0.50); everything else is flagged for review. Include a manual_review class in the catalog if you want an explicit escape hatch; the tool never invents one.

**Required inputs:** `items`, `classes`
**Optional inputs:** `purpose`, `context`, `auto_accept`, `minimum_margin`
**Annotations:** none

## `jev_decide` - Decide between bounded alternatives

One unresolved, bounded decision where semantic judgment over supplied evidence could change your plan: implementation alternatives, product tradeoffs with known preferences, workflow selection. Supply 2-6 candidates, evidence, and explicit priorities. Jev returns a Choice distribution over the candidates plus escape hatches (ask_user / investigate / none), and a per-candidate per-requirement supported / contradicted / unknown judgment for each optional requirement, all in one request. One call per unchanged decision; do not repeat a call to obtain a more pleasing answer. Use source inspection, tests, the user, or a reasoning model for open-ended research, routine choices, correctness proofs, or predicting user consent. High probability is not proof.

**Required inputs:** `decision`, `evidence`, `priorities`, `candidates`
**Optional inputs:** `requirements`, `escape_hatches`, `escalate_on_contradiction`
**Annotations:** none

## `jev_rerank` - Score every candidate's relevance and return them sorted

Rerank candidates against a query with TypeSafe Jev: one independent relevance probability per candidate, all in a single request, then sorted by score. Unlike jev_find (which picks one best answer), rerank scores every candidate so the full ordering survives. TypeSafe's rerank cookbook reports that on the CLERC benchmark this pattern lifted top-1 from 5% to 18% and top-10 from 38% to 62% (docs.typesafe.ai/cookbooks). Use for retrieval ordering, dedup triage, or feed ranking across up to 250 candidates.

**Required inputs:** `query`, `candidates`
**Optional inputs:** `top_k`
**Annotations:** none

## `jev_compare` - Compare two passages for factual agreement

Judge the relation between two passages with TypeSafe Jev: same_fact, contradicts, or different_facts, with the full probability distribution, confidence, and an auto-versus-review decision. Optionally supply aspects (price, date, method, …) and each gets an independent per-aspect judgment in the same single request. Use for source reconciliation, changelog-vs-code drift, or merge sanity checks. The request supplies no evidence beyond the two passages, so a same_fact verdict means they agree with each other, not that they are true.

**Required inputs:** `passage_a`, `passage_b`
**Optional inputs:** `aspects`, `purpose`, `auto_accept`, `minimum_margin`
**Annotations:** none

## `jev_extract` - Extract fields by regex, Jev picks the right match

Extract structured fields from a document with TypeSafe Jev as the picker, not the generator: your regex finds candidate substrings in code, Jev chooses which candidate is the field's true value, and the result is returned verbatim — never model-generated text. Fields with zero regex matches never reach the model (not_found); if no field has matches, no API call is made. Ambiguous picks are flagged for review. Use for prices, dates, version numbers, IDs, and anything with a recognizable shape; keep documents bounded.

**Required inputs:** `document`, `fields`
**Optional inputs:** `purpose`, `auto_accept`, `minimum_margin`
**Annotations:** none

## `jev_audit` - Audit extracted values against their source text

Audit extracted values against the text they claim to come from, before the values are trusted: one request with a per-value failure-mode battery (hallucinated / off-target / incomplete / wrong format, each framed so true = something is wrong) plus a dedicated omission check for empty values. Any value's P(wrong) at wrong_at escalates the whole audit; max-gated, never averaged. For multimodal intake: run your vision or ASR model first to produce a dense transcript of the image, scan, or recording, screen that transcript with jev_screen, then audit the extracted values against it here — the tool never sees pixels or audio, it audits two text artifacts against each other. Schema validation catches structural errors; it can flag a schema-valid fabrication against the supplied source text — a limited cross-check, not verification of the original.

**Required inputs:** `source`, `records`
**Optional inputs:** `wrong_at`
**Annotations:** none

## `jev_review` - Review a proposed patch

Score a proposed diff against the request with TypeSafe Jev before the task is called done. Returns 0..2 rubric scores for correctness, spec match, test gap, and blast radius (the last two lower the weighted composite), a safe_to_apply probability, and an auto | review | escalate action. Auto requires safe_to_apply and min score confidence at auto_accept and the composite at composite_floor; truncated or malformed input never returns auto. Does not apply the patch or run tests. For a multi-file change, pass files instead of diff: the rubric is asked once per file in the same request and the action composes in code (auto only when every file is auto). Use jev_gate to also verify completion claims against evidence in the same call.

**Required inputs:** `request`
**Optional inputs:** `diff`, `files`, `tests`, `auto_accept`, `review_at`, `composite_floor`
**Annotations:** none

## `jev_gate` - Gate completion: review a patch and verify claims

Review a proposed patch and verify completion claims against supplied evidence in one TypeSafe Jev call. Auto only when the patch review is accepted and every claim is verified at or above auto_accept. Unsupported claims require review; confident contradictions, unknown confidence, or low confidence escalate. The request and claims are assertions to check, never proof; put supporting diff excerpts and test logs in evidence. Evidence is capped at 16 items and 200,000 characters in aggregate. Does not run tests or apply changes. Use jev_review for a patch without claims, jev_verify for claims without a patch review.

**Required inputs:** `request`, `claims`, `evidence`
**Optional inputs:** `diff`, `files`, `tests`, `auto_accept`, `review_at`, `composite_floor`
**Annotations:** none

## `kit_guard_command` - Guard a shell command or file read before an agent runs it

PreToolUse-style guard ported from jev-kit's airlock (MIT). A deterministic code prefilter runs first and decides most calls without any model call: `rm -rf ~`, `cat .env`, `echo $API_KEY`, `sudo` outside a named package install and staging a secret return block; force pushes, `reset --hard`, `DROP TABLE`, `curl | sh` return ask; plain commands such as `ls` return allow. Only calls the prefilter cannot settle (a reader aimed at a path that merely might hold secrets, or a command that reaches outside the working tree: outside writes, uploads, publishes, DB writes, service control, wildcard file ops) go to one Jev question. For those, a Jev risk score P(moderate-or-worse) >= ask_at (default 0.65) returns ask. `user_request` (the user's own words) can only soften an ask to allow, never tighten. If Jev is unavailable the guard fails open (allow) and says so in `notes`/`jev`. Output: decision allow|ask|block, score 0..1, reason, rule, suggestion.

**Required inputs:** none
**Optional inputs:** `tool`, `command`, `file_path`, `cwd`, `description`, `home`, `user_request`, `ask_at`, `disable_rules`, `host`, `correlation_id`
**Annotations:** none

## `kit_size_dispatch` - Right-size a sub-agent dispatch: is the chosen model/tier too big for the task?

Sub-agent tier guard ported from jev-kit (MIT). Jev classifies the task (lookup, mechanical_edit, scoped_implementation, judgement, hard_problem, unclear) from the description and prompt, the answer is mapped to the cheapest adequate rung of a ladder (scout-find < scout/haiku < workerS/sonnet < workerO < director/opus < fable) and compared with the chosen model. Over-tiered by 2+ rungs, or the top rung with no stated prior failure, returns action block; one rung over returns warn; cheaper than needed is flagged but never blocked. Only judged when Jev's confidence >= 0.8 and margin >= 0.4. Pass `ladder` to use your own model/agent names. Fails open if Jev is unavailable.

**Required inputs:** `description`, `model`
**Optional inputs:** `prompt`, `ladder`, `host`, `correlation_id`
**Annotations:** none

## `kit_verify_done` - Check whether an agent's 'done' was verified

Done-without-verifying check ported from jev-kit's belay (jev-belay, MIT). Deterministic first: a passing test/build/lint run AFTER the last file change means verified (it can never block); no file changes means not applicable. Otherwise one Jev call asks four questions (claims done? claims checks passed? would checks apply? outcome) and returns verdict unverified/block when the agent presents changed work as finished with no fresh passing check. Give it `transcript_tail` (Claude Code JSONL of the last turn) or `file_changes` + `checks`, plus `final_message`. Output: verified true|false|null, verdict, action allow|block, reason. Fails open if Jev is unavailable.

**Required inputs:** none
**Optional inputs:** `final_message`, `task`, `transcript_tail`, `file_changes`, `checks`, `threshold`, `host`, `correlation_id`
**Annotations:** none

## `kit_decide` - Decide from a spec

Evaluate a decision spec, given inline or as a class resolved from policy layers: an ordered rule table over facts you supply and yes/no or pick-one questions Jev answers about `state`. Fact-only rules decide with no model call; otherwise one Jev call asks the spec's questions and the first matching rule decides. Returns the decision, the matching rule id, whether it came from facts, Jev or the spec's failure path, the answers used, and a content-free record. The spec fixes what happens when Jev is unavailable (on_unavailable) and the decision a host takes with no decider (baseline). An error result means NO decision was made (bad spec, facts or state): apply your own failure policy. state is redacted by a deny-list before it leaves, so do not put secrets in it.

**Required inputs:** none
**Optional inputs:** `spec`, `class`, `policy_layers`, `state`, `facts`, `budget_ms`, `host`, `correlation_id`
**Annotations:** none

<!-- inputSchema sha256 (full, canonical JSON of each tool's schema):
jev_verify 4d8c0edff7fb36249cacd6943c256c5e3e058566b09fb5cab0cb9c9b8fc6a4f8
jev_screen aa0958f5a0cc4346f7a3c7b15f4848e5bab29fef09d2bfe2f37a6f08f35dac59
jev_noul eea83f831d42eb9f2a4ef2d55ab8997ccf838d3d1d51a885db4185b7104fb3b5
jev_find d0fe7be90b1755e0c1025634eba6cbbb19f565bb6675a9e920caa7b4614f3499
jev_classify f07dd0d578d52eed23e9c14c78375b3f1d50432aa535d95669c6c63a5e8202df
jev_decide 0c71dc85abf347f4b7ada16a696e75f3181a00327d3eaa910ce2f1bc37485990
jev_rerank 3989fa39235ea388004c55c6eada18afbfa18660481edbbed8d723d51efcf958
jev_compare 60426b6f82fe2ea9626a21bc5fa3f76c3f0ef41a1f1b97e47904eae665f8eae5
jev_extract d89ebbf26490fddbdf80e63bdf8f14ffc295fdb2731f0d9bdd0f89fd51f5b20f
jev_audit 156df43208c9373ba27e2d659380bab95291b062fe2a56df38e52801a6867649
jev_review 53cec1969782add4700b4c461ad89631bdaba8309ef9c1dd942780231009aa70
jev_gate eb8919e5a845b87eb29d846a365a668d9a49ea1cdd47348c77dd414baca8a09d
kit_guard_command 5165c5a396af7ca0f9b985257e23f8755b2a327c8b947375dce284029d4fdce6
kit_size_dispatch 03aa96e58958a6dd197e0c3a9ec327444dd5ecbdef943889747fdb00e96d46bd
kit_verify_done 3737436f1570c3d540acd68a1e38777ee4c0bfedc49b0f3322c00e0d8999b5a2
kit_decide 0e0e533c7a4b1dc48b4423abbda266e758526829641f00ecf0a980fde926fd3d
-->
