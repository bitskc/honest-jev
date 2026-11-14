// Policy triggers (openspec change add-policy-hook-adapter). A `trigger` on a user-layer decision opts that class into the
// PreToolUse hooks: when a Bash command matches, the hook calls the class for the agent instead of waiting to be asked.
//
//   "trigger": {
//     "tool": "Bash",
//     "command": ["gh", "pr", "merge"],
//     "facts":  { "gstack_reviewed": { "source": "gh_pr_review_marker", "marker": "gstack-review: pass", "target_from": "pr" },
//                 "pr": { "source": "gh_pr_target" } },
//     "effect": { "ask_user": "ask" }
//   }
//
// The grammar is CLOSED and has no pattern language: a tool from an enum, one to four command words, fact sources from a
// fixed list, effects from {ask, deny}. Matching reuses the guard's shell parser (server/src/kit/shell.mjs) and errs toward
// firing: an extra firing costs one decision, a missed one bypasses the gate. Everything here is pure (no I/O, no clock); the
// code that runs `git` and `gh` is scripts/jev-policy-hook.mjs.
import {
  foldLiterals, inputScripts, pipeFedScripts, processSubBodies, resolveCommand, splitSegments, stripHeredocs, substitutionSpans, unwrapScripts,
} from "../kit/shell.mjs";

export const TRIGGER_TOOLS = Object.freeze(["Bash"]);
export const TRIGGER_KEYS = Object.freeze(["tool", "command", "facts", "effect"]);
export const FACT_SOURCES = Object.freeze(["repo_root", "branch", "gh_pr_target", "gh_pr_review_marker"]);
export const EFFECTS = Object.freeze(["ask", "deny"]);
export const TRIGGER_LIMITS = Object.freeze({ command_words: 4, facts: 8, marker_chars: 80, timeout_min_ms: 100, timeout_max_ms: 1500, timeout_default_ms: 1000, command_chars: 20_000 });

const WORD = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;
const FACT = /^[a-z][a-z0-9_]{0,47}$/;
const MARKER = /^[A-Za-z0-9 ._:/@#-]{1,80}$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const SOURCE_KEYS = { repo_root: ["source"], branch: ["source"], gh_pr_target: ["source"], gh_pr_review_marker: ["source", "marker", "timeout_ms", "target_from"] };

/**
 * Validate a trigger against the decision spec it belongs to. Returns {ok:true, trigger} (normalised: defaults filled in) or
 * {ok:false, errors}. Never throws. `spec` is a validated decision spec (vocabulary and the facts its rules read).
 */
export function validateTrigger(t, spec, path = "trigger") {
  const errs = [];
  if (!isObj(t)) return { ok: false, errors: [`${path}: must be an object`] };
  for (const k of Object.keys(t)) if (!TRIGGER_KEYS.includes(k)) errs.push(`${path}: unknown key "${k.slice(0, 40)}"`);
  if (!TRIGGER_TOOLS.includes(t.tool)) errs.push(`${path}.tool: must be one of ${TRIGGER_TOOLS.join(", ")}`);
  if (!Array.isArray(t.command) || t.command.length < 1 || t.command.length > TRIGGER_LIMITS.command_words) errs.push(`${path}.command: an array of 1 to ${TRIGGER_LIMITS.command_words} words`);
  else t.command.forEach((w, i) => { if (typeof w !== "string" || !WORD.test(w)) errs.push(`${path}.command[${i}]: a word must match ${WORD} (no spaces, no pattern syntax)`); });

  const used = new Set(spec && spec.rules ? factNames(spec) : []);
  // a fact that only feeds another fact's provider (target_from) need not be read by a rule
  const feeders = new Set(isObj(t.facts) ? Object.values(t.facts).filter((x) => isObj(x) && typeof x.target_from === "string").map((x) => x.target_from) : []);
  // gh_pr_target understands the flags of `gh pr merge` only, so it is offered only to a trigger that starts with those words
  const isGhPrMerge = Array.isArray(t.command) && ["gh", "pr", "merge"].every((w, i) => t.command[i] === w);
  const facts = {};
  if (t.facts !== undefined) {
    if (!isObj(t.facts)) errs.push(`${path}.facts: must be an object`);
    else if (Object.keys(t.facts).length > TRIGGER_LIMITS.facts) errs.push(`${path}.facts: at most ${TRIGGER_LIMITS.facts} entries`);
    else {
      for (const [name, src] of Object.entries(t.facts)) {
        const p = `${path}.facts.${name.slice(0, 48)}`;
        if (!FACT.test(name)) { errs.push(`${path}.facts: key "${name.slice(0, 40)}" must match ${FACT}`); continue; }
        if (spec && !used.has(name) && !feeders.has(name)) errs.push(`${p}: no rule of the class reads fact "${name}" (a typo here would leave the gate unable to see it)`);
        if (!isObj(src) || !FACT_SOURCES.includes(src.source)) { errs.push(`${p}.source: must be one of ${FACT_SOURCES.join(", ")}`); continue; }
        for (const k of Object.keys(src)) if (!SOURCE_KEYS[src.source].includes(k)) errs.push(`${p}: unknown key "${k.slice(0, 40)}" for source ${src.source}`);
        const out = { source: src.source };
        if (src.source === "gh_pr_target" && !isGhPrMerge) errs.push(`${p}.source: gh_pr_target reads the argument list of \`gh pr merge\`, so the trigger's command must start with gh pr merge`);
        if (src.source === "gh_pr_review_marker") {
          if (typeof src.marker !== "string" || !MARKER.test(src.marker)) errs.push(`${p}.marker: a string of 1 to ${TRIGGER_LIMITS.marker_chars} characters from [A-Za-z0-9 ._:/@#-] (matched as plain text, never as a pattern)`);
          else out.marker = src.marker;
          if (src.timeout_ms !== undefined && !(Number.isInteger(src.timeout_ms) && src.timeout_ms >= TRIGGER_LIMITS.timeout_min_ms && src.timeout_ms <= TRIGGER_LIMITS.timeout_max_ms)) errs.push(`${p}.timeout_ms: an integer from ${TRIGGER_LIMITS.timeout_min_ms} to ${TRIGGER_LIMITS.timeout_max_ms}`);
          else out.timeout_ms = src.timeout_ms ?? TRIGGER_LIMITS.timeout_default_ms;
          // the provider must say WHICH pull request it asks about: without a target it would read the current branch's PR, which
          // is not the one being merged whenever the command names another
          const ref = isObj(t.facts) && typeof src.target_from === "string" ? t.facts[src.target_from] : undefined;
          if (!isObj(ref) || ref.source !== "gh_pr_target") errs.push(`${p}.target_from: required, and must name a gh_pr_target fact of this trigger`);
          else out.target_from = src.target_from;
        }
        facts[name] = out;
      }
    }
  }
  const effect = {};
  if (t.effect !== undefined) {
    if (!isObj(t.effect)) errs.push(`${path}.effect: must be an object`);
    else {
      for (const [word, e] of Object.entries(t.effect)) {
        if (spec && !spec.vocabulary.includes(word)) errs.push(`${path}.effect: "${word.slice(0, 40)}" is not a decision word of the class`);
        else if (!EFFECTS.includes(e)) errs.push(`${path}.effect.${word.slice(0, 40)}: must be one of ${EFFECTS.join(", ")}`);
        else effect[word] = e;
      }
    }
  }
  return errs.length ? { ok: false, errors: errs } : { ok: true, trigger: { tool: t.tool, command: [...t.command], facts, effect } };
}

/** Names of the facts a spec's rules read (this walks the `when` trees). */
export function factNames(spec) {
  const out = [];
  const walk = (n) => {
    if (Array.isArray(n)) { n.forEach(walk); return; }
    if (!isObj(n)) return;
    if (typeof n.fact === "string") out.push(n.fact);
    for (const v of Object.values(n)) if (typeof v === "object") walk(v);
  };
  walk(spec.rules.map((r) => r.when));
  return out;
}

/** decision word -> allow | ask | deny. An unmapped word is allow if the class grants it, otherwise ask. */
export function effectMap(spec, trigger) {
  const out = {};
  for (const w of spec.vocabulary) out[w] = trigger.effect[w] ?? (spec.grants.includes(w) ? "allow" : "ask");
  return out;
}

export const RANK = Object.freeze({ allow: 0, ask: 1, deny: 2 });
/** The stricter of two effects (allow < ask < deny). */
export const stricter = (a, b) => (RANK[b] > RANK[a] ? b : a);

// ── matching ─────────────────────────────────────────────────────────────────────────────────────────────────────
const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };
const SUBST_DEPTH = 6;
const UNWRAP_DEPTH = 8;

/**
 * Every command segment the guard would look at, plus whether a depth limit was hit. A substitution that is an assignment's
 * value (`x=$(gh pr merge 3)`) is walked too: the guard's own substitutedSegments skips it because for its rules that is data a
 * command produces; for a gate it is a command that RUNS. `truncated` means a nested body was NOT walked, so the caller must
 * not trust a "no match".
 */
export function walkSegments(command) {
  const st = { truncated: false };
  const withSubstitutions = (text, depth = 0) => {
    const segs = safe(() => splitSegments(stripHeredocs(text)), []);
    const spans = safe(() => substitutionSpans(text), []);
    if (depth >= SUBST_DEPTH) { if (spans.length) st.truncated = true; return segs; }
    return [...segs, ...spans.flatMap((sp) => withSubstitutions(text.slice(sp.bodyStart, sp.bodyEnd), depth + 1))];
  };
  const folded = safe(() => foldLiterals(command), command);
  const top = withSubstitutions(folded);
  const unwrapped = safe(() => unwrapScripts(top, UNWRAP_DEPTH), []);
  if (safe(() => unwrapScripts(top, UNWRAP_DEPTH + 1), []).length > unwrapped.length) st.truncated = true;
  const bodies = [
    ...unwrapped,
    ...safe(() => pipeFedScripts(folded), []),
    ...safe(() => processSubBodies(folded), []),
    ...safe(() => inputScripts(folded).map((b) => b.body), []),
  ];
  const nested = bodies.flatMap((b) => withSubstitutions(safe(() => foldLiterals(b), b)));
  return { segments: [...top, ...nested], truncated: st.truncated };
}
export const commandSegments = (command) => walkSegments(command).segments;

/** Indices in `args` of `want` found in order (not necessarily adjacent), or null. */
function subsequenceIdx(want, args) {
  const idx = [];
  let at = -1;
  for (const w of want) {
    const next = args.indexOf(w, at + 1);
    if (next < 0) return null;
    idx.push(next); at = next;
  }
  return idx;
}
const without = (args, idx) => args.filter((_, i) => !idx.includes(i));

/**
 * Does the trigger's command match this Bash command? EVERY matching segment counts (a command that merges two pull requests
 * must be judged on both). Returns {matched, hits, segment_count, fallback}: `hits` has one entry per matching segment, its
 * arguments with the matched subcommand words removed (flags and operands, in order); `segment_count` is how many segments the
 * parser saw in total (a lone merge is 1; anything piped, chained or nested is more); `fallback` is true when the answer
 * came from a whitespace scan instead of the parser (over-long command, a parser exception) or when a depth limit left a
 * nested body unwalked, so there may be matches nobody looked at. A fallback only ever widens the match and means quoting is
 * unknown. `segments` is a test seam for the parser.
 */
export function matchCommand(trigger, command, { segments } = {}) {
  const [prog, ...sub] = trigger.command;
  const none = { matched: false, hits: [], segment_count: 0, fallback: false };
  if (typeof command !== "string" || command === "") return none;
  let walked = null;
  if (command.length <= TRIGGER_LIMITS.command_chars) {
    walked = segments ? safe(() => ({ segments: segments(command), truncated: false }), null) : safe(() => walkSegments(command), null);
  }
  if (walked) {
    const hits = [];
    for (const seg of walked.segments) {
      const [p, args] = safe(() => resolveCommand(seg), [null, []]);
      if (p !== prog) continue;
      const idx = subsequenceIdx(sub, args);
      if (idx) hits.push(without(args, idx));
    }
    // a depth limit means a nested body was not walked: more merges may be hiding there, so what was found is not the whole story
    if (hits.length) return { matched: true, hits, segment_count: walked.segments.length, fallback: walked.truncated };
    if (!walked.truncated) return { ...none, segment_count: walked.segments.length };
  }
  // whitespace scan: widens the match when the parser could not be used or did not see everything
  const toks = command.replace(/[$()`;&|<>{}"'\\]/g, " ").split(/\s+/).filter(Boolean); // punctuation never glues a word to its neighbour
  const hits = [];
  for (let at = toks.indexOf(prog); at >= 0; at = toks.indexOf(prog, at + 1)) {
    const next = toks.indexOf(prog, at + 1);
    const rest = toks.slice(at + 1, next < 0 ? undefined : next); // up to the next occurrence of the program: one hit per use
    const idx = subsequenceIdx(sub, rest);
    if (idx) hits.push(without(rest, idx));
  }
  return hits.length ? { matched: true, hits, segment_count: 0, fallback: true } : none;
}

// ── which pull request does `gh pr merge ...` name? ───────────────────────────────────────────────────────────────
// The review provider must ask about the PR that is being merged. `gh pr merge` takes at most one positional (a number, a URL
// or a branch) and flags, some of which take a value that can itself look like a number (`--subject 12 99`). gh's own flag
// arity is encoded here; anything this table does not know is AMBIGUOUS, and ambiguous means the provider cannot answer.
const GH_MERGE_BOOL_LONG = new Set(["admin", "auto", "delete-branch", "disable-auto", "help", "merge", "rebase", "squash"]);
const GH_MERGE_VALUE_LONG = new Set(["author-email", "body", "body-file", "match-head-commit", "repo", "subject"]);
const GH_MERGE_BOOL_SHORT = new Set(["d", "h", "m", "r", "s"]);
const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "b", "t"]);
const REPO_SHAPE = /^(?:[A-Za-z0-9][A-Za-z0-9.-]{0,252}\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,99}\/[A-Za-z0-9._-]{1,100}$/;
const PR_URL_SHAPE = /^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]{0,252}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\/[A-Za-z0-9._-]{1,100}\/pull\/[0-9]{1,9}$/;
const PR_NUMBER = /^[0-9]{1,9}$/;
const AMBIGUOUS = Object.freeze({ kind: "ambiguous" });

/**
 * @param argsRest the arguments of a matched `gh pr merge` segment, matched words removed (see matchCommand)
 * @returns {kind: "number", n, repo|null} | {kind: "url", url} | {kind: "none"} (no positional: gh uses the current branch's
 *          PR) | {kind: "ambiguous"}. `repo` and `url` are validated shapes that can go into an argv unchanged; nothing else can.
 */
export function ghPrMergeTarget(argsRest) {
  if (!Array.isArray(argsRest)) return AMBIGUOUS;
  let repo = null, repoSeen = false, endOfFlags = false;
  const positional = [];
  const take = (v) => v; // a value is consumed, never interpreted, except --repo
  for (let i = 0; i < argsRest.length; i++) {
    const a = argsRest[i];
    if (typeof a !== "string") return AMBIGUOUS;
    if (endOfFlags || a === "-" || !a.startsWith("-")) { positional.push(a); continue; }
    if (a === "--") { endOfFlags = true; continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq < 0 ? a.slice(2) : a.slice(2, eq);
      if (GH_MERGE_VALUE_LONG.has(name)) {
        const v = eq < 0 ? argsRest[++i] : a.slice(eq + 1);
        if (v === undefined) return AMBIGUOUS;
        if (name === "repo") { if (repoSeen) return AMBIGUOUS; repoSeen = true; repo = take(v); }
      } else if (GH_MERGE_BOOL_LONG.has(name)) {
        if (eq >= 0 && !["true", "false"].includes(a.slice(eq + 1))) return AMBIGUOUS;
      } else return AMBIGUOUS;
      continue;
    }
    for (let k = 1; k < a.length; k++) { // a cluster of short flags; a value-taking one ends it
      const c = a[k];
      if (GH_MERGE_BOOL_SHORT.has(c)) continue;
      if (!GH_MERGE_VALUE_SHORT.has(c)) return AMBIGUOUS;
      const rest = a.slice(k + 1);
      const v = rest === "" ? argsRest[++i] : rest.startsWith("=") ? rest.slice(1) : rest;
      if (v === undefined) return AMBIGUOUS;
      if (c === "R") { if (repoSeen) return AMBIGUOUS; repoSeen = true; repo = v; }
      break;
    }
  }
  if (repoSeen && !(typeof repo === "string" && REPO_SHAPE.test(repo))) return AMBIGUOUS;
  if (positional.length === 0) return repoSeen ? AMBIGUOUS : { kind: "none" }; // gh itself refuses --repo without a PR
  if (positional.length > 1) return AMBIGUOUS;
  const [p] = positional;
  if (PR_NUMBER.test(p)) return { kind: "number", n: Number(p), repo };
  if (PR_URL_SHAPE.test(p) && !repoSeen) return { kind: "url", url: p };
  return AMBIGUOUS; // a branch name, `#99`, a URL of another shape, a 10-digit number
}

/**
 * Things in a command that change which repository `gh` talks to, or which pull request it means, without appearing in its
 * own arguments: a directory change, a repository or host chosen through the environment (any `GH_` name, also spelled with
 * split quotes, `GH_RE''PO`, or built from a variable, hence export/eval/source and expansions in an env name), a remote or the default
 * repository rewritten (`git remote`, `git config`, `gh repo set-default`), and anything that supplies the operands from
 * outside the command (`xargs`, `parallel`, `find -exec`). The plan helper runs `gh` in the call's own directory and
 * environment, so any of these makes every target ambiguous. Text-level and deliberately wide (it may also match harmless
 * text, which only means the provider cannot answer and the class's failure rule applies).
 */
const HAZARDS = [
  /(?:^|[^A-Za-z0-9_])(?:cd|pushd|popd|chdir)(?![A-Za-z0-9_])/,
  /GH_|GITHUB_ENTERPRISE|GIT_DIR|GIT_WORK_TREE|GIT_CONFIG|--git-dir/,
  /(?:^|[^A-Za-z0-9_-])env(?![A-Za-z0-9_-])[^;&|\n]*[$`]|(?:^|[\s;&|(])[A-Za-z_0-9]*[$`][^\s=]*=/, // an environment name or value built from an expansion
  /(?:^|\s)(?:-C|--chdir|--cwd)(?![A-Za-z0-9_-])/,
  /(?:^|[^A-Za-z0-9_])git(?![A-Za-z0-9_-])[^;&|\n]*(?:^|[^A-Za-z0-9_])(?:remote|config)(?![A-Za-z0-9_])/,
  /(?:^|[^A-Za-z0-9_-])set-default(?![A-Za-z0-9_-])/,
  /(?:^|[^A-Za-z0-9_-])(?:export|declare|typeset|readonly|eval|source)(?![A-Za-z0-9_-])/,
  /(?:^|[;&|(\n]\s*)\.\s+\S/,
  /(?:^|[^A-Za-z0-9_-])(?:xargs|parallel)(?![A-Za-z0-9_-])|(?:^|\s)-exec(?:dir)?(?![A-Za-z0-9_-])/,
];
export function targetHazard(command) {
  if (typeof command !== "string") return true;
  const texts = [command, command.replace(/['"\\]/g, "")]; // the second joins names split by quotes: GH_RE''PO
  return texts.some((t) => HAZARDS.some((re) => re.test(t)));
}

export const MAX_MERGE_TARGETS = 3;

/**
 * The targets of every merge in a matched command, one per hit. A command is trusted to name its target only when nothing in
 * it can change what the target means: no hazard (above), no whitespace-scan or depth-limited match, at most MAX_MERGE_TARGETS
 * merges, and a merge with no PR named (gh uses the current branch's) only when it is the whole command: the sole segment,
 * so nothing runs before it that could switch branch, and nothing is piped into it. Anything else is `ambiguous`, and an
 * ambiguous target makes the review provider unavailable.
 * @param m the result of matchCommand for a gh pr merge trigger
 * @returns array of targets (see ghPrMergeTarget); never empty for a matched command
 */
export function ghPrMergeTargets(m, command) {
  if (!m || !m.matched || m.fallback || targetHazard(command) || m.hits.length > MAX_MERGE_TARGETS) return [AMBIGUOUS];
  const sole = m.hits.length === 1 && m.segment_count === 1;
  return m.hits.map((h) => {
    const t = ghPrMergeTarget(h);
    return t.kind === "none" && !sole ? AMBIGUOUS : t;
  });
}
