// Extracts every regular-expression literal from a JavaScript source text, and builds adversarial inputs from a regex's own
// characters. Dependency-free: a small tokenizer that tracks strings, template literals (with `${}` nesting), comments and
// whether a `/` starts a regex or is a division, from the previous significant token.
const REGEX_PRECEDERS = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^", "\n", ""]);
const KEYWORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "void", "yield", "await", "delete", "throw", "new", "instanceof"]);

/** @returns {{source: string, flags: string, line: number}[]} */
export function extractRegexLiterals(src) {
  const out = [];
  let i = 0;
  let line = 1;
  let prev = ""; // previous significant character (or keyword marker)
  let prevWord = "";
  const n = src.length;
  const tmplStack = []; // brace depth at which a `${` opened inside a template
  let depth = 0;
  const readTemplate = () => {
    // at src[i] === "`" or just after a `}` closing an interpolation: scan template characters until "`" or "${"
    while (i < n) {
      const c = src[i];
      if (c === "\n") line++;
      if (c === "\\") { i += 2; continue; }
      if (c === "`") { i++; return "end"; }
      if (c === "$" && src[i + 1] === "{") { i += 2; tmplStack.push(depth); depth++; return "interp"; }
      i++;
    }
    return "end";
  };
  while (i < n) {
    const c = src[i];
    if (c === "\n") { line++; i++; prev = "\n"; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === "/" && src[i + 1] === "/") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); const body = src.slice(i, e < 0 ? n : e + 2); line += (body.match(/\n/g) || []).length; i = e < 0 ? n : e + 2; continue; }
    if (c === "'" || c === '"') {
      const q = c; i++;
      while (i < n && src[i] !== q) { if (src[i] === "\\") i++; if (src[i] === "\n") line++; i++; }
      i++; prev = "a"; prevWord = ""; continue;
    }
    if (c === "`") { i++; const r = readTemplate(); prev = r === "end" ? "a" : "{"; prevWord = ""; continue; }
    if (c === "{") { depth++; prev = "{"; i++; continue; }
    if (c === "}") {
      depth--;
      i++;
      if (tmplStack.length && tmplStack[tmplStack.length - 1] === depth) { tmplStack.pop(); const r = readTemplate(); prev = r === "end" ? "a" : "{"; prevWord = ""; continue; }
      prev = "}"; continue;
    }
    if (c === "/") {
      const isRegex = REGEX_PRECEDERS.has(prev) || (prev === "w" && KEYWORDS.has(prevWord));
      if (isRegex) {
        const start = i; i++;
        let inClass = false;
        while (i < n) {
          const d = src[i];
          if (d === "\\") { i += 2; continue; }
          if (d === "\n") break;
          if (d === "[") inClass = true;
          else if (d === "]") inClass = false;
          else if (d === "/" && !inClass) break;
          i++;
        }
        const body = src.slice(start + 1, i);
        i++;
        let fl = "";
        while (i < n && /[a-z]/.test(src[i])) fl += src[i++];
        out.push({ source: body, flags: fl, line });
        prev = "a"; prevWord = ""; continue;
      }
      i++; prev = "/"; continue;
    }
    if (/[A-Za-z_$]/.test(c)) { let w = ""; while (i < n && /[\w$]/.test(src[i])) w += src[i++]; prev = "w"; prevWord = w; continue; }
    if (/[0-9]/.test(c)) { while (i < n && /[\w.]/.test(src[i])) i++; prev = "a"; prevWord = ""; continue; }
    prev = c === ")" || c === "]" ? "a" : c; prevWord = ""; i++;
  }
  return out;
}

/** Literal runs (>= 2 chars of non-metacharacters) and single characters of a regex source, used to build a pump. */
export function regexAlphabet(source) {
  const chars = new Set();
  const classes = [];
  let literalRuns = [];
  let run = "";
  const flush = () => { if (run.length >= 2) literalRuns.push(run); run = ""; };
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === "\\") {
      const d = source[++i];
      flush();
      if (d === "s") { chars.add(" "); chars.add("\t"); } else if (d === "S" || d === "w") chars.add("a"); else if (d === "d") chars.add("1");
      else if (d === "n") chars.add("\n"); else if (d === "t") chars.add("\t"); else if (d === "r") chars.add("\r"); else if (d === "W" || d === "D" || d === "b" || d === "B") chars.add("-");
      else if (d !== undefined && !/[0-9A-Za-z]/.test(d)) { chars.add(d); run += d; continue; }
      continue;
    }
    if (c === "[") {
      flush();
      let j = i + 1; if (source[j] === "^") j++;
      const members = [];
      while (j < source.length && source[j] !== "]") {
        if (source[j] === "\\") { const d = source[j + 1]; members.push(d === "s" ? " " : d === "d" ? "1" : d === "w" ? "a" : d === "n" ? "\n" : d === "t" ? "\t" : d); j += 2; continue; }
        if (source[j + 1] === "-" && source[j + 2] && source[j + 2] !== "]") { members.push(source[j], source[j + 2]); j += 3; continue; }
        members.push(source[j]); j++;
      }
      for (const m of members) chars.add(m);
      classes.push(members);
      i = j; continue;
    }
    if ("()|?*+{}^$".includes(c)) { flush(); continue; }
    if (c === ".") { flush(); chars.add("a"); chars.add("."); continue; }
    chars.add(c); run += c;
  }
  flush();
  return { chars: [...chars], literalRuns };
}

import vm from "node:vm";

/** Adversarial inputs for one regex, built from the regex's own characters: a prefix that lets a match start (an empty one, or
 *  one of its own literal runs), a pump (one character or a short pair repeated) and a failing suffix. `exp` probes are short
 *  (an exponential regex is seconds at this length); `poly` probes are 20 KB (a polynomial one is). */
export function adversarialInputs({ source }, { polyLength = 20000, pumpCount = 36, polyUnits = 5 } = {}) {
  const { chars, literalRuns } = regexAlphabet(source);
  const prefer = ["a", ".", " ", "-", "_", "/", "=", ":", ",", ";", "1", "\n", "'", '"', "(", ")"];
  const pool = [...new Set([...chars.filter((c) => c.length === 1), "a", "."])].sort((x, y) => (prefer.indexOf(x) < 0 ? 99 : prefer.indexOf(x)) - (prefer.indexOf(y) < 0 ? 99 : prefer.indexOf(y)));
  const singles = pool.slice(0, 10);
  const punct = pool.filter((c) => /[^A-Za-z0-9]/.test(c)).slice(0, 7);
  const pairs = [];
  for (const p of punct) for (const l of ["a", "1"]) pairs.push(p + l, l + p);
  const units = [...new Set([...singles, ...pairs.slice(0, 14)])];
  const runs = [...new Set(literalRuns)].sort((a, b) => b.length - a.length).slice(0, 2);
  const prefixes = ["", ...runs, ...runs.slice(0, 1).map((r) => r + " ")];
  // the failing suffix: a bare character a `\S*` can absorb (so a match still succeeds), a newline, and WHITESPACE then a character, which
  // ends a `\S*`-style repeat and makes the whole match fail after the pump (the shape `(?:NAME=\S*\s*)+$` needs)
  const suffixes = ["!", "\n!", " !"];
  const out = [];
  for (const prefix of prefixes) for (const unit of units) for (const suffix of suffixes) {
    out.push({ kind: "exp", input: prefix + unit.repeat(pumpCount) + suffix, label: `${JSON.stringify(prefix)}+${JSON.stringify(unit)}x${pumpCount}+${JSON.stringify(suffix)}` });
  }
  // 20 KB probes cost milliseconds each for a linear regex but a quadratic one needs the whole length: fewer of them.
  for (const prefix of prefixes.slice(0, 2)) for (const unit of units.slice(0, polyUnits)) {
    out.push({ kind: "poly", input: prefix + unit.repeat(Math.ceil((polyLength - prefix.length) / unit.length)).slice(0, polyLength - prefix.length) + "!", label: `${JSON.stringify(prefix)}+${JSON.stringify(unit)}x(${polyLength} chars)+"!"` });
  }
  return out;
}

/** Runs every adversarial input against `new RegExp(source, flags)` in a vm context with a wall-clock kill, and reports the
 *  slowest exponential-style (`exp`) and 20 KB (`poly`) probe in CPU milliseconds. `timedOut` is set when the engine had to
 *  be interrupted (the probe then counts as unbounded). */
export function sweepRegex(re, { timeoutMs = 2000, ...opts } = {}) {
  const ctx = vm.createContext({ src: re.source, fl: (re.flags || "").replace(/[gy]/g, ""), s: "" });
  const script = new vm.Script("new RegExp(src, fl).test(s)");
  const worst = { exp: { ms: 0, label: "", timedOut: false }, poly: { ms: 0, label: "", timedOut: false } };
  for (const probe of adversarialInputs(re, opts)) {
    ctx.s = probe.input;
    const t0 = process.cpuUsage();
    let timedOut = false;
    try { script.runInContext(ctx, { timeout: timeoutMs }); } catch (e) { if (e && e.code === "ERR_SCRIPT_EXECUTION_TIMEOUT") timedOut = true; else return { ...worst, error: String(e).slice(0, 80) }; }
    const u = process.cpuUsage(t0);
    const ms = timedOut ? Infinity : (u.user + u.system) / 1000;
    if (ms > worst[probe.kind].ms) worst[probe.kind] = { ms, label: probe.label, timedOut };
    if (timedOut) break;
  }
  return worst;
}

/** Groups of a regex source that are repeated without an upper bound (`*`, `+`, `{n,}`) and whose body holds another unbounded
 *  quantifier or an alternation: the shapes a catastrophic backtrack needs. Lookarounds are skipped. Structural only: it lists
 *  candidates for review, it does not decide they are slow (the timing sweep does that). */
export function nestedQuantifierGroups(src) {
  const stack = [];
  const hits = [];
  const unbounded = (at) => src[at] === "*" || src[at] === "+" || (src[at] === "{" && /^\{\d+,\}/.test(src.slice(at, at + 12)));
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") { i++; continue; }
    if (c === "[") { i++; while (i < src.length && src[i] !== "]") { if (src[i] === "\\") i++; i++; } continue; }
    if (c === "(") { stack.push({ start: i, q: false, alt: false, look: /^\(\?<?[=!]/.test(src.slice(i, i + 4)) }); continue; }
    if (c === ")") {
      const g = stack.pop();
      if (!g) continue;
      const rep = unbounded(i + 1);
      if (rep && !g.look && (g.q || g.alt)) hits.push(src.slice(g.start, Math.min(i + 2, g.start + 70)));
      if (stack.length && (g.q || rep)) stack[stack.length - 1].q = true;
      continue;
    }
    if (c === "|" && stack.length) { stack[stack.length - 1].alt = true; continue; }
    if (stack.length && unbounded(i)) stack[stack.length - 1].q = true;
  }
  return hits;
}
