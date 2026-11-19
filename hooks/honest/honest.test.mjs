// node --test "hooks/honest/**/*.test.mjs"
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const here = path.dirname(new URL(import.meta.url).pathname);
const rt = require("./jev-honest-runtime.js");

const fresh = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "honest-")); process.env.CLAUDE_CONFIG_DIR = d; return d; };
const freshXdg = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-")); process.env.XDG_CONFIG_HOME = d; return d; };
const freshRepo = () => fs.mkdtempSync(path.join(os.tmpdir(), "repo-"));
const run = (script, stdin = "", env = {}) =>
  execFileSync("node", [path.join(here, script)], { input: stdin, env: { ...process.env, ...env }, encoding: "utf8" });
const inRepo = (repo, fn) => {
  const prev = process.cwd();
  process.chdir(repo);
  try { return fn(); } finally { process.chdir(prev); }
};

// Every test that touches CLAUDE_CONFIG_DIR, XDG_CONFIG_HOME, JEV_HONEST_DEFAULT_LEVEL or cwd (via fresh(),
// freshXdg(), or a direct process.env/process.chdir write) is auto-isolated here: a leaked env var or a
// cwd left pointing at a scratch dir can never bleed into the next test, regardless of whether that test
// remembers to clean up after itself.
const ISOLATED_ENV_KEYS = ["CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "JEV_HONEST_DEFAULT_LEVEL"];
let savedEnv, savedCwd;
test.beforeEach(() => {
  savedEnv = Object.fromEntries(ISOLATED_ENV_KEYS.map((k) => [k, process.env[k]]));
  savedCwd = process.cwd();
});
test.afterEach(() => {
  for (const k of ISOLATED_ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  process.chdir(savedCwd);
});

test("rules: no built-in rules ship; the list is empty with no user or repo files", () => {
  freshXdg();
  inRepo(freshRepo(), () => {
    assert.equal(rt.rules().length, 0);
  });
});

test("rules: layer merge order — user global beats built-in, repo beats user global, on the same id", () => {
  const xdg = freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([{ id: "pr-gstack-reviewed", when: "user override", ask: "user ask", evidence: "user" }]));
    assert.equal(rt.rules().find((r) => r.id === "pr-gstack-reviewed").when, "user override");
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "pr-gstack-reviewed", when: "repo override", ask: "repo ask", evidence: "repo" }]));
    assert.equal(rt.rules().find((r) => r.id === "pr-gstack-reviewed").when, "repo override");
  });
});

test("rules: a disabled entry at a later layer removes an earlier layer's same-id rule", () => {
  const xdg = freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([{ id: "migration-prod-safe", when: "w", ask: "a", evidence: "e" }]));
    assert.ok(rt.rules().some((r) => r.id === "migration-prod-safe"));
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "migration-prod-safe", disabled: true }]));
    assert.equal(rt.rules().find((r) => r.id === "migration-prod-safe"), undefined);
  });
});

test("rules: malformed entries and an unparsable file are skipped, never crash", () => {
  const xdg = freshXdg();
  inRepo(freshRepo(), () => {
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([
      { id: "bad id with spaces", when: "x", ask: "y" },
      { id: "no-ask", when: "x" },
      { when: "x", ask: "y" },
      { id: "good-one", when: "a real situation", ask: "a real question", evidence: "proof" },
    ]));
    const list = rt.rules();
    assert.ok(list.some((r) => r.id === "good-one"));
    assert.equal(list.length, 1); // good-one only; every malformed entry skipped
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), "not json at all");
    assert.doesNotThrow(() => rt.rules());
    assert.equal(rt.rules().length, 0); // unparsable file contributes nothing; no built-in rules ship
  });
});

test("repo rules: a rules file over 8 KB is ignored whole; a small one still loads", () => {
  freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    const file = path.join(repo, ".jev", "rules.json");
    fs.writeFileSync(file, JSON.stringify([{ id: "repo-small-rule", when: "a real situation", ask: "a real question", evidence: "proof" }]));
    assert.ok(rt.rules().some((r) => r.id === "repo-small-rule"));
    fs.writeFileSync(file, JSON.stringify([{ id: "repo-small-rule", when: "a real situation", ask: "a real question", evidence: "x".repeat(9000) }]));
    assert.ok(fs.statSync(file).size > 8192);
    assert.ok(!rt.rules().some((r) => r.id === "repo-small-rule"));
  });
});

test("repo rules: control, bidi and format characters are stripped from rule text before it reaches the model", () => {
  freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "repo-cleaned-rule", when: "deploy\u202e \u200bto\u0007 prod\u001b[31m", ask: "did\u2066 migrations\u00ad run?", evidence: "proof\ufeff" }]));
    const r = rt.rules().find((x) => x.id === "repo-cleaned-rule");
    assert.equal(r.when, "deploy to prod");
    assert.equal(r.ask, "did migrations run?");
    assert.equal(r.evidence, "proof");
  });
});

test("parseRuleCommand: quoted, natural-language, list, remove, disable, and explicit repo-scope forms", () => {
  assert.deepEqual(rt.parseRuleCommand('honest-jev rule add "deploying to prod" -> "did migrations run?"'),
    { action: "add", when: "deploying to prod", ask: "did migrations run?", evidence: "", repo: false });
  assert.deepEqual(rt.parseRuleCommand('/honest-jev rule add "x" -> "y" evidence: "z"'),
    { action: "add", when: "x", ask: "y", evidence: "z", repo: false });
  // the jev-honest alias (same as parseCommand's level-switch alias) must also match rule commands
  assert.deepEqual(rt.parseRuleCommand("jev-honest rule list"), { action: "list" });
  assert.deepEqual(rt.parseRuleCommand('/jev-honest rule add "x" -> "y"'),
    { action: "add", when: "x", ask: "y", evidence: "", repo: false });
  // a "repo" substring inside when/ask/evidence is not a scope marker: stays user-global
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule add: when touching the repo ask is CI green evidence CI link"),
    { action: "add", when: "touching the repo", ask: "is CI green", evidence: "CI link", repo: false });
  // trailing --repo / (repo) on the whole command selects the repo layer
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule add: when touching the repo ask is CI green evidence CI link --repo"),
    { action: "add", when: "touching the repo", ask: "is CI green", evidence: "CI link", repo: true });
  assert.deepEqual(rt.parseRuleCommand('honest-jev rule add "x" -> "y" (repo)'),
    { action: "add", when: "x", ask: "y", evidence: "", repo: true });
  // a leading "repo" token right after add/remove/disable also selects the repo layer
  assert.deepEqual(rt.parseRuleCommand('honest-jev rule add repo "x" -> "y"'),
    { action: "add", when: "x", ask: "y", evidence: "", repo: true });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule list"), { action: "list" });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule remove some-id"), { action: "remove", id: "some-id", repo: false });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule remove repo some-id"), { action: "remove", id: "some-id", repo: true });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule remove some-id --repo"), { action: "remove", id: "some-id", repo: true });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule disable some-id"), { action: "disable", id: "some-id", repo: false });
  assert.deepEqual(rt.parseRuleCommand("honest-jev rule disable some-id (repo)"), { action: "disable", id: "some-id", repo: true });
  assert.equal(rt.parseRuleCommand("talk about honest-jev rule stuff"), null);
  assert.equal(rt.parseRuleCommand("just a normal prompt"), null);
});

test("hooks end to end: rule add via mode-tracker writes the file and emits the rule; rule remove masks it", () => {
  const d = fresh(); freshXdg(); // CLAUDE_CONFIG_DIR set AND XDG_CONFIG_HOME set: the former must win
  inRepo(freshRepo(), () => {
    const added = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: 'honest-jev rule add "shipping a release" -> "did CI run?" evidence: "CI link"' }));
    assert.match(added, /^HONEST JEV RULE ADDED: \[shipping-a-release\]/);
    const file = JSON.parse(fs.readFileSync(path.join(d, "jev", "rules.json"), "utf8"));
    assert.equal(file.length, 1);
    assert.equal(file[0].id, "shipping-a-release");
    const removed = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "honest-jev rule remove shipping-a-release" }));
    assert.equal(removed, "HONEST JEV RULE REMOVED: shipping-a-release");
    assert.ok(!rt.rules().some((r) => r.id === "shipping-a-release"));
  });
});

test("userConfigDir/userRulesPath: CLAUDE_CONFIG_DIR wins over a populated XDG_CONFIG_HOME", () => {
  const d = fresh();
  const xdg = freshXdg();
  assert.equal(rt.userConfigDir(), path.join(d, "jev"));
  fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
  fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([{ id: "xdg-only", when: "x", ask: "y" }]));
  inRepo(freshRepo(), () => {
    assert.ok(!rt.rules().some((r) => r.id === "xdg-only")); // the XDG file is never read while CLAUDE_CONFIG_DIR is set
  });
  delete process.env.CLAUDE_CONFIG_DIR;
  assert.equal(rt.userConfigDir(), path.join(xdg, "jev")); // unset CLAUDE_CONFIG_DIR: falls back to XDG_CONFIG_HOME
  inRepo(freshRepo(), () => {
    assert.ok(rt.rules().some((r) => r.id === "xdg-only"));
  });
});

test("instructions: no Rules section (or anything else) at level off", () => {
  assert.equal(rt.instructions("off"), "HONEST JEV ACTIVE — level: off\n\n");
});

test("parseCommand: whole-message switch only, aliases and namespaced forms", () => {
  const cases = {
    "/honest-jev strict": "strict", "honest-jev soft": "soft", "/jev-honest standard": "standard",
    "/honest-jev:honest-jev strict": "strict", "@honest-jev off": "off", "/honest-jev": "standard",
    "/honest-jev lite": "soft", "/honest-jev full": "standard", "/honest-jev on": "standard",
    "Normal mode.": "off", "stop honest-jev": "off",
    "/honest-jev bogus": null, "please set honest-jev strict later": null, "add a normal mode toggle": null, "": null,
  };
  for (const [prompt, want] of Object.entries(cases)) assert.equal(rt.parseCommand(prompt), want, JSON.stringify(prompt));
});

test("filterSkillBody: only the active level's table row survives, everything else verbatim", () => {
  const body = "---\nname: x\n---\n# T\n| Level | What |\n|---|---|\n| **soft** | a |\n| **standard** | b |\n| **strict** | c |\n- rule stays\n| **Other** | not a level |";
  const out = rt.filterSkillBody(body, "strict");
  assert.ok(out.includes("| **strict** | c |") && !out.includes("**soft**") && !out.includes("**standard**"));
  assert.ok(out.includes("- rule stays") && out.includes("| **Other** |") && !out.includes("name: x"));
});

test("instructions: real SKILL.md is injected with exactly one level row", () => {
  fresh(); const xdg = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-")); process.env.XDG_CONFIG_HOME = xdg;
  inRepo(freshRepo(), () => {
    for (const level of ["soft", "standard", "strict"]) {
      const text = rt.instructions(level);
      assert.ok(text.startsWith(`HONEST JEV ACTIVE — level: ${level}`));
      assert.equal((text.match(/^\| \*\*/gm) || []).length, 1, level);
    }
  });
});

test("defaultLevel: env beats config file beats off", () => {
  const d = fresh();
  freshXdg(); // populated but ignored: CLAUDE_CONFIG_DIR wins over XDG_CONFIG_HOME
  delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  assert.equal(rt.defaultLevel(), "off");
  fs.mkdirSync(path.join(d, "jev")); fs.writeFileSync(path.join(d, "jev", "config.json"), '{"honestLevel":"soft"}');
  assert.equal(rt.defaultLevel(), "soft");
  process.env.JEV_HONEST_DEFAULT_LEVEL = "strict";
  assert.equal(rt.defaultLevel(), "strict");
  assert.equal(fs.existsSync(path.join(d, ".jev-honest-active")), false);
});
test("activate/subagent: a config-default level is never persisted, so editing the config takes effect next session", () => {
  const d = fresh();
  freshXdg(); delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  fs.mkdirSync(path.join(d, "jev")); fs.writeFileSync(path.join(d, "jev", "config.json"), '{"honestLevel":"soft"}');
  assert.match(run("jev-honest-activate.js"), /^HONEST JEV ACTIVE — level: soft/);
  assert.equal(fs.existsSync(path.join(d, ".jev-honest-active")), false); // never persisted: a default resolution is not an explicit choice
  fs.writeFileSync(path.join(d, "jev", "config.json"), '{"honestLevel":"strict"}');
  assert.match(run("jev-honest-activate.js"), /^HONEST JEV ACTIVE — level: strict/); // picks up the edited config, not frozen at "soft"
  const sub = JSON.parse(run("jev-honest-subagent.js"));
  assert.match(sub.hookSpecificOutput.additionalContext, /level: strict/); // subagent independently resolves the same live default
  // an explicit switch still persists and still wins over the config default
  assert.match(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "/honest-jev soft" })), /^HONEST JEV LEVEL CHANGED/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "soft\n");
  fs.writeFileSync(path.join(d, "jev", "config.json"), '{"honestLevel":"strict"}');
  assert.match(run("jev-honest-activate.js"), /^HONEST JEV ACTIVE — level: soft/); // explicit choice still beats the (now different) default
});

test("hooks end to end: fresh install is silent; prompt switch writes flag and injects; subagent mirrors; off persists", () => {
  const d = fresh(); delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  assert.equal(run("jev-honest-activate.js"), "");
  assert.equal(run("jev-honest-subagent.js"), "");
  const changed = run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "/honest-jev strict" }));
  assert.match(changed, /^HONEST JEV LEVEL CHANGED — level: strict/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "strict\n");
  assert.match(run("jev-honest-activate.js"), /^HONEST JEV ACTIVE — level: strict/);
  const sub = JSON.parse(run("jev-honest-subagent.js"));
  assert.equal(sub.hookSpecificOutput.hookEventName, "SubagentStart");
  assert.match(sub.hookSpecificOutput.additionalContext, /level: strict/);
  assert.equal(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "talk about honest-jev strict mode" })), "");
  assert.match(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "honest-jev off" })), /^HONEST JEV OFF.*The command guard is separate and still on \(JEV_GUARD_MODE=shadow \+ restart to log only\)/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  assert.equal(run("jev-honest-mode-tracker.js", "not json"), "");
});
test("off persists across resume even with a configured default: activate never re-arms a turned-off flag", () => {
  // P2: clearLevel() instead of writing "off" let an absent flag fall through to defaultLevel() on the
  // very next SessionStart, silently re-arming a configured non-off default one or two activations later.
  const d = fresh();
  const xdg = fs.mkdtempSync(path.join(os.tmpdir(), "xdg-"));
  process.env.XDG_CONFIG_HOME = xdg; delete process.env.JEV_HONEST_DEFAULT_LEVEL;
  fs.mkdirSync(path.join(xdg, "jev")); fs.writeFileSync(path.join(xdg, "jev", "config.json"), '{"honestLevel":"strict"}');
  assert.match(run("jev-honest-mode-tracker.js", JSON.stringify({ prompt: "/honest-jev off" })), /^HONEST JEV OFF/);
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  // first activate (e.g. resume): the legacy-config notice is the only output, sent to the user as systemMessage (it is
  // named once per config dir), and the flag is untouched
  const first = JSON.parse(run("jev-honest-activate.js"));
  assert.match(first.systemMessage, /^HONEST JEV: a legacy ~\/\.config\/jev settings file/);
  assert.equal(first.hookSpecificOutput.additionalContext, "");
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
  // second activate (e.g. a later compact/resume of the same session): silent, still off, despite the configured default
  assert.equal(run("jev-honest-activate.js"), "");
  assert.equal(fs.readFileSync(path.join(d, ".jev-honest-active"), "utf8"), "off\n");
});

test("activate: statusline nudge composes with an existing command and is skipped once wired", () => {
  const d = fresh();
  fs.writeFileSync(path.join(d, ".jev-honest-active"), "standard\n");
  fs.writeFileSync(path.join(d, "settings.json"), JSON.stringify({ statusLine: { type: "command", command: "bash /x/ponytail-statusline.sh" } }));
  const out = run("jev-honest-activate.js");
  assert.match(out, /STATUSLINE SETUP NEEDED/);
  assert.match(out, /"command":"bash \/x\/ponytail-statusline\.sh; bash \\"[^"]*jev-honest-statusline\.sh\\""/);
  fs.writeFileSync(path.join(d, "settings.json"), JSON.stringify({ statusLine: { type: "command", command: "bash /x/jev-honest-statusline.sh" } }));
  assert.doesNotMatch(run("jev-honest-activate.js"), /STATUSLINE SETUP NEEDED/);
});

test("control/format class is one literal in the runtime, the omp hook and the report", () => {
  const cls = String.raw`[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\u206a-\u206f\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}\p{Cf}]`;
  const ansi = String.raw`\x1b\[[0-9;]*[A-Za-z]`;
  for (const f of ["hooks/honest/jev-honest-runtime.js", "hooks/omp/jev-honest.ts", "scripts/jev-report.mjs"]) {
    const text = fs.readFileSync(new URL("../../" + f, import.meta.url), "utf8");
    assert.ok(text.includes(cls), `${f}: control/format class differs from the shared literal`);
    assert.ok(text.includes(ansi), `${f}: ANSI pattern differs`);
  }
});

test("legacy config notice: a fixed sentence, once per config dir; legacy copies are never loaded", async () => {
  const { createRequire } = await import("node:module");
  const rt = createRequire(import.meta.url)("./jev-honest-runtime.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "jev-legacy-"));
  const saved = { c: process.env.CLAUDE_CONFIG_DIR, x: process.env.XDG_CONFIG_HOME };
  try {
    const xdg = path.join(root, "xdg");
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify([{ id: "legacy-rule", when: "w", ask: "a" }]));
    process.env.CLAUDE_CONFIG_DIR = path.join(root, "claude");
    process.env.XDG_CONFIG_HOME = xdg;
    const first = rt.legacyNoticeOnce();
    assert.equal(first, "HONEST JEV: a legacy ~/.config/jev settings file (rules.json or config.json) is ignored in this sandboxed session; see README 'CLAUDE_CONFIG_DIR'.");
    assert.doesNotMatch(first, /cp |mkdir|jev\/rules/);
    assert.equal(rt.legacyNoticeOnce(), null);
    assert.ok(!rt.rules().some((r) => r.id === "legacy-rule"));
    process.env.CLAUDE_CONFIG_DIR = path.join(root, "claude2");
    assert.notEqual(rt.legacyNoticeOnce(), null);
  } finally {
    for (const [k, v] of [["CLAUDE_CONFIG_DIR", saved.c], ["XDG_CONFIG_HOME", saved.x]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// Runs rules() in a child process so a blocking read (a FIFO) shows up as a timeout instead of hanging the suite.
async function rulesInChild(repo, home) {
  const { spawnSync } = await import("node:child_process");
  const rtPath = new URL("./jev-honest-runtime.js", import.meta.url).pathname;
  return spawnSync(process.execPath, ["-e", `process.stdout.write(JSON.stringify(require(${JSON.stringify(rtPath)}).rules()))`], {
    cwd: repo, timeout: 5000, encoding: "utf8",
    env: { ...process.env, CLAUDE_CONFIG_DIR: path.join(home, "claude"), XDG_CONFIG_HOME: path.join(home, "xdg") },
  });
}

test("repo rules: a FIFO at .jev/rules.json is ignored and never blocks the hook", async () => {
  const { spawnSync } = await import("node:child_process");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "jev-fifo-home-"));
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "jev-fifo-repo-"));
  fs.mkdirSync(path.join(repo, ".jev"));
  assert.equal(spawnSync("mkfifo", [path.join(repo, ".jev", "rules.json")]).status, 0);
  const r = await rulesInChild(repo, home);
  assert.ifError(r.error); // ETIMEDOUT here means the read blocked on the FIFO
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!JSON.parse(r.stdout).some((x) => x.id === "fifo-rule"));
});

test("repo rules: a newline between words becomes a space, not a join", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "jev-glue-home-"));
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "jev-glue-repo-"));
  fs.mkdirSync(path.join(repo, ".jev"));
  fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "glued-rule", when: "alpha\nbeta\u001b[0m\tgamma", ask: "x" }]));
  const r = await rulesInChild(repo, home);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).find((x) => x.id === "glued-rule").when, "alpha beta gamma");
});

const EXAMPLE = JSON.parse(fs.readFileSync(path.join(here, "..", "..", "examples", "rules", "migration-prod-safe.json"), "utf8"));
const MIGRATION_LINE = "- [migration-prod-safe] When describing a database migration as safe: Was it run against a copy of prod data? — Evidence: the command and its output";

test("injection: the opt-in migration example reaches standard and strict instructions once copied to the user layer", () => {
  const xdg = freshXdg();
  fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
  fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify(EXAMPLE));
  inRepo(freshRepo(), () => {
    assert.ok(rt.instructions("standard").includes(MIGRATION_LINE));
    assert.ok(rt.instructions("strict").includes(MIGRATION_LINE));
    assert.ok(!rt.instructions("off").includes("- [migration-prod-safe] When"));
  });
});

test("injection: the migration line is absent with no rule files, and a repo disabled mask removes it", () => {
  const xdg = freshXdg();
  inRepo(freshRepo(), (repo = process.cwd()) => {
    assert.ok(!rt.instructions("standard").includes("- [migration-prod-safe] When"));
    fs.mkdirSync(path.join(xdg, "jev"), { recursive: true });
    fs.writeFileSync(path.join(xdg, "jev", "rules.json"), JSON.stringify(EXAMPLE));
    assert.ok(rt.instructions("standard").includes(MIGRATION_LINE));
    fs.mkdirSync(path.join(repo, ".jev"), { recursive: true });
    fs.writeFileSync(path.join(repo, ".jev", "rules.json"), JSON.stringify([{ id: "migration-prod-safe", disabled: true }]));
    assert.ok(!rt.instructions("standard").includes("- [migration-prod-safe] When"));
  });
});

test("parity: the SKILL.md worked example parses to exactly the shipped migration-prod-safe example", () => {
  assert.equal(EXAMPLE.length, 1);
  const skill = fs.readFileSync(path.join(here, "..", "..", "skills", "jev-honest", "SKILL.md"), "utf8");
  const m = skill.match(/rule `(\{"id": "migration-prod-safe"[^`]*\})`/);
  assert.ok(m, "SKILL.md worked example not found");
  assert.deepEqual(JSON.parse(m[1]), EXAMPLE[0]);
});
