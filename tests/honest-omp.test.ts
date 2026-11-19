// omp Honest Jev hook behaviour (hooks/omp/jev-honest.ts): repo-rule size cap, rule-text cleaning, the legacy-config
// notice, and FIFO safety. Behavioural, not source greps. Run with bun:
//   bun test tests/honest-omp.test.ts
// The hook reads PI_CODING_AGENT_DIR per call, so an in-process instance follows the env. The legacy-notice checks still
// run in a child process per session, like a real omp session does; the in-process hook instances below cover rules()
// and the /honest-jev level flag.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "jev-omp-honest-"));
const XDG = join(root, "xdg");
const REPO = join(root, "repo");
const LEGACY_NOTICE = "HONEST JEV: a legacy ~/.config/jev settings file (rules.json or config.json) is ignored in this sandboxed session; see README 'CLAUDE_CONFIG_DIR'.";
const HOOK_URL = new URL("../hooks/omp/jev-honest.ts", import.meta.url).href;
const savedEnv = { agent: process.env.PI_CODING_AGENT_DIR, xdg: process.env.XDG_CONFIG_HOME };
const savedCwd = process.cwd();

beforeAll(() => {
  mkdirSync(join(XDG, "jev"), { recursive: true });
  mkdirSync(join(REPO, ".jev"), { recursive: true });
  process.env.XDG_CONFIG_HOME = XDG;
  process.chdir(REPO);
});
afterAll(() => {
  process.chdir(savedCwd);
  for (const [k, v] of [["PI_CODING_AGENT_DIR", savedEnv.agent], ["XDG_CONFIG_HOME", savedEnv.xdg]]) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  rmSync(root, { recursive: true, force: true });
});

// An in-process hook instance: the registered command, the captured event handlers, and the messages it sent.
async function freshHook(agentDir: string) {
  process.env.PI_CODING_AGENT_DIR = agentDir;
  const mod = await import(`${HOOK_URL}?agent=${encodeURIComponent(agentDir)}`);
  const cmds: Record<string, { handler: (args: string, ctx: unknown) => Promise<void> }> = {};
  const handlers: Record<string, (e: unknown, ctx: unknown) => Promise<unknown>> = {};
  const sent: string[] = [];
  mod.default({
    on: (name: string, fn: (e: unknown, ctx: unknown) => Promise<unknown>) => { handlers[name] = fn; },
    registerCommand: (name: string, opts: { handler: (args: string, ctx: unknown) => Promise<void> }) => { cmds[name] = opts; },
    sendMessage: (m: { content: string }) => { sent.push(m.content); },
  });
  return { cmds, handlers, sent };
}

// One omp session start in a fresh process: returns the notices the hook sent through ctx.ui.notify.
function sessionStartNotices(agentDir: string): string[] {
  const script = `(async () => {
    const m = await import(${JSON.stringify(HOOK_URL)});
    const handlers = {};
    m.default({ on(n, f) { handlers[n] = f; }, registerCommand() {}, sendMessage() {} });
    const notes = [];
    await handlers["session_start"]({}, { ui: { notify: (msg) => notes.push(msg), setStatus() {} } });
    process.stdout.write(JSON.stringify(notes));
  })();`;
  const r = spawnSync(process.execPath, ["-e", script], {
    cwd: REPO,
    env: { ...process.env, PI_CODING_AGENT_DIR: agentDir, XDG_CONFIG_HOME: XDG },
    timeout: 10000,
    encoding: "utf8",
  });
  expect(r.error).toBeUndefined();
  expect(r.status, r.stderr).toBe(0);
  return JSON.parse(r.stdout);
}

test("repo rules over 8 KB are ignored whole; a small repo rules file still loads", async () => {
  const h = await freshHook(join(root, "agent-size"));
  const file = join(REPO, ".jev", "rules.json");
  writeFileSync(file, JSON.stringify([{ id: "big-rule", when: "w", ask: "a".repeat(9000) }]));
  await h.cmds["honest-jev"].handler("rule list", {});
  expect(h.sent.at(-1)).not.toContain("big-rule");

  writeFileSync(file, JSON.stringify([{ id: "small-rule", when: "w", ask: "a" }]));
  await h.cmds["honest-jev"].handler("rule list", {});
  expect(h.sent.at(-1)).toContain("small-rule");
});

test("repo rule text: newlines and tabs separate words, ANSI and control characters are removed", async () => {
  const h = await freshHook(join(root, "agent-clean"));
  writeFileSync(join(REPO, ".jev", "rules.json"), JSON.stringify([
    { id: "clean-rule", when: "alpha\nbeta\t\u001b[31mgamma\u0007 delta", ask: "x" },
  ]));
  await h.cmds["honest-jev"].handler("rule list", {});
  expect(h.sent.at(-1)).toContain("alpha beta gamma delta");
  expect(h.sent.at(-1)).not.toContain("alphabeta");
});

test("legacy config notice: fixed sentence, once per agent dir, legacy copies never loaded", async () => {
  writeFileSync(join(XDG, "jev", "rules.json"), JSON.stringify([{ id: "legacy-rule", when: "w", ask: "a" }]));
  const agent1 = join(root, "agent-legacy-1");
  const agent2 = join(root, "agent-legacy-2");

  // first session in this agent dir: told once, with no path and no copy command
  const first = sessionStartNotices(agent1);
  expect(first).toEqual([LEGACY_NOTICE]);
  expect(first[0]).not.toContain(XDG);

  // later sessions in the same agent dir (including a restart): quiet, the marker lives in the agent dir
  expect(sessionStartNotices(agent1)).toEqual([]);

  // a different agent dir is a different sandbox: told again
  expect(sessionStartNotices(agent2)).toEqual([LEGACY_NOTICE]);

  // and the legacy copy is still never loaded into rules
  const h = await freshHook(agent1);
  await h.cmds["honest-jev"].handler("rule list", {});
  expect(h.sent.at(-1)).not.toContain("legacy-rule");
});

test("repo rules: a FIFO at .jev/rules.json is ignored and never blocks the hook", () => {
  const fifoRepo = mkdtempSync(join(tmpdir(), "jev-omp-fifo-"));
  mkdirSync(join(fifoRepo, ".jev"));
  expect(spawnSync("mkfifo", [join(fifoRepo, ".jev", "rules.json")]).status).toBe(0);
  const script = `(async () => {
    const m = await import(${JSON.stringify(HOOK_URL)});
    const cmds = {};
    m.default({ on() {}, registerCommand(n, o) { cmds[n] = o; }, sendMessage(msg) { process.stdout.write(msg.content); } });
    await cmds["honest-jev"].handler("rule list", {});
  })();`;
  const r = spawnSync(process.execPath, ["-e", script], {
    cwd: fifoRepo,
    env: { ...process.env, PI_CODING_AGENT_DIR: join(root, "agent-fifo"), XDG_CONFIG_HOME: XDG },
    timeout: 10000,
    encoding: "utf8",
  });
  expect(r.error).toBeUndefined(); // ETIMEDOUT here means the read blocked on the FIFO
  expect(r.status).toBe(0);
  expect(r.stdout).toContain("HONEST JEV RULES");
  rmSync(fifoRepo, { recursive: true, force: true });
});

test("omp hook never reads the contents of legacy rules/config under CLAUDE/PI overrides (fs spy)", () => {
  const home = join(root, "spy-home");
  const agent = join(root, "agent-spy");
  const legacy = [
    join(home, ".config", "jev", "rules.json"),
    join(home, ".config", "jev", "config.json"),
    join(XDG, "jev", "rules.json"),
    join(XDG, "jev", "config.json"),
  ];
  mkdirSync(join(home, ".config", "jev"), { recursive: true });
  mkdirSync(agent, { recursive: true });
  for (const f of legacy) writeFileSync(f, '{"secret":"LEGACY-SECRET"}');
  const probe = join(root, "spy-probe.txt");
  writeFileSync(probe, "probe");
  const script = `(async () => {
    const fs = require("node:fs");
    const reads = [];
    for (const name of ["readFileSync", "openSync", "readFile"]) {
      const orig = fs[name];
      fs[name] = function (p, ...rest) { if (typeof p === "string") reads.push(p); return orig.call(this, p, ...rest); };
    }
    fs.readFileSync(${JSON.stringify(probe)}, "utf8"); // wiring check: the spy must see this read
    const m = await import(${JSON.stringify(HOOK_URL)});
    const handlers = {};
    const cmds = {};
    const sent = [];
    m.default({ on(n, f) { handlers[n] = f; }, registerCommand(n, o) { cmds[n] = o; }, sendMessage(msg) { sent.push(msg.content); } });
    await handlers["session_start"]({}, { ui: { notify() {}, setStatus() {} } });
    await cmds["honest-jev"].handler("rule list", {});
    process.stdout.write(JSON.stringify({ reads, sent }));
  })();`;
  const r = spawnSync(process.execPath, ["-e", script], {
    cwd: REPO,
    env: { ...process.env, HOME: home, PI_CODING_AGENT_DIR: agent, XDG_CONFIG_HOME: XDG },
    timeout: 10000,
    encoding: "utf8",
  });
  expect(r.error).toBeUndefined();
  expect(r.status, r.stderr).toBe(0);
  const { reads, sent } = JSON.parse(r.stdout);
  expect(reads).toContain(probe);
  for (const f of legacy) expect(reads).not.toContain(f);
  expect(sent.join("\n")).not.toContain("LEGACY-SECRET");
});

test("PI_CODING_AGENT_DIR changed after import is honoured: the level flag lands in the new dir", async () => {
  const a = join(root, "agent-late-a");
  const b = join(root, "agent-late-b");
  mkdirSync(a, { recursive: true });
  mkdirSync(b, { recursive: true });
  const h = await freshHook(a); // hook imported while PI_CODING_AGENT_DIR = a
  process.env.PI_CODING_AGENT_DIR = b;
  await h.cmds["honest-jev"].handler("strict", { ui: {} });
  expect(readFileSync(join(b, ".jev-honest-active"), "utf8").trim()).toBe("strict");
  expect(existsSync(join(a, ".jev-honest-active"))).toBe(false);
});

// The shipped opt-in example and the line the hook injects for it. Tests key on the "- [id] When" line, not the bare id,
// because SKILL.md itself mentions the id.
const EXAMPLE_PATH = new URL("../examples/rules/migration-prod-safe.json", import.meta.url);
const MIGRATION_LINE = "- [migration-prod-safe] When describing a database migration as safe: Was it run against a copy of prod data? — Evidence: the command and its output";

test("omp injection: the opt-in migration example is injected only once copied to the user layer; a repo mask removes it", async () => {
  const agent = join(root, "agent-inject");
  mkdirSync(join(agent, "jev"), { recursive: true });
  const h = await freshHook(agent);
  await h.cmds["honest-jev"].handler("standard", { ui: {} });
  const beforeCopy = (await h.handlers["before_agent_start"]({}, { ui: {} })) as { message: { content: string } };
  expect(beforeCopy.message.content).not.toContain("- [migration-prod-safe] When");
  writeFileSync(join(agent, "jev", "rules.json"), readFileSync(EXAMPLE_PATH, "utf8"));
  const injected = (await h.handlers["before_agent_start"]({}, { ui: {} })) as { message: { content: string } };
  expect(injected.message.content).toContain(MIGRATION_LINE);
  const repoMask = join(REPO, ".jev", "rules.json");
  writeFileSync(repoMask, JSON.stringify([{ id: "migration-prod-safe", disabled: true }]));
  try {
    const masked = (await h.handlers["before_agent_start"]({}, { ui: {} })) as { message: { content: string } };
    expect(masked.message.content).not.toContain("- [migration-prod-safe] When");
  } finally {
    rmSync(repoMask, { force: true });
  }
});

test("omp plain text: honest-jev strict and rule list are handled; slash commands, other prompts, and unknown words pass through", async () => {
  const agent = join(root, "agent-input");
  mkdirSync(agent, { recursive: true });
  const h = await freshHook(agent);
  const input = h.handlers["input"];
  const ctx = { ui: {} };
  expect(await input({ text: "honest-jev strict" }, ctx)).toEqual({ handled: true });
  expect(readFileSync(join(agent, ".jev-honest-active"), "utf8").trim()).toBe("strict");
  expect(await input({ text: "honest-jev rule list" }, ctx)).toEqual({ handled: true });
  expect(await input({ text: "/honest-jev strict" }, ctx)).toBeUndefined();
  expect(await input({ text: "hello there" }, ctx)).toBeUndefined();
  expect(await input({ text: "honest-jev please" }, ctx)).toBeUndefined();
  expect(await input({ text: "stop honest-jev" }, ctx)).toEqual({ handled: true });
  expect(readFileSync(join(agent, ".jev-honest-active"), "utf8").trim()).toBe("off");
});

test("omp plain text: normal mode turns Honest Jev off but reaches the model; malformed rule prose passes through; level args tolerate trailing punctuation", async () => {
  const agent = join(root, "agent-normal-mode");
  mkdirSync(agent, { recursive: true });
  const h = await freshHook(agent);
  const input = h.handlers["input"];
  const ctx = { ui: {} };
  expect(await input({ text: "honest-jev strict" }, ctx)).toEqual({ handled: true });
  expect(await input({ text: "normal mode" }, ctx)).toBeUndefined();
  expect(readFileSync(join(agent, ".jev-honest-active"), "utf8").trim()).toBe("off");
  expect(h.sent.at(-1)).toBe('HONEST JEV OFF — confirm in one line: "Honest Jev off. The command guard is separate and still on (JEV_GUARD_MODE=shadow + restart to log only)."');
  expect(await input({ text: "honest-jev strict" }, ctx)).toEqual({ handled: true });
  expect(await input({ text: "Normal mode." }, ctx)).toBeUndefined();
  expect(readFileSync(join(agent, ".jev-honest-active"), "utf8").trim()).toBe("off");
  expect(await input({ text: "stop honest-jev" }, ctx)).toEqual({ handled: true });
  expect(await input({ text: "honest-jev rule of thumb: always check" }, ctx)).toBeUndefined();
  expect(await input({ text: "honest-jev strict." }, ctx)).toEqual({ handled: true });
  expect(readFileSync(join(agent, ".jev-honest-active"), "utf8").trim()).toBe("strict");
});
