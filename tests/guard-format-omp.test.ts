// The omp guard hook's prompt text, against the fixture the Claude hook's test (tests/test_guard_format.py) reads too: both hooks must
// say the same words. Run with bun:  bun test tests/guard-format-omp.test.ts
import { expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));
// dynamic: the omp import in the hook must be stubbed (line above) before the hook module loads, and static imports hoist above it
const hook = await import("../hooks/omp/jev-guard.ts");
const fx = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "guard-format.json"), "utf8"));

test("the Next lines are the fixture's", () => {
  expect(hook.NEXT_SAFER).toBe(fx.next_safer);
  expect(hook.NEXT_ASK).toBe(fx.next_ask);
});

for (const c of fx.cases) {
  test(`guard reply: ${c.name}`, () => {
    const m = hook.guardMsg(c.reply);
    expect(hook.msgTitle(m, "ask")).toBe(c.title);
    expect(m.body.join("\n")).toBe(c.message);
    expect(hook.renderMsg(m, "declined", true)).toBe(c.declined);
    expect(hook.renderMsg(m, "needs approval", true)).toBe(c.needs_approval);
    expect(hook.renderMsg(m, "block", true, true)).toBe(c.block);
    const policy = hook.policyMsg("Jev policy [pr-merge-gate/R1-unreviewed-merge]: ask the user first.");
    expect(hook.joinMsg(m, policy).body.join("\n")).toBe(c.both_message);
    if (c.both_block) expect(hook.renderMsg(hook.joinMsg(m, policy), "block", true, true)).toBe(c.both_block);
  });
}

for (const c of fx.hook_messages) {
  test(`hook message: ${c.name}`, () => {
    const m = hook.hookMsg(c.label, c.why);
    expect(hook.msgTitle(m, "ask")).toBe(c.title);
    expect(m.body.join("\n")).toBe(c.message);
    expect(hook.renderMsg(m, "declined", true)).toBe(c.declined);
  });
}

test("a policy gate's own reason is shown untouched", () => {
  const p = fx.policy_only;
  const m = hook.policyMsg(p.reason);
  expect(hook.msgTitle(m, "ask")).toBe(p.title);
  expect(m.body.join("\n")).toBe(p.message);
  expect(hook.renderMsg(m, "declined", true)).toBe(p.declined);
  expect(hook.renderMsg(m, "needs approval", true)).toBe(p.needs_approval);
});

test("a block's line 1 carries the Why (a Claude Code deny row shows only line 1); the dialog title has no backticks (it is inline markdown)", () => {
  for (const c of fx.cases) {
    const m = hook.guardMsg(c.reply);
    const lines = hook.renderMsg(m, "block", true, true).split("\n");
    expect(lines.length).toBeLessThanOrEqual(3);
    expect(lines[0].startsWith(`${hook.msgTitle(m, "block")}: `)).toBe(true);
    expect(hook.msgTitle(m, "ask")).not.toContain("`");
    expect(lines.filter((l: string) => l.startsWith("Next:")).length).toBe(1);
  }
});

test("an over-long text is cut before its Next line, never through it", () => {
  const m = hook.guardMsg({ label: "secret", reason: "r".repeat(900), suggestion: "s".repeat(120) });
  const block = hook.renderMsg(m, "block", true, true);
  expect(block.length).toBeLessThanOrEqual(hook.MESSAGE_CAP);
  expect(block.endsWith(`…\n${hook.NEXT_SAFER}`)).toBe(true);
  const ask = hook.renderMsg(hook.joinMsg(m, hook.policyMsg("p".repeat(300))), "ask");
  expect(ask.length).toBeLessThanOrEqual(hook.MESSAGE_CAP);
  const typical = hook.renderMsg(hook.joinMsg(hook.guardMsg({ label: "secret", reason: "r".repeat(120), suggestion: "s".repeat(120) }), hook.policyMsg(`Jev policy [pr-merge-gate/R1-unreviewed-merge]: ${"p".repeat(300)}`)), "needs approval", true);
  expect(typical.length).toBeLessThanOrEqual(hook.MESSAGE_CAP);
  expect(typical).not.toContain("…");
  expect(typical.endsWith(hook.NEXT_SAFER)).toBe(true);
});

test("the notices are one line and short", () => {
  for (const n of [hook.LOCAL_NOTICE, hook.LOCAL_DOWN_NOTICE, ...Object.values(hook.TRUST_NOTICES) as string[]]) {
    expect(n.startsWith("Jev guard · ")).toBe(true);
    expect(n).not.toContain("\n");
    expect(n.length).toBeLessThanOrEqual(220);
  }
});
