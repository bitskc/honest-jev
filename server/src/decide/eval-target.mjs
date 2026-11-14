// jev-eval `module` target for decision specs (scripts/jev-eval, openspec add-deployment-eval-calibration):
//   export decide (input, params) -> output
// input  {example: "<name in examples/decisions>" | spec: {...}, facts?, answers}   answers are raw upstream-style answers
// params named knob overrides, e.g. {"read_min": 0.85}: the same `knob` thresholds a spec declares
// output {decision, rule_id, decided_by, fail_reason}
// It runs decideOffline, the function the tool runs after the upstream replies, so a sweep measures production logic.
import { readFileSync } from "node:fs";
import { decideOffline } from "./core.mjs";
import { validateSpec } from "./validate.mjs";

const cache = new Map();
function specFor(input) {
  if (input.spec) return input.spec;
  if (typeof input.example !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(input.example)) throw new Error("input needs spec, or example: a name from examples/decisions");
  if (!cache.has(input.example)) cache.set(input.example, JSON.parse(readFileSync(new URL(`../../../examples/decisions/${input.example}.json`, import.meta.url), "utf8")));
  return cache.get(input.example);
}

export function decide(input, params = {}) {
  const v = validateSpec(specFor(input));
  if (!v.ok) throw new Error(`invalid spec: ${v.errors[0]}`);
  const r = decideOffline(v.spec, { facts: input.facts ?? {}, rawAnswers: input.answers ?? {}, knobs: params });
  return { decision: r.decision, rule_id: r.rule_id, decided_by: r.decided_by, fail_reason: r.fail_reason };
}
