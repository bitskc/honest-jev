// A pure decision function shaped like a routing gate (vetoes, then a read bar), with placeholder bars, for tests only. It takes a stored answer
// vector (no text) and sweepable bars, and counts its calls so tests can prove a holdout row was or was not run.
let calls = 0;
export const callCount = () => calls;
export const resetCalls = () => { calls = 0; };

export function decide(input, params = {}) {
  calls++;
  const answer_min = params.answer_min ?? 0.7, change_max = params.change_max ?? 0.2, block_at = params.block_at ?? 0.6, write_max = params.write_max ?? 0.15;
  const n = input.answers ?? {};
  const get = (k, missing) => (typeof n[k] === "number" ? n[k] : missing);
  const asks = get("wants_answer", 0), rc = get("wants_change", 1), pWB = typeof input.write_mass === "number" ? input.write_mass : 1;
  if (input.facts?.open_ask) return { decision: "open_ask" };
  if (rc >= block_at || pWB > write_max) return { decision: "vetoed" };
  if (asks >= answer_min && rc <= change_max) return { decision: "routed" };
  return { decision: asks < 0.35 ? "not_read" : "uncertain" };
}

/** A fixture whose output carries a model id and a "needs a model" marker, for not_evaluated and compare tests. */
export function modelish(input) {
  calls++;
  if (input.needs_model) return { decision: null, jev: { status: "unavailable" } };
  return { decision: input.answer, jev: { status: "ok", model: input.model ?? "m1", usage: { input_tokens: 10, output_tokens: 1, cost: 0.00001 } } };
}
export function boom() { calls++; throw new Error("target exploded: secret-looking text sk-NOT-A-REAL-KEY"); }
