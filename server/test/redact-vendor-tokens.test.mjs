import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { redact } from "../src/kit/shell.mjs";

// Bare vendor tokens in tool output (no `token=` name beside them) must be scrubbed before text reaches Jev or a ledger.
// Every value below is synthetic: the right shape, no real credential. Data only: every string is handed to redact().
const hook = createRequire(import.meta.url)("../../hooks/jev-redact.js");
const r = (n, ch = "a") => ch.repeat(n);
const TOKENS = {
  aws_sts: "ASIA" + "Q".repeat(16),
  gitlab: "glpat-" + r(20, "x"),
  sendgrid: "SG." + r(22, "b") + "." + r(43, "c"),
  slack_app: "xapp-1-" + r(30, "D"),
  stripe_webhook: "whsec_" + r(32, "e"),
  huggingface: "hf_" + r(34, "F"),
  google_oauth: "ya29." + r(40, "g"),
  pypi: "pypi-AgEIcHlwaS5vcmc" + r(60, "h"),
  xai: "xai-" + r(40, "i"), groq: "gsk_" + r(40, "j"), replicate: "r8_" + r(30, "k"), linear: "lin_api_" + r(30, "l"), notion: "ntn_" + r(40, "m"),
  shopify: "shpat_" + r(32, "a"),
  digitalocean: "dop_v1_" + r(64, "b"),
  doppler: "dp.st.prod." + r(40, "n"),
  atlassian: "ATATT3x" + r(40, "o"),
};

for (const [name, tok] of Object.entries(TOKENS)) {
  test(`a bare ${name} token in tool output is redacted by the server and the hook copy`, () => {
    for (const [who, fn] of [["server", redact], ["hook", hook.redact]]) {
      const line = `{"result": "ok"}\n${tok}\nprocess exited 0`;
      const out = fn(line);
      assert.ok(!out.includes(tok), `${who} left ${name} in the clear: ${out}`);
      assert.ok(out.includes("<redacted>") && out.includes("process exited 0"), `${who}: ${out}`);
    }
  });
}
test("ordinary words that share a prefix are left alone", () => {
  for (const s of ["glpat-short", "SG.config.json", "ASIA-Pacific", "hf_model", "ya29.short", "gsk_test", "r8_x", "shpat_123", "dp.st.x", "ATATTx", "xai-sdk", "lin_api_v2"]) {
    assert.equal(redact(s), s, s);
    assert.equal(hook.redact(s), s, s);
  }
});
