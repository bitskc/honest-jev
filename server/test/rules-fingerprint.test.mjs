// The rules fingerprint contract between the hooks and the Worker: the Worker reports a constant, the hooks compute the same
// function over the files they run; equal means the same bytes. Offline, no network.
import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { RULE_FILES, rulesFingerprint } from "../../hooks/jev-rules-fingerprint.mjs";
import { RULES_FINGERPRINT } from "../src/rules-fingerprint.mjs";
import { FINGERPRINT_HEADER, handleHealth, tokenOk } from "../src/health.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const KIT = join(here, "..", "src", "kit");
const scratch = mkdtempSync(join(tmpdir(), "jev-fp-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

function copyKit() {
  const d = mkdtempSync(join(scratch, "kit-"));
  for (const f of RULE_FILES) cpSync(join(KIT, f), join(d, f));
  return d;
}

test("the committed constant is the fingerprint of the rule files in src/kit (run npm run fingerprint when this fails)", () => {
  assert.match(RULES_FINGERPRINT, /^[0-9a-f]{64}$/);
  assert.equal(RULES_FINGERPRINT, rulesFingerprint(KIT));
  // the generator agrees with the committed file, the same check CI relies on
  execFileSync(process.execPath, [join(here, "..", "scripts", "gen-rules-fingerprint.mjs"), "--check"], { stdio: "pipe" });
});

test("RULE_FILES is exactly the transitive relative-import closure of guard.mjs, sorted (a rule file added later cannot be left out)", () => {
  const seen = new Set();
  const walk = (name) => {
    if (seen.has(name)) return;
    seen.add(name);
    const text = readFileSync(join(KIT, name), "utf8");
    for (const m of text.matchAll(/(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+["'](\.[^"']+)["']/g)) walk(m[1].replace(/^\.\//, ""));
    for (const m of text.matchAll(/\bimport\(\s*["'](\.[^"']+)["']\s*\)/g)) walk(m[1].replace(/^\.\//, ""));
  };
  walk("guard.mjs");
  assert.deepEqual([...seen].sort(), [...RULE_FILES]);
  assert.deepEqual([...RULE_FILES], [...RULE_FILES].sort());
});

test("any byte change in any rule file changes the fingerprint; an identical copy does not", () => {
  const base = rulesFingerprint(KIT);
  assert.equal(rulesFingerprint(copyKit()), base);
  for (const f of RULE_FILES) {
    const d = copyKit();
    writeFileSync(join(d, f), `${readFileSync(join(d, f), "utf8")}\n`);
    assert.notEqual(rulesFingerprint(d), base, `appending a newline to ${f} must change the fingerprint`);
  }
});

test("a byte moved from the end of one rule file to the start of the next changes the fingerprint (files are length-framed)", () => {
  const d = copyKit();
  const a = readFileSync(join(d, RULE_FILES[0]));
  const b = readFileSync(join(d, RULE_FILES[1]));
  writeFileSync(join(d, RULE_FILES[0]), a.subarray(0, a.length - 1));
  writeFileSync(join(d, RULE_FILES[1]), Buffer.concat([a.subarray(a.length - 1), b]));
  assert.notEqual(rulesFingerprint(d), rulesFingerprint(KIT));
});

test("a missing rule file is an error, not a fingerprint of the rest", () => {
  const d = copyKit();
  rmSync(join(d, "safere.mjs"));
  assert.throws(() => rulesFingerprint(d));
});

test("GET /health: body ok for everyone; the fingerprint header only with the right bearer token", async () => {
  const env = { MCP_BEARER_TOKEN: "right-token" };
  const req = (auth) => new Request("https://w.example/health", auth ? { headers: { authorization: auth } } : undefined);
  const authed = await handleHealth(req("Bearer right-token"), env);
  assert.equal(await authed.text(), "ok");
  assert.equal(authed.status, 200);
  assert.equal(authed.headers.get(FINGERPRINT_HEADER), RULES_FINGERPRINT);
  assert.equal(FINGERPRINT_HEADER, "x-jev-rules-fingerprint");
  for (const auth of [undefined, "Bearer wrong", "right-token", "Bearer ", "Basic right-token"]) {
    const r = await handleHealth(req(auth), env);
    assert.equal(await r.text(), "ok", String(auth));
    assert.equal(r.status, 200);
    assert.equal(r.headers.get(FINGERPRINT_HEADER), null, `no fingerprint for ${auth}`);
  }
  // a Worker with no token configured never authorizes anyone (an empty bearer must not match an unset secret)
  for (const e of [{}, { MCP_BEARER_TOKEN: "" }, undefined]) {
    const r = await handleHealth(req("Bearer "), e);
    assert.equal(r.headers.get(FINGERPRINT_HEADER), null);
  }
  assert.equal(await tokenOk("Bearer right-token", "right-token"), true);
  assert.equal(await tokenOk("Bearer right-token", ""), false);
});
