// PR-1 shrink batteries (owner decision "shrink" 2026-11-20): keep-ask refspec/filter/class-c predicates,
// the P1-1 print split, rule A, would_have on converted allows, the P3 known-limit pins, and the 10
// owner-STOP rows from the redacted fixture (§1.8 of the shrink plan). Data only: every string is
// handed to guardCommand(); nothing is executed.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { guardCommand, keepAsk, apiDeleteAsk, payloadPrintsValue } from "../src/kit/guard.mjs";

const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);
const ask = async (c) => { const r = await g(c); assert.equal(r.decision, "ask", `${c} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); return r; };
const allowWould = async (c) => { const r = await g(c); assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); assert.equal(r.would_have, "ask", `${c} would_have`); return r; };
const allowPlain = async (c) => { const r = await g(c); assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); return r; };
const block = async (c) => { const r = await g(c); assert.equal(r.decision, "block", `${c} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); return r; };

test("keep-ask: protected, unprovable and refspec-less force pushes keep the ask (D1-strict)", async () => {
  for (const c of [
    "git push -f origin main", "git push -f origin master", "git push origin +main", "git push origin +refs/heads/main",
    "git push -f origin refs/heads/main", "git push -f origin HEAD:main", "git push -f origin HEAD", "git push -qf",
    "git push --force-with-lease=main", "git push -f 'origin' 'main'", "git push --force origin $BRANCH",
    "git push --mirror origin", "git push -fu origin main", "git -C repo push -uf origin main", "git push --force-if-includes origin main",
  ]) await ask(c);
});

test("keep-ask: non-protected refspecs, deletes and statement scoping convert (owner shrink)", async () => {
  for (const c of [
    "git push -f origin feature", "git push -u origin +feature", "git push origin '+refs/heads/*:refs/heads/*'",
    "git push -vf origin x", "git push --delete origin b", "git push -d origin b", "git push origin :refs/heads/b",
    "git push -f origin feature && git fetch origin main", "git push -f origin feature; echo main", "git push --prune origin",
    "git push -filter origin main",
  ]) await allowWould(c);
  // kubectl delete's "removes a live resource" is an R10 flag: with the model path off (PR-2 default) it
  // fails open to allow + would_have, exactly as main did with no Jev configured.
  await allowWould("kubectl delete deploy api");
});

test("keep-ask: filter-branch/filter-repo real rewrites ask; --version/--help-only probes convert (D2 carve)", async () => {
  await ask("git filter-branch -f --index-filter 'git rm -r --cached x' origin/main");
  await ask("git filter-repo --force --path foundry-pdf/");
  await allowWould("git filter-branch --version 2>/dev/null");
  await allowWould("git filter-repo --version || pip3 install --user git-filter-repo");
  await allowWould("git filter-repo --help");
});

test("keep-ask: class (c) destructive reasons stay asks; owner-listed operations convert", async () => {
  for (const c of [
    "echo 'DROP TABLE users' | psql -d prod", "echo 'DROP DATABASE app' | mysql -u root", "psql -c 'DROP TABLE t'",
    "docker volume rm v1", "docker volume prune", "docker compose down -v", "docker system prune -a",
    "rm -rf ~/.ssh", "rm -rf ~/Documents/*", "find ~ -name '*.tmp' -delete", "find / -name core -delete",
    "terraform destroy", "pulumi destroy", "helm uninstall myrelease",
  ]) await ask(c);
  await ask("rm -rf ./.git");
  await ask("pulumi up --yes"); await ask("pulumi up -y");
  for (const c of ["git clean -f", "git reset --hard HEAD~3", "git update-ref -d refs/heads/main", "git tag -d v1.0"]) await allowWould(c);
});

test("P1-1 print split: a print sink keeps the block; read-and-use converts with would_have", async () => {
  await block("node -e 'console.log(process.env.DB_PASS)'");
  await block("python3 -c \"import os; print(os.environ['API_TOKEN'])\"");
  await block("node -e 'console.log(!!process.env.DB_PASS)'"); // existence print: conservative keep
  await block("ruby -e 'puts ENV[\"DB_PASS\"]'"); // paren-less sink (review P3)
  await allowWould("python3 -c \"import os,requests; requests.post('https://x', headers={'Authorization': os.environ['API_TOKEN']})\"");
  await allowWould("node -e 'fetch(\"https://x\",{headers:{Authorization:process.env.API_TOKEN}})'");
});

test("P1-1 P3-1 pins: a bare 2-hop ident chain prints (fixed); a wrapper-function param print is a known limit", async () => {
  await block("node -e 'b=process.env.DB_PASS; a=b; console.log(a)'"); // regression: chain propagation fixed in PR-1
  // KNOWN LIMIT (deliberate): call-graph propagation is excluded so response prints never false-keep;
  // the wrapper-fn-param shape slips to allow+would_have and is pinned here so a future change is visible.
  await allowWould("node -e 'function w(v){console.log(v)}; w(process.env.DB_PASS)'");
});

test("rule A: token-level statement-scoped API DELETEs ask in every spelling", async () => {
  for (const c of [
    "curl -X DELETE https://example.com/v1/things/1",
    "curl -X 'DELETE' https://api.github.com/repos/o/r/git/refs/heads/x",
    "curl -X \"DELETE\" https://example.com/a",
    "curl -XDELETE https://example.com/a",
    "curl -X'DELETE' https://example.com/a",
    "curl --request=DELETE https://example.com/a",
    "curl --request DELETE https://example.com/a",
    "wget --method=DELETE https://example.com/a",
    "wget --method=DELETE https://example.com/a",
    "curl \\\n  -X DELETE https://example.com/a",
    "curl -X DELETE https://api.example.com/a && echo done",
  ]) await ask(c);
  // remote DELETE in its own statement still asks when a later statement is localhost
  await ask("curl -X DELETE https://api.example.com/a && curl http://localhost:9/x");
});

test("rule A exclusions: proxy -x, local URLs, no URL, gh api all convert (decided out)", async () => {
  await allowPlain("curl -x delete https://example.com/v1/things/1");
  await allowPlain("curl -X DELETE http://127.0.0.1:8798/x");
  await allowPlain("curl -X DELETE http://10.0.0.5/x");
  await allowPlain("curl -X DELETE http://192.168.1.9/x");
  await allowPlain("curl -X DELETE");
  await allowPlain("gh api -X DELETE /repos/o/r/issues/1/comments/2");
});

test("keepAsk/apiDeleteAsk/payloadPrintsValue are exported and agree with guardCommand", () => {
  assert.equal(typeof keepAsk, "function");
  assert.equal(typeof apiDeleteAsk, "function");
  assert.equal(typeof payloadPrintsValue, "function");
  assert.equal(keepAsk({ rule: "R7-destructive", reason: "`git push` deleting or lease-forcing published refs rewrites shared history" }, "git push -f origin main"), true);
  assert.equal(keepAsk({ rule: "R7-destructive", reason: "`git reset --hard` discards uncommitted work irreversibly" }, "git reset --hard"), false);
  assert.equal(apiDeleteAsk("curl -X DELETE https://example.com/a"), true);
  assert.equal(apiDeleteAsk("gh api -X DELETE /repos/o/r/issues/1"), false);
  assert.equal(payloadPrintsValue("console.log(process.env.DB_PASS)", "DB_PASS"), true);
  assert.equal(payloadPrintsValue("const t = process.env.DB_PASS; api.setSecret(t)", "DB_PASS"), false);
});

// ── the 10 owner-STOP rows (redacted fixture; §1.8 of the shrink plan) ──────────────────────────────
const stop = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/stop-shrunk.json", import.meta.url)), "utf8"));
const STOP_HOME = "/home/andy";
const STOP_CWD = "/home/andy/Documents/GitHub";

test("the 10 owner-STOP rows decide as §1.8: 7 blocks, 2 interactive asks, 1 documented known-limit allow", async () => {
  let blocks = 0;
  let asks = 0;
  let knownLimit = 0;
  for (const row of stop.rows) {
    const r = await guardCommand({ command: row.command, cwd: STOP_CWD, home: STOP_HOME, tool: "Bash" }, noJev);
    if (row.want === "block") { assert.equal(r.decision, "block", `${row.id} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); blocks++; }
    else if (row.want === "ask") { assert.equal(r.decision, "ask", `${row.id} -> ${r.decision} ${String(r.reason).slice(0, 80)}`); asks++; }
    else { assert.equal(r.decision, "allow", `${row.id} -> ${r.decision}`); assert.equal(r.would_have, "ask", `${row.id} would_have`); knownLimit++; }
  }
  assert.equal(blocks, 7);
  assert.equal(asks, 2);
  assert.equal(knownLimit, 1); // q281: inline literal in a POST body - the documented known limit
});

test("the redacted fixture carries no live-looking material", () => {
  const text = JSON.stringify(stop);
  // no vendor token shapes (sk-, ghp_, AKIA, xox…)
  assert.ok(!/(?:sk-|ghp_|gho_|ghs_|github_pat_|xox[a-z]-?|AKIA)[A-Za-z0-9_\-]+/.test(text), "vendor token shape in fixture");
  // no Bearer with a real value (only <r> or a $VAR name may follow)
  assert.ok(!/Bearer\s+(?!<r>|\$[A-Za-z_])/i.test(text), "Bearer with a value in fixture");
  // no long secret-shaped run once URLs and filesystem paths are removed
  const scrubbed = text.replace(/https?:\/\/[^\s"\\]+/g, " <url> ").replace(/(?:~|\.{1,2})?\/[A-Za-z0-9._\-/]+/g, " <path> ");
  assert.ok(!/[A-Za-z0-9_\-+/=.]{25,}/.test(scrubbed), `long token-like run: ${/[A-Za-z0-9_\-+/=.]{25,}/.exec(scrubbed)?.[0]}`);
});

test("review P1-1: a force push to main keeps the ask inside terraform sequences, ssh and su -c payloads", async () => {
  await ask("terraform apply -auto-approve; git push -f origin main");
  await ask("ssh host 'git push -f origin main'");
  await ask("su -c 'git push -f origin main'");
});
test("review P1-1: a commit message that quotes a force push stays allow", async () => {
  await allowPlain("git commit -m 'git push -f origin main'");
});
test("review P1-2: per-element and subscript-alias flows from env into print sinks stay block", async () => {
  await block("node -e \"for (const c of process.env.API_TOKEN) console.log(c)\"");
  await block("python3 -c \"[print(c) for c in os.environ['DB_PASS']]\"");
  await block("python3 -c \"d={}; d['k']=os.environ['DB_PASS']; print(d)\"");
});
test("review P2-1: curl short-option clusters that set DELETE are rule A asks", async () => {
  await ask("curl -sXDELETE https://api.example.com/x");
  await ask("curl -fsSLX DELETE https://api.example.com/x");
  await ask("curl -sSX DELETE https://api.example.com/x");
  await allowPlain("curl -sSL https://api.example.com/x");
});
test("review P2-2: link-local 169.254 is not a local host; DELETE to it asks", async () => {
  await ask("curl -X DELETE http://169.254.169.254/x");
  await allowWould("curl -X DELETE http://10.0.0.5/x");
  await allowWould("curl -X DELETE http://172.20.0.5/x");
  await allowPlain("curl -X DELETE http://127.0.0.1:3000/x");
});
