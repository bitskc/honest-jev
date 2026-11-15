import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);

test("Q6: metadata verbs that touch secret paths ask", async () => {
  for (const c of [
    "find . -name .env -print",
    "find ~/.ssh -print",
    "docker compose --env-file .env up",
    "kubectl --kubeconfig ~/.kube/config get pods",
  ]) {
    assert.equal((await g(c)).decision, "ask", c);
  }
  assert.equal((await g('find . -name "*.ts"')).decision, "allow");
  assert.equal((await g("node --env-file=.env server.js")).decision, "allow");
  assert.equal((await g("docker run --env-file .env app")).decision, "allow");
});

test("Q6: source/.env asks", async () => {
  for (const c of ["source .env", ". .env", "set -a; . ./.env; set +a"]) {
    assert.equal((await g(c)).decision, "ask", c);
  }
});

test("Q6: vendor key names block when printed", async () => {
  for (const c of ["printenv OPENAI_KEY", "echo $OPENAI_API_KEY", "printenv ANTHROPIC_API_KEY"]) {
    assert.equal((await g(c)).decision, "block", c);
  }
});

test("Q6: credentials* on read-only tools allow; cat still asks", async () => {
  for (const c of ["git diff src/credentials*", "sort credentials*"]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
  assert.equal((await g("cat credentials*")).decision, "ask");
  assert.equal((await g("cat .env")).decision, "block");
});
