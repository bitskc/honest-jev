import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

// macOS (default APFS) and Windows filesystems are case-insensitive: `.ENV` is `.env`. Data only: every string is handed
// to guardCommand(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/Users/u/proj", home: "/Users/u", tool: "Bash" }, noJev);
const r = (file_path) => guardCommand({ tool: "Read", file_path, cwd: "/Users/u/proj", home: "/Users/u" }, noJev);
const expectAll = async (cmds, want) => { for (const c of cmds) assert.equal((await g(c)).decision, want, c); };

test("upper/mixed-case spellings of secret stores block like the lowercase spelling", async () => {
  await expectAll(["cat .ENV", "cat .Env", "cat .ENV.local", "cat ./.Env.Production", "head .NETRC", "cat ID_RSA", "cat ~/.SSH/config",
    "cat ~/.Docker/config.json", "cat ~/.KUBE/config", "cat server.PEM", "cat Credentials.json", "cat .DEV.VARS", "python3 -c 'print(open(\".ENV\").read())'"], "block");
});
test("Read of a case-variant secret store blocks", async () => {
  for (const f of ["/Users/u/proj/.ENV", "/Users/u/.SSH/id_ed25519", "/Users/u/proj/Server.Key"]) assert.equal((await r(f)).decision, "block", f);
});
test("case-variant safe files and ordinary names stay allowed", async () => {
  await expectAll(["cat .ENV.EXAMPLE", "cat .Env.Sample", "cat ~/.SSH/known_hosts", "cat ID_RSA.PUB", "cat README.md", "cat Envoy.yaml", "cat MyKeyboard.txt", "ls ~/.SSH"], "allow");
  assert.equal((await r("/Users/u/proj/.ENV.example")).decision, "allow");
});
