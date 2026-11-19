import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

// Force pushes git accepts that the R7 ask missed: bundled short flags, `+` refspecs, --mirror/--prune, and bundled
// `git branch -D` spellings. Data only: every string is handed to guardCommand(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);
const expectAll = async (cmds, want) => { for (const c of cmds) assert.equal((await g(c)).decision, want, c); };

test("bundled -f, + refspecs, --force-if-includes, --mirror and --prune all ask like `git push --force`", async () => {
  await expectAll([
    "git push -fu origin main", "git push -uf origin main", "git push -qf", "git push -vf origin x",
    "git push origin +main", "git push origin +HEAD:main", "git push -u origin +feature", "git push origin '+refs/heads/*:refs/heads/*'",
    "git push origin main +dev", "git push origin -- +main", "git push --force-if-includes origin main",
    "git push --mirror origin", "git push --prune origin", "git -C repo push -uf origin main", "git push -ud origin old",
  ], "ask");
});
test("ordinary pushes and push options that only look like a flag stay allowed", async () => {
  await expectAll([
    "git push", "git push -u origin main", "git push origin main", "git push --tags", "git push -o ci.skip origin main",
    "git push -oforce origin main", "git push --push-option +x origin main", "git push origin HEAD:refs/for/main", "git push -n -u origin main",
  ], "allow");
});
test("git branch force-delete spellings ask; a plain delete does not", async () => {
  await expectAll(["git branch -D x", "git branch -Df x", "git branch -df x", "git branch -fd x", "git branch -d -f x", "git branch --delete --force x", "git branch -d --force x"], "ask");
  await expectAll(["git branch -d x", "git branch --delete x", "git branch -f x HEAD~1", "git branch -v"], "allow");
});
