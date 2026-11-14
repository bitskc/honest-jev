import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// The hook's hooks/jev-redact.js is a hand-kept copy of server/src/kit/shell.mjs's SECRET_RULES (hooks are zero-dependency
// CommonJS, the server is a separate package). Two guards so the copies cannot drift:
//  1. the rule literals are compared SOURCE TO SOURCE (any edit to one table and not the other fails here, even for a rule no
//     test string exercises);
//  2. the leak table, benign controls and exact-output cases of issue #27 (server/test/kit.test.mjs, PR #134) run through BOTH.
// Data only: every string is handed to redact(); nothing is executed.
const here = path.dirname(fileURLToPath(import.meta.url));
const hookPath = path.join(here, "jev-redact.js");
const serverPath = path.join(here, "..", "server", "src", "kit", "shell.mjs");
const hook = createRequire(import.meta.url)("./jev-redact.js");
const server = await import(serverPath);

/** The lines of a source file's `const SECRET_RULES = [ ... ];` literal, comments and blank lines dropped, quote style and
 *  indentation normalised, so only the rules themselves are compared. */
function ruleLines(file) {
  const src = fs.readFileSync(file, "utf8");
  const a = src.indexOf("const SECRET_RULES = [");
  assert.ok(a >= 0, `${file}: no SECRET_RULES literal`);
  const b = src.indexOf("\n];\n", a);
  assert.ok(b > a, `${file}: SECRET_RULES literal does not end`);
  return src.slice(a, b + 3).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("//"));
}

test("hook SECRET_RULES literals equal server/src/kit/shell.mjs's, rule for rule", () => {
  const h = ruleLines(hookPath);
  const s = ruleLines(serverPath);
  assert.ok(s.length >= 20, `parsed only ${s.length} server rule lines: the extraction broke`);
  assert.equal(h.length, s.length, `hook has ${h.length} rule lines, server ${s.length}`);
  for (let i = 0; i < s.length; i++) assert.equal(h[i], s[i], `rule line ${i + 1} differs`);
  // the constant the rules substitute
  const red = (f) => /const REDACTED = ["']([^"']+)["']/.exec(fs.readFileSync(f, "utf8"))[1];
  assert.equal(red(hookPath), red(serverPath));
});

test("the drift check fails on a changed, dropped or added rule (mutated temp copies of the hook source)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "redact-drift-"));
  const src = fs.readFileSync(hookPath, "utf8");
  const server = ruleLines(serverPath);
  const mutate = (name, edit) => {
    const f = path.join(dir, `${name}.js`);
    const out = edit(src);
    assert.notEqual(out, src, `${name}: the mutation changed nothing`);
    fs.writeFileSync(f, out);
    return ruleLines(f);
  };
  const differs = (lines) => lines.length !== server.length || lines.some((l, i) => l !== server[i]);
  assert.ok(differs(mutate("changed", (t) => t.replace("(?:--password|", "(?:--passwd|"))), "a changed alternation must differ");
  assert.ok(differs(mutate("flag", (t) => t.replace("/gi, `$1${REDACTED}`],", "/g, `$1${REDACTED}`],"))), "a changed flag must differ");
  assert.ok(differs(mutate("dropped", (t) => t.replace(/\n  \[\/\\bxox\[abprs\][^\n]*/, ""))), "a dropped rule must differ");
  assert.ok(differs(mutate("added", (t) => t.replace("const SECRET_RULES = [", "const SECRET_RULES = [\n  [/x/g, REDACTED],"))), "an added rule must differ");
});

// ── PR #134 / issue #27 cases, through both copies ──────────────────────────────────────────────────────────────────────
const redact = server.redact;
const leaks = [
  // curl user:password, every separator and bundling
  ["curl -u admin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl -uadmin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl -sSu admin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl --user admin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl --user=admin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl --username=admin:Tr0ub4dor https://x", "Tr0ub4dor"],
  ['curl -u "admin:Tr0ub4dor with space" https://x', "with space"],
  ["curl -U px:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl -Upx:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl --proxy-user px:Tr0ub4dor https://x", "Tr0ub4dor"],
  ["curl --proxy-user=px:Tr0ub4dor https://x", "Tr0ub4dor"],
  // --auth and the other long options, `=` and space
  ["tool --auth=s3cretvalue", "s3cretvalue"],
  ["tool --auth s3cretvalue", "s3cretvalue"],
  ["tool --token=s3cretvalue", "s3cretvalue"],
  ["tool --api-key=s3cretvalue", "s3cretvalue"],
  ["tool --secret=s3cretvalue", "s3cretvalue"],
  ["tool --secret 's3cret value'", "value"],
  ['tool --password="s3cret value"', "value"],
  ["curl --oauth2-bearer s3cretvalue https://x", "s3cretvalue"],
  // headers
  ["curl -H 'Cookie: session=abcdef123456' https://x", "abcdef123456"],
  ['curl -H "Cookie: a=b; sid=abcdef123456" https://x', "abcdef123456"],
  ["curl -H 'cookie: sid=abcdef123456' https://x", "abcdef123456"],
  ['curl -H "Set-Cookie: sid=abcdef123456; Path=/"', "abcdef123456"],
  ['curl -H "Authorization: Bearer abcdefghijklmnop1234" https://x', "abcdefghijklmnop1234"],
  ['curl -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" https://x', "dXNlcjpwYXNzd29yZA"],
  ['curl -H "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==" https://x', "dXNlcjpwYXNzd29yZA"],
  // quoted Authorization values (the value itself starts with a quote, or the scheme precedes one): every spelling redacts
  ['authorization="s3cretvalue1234"', "s3cretvalue1234"],
  ["authorization='s3cretvalue1234'", "s3cretvalue1234"],
  ['authorization = "s3cretvalue1234"', "s3cretvalue1234"],
  ['authorization: "s3cretvalue1234"', "s3cretvalue1234"],
  ["authorization: 's3cretvalue1234'", "s3cretvalue1234"],
  ['headers = { authorization: "s3cretvalue1234" }', "s3cretvalue1234"],
  ['x-authorization: "s3cretvalue1234"', "s3cretvalue1234"],
  ['Authorization: Bearer "s3cretvalue1234"', "s3cretvalue1234"],
  ["Authorization: Bearer 's3cretvalue1234'", "s3cretvalue1234"],
  ['Authorization: Basic "s3cretvalue1234"', "s3cretvalue1234"],
  ['Authorization: token "s3cretvalue1234"', "s3cretvalue1234"],
  ["Authorization: 's3cretvalue1234'", "s3cretvalue1234"],
  // --cookie / -b with a name=value string
  ["curl --cookie 'sid=abcdef123456' https://x", "abcdef123456"],
  ["curl --cookie=sid=abcdef123456 https://x", "abcdef123456"],
  ["curl -b sid=abcdef123456 https://x", "abcdef123456"],
  ["curl -b 'sid=abcdef123456; t=9' https://x", "abcdef123456"],
  ['curl -b "sid=abcdef123456" https://x', "abcdef123456"],
  ["curl -bsid=abcdef123456 https://x", "abcdef123456"],
  // wget
  ["wget --password=hunter2hunter2 https://x", "hunter2"],
  ["wget --http-password=hunter2hunter2 https://x", "hunter2"],
  ["wget --ftp-password hunter2hunter2 ftp://x", "hunter2"],
  ["wget --proxy-password=hunter2hunter2 https://x", "hunter2"],
  ["wget --http-user=bobthebuilder --http-password=hunter2hunter2 https://x", "bobthebuilder"],
  ["wget --proxy-user=bobthebuilder https://x", "bobthebuilder"],
  // URLs with userinfo, including a password that holds an `@`
  ["git clone https://bob:hunter2hunter2@github.com/a/b", "hunter2"],
  ["git clone https://bob:p@sshunter2@github.com/a/b", "hunter2"],
  ["psql postgres://app:hunter2hunter2@db:5432/x", "hunter2"],
  // mysql family, attached, spaced and quoted
  ["mysql -u root -phunter2hunter2 db", "hunter2"],
  ["mysql -u root -p hunter2hunter2 db", "hunter2"],
  ["mysql -p'hunter two three' db", "two three"],
  ['mysqldump -p"hunter two three" db', "two three"],
  ["mysql --password=hunter2hunter2 db", "hunter2"],
  ["mysql -u root " + "a".repeat(600) + " -p hunter2hunter2", "hunter2"],
  ["PGPASSWORD=hunter2hunter2 psql -h x", "hunter2"],
  // an unclosed quote used to skip the -u rule and leak the credential
  ['curl -u "admin:Tr0ub4dor https://x', "Tr0ub4dor"],
  // curl bundled headers: -H takes an argument, so the cookie/auth header must not be read as a -u bundle
  ["curl -HCookie:sid=abcdef123456 https://x", "abcdef123456"],
  ["curl -HAuthorization:Bearer-tok1234567 https://x", "tok1234567"],
];
const benign = [
  "curl -b cookies.txt https://x", "curl --cookie cookies.txt https://x", "curl --cookie-jar jar.txt https://x", "curl -c jar.txt https://x",
  "go test -bench=. -benchmem ./...", "go test -benchtime=2s", "git checkout -b feature/x", "git branch -b",
  "wget --user=bob https://x", "systemctl --user status foo", "docker run --user root img", "psql -p 5432 -U app",
  "sort -u a.txt", "git push -u origin main", "ls -lu src", "npm install -U left-pad", "pip install -U pip",
  "curl -H 'Accept: application/json' https://x", "curl -H 'Content-Type: application/json' -d '{}' https://x",
  "echo cookie", "echo 'a cookie recipe'", "curl https://example.com/a@b/c", "git clone https://github.com/a/b",
  "ssh -p 22 user@host", "scp -p file host:/tmp", "mysql -h db -D app", "wget --no-check-certificate https://x",
  "make -b a=b", "git checkout -b x=y", "grep -b a=b file", "rsync -avu host:/a /b", "id -u 1000:1000",
  "curl --user=1000:1000 https://x", "echo 'fix: cookie: expiry bug'", "git commit -m 'cookie: expiry'",
];
test("#27 leak table: the hook's copy scrubs every spelling the server does, and gives the same output", () => {
  for (const [input, secret] of leaks) {
    const h = hook.redact(input);
    assert.ok(!h.includes(secret), `hook leaked ${JSON.stringify(secret)}: ${h}`);
    assert.equal(h, redact(input), `diverged on: ${input}`);
  }
});
test("#27 benign controls: the hook leaves flags that only look like credential options byte-identical", () => {
  for (const c of benign) {
    assert.equal(hook.redact(c), c, c);
    assert.equal(hook.redact(c), redact(c), c);
  }
});
test("#27 exact outputs: the option and the rest of the command survive in the hook too", () => {
  const exact = [
    ["curl --user=admin:Tr0ub4dor https://x", "curl --user=<redacted> https://x"],
    ["curl -uadmin:Tr0ub4dor https://x", "curl -u<redacted> https://x"],
    ["curl -H 'Cookie: session=abcdef123456' https://x", "curl -H 'Cookie: <redacted>' https://x"],
    ["tool --auth=s3cretvalue run", "tool --auth=<redacted> run"],
    ["curl -b sid=abcdef123456 https://x", "curl -b <redacted> https://x"],
    ["mysql -p'hunter two three' db", "mysql -p<redacted> db"],
  ];
  for (const [input, want] of exact) {
    assert.equal(hook.redact(input), want);
    assert.equal(redact(input), want);
  }
});
test("hook redact()/redactCap() stay linear on hostile credential-option runs (CPU time)", () => {
  const cpu = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };
  const units = ["--auth=", "-u", "-b ", "-bench=", "--cookie ", "-H cookie:", "mysql -p", "--user=", "--proxy-user ", "-sSu ", "--auth '", "--password \"", "-u 'a", "cookie:"];
  for (const unit of units) {
    const payload = unit.repeat(Math.ceil(80000 / unit.length)).slice(0, 80000);
    const t0 = cpu();
    hook.redact(payload);
    hook.redactCap(payload, 100);
    const ms = cpu() - t0;
    assert.ok(ms < 1200, `hook redact used ${ms.toFixed(0)} ms CPU on 80000 chars of ${JSON.stringify(unit)}`);
  }
});
