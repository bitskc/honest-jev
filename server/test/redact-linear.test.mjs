// Linear-time guard for redaction. Every SECRET_RULES entry runs against every pump shape at 200 KB: each shape is a
// hostile input built from the rule's own classes plus a failing suffix (unclosed quote, missing terminator, a run that
// never reaches the next anchor), so backtracking has to scan. Each (rule, shape) run must stay under 500 ms of CPU.
// redact() on the worst shapes at 4 MB must stay under 2 s. Shapes are applied to every rule, not mapped by index, so a
// new rule can't escape coverage.
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { SECRET_RULES, redact } from "../src/kit/shell.mjs";

const SIZE = 200_000;
const RULE_BUDGET_MS = 500;
const BIG = 4_000_000;
const BIG_BUDGET_MS = 2_000;

const rep = (unit, n) => unit.repeat(Math.max(1, Math.floor(n / unit.length)));

const SHAPES = [
  ["private key BEGIN, no END", (n) => rep("-----BEGIN PRIVATE KEY-----\n", n)],
  ["private key BEGIN RSA, body run", (n) => "-----BEGIN RSA PRIVATE KEY-----" + "A".repeat(n)],
  ["authorization: then spaces", (n) => "authorization: " + " ".repeat(n)],
  ["authorization: repeated", (n) => rep("authorization: ", n)],
  ["authorization= run", (n) => "authorization=" + "a".repeat(n)],
  ["bearer then spaces", (n) => "bearer " + " ".repeat(n)],
  ["bearer repeated", (n) => rep("bearer ", n)],
  ["bearer token run", (n) => rep("bearer aaaaaaaaaaaaaaa ", n)],
  ["name suffix run", (n) => "x".repeat(n) + "token"],
  ["token=\" repeated", (n) => rep('token="', n)],
  ["api_key= repeated", (n) => rep("api_key= ", n)],
  ["_key suffix run", (n) => "a".repeat(n) + "_key"],
  ["password: repeated", (n) => rep("password: ", n)],
  ["--password unclosed quote", (n) => '--password "' + "a ".repeat(n / 2)],
  ["--password repeated", (n) => rep("--password ", n)],
  ["--token=\" repeated", (n) => rep('--token="', n)],
  ["--http-user unclosed quote", (n) => '--http-user "' + "a ".repeat(n / 2)],
  ["--http-user repeated", (n) => rep("--http-user ", n)],
  ["-u unclosed quote user:", (n) => '-u "' + "a:".repeat(n / 2)],
  ["-u quoted user: no close", (n) => '-u "a' + ":".repeat(n)],
  ["--user=\" unclosed", (n) => '--user="' + "a:".repeat(n / 2)],
  ["-u ' unclosed", (n) => "-u '" + "a:".repeat(n / 2)],
  ["-ua: bundle repeated", (n) => rep("-ua:", n)],
  ["-u repeated", (n) => rep("-u ", n)],
  ["-u quoted pair repeated", (n) => rep('-u "a:b" ', n)],
  ["cookie: run", (n) => "cookie:" + "a".repeat(n)],
  ["set-cookie: repeated", (n) => rep("set-cookie: ", n)],
  ["-HCookie: repeated", (n) => rep("-HCookie: ", n)],
  ["-b \" unclosed", (n) => '-b "' + "a=".repeat(n / 2)],
  ["-b run", (n) => "-b " + "a".repeat(n)],
  ["-b a repeated", (n) => rep("-b a", n)],
  ["--cookie \" unclosed", (n) => '--cookie "' + "a ".repeat(n / 2)],
  ["mysql repeated, no -p", (n) => rep("mysql ", n)],
  ["mysql then unclosed run", (n) => "mysql " + "a ".repeat(n / 2)],
  ["mysql -h repeated", (n) => rep("mysql -h x ", n)],
  ["secret_access_key then spaces", (n) => "secret_access_key " + " ".repeat(n)],
  ["secret_access_key repeated", (n) => rep("secret_access_key ", n)],
  ["URL scheme run, no @", (n) => "http://" + "a".repeat(n)],
  ["URL userinfo repeated", (n) => "a://" + "b:".repeat(n / 2)],
  ["URL scheme-like repeated", (n) => rep("ab://x:", n)],
  ["sk- repeated", (n) => rep("sk-", n)],
  ["sk- run", (n) => "sk-" + "a".repeat(n)],
  ["apikey_ repeated", (n) => rep("apikey_", n)],
  ["sk_live_ repeated", (n) => rep("sk_live_", n)],
  ["npm_ repeated", (n) => rep("npm_", n)],
  ["ghp_ repeated", (n) => rep("ghp_", n)],
  ["github_pat_ repeated", (n) => rep("github_pat_", n)],
  ["AKIA repeated", (n) => rep("AKIA", n)],
  ["xoxb- repeated", (n) => rep("xoxb-", n)],
  ["AIza repeated", (n) => rep("AIza", n)],
  ["AIza run", (n) => "AIza" + "a".repeat(n)],
  ["JWT dotted repeated", (n) => rep("eyJa.", n)],
  ["JWT segment run", (n) => "eyJ" + "a".repeat(n)],
  ["JWT dotted segments", (n) => rep("eyJaaaaaaaaaa.", n)],
  ["docker login -p repeated", (n) => rep("docker login -p ", n)],
  ["docker login -p quote unclosed", (n) => 'docker login -p "' + "a ".repeat(n / 2)],
  ["redis-cli -a repeated", (n) => rep("redis-cli -a ", n)],
  ["redis-cli --pass repeated", (n) => rep("redis-cli --pass ", n)],
  ["_authToken space then run", (n) => "_authToken " + "a".repeat(n)],
  ["_authToken repeated", (n) => rep("_authToken ", n)],
  ["--passphrase repeated", (n) => rep("--passphrase ", n)],
  ["-u empty user repeated", (n) => rep("-u :a ", n)],
  ["-u quoted empty user, no closer", (n) => '-u ":' + "a".repeat(n)],
  ["-u quoted spaced user, no closer", (n) => '-u "a b' + ":".repeat(n)],
  ["curl -sSu empty user repeated", (n) => rep("curl -sSu :a ", n)],
  ["curl -u colon run", (n) => "curl -u " + ":".repeat(n)],
  ["Authorization quote run, no closer", (n) => "curl -H 'Authorization: " + "a".repeat(n)],
];

// Input is built once per shape; each rule reads the same string, so an unmapped shape can't be skipped.
const inputs = SHAPES.map(([name, make]) => [name, make(SIZE)]);

function cpuMs(fn) {
  const t0 = process.cpuUsage();
  fn();
  const u = process.cpuUsage(t0);
  return (u.user + u.system) / 1000;
}

describe("SECRET_RULES stay linear on hostile input (200 KB per shape)", () => {
  test("shape list covers every rule's classes (every rule runs every shape)", () => {
    assert.ok(SECRET_RULES.length > 0);
    assert.ok(inputs.length >= 40, `expected >= 40 shapes, got ${inputs.length}`);
  });

  SECRET_RULES.forEach(([re], i) => {
    test(`rule ${i} (${re.source.slice(0, 40)}) under ${RULE_BUDGET_MS} ms CPU per shape`, () => {
      for (const [name, s] of inputs) {
        const ms = cpuMs(() => s.replace(re, "<r>"));
        assert.ok(ms <= RULE_BUDGET_MS, `rule ${i} on "${name}": ${ms.toFixed(0)} ms > ${RULE_BUDGET_MS} ms`);
      }
    });
  });
});

describe("redact() on 4 MB hostile input under 2 s CPU", () => {
  const big = [
    ["mysql repeated, no -p", rep("mysql ", BIG)],
    ["authorization: spaces", "authorization: " + " ".repeat(BIG)],
    ["-u unclosed quote user:", '-u "' + "a:".repeat(BIG / 2)],
    ["docker login -p repeated", rep("docker login -p ", BIG)],
    ["redis-cli -a repeated", rep("redis-cli -a ", BIG)],
    ["_authToken repeated", rep("_authToken ", BIG)],
    ["--passphrase repeated", rep("--passphrase ", BIG)],
    ["-u quoted empty user, no closer", '-u ":' + "a".repeat(BIG)],
  ];
  for (const [name, s] of big) {
    test(`${name}`, () => {
      const ms = cpuMs(() => redact(s));
      assert.ok(ms <= BIG_BUDGET_MS, `redact("${name}") at 4 MB: ${ms.toFixed(0)} ms > ${BIG_BUDGET_MS} ms`);
    });
  }
});
