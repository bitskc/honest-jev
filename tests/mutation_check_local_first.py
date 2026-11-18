#!/usr/bin/env python3
"""Mutation check for the local-first guard tests.

Copies the relevant tree to a scratch directory, applies one deliberate defect (one or more coordinated edits) at a time,
and requires the matching test suite to FAIL. The first mutation of each hook disables the local step altogether: the new
tests must notice that nothing is settled locally any more. A mutation that survives means the test it targets cannot catch
that defect. The real tree is never modified. Data only: nothing here executes a guarded command string.

    python3 tests/mutation_check_local_first.py            # all mutations
    python3 tests/mutation_check_local_first.py -v         # also print the failing test output of each killed mutation's first failure
    python3 tests/mutation_check_local_first.py disabled   # only the mutations whose name contains "disabled"
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# the unit under mutation is the whole tree: every suite below runs unchanged against the copy

PYT = [sys.executable, "-W", "ignore", "-m", "unittest", "tests/test_local_first.py"]
RUNT = ["node", "--test", "hooks/jev-guard-local.test.mjs"]
LEDT = [sys.executable, "-W", "ignore", "-m", "unittest", "tests/test_ledger_hook.py"]
OMPT = ["bun", "test", "tests/local-first-omp.test.ts"]
SCRIPTS = ["bash", "tests/test-scripts.sh"]
# the generated constant is not committed: the copy has none, and this command makes it exactly as `npm test` does (pretest)
FPT = ["sh", "-c", "cd server && npm run fingerprint --silent && node --test test/rules-fingerprint.test.mjs"]

PYH = "hooks/jev_guard_hook.py"
PYL = "hooks/jev_ledger.py"
RUN = "hooks/jev-guard-local.mjs"
TS = "hooks/omp/jev-guard.ts"
INST = "install.sh"
FPMOD = "hooks/jev-rules-fingerprint.mjs"
HEALTH = "server/src/health.mjs"
GENS = "server/scripts/gen-rules-fingerprint.mjs"
PKG = "server/package.json"
WRANGLER = "server/wrangler.jsonc"
CI = ".github/workflows/test.yml"
GITIGNORE = ".gitignore"
GUARD = "server/src/kit/guard.mjs"
KITT = ["sh", "-c", "cd server && node --test test/kit.test.mjs"]

# The first version of the omp hook kept the fingerprint in a per-path map on the main thread. These two edits put such a memo back (used by the
# "remembered per rules path" mutations below, each of which then clears it on every worker replacement but one).
MEMO = [
    (TS, "export type LocalVerdict", "const memo = new Map<string, string | null>();\nexport type LocalVerdict"),
    (TS, 'reply.decision !== "block"), fp: judged.fp };', 'reply.decision !== "block"), fp: memo.has(path) ? memo.get(path)! : (memo.set(path, judged.fp), judged.fp) };'),
]

# (name, [(file, old, new), ...], command). `old` must occur exactly once.
MUTATIONS = [
    # ── python hook ──
    ("hook-py: local step disabled", [(PYH, '    if not local_enabled():\n        return None\n    _CTX["local_why"] = "failed"', '    if True:\n        return None\n    _CTX["local_why"] = "failed"')], PYT),
    ("hook-py: JEV_GUARD_LOCAL=off ignored", [(PYH, 'return os.environ.get("JEV_GUARD_LOCAL", "").strip().lower() != "off"', "return True")], PYT),
    ("hook-py: an unclear command is treated as settled", [(PYH, 'return local is not None and (local.get("unclear") is True or local.get("decided_by") == "fail_open")', "return False")], PYT),
    ("hook-py: the runner's unclear flag is ignored (decided_by only)", [(PYH, 'local.get("unclear") is True or local.get("decided_by") == "fail_open"', 'local.get("decided_by") == "fail_open"')], PYT),
    ("hook-py: a notice on every call", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-" + sid))', "return True")], PYT),
    ("hook-py: the notice is not keyed by session", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-" + sid))', 'return bool(_ledger is not None and _ledger.mark_once("notice-x"))')], PYT),
    ("hook-py: the notice is shown without a local unclear verdict", [(PYH, 'notice = LOCAL_NOTICE if unclear and e.code == "client_config" and first_unclear_in_session() else None', 'notice = LOCAL_NOTICE if e.code == "client_config" and first_unclear_in_session() else None')], PYT),
    ("hook-py: the flagged rule is dropped from the fail_open row", [(PYH, 'hint = {"rule": local.get("rule")} if unclear and isinstance(local.get("rule"), str) else None', "hint = None")], PYT),
    ("hook-py: a rule_error row loses its closed fail_reason", [(PYH, '        row["fail_reason"] = "rule_error"  # a server reply carries this in its record; a local reply has none', "        pass")], PYT),
    ("hook-py: the runner's time budget is not enforced", [(PYH, "capture_output=True, timeout=local_timeout())", "capture_output=True, timeout=None)")], PYT),
    ("hook-py: the network stack is imported eagerly", [(PYH, "import threading\nimport time\n", "import threading\nimport time\nimport urllib.request\n")], PYT),
    ("hook-py: a settled reply still calls the server", [(PYH, "        return reply_outcome(local)\n", "        pass\n")], PYT),
    ("hook-py: a local ask is downgraded to allow when the server is unavailable (no server)", [(PYH, "        note(\"fail-open: %s\" % e.why)\n        if stands is not None:\n            return reply_outcome(stands)\n", "        note(\"fail-open: %s\" % e.why)\n")], PYT),
    ("hook-py: a local ask is downgraded to allow when the server is unavailable (network failure)", [(PYH, "the server is down for the next minute\n        if stands is not None:\n            return reply_outcome(stands)\n", "the server is down for the next minute\n")], PYT),
    ("hook-py: a pure-unclear allow is turned into a stand", [(PYH, 'stands = local if unclear and local.get("decision") in ("ask", "block") else None', "stands = local if unclear else None")], PYT),
    ("hook-py: the not-run row keeps the plain client_config reason", [(PYH, 'fail_reason="local_rules_unavailable", enforced=True), notice=notice)', "fail_reason=e.code, enforced=True), notice=notice)")], PYT),
    ("hook-py: no notice when the local rules did not run", [(PYH, 'notice = LOCAL_DOWN_NOTICE if local_down_notice(_CTX["local_why"]) else None', "notice = None")], PYT),
    ("hook-py: the not-run notice repeats on every call", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-down-" + _session_key()))', "return True")], PYT),
    ("hook-py: the not-run notice is not keyed by session", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-down-" + _session_key()))', 'return bool(_ledger is not None and _ledger.mark_once("notice-down-x"))')], PYT),
    ("hook-py: one slow command says 'commands are not being checked'", [(PYH, 'if why == "timeout" and _ledger is not None and _ledger.mark_once("notice-slow-" + _session_key()):', "if False:")], PYT),
    ("hook-py: a time-budget miss is never counted toward the notice", [(PYH, 'if why == "timeout" and _ledger is not None and _ledger.mark_once("notice-slow-" + _session_key()):', 'if why == "timeout":')], PYT),
    ("hook-py: the off switch counts as 'did not run'", [(PYH, '    if not local_enabled():\n        return None\n    _CTX["local_why"] = "failed"', '    if not local_enabled():\n        _CTX["local_why"] = "failed"\n        return None\n    _CTX["local_why"] = "failed"')], PYT),
    ("hook-py: a hard failure is reported as a time-budget miss (the first one stays quiet)", [(PYH, '    _CTX["local_why"] = "failed"  # until proven otherwise below', '    _CTX["local_why"] = "timeout"  # until proven otherwise below')], PYT),
    ("ledger-py: local_rules_unavailable is not in the closed list", [(PYL, '    "local_rules_unavailable",  # the hook\'s local rules did not run (and no server answered): see hooks/jev_guard_hook.py\n', "")], PYT),
    ("record.mjs: the shared closed list lacks local_rules_unavailable (the Python/Node/TS parity test)", [("server/src/ledger/record.mjs", '  "local_rules_unavailable", // written by the guard hooks\' own rows only (hooks/jev_ledger.py, hooks/omp/jev-guard.ts); the Worker never emits it\n', "")], LEDT),
    ("ledger-py: the notice marker is not exclusive", [(PYL, "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)", "os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)")], PYT),
    ("ledger-py: old markers are never pruned", [(PYL, "                if now - os.lstat(p).st_mtime > MARKER_MAX_AGE:", "                if False:")], PYT),
    # ── node runner ──
    ("runner: the unclear flag ignores a model question that only the masked reading raised", [(RUN, 'reply.unclear = consulted > 0 && reply.decision !== "block";', 'reply.unclear = reply.decided_by === "fail_open";')], RUNT),
    ("runner: a block with a model question is called unclear", [(RUN, 'reply.unclear = consulted > 0 && reply.decision !== "block";', "reply.unclear = consulted > 0;")], RUNT),
    ("runner: the release beside the hook is not looked at first", [(RUN, '    resolve(here, "..", "server", "src", "kit", "guard.mjs"),\n', "")], RUNT),
    ("runner: a relative JEV_GUARD_RULES is accepted", [(RUN, "if (custom) return isAbsolute(custom) ? [custom] : [];", "if (custom) return [resolve(custom)];")], RUNT),
    ("runner: a group- or world-writable compile-cache directory is used", [(RUN, "    if ((st.mode & 0o022) !== 0) return; // group- or world-writable: anyone it names could plant compiled code the guard would then load\n", "")], RUNT),
    ("runner: judgeStdin drops the rule's suggestion (the in-process corpus run)", [(RUN, "  reply.unclear = consulted > 0 && reply.decision !== \"block\";\n  return reply;", "  reply.unclear = consulted > 0 && reply.decision !== \"block\";\n  return { ...reply, suggestion: null };")], RUNT),
    ("runner: the one-shot entry drops the rule id (only the real spawns see it)", [(RUN, "  process.stdout.write(`${JSON.stringify({ ...reply, rules_fp: fp })}\\n`);\n  return 0;\n}\n\n// Run only", "  process.stdout.write(`${JSON.stringify({ ...reply, rules_fp: fp, rule: null })}\\n`);\n  return 0;\n}\n\n// Run only")], RUNT),
    # ── omp hook ──
    ("hook-omp: local step disabled", [(TS, '  if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;', "  return null;")], OMPT),
    ("hook-omp: JEV_GUARD_LOCAL=off ignored", [(TS, '  if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;', "")], OMPT),
    ("hook-omp: the masked-reading model question is not unclear", [(TS, 'unclear: by === "fail_open" || (judged.consulted > 0 && reply.decision !== "block"), fp: judged.fp };', 'unclear: by === "fail_open", fp: judged.fp };')], OMPT),
    ("hook-omp: an unclear command is treated as settled", [(TS, "const ruleSettled = local !== null && !local.unclear && (", "const ruleSettled = local !== null && (")], OMPT),
    ("hook-omp: a notice on every call", [(TS, 'local?.unclear && g.code === "client_config" && !noticed ? LOCAL_NOTICE : null;', 'local?.unclear && g.code === "client_config" ? LOCAL_NOTICE : null;')], OMPT),
    ("hook-omp: a new session is never told again", [(TS, 'async () => { noticed = false; downNoticed = false; trustNoticed.clear(); });', 'async () => { downNoticed = false; trustNoticed.clear(); });')], OMPT),
    ("hook-omp: the flagged rule is dropped from the fail_open row", [(TS, 'failReason: nothingRan ? "local_rules_unavailable" : g.code, rule: flagged });', 'failReason: nothingRan ? "local_rules_unavailable" : g.code });')], OMPT),
    ("hook-omp: a rule_error row loses its closed fail_reason", [(TS, 'wouldHave: would, failReason: ruleError });', "wouldHave: would });")], OMPT),
    ("hook-omp: rules found only through the override", [(TS, 'for (const dir of ["honest-jev", "jev-agent-skills"]) {', "for (const dir of []) {")], OMPT),
    ("hook-omp: a local ask is downgraded to allow when the server is unavailable", [(TS, 'const g: McpResult<GuardReply> = answered.kind === "unavailable" && local?.unclear && local.reply.decision !== "allow" ? { kind: "reply", reply: local.reply as GuardReply } : answered;', "const g: McpResult<GuardReply> = answered;")], OMPT),
    ("hook-omp: a pure-unclear allow is turned into a stand (no notice, no fail_open row)", [(TS, 'answered.kind === "unavailable" && local?.unclear && local.reply.decision !== "allow" ?', 'answered.kind === "unavailable" && local?.unclear ?')], OMPT),
    # ── the local rules could not run, and no server answers ──
    ("hook-omp: not-run row keeps the plain client_config reason", [(TS, 'failReason: nothingRan ? "local_rules_unavailable" : g.code,', "failReason: g.code,")], OMPT),
    ("hook-omp: no notice when the local rules did not run", [(TS, "const say = nothingRan ? (downNoticed ? null : LOCAL_DOWN_NOTICE) :", "const say = nothingRan ? null :")], OMPT),
    ("hook-omp: the not-run notice repeats on every call", [(TS, "const say = nothingRan ? (downNoticed ? null : LOCAL_DOWN_NOTICE) :", "const say = nothingRan ? LOCAL_DOWN_NOTICE :")], OMPT),
    ("hook-omp: a new session never hears the not-run notice again", [(TS, "noticed = false; downNoticed = false; trustNoticed.clear(); });", "noticed = false; trustNoticed.clear(); });")], OMPT),
    ("hook-omp: the off switch counts as 'did not run'", [(TS, '  if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;', '  if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return { notRun: true };')], OMPT),
    ("hook-omp: a rules failure is reported as the off switch (no notice, no marked row)", [(TS, "    if (!path) return { notRun: true };", "    if (!path) return null;")], OMPT),
    # ── install.sh doctor ──
    ("doctor: the local-rules-only note is never printed", [(INST, 'echo "note guard runs on local rules only, not checked against any server; unclear commands are allowed without a model check"', "true")], SCRIPTS),
    ("doctor: the local rules line is never checked", [(INST, '  elif rp=$("$rt" "$runner" --check 2>/dev/null); then ok "guard rules load locally ($rp)"', '  elif true; then ok "guard rules load locally ($runner)"')], SCRIPTS),
    ("doctor: the 'local rules only' note is printed although the rules do not load", [(INST, '  elif [ "$rules_ok" = 1 ]; then echo "note guard runs on local rules only', '  elif true; then echo "note guard runs on local rules only')], SCRIPTS),
    ("doctor: no note when the rules do not load and a server is configured", [(INST, '[ "$rules_ok" = 1 ] || echo "note the local rules do not load; every command is sent to the server"', "true")], SCRIPTS),
    ("doctor: no note when neither the rules nor a server work", [(INST, '  else echo "note the guard is not checking commands: the local rules do not load and no server is configured"; fi', "  else :; fi")], SCRIPTS),
    ("doctor: the 'from file only' marker is never set", [(INST, 'if [ -n "$JEV_MCP_URL" ]; then url_file_only=1; fi', 'true'), (INST, 'if [ -n "$JEV_MCP_TOKEN" ]; then tok_file_only=1; fi', 'true')], SCRIPTS),
    ("doctor: the token line never says it came from the file", [(INST, 'elif [ "$tok_file_only" = 1 ]; then ok "JEV_MCP_TOKEN set (from $envfile only)"', 'elif false; then ok "JEV_MCP_TOKEN set"')], SCRIPTS),
    ("doctor: the file-only note is printed for the URL alone", [(INST, 'if [ "$url_file_only" = 1 ] || [ "$tok_file_only" = 1 ]; then', 'if [ "$url_file_only" = 1 ]; then')], SCRIPTS),
    ("doctor: the file-only note is printed even when both values come from the environment", [(INST, 'if [ "$url_file_only" = 1 ] || [ "$tok_file_only" = 1 ]; then', 'if true; then')], SCRIPTS),
    ("doctor: a passing rules check is never recorded", [(INST, 'ok "guard rules load locally ($rp)"; rules_ok=1', 'ok "guard rules load locally ($rp)"')], SCRIPTS),
    # ── the rules fingerprint: a local allow is final only when the rules here are the server's ──
    ("hook-py: a different fingerprint still trusts the local allow (trust the local allow on mismatch)", [(PYH, 'return "match" if theirs == mine else "mismatch"', 'return "match"')], PYT),
    ("hook-py: an unavailable server fingerprint counts as a match", [(PYH, '    if theirs is None:\n        return "unverified"\n', '    if theirs is None:\n        return "match"\n')], PYT),
    ("hook-py: rules that are not the whole release count as a match", [(PYH, 'if not (isinstance(mine, str) and FP_RE.fullmatch(mine)):\n        return "unverified"', 'if not (isinstance(mine, str) and FP_RE.fullmatch(mine)):\n        return "match"')], PYT),
    ("hook-py: the runner's rules_fp is ignored (every local allow goes to the server)", [(PYH, 'mine = local.get("rules_fp")', "mine = None")], PYT),
    ("hook-py: a local ask or block is judged by the fingerprint too (stricter is not kept)", [(PYH, 'if local.get("decision") == "allow" and server_configured():', "if server_configured():")], PYT),
    ("hook-py: the fingerprint is looked up even with no server configured", [(PYH, 'if local.get("decision") == "allow" and server_configured():', 'if local.get("decision") == "allow":')], PYT),
    ("hook-py: no notice for a rules mismatch", [(PYH, "if trust in TRUST_NOTICES and _ledger is not None and", "if False and")], PYT),
    ("hook-py: the rules notice repeats on every call", [(PYH, 'if trust in TRUST_NOTICES and _ledger is not None and _ledger.mark_once("notice-rules-%s-%s" % (trust, _session_key())):', "if trust in TRUST_NOTICES:")], PYT),
    ("hook-py: the rules notice is not keyed by session", [(PYH, '"notice-rules-%s-%s" % (trust, _session_key())', '"notice-rules-%s-%s" % (trust, "x")')], PYT),
    ("hook-py: the cached fingerprint never expires", [(PYH, "return (fp,) if 0 <= age <= (FP_TTL if fp else FP_TTL_DOWN) else None", "return (fp,)")], PYT),
    ("hook-py: 'the server gave none' is remembered as long as a real fingerprint", [(PYH, "(FP_TTL if fp else FP_TTL_DOWN)", "FP_TTL")], PYT),
    ("hook-py: the fingerprint cache is never written", [(PYH, "        os.replace(tmp, where[1])\n", "        os.unlink(tmp)\n")], PYT),
    ("hook-py: the cache is shared between servers", [(PYH, "hashlib.sha256(URL.encode())", 'hashlib.sha256(b"x")')], PYT),
    ("hook-py: a symlinked cache file is followed", [(PYH, "fd = os.open(where[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)", "fd = os.open(where[1], os.O_RDONLY | os.O_NONBLOCK)")], PYT),
    ("hook-py: the fingerprint fetch has no time budget", [(PYH, "        signal.setitimer(signal.ITIMER_REAL, FP_FETCH_BUDGET)\n", ""), (PYH, "timeout=FP_FETCH_BUDGET - 0.1)", "timeout=60)")], PYT),
    ("hook-py: the fingerprint is fetched without the token", [(PYH, '"authorization": "Bearer " + os.environ.get("JEV_MCP_TOKEN", "").strip(),', '"x-none": "0",')], PYT),
    ("runner: rules_fp is missing from the reply", [(RUN, "JSON.stringify({ ...reply, rules_fp: fp })", "JSON.stringify(reply)")], RUNT),
    ("runner: the fingerprint is not taken from the loaded rules' directory", [(FPMOD, 'return { path: join(dir, "guard.mjs"), fp: rulesFingerprint(dir) };', 'return { path: join(dir, "guard.mjs"), fp: rulesFingerprint(dirname(dir)) };')], RUNT),
    ("fingerprint: shell.mjs is not covered", [(FPMOD, 'Object.freeze(["guard.mjs", "safere.mjs", "shell.mjs"])', 'Object.freeze(["guard.mjs", "safere.mjs"])')], RUNT),
    ("fingerprint: files are not length-framed", [(FPMOD, "    h.update(`${name}\\0${bytes.length}\\0`);\n", "")], FPT),
    ("server: /health reports the fingerprint to everyone", [(HEALTH, "return new Response(\"ok\", authorized ? {", "return new Response(\"ok\", true ? {")], FPT),
    ("server: an unset token authorizes an empty bearer", [(HEALTH, "  if (!expected) return false;\n", "")], FPT),
    ("server: the generator writes a constant that is not the fingerprint", [(GENS, '${rulesFingerprint(join(server, "src", "kit"))}', '${"0".repeat(64)}')], FPT),
    ("server: npm test does not generate the constant (no pretest)", [(PKG, '    "pretest": "npm run fingerprint",\n', "")], FPT),
    ("server: wrangler's build step does not generate the constant (a raw wrangler deploy ships a stale one)", [(WRANGLER, '    "command": "npm run fingerprint",\n', "")], FPT),
    ("server: npm run deploy does not generate the constant", [(PKG, "npm run vendor && npm run fingerprint && wrangler deploy", "npm run vendor && wrangler deploy")], FPT),
    ("server: the generated constant is no longer ignored (it would be committed and go stale)", [(GITIGNORE, "server/src/rules-fingerprint.mjs\n", "")], FPT),
    ("server: CI runs the server tests without npm (no pretest)", [(CI, "        working-directory: server\n        run: npm test", '        working-directory: server\n        run: node --test "test/**/*.test.mjs"')], FPT),
    ("fingerprint: a symlinked rule file is hashed through the link", [(FPMOD, "    if (!lstatSync(file).isFile()) throw new Error(`${name} is not a regular file`);\n", "")], RUNT),
    ("runner: a rule file not named guard.mjs is fingerprinted", [(FPMOD, 'if (basename(guardPath) !== "guard.mjs") return { path: guardPath, fp: null };', "")], RUNT),
    ("hook-omp: a symlinked rule file is hashed through the link", [(TS, '    if (!lstatSync(file).isFile()) throw new Error(name + " is not a regular file");\n', "")], OMPT),
    ("doctor: rules that cannot be fingerprinted are not a failure", [(INST, 'if [ -z "$lfp" ]; then bad "guard rules cannot be fingerprinted', 'if [ -z "$lfp" ]; then ok "guard rules cannot be fingerprinted')], SCRIPTS),
    ("hook-omp: a rule file not named guard.mjs is fingerprinted", [(TS, 'if (basename(path) === "guard.mjs") {', "if (true) {")], OMPT),
    ("hook-omp: a different fingerprint still trusts the local allow (trust the local allow on mismatch)", [(TS, 'return theirs === null ? "unverified" : "mismatch";', 'return theirs === null ? "unverified" : "match";')], OMPT),
    ("hook-omp: an unavailable server fingerprint counts as a match", [(TS, 'return theirs === null ? "unverified" : "mismatch";', 'return theirs === null ? "match" : "mismatch";')], OMPT),
    ("hook-omp: rules that are not the whole release count as a match", [(TS, 'if (local.fp === null || !FP_RE.test(local.fp)) return serverDownCode() ? "down" : "unverified";', 'if (local.fp === null || !FP_RE.test(local.fp)) return "match";')], OMPT),
    ("hook-omp: a local ask or block is judged by the fingerprint too (stricter is not kept)", [(TS, 'if (ruleSettled && local!.reply.decision === "allow" && mcpToken() !== ""', 'if (ruleSettled && mcpToken() !== ""')], OMPT),
    ("hook-omp: no notice for a rules mismatch", [(TS, 'if ((trust === "mismatch" || trust === "unverified" || trust === "down") && !trustNoticed.has(trust)) {', "if (false) {")], OMPT),
    ("hook-omp: the rules notice repeats on every call", [(TS, 'if ((trust === "mismatch" || trust === "unverified" || trust === "down") && !trustNoticed.has(trust)) {', 'if (trust === "mismatch" || trust === "unverified" || trust === "down") {')], OMPT),
    ("hook-omp: a new session never hears the rules notice again", [(TS, "downNoticed = false; trustNoticed.clear(); });", "downNoticed = false; });")], OMPT),
    ("hook-omp: the cached server fingerprint never expires", [(TS, "now - serverFp.at < (serverFp.fp ? FP_TTL_MS : FP_TTL_DOWN_MS)", "true")], OMPT),
    ("hook-omp: 'the server gave none' is remembered as long as a real fingerprint", [(TS, "(serverFp.fp ? FP_TTL_MS : FP_TTL_DOWN_MS)", "FP_TTL_MS")], OMPT),
    ("hook-omp: the fingerprint fetch has no time budget", [(TS, "      signal: AbortSignal.timeout(FP_FETCH_MS),\n", "")], OMPT),
    ("hook-omp: the fingerprint is fetched without the token", [(TS, 'headers: { authorization: `Bearer ${mcpToken()}`, "user-agent": "jev-guard-hook-omp/1.0" },', 'headers: { "user-agent": "jev-guard-hook-omp/1.0" },')], OMPT),
    ("hook-omp: the fingerprint function misses a file", [(TS, 'export const RULE_FILES = ["guard.mjs", "safere.mjs", "shell.mjs"] as const;', 'export const RULE_FILES = ["guard.mjs", "safere.mjs"] as const;')], OMPT),
    ("hook-omp: the fingerprint is not length-framed", [(TS, '    h.update(name + "\\\\0" + bytes.length + "\\\\0");\n', "")], OMPT),
    ("hook-omp: the rules are looked up again on every call (a rewritten file takes effect)", [(TS, "    let loaded = cache.get(path);\n    if (!loaded) {", "    let loaded;\n    if (!loaded) {")], OMPT),
    # ── the fingerprint describes what the worker that produced the verdict loaded ──
    ("hook-omp: the fingerprint is the hash taken before the import only", [(TS, "if (after === before) fp = after;", "fp = before;")], OMPT),
    ("hook-omp: the fingerprint is the hash taken after the import only", [(TS, "if (after === before) fp = after;", "fp = after;")], OMPT),
    ("hook-omp: a crashed worker is waited out until the budget", [(TS, '    w.on("exit", onDead);\n    w.postMessage', "    w.postMessage"), (TS, '    w.on("error", onDead);\n', "")], OMPT),
    ("hook-omp: a rules failure keeps the worker (the next call cannot re-import)", [(TS, "else { dropWorker(w); finish({ ok: false }); }", "else { finish({ ok: false }); }")], OMPT),
    ("hook-omp: the worker is not forgotten when it exits", [(TS, '    w.on("exit", gone);\n', "")], OMPT),
    # A per-path memo of the fingerprint on the main thread, as the first version had it (put back here to prove the tests catch each way it goes stale).
    ("hook-omp: a fingerprint remembered per rules path survives a worker timeout", [*MEMO, (TS, "const onDead = () => finish({ ok: false });", "const onDead = () => { memo.clear(); finish({ ok: false }); };"), (TS, "const gone = () => { if (rulesWorker === w) rulesWorker = null; };", "const gone = () => { memo.clear(); if (rulesWorker === w) rulesWorker = null; };"), (TS, "else { dropWorker(w); finish({ ok: false }); }", "else { memo.clear(); dropWorker(w); finish({ ok: false }); }")], OMPT),
    ("hook-omp: a fingerprint remembered per rules path survives a worker crash or an uncaught error in it", [*MEMO, (TS, "const timer = setTimeout(() => { dropWorker(w); finish({ notRun: true }); }, localBudgetMs());", "const timer = setTimeout(() => { memo.clear(); dropWorker(w); finish({ notRun: true }); }, localBudgetMs());"), (TS, "else { dropWorker(w); finish({ ok: false }); }", "else { memo.clear(); dropWorker(w); finish({ ok: false }); }")], OMPT),
    ("hook-omp: a fingerprint remembered per rules path survives a rules failure (a throw in the guard)", [*MEMO, (TS, "const timer = setTimeout(() => { dropWorker(w); finish({ notRun: true }); }, localBudgetMs());", "const timer = setTimeout(() => { memo.clear(); dropWorker(w); finish({ notRun: true }); }, localBudgetMs());"), (TS, "const onDead = () => finish({ ok: false });", "const onDead = () => { memo.clear(); finish({ ok: false }); };"), (TS, "const gone = () => { if (rulesWorker === w) rulesWorker = null; };", "const gone = () => { memo.clear(); if (rulesWorker === w) rulesWorker = null; };")], OMPT),
    # ── the kit token file (~/.config/jev/env): READ and glob coverage, and the narrow WRITE rule (not the dotenv read list) ──
    ("guard: a write is judged by the whole read list (cp .env.example .env blocks again)", [(GUARD, "return KIT_TOKEN_FILE_RE.test(normalizePath(expand(a, home)));", "return SECRET_PATH_RES.some((r) => r.test(normalizePath(expand(a, home))));")], KITT),
    ("guard: a redirect onto the token file is not blocked", [(GUARD, "else if (isKitTokenFileTok(t, ctx.home)) yield tokenFile(", "else if (false) yield tokenFile(")], KITT),
    ("guard: cp/mv/install onto the token file is not blocked", [(GUARD, "} else if (dest && isKitTokenFileTok(dest, ctx.home)) {", "} else if (false) {")], KITT),
    ("guard: the token file write is reported as an irreversible overwrite", [(GUARD, 'const tokenFile = (reason) => ({ rule: "R1-secret-exfiltration", severity: "block"', 'const tokenFile = (reason) => ({ rule: "R7-irreversible", severity: "block"')], KITT),
    ("guard: a backup named after the token file is not a secret store", [(GUARD, "\\.config\\/jev\\/env(?![A-Za-z0-9])/,", "\\.config\\/jev\\/env$/,")], KITT),
    ("guard: glob spellings of the token file are not covered", [(GUARD, '["airlock", "env"], ["jev", "env"]];', '["airlock", "env"]];')], KITT),
    ("guard: the whole of ~/.config/jev is a secret store", [(GUARD, "\\.config\\/jev\\/env(?![A-Za-z0-9])/,", "\\.config\\/jev\\//,")], KITT),
    # ── the remembered "server down" window ──
    ("hook-py: the down window is never opened", [(PYH, "        if is_network_error(e):\n            code = _ledger.fail_reason_for(e)", "        if False:\n            code = _ledger.fail_reason_for(e)")], PYT),
    ("hook-py: an HTTPError (the server answered: 5xx with a body) counts as a network error", [(PYH, "        if isinstance(e, urllib.error.HTTPError):\n            return False\n", "        pass\n")], PYT),
    ("hook-py: a 401 (server rejected the call) opens the window", [(PYH, "    except (ServerRejected, RedirectRefused) as e:  # server reachable but refused/redirected the call: ask, never allow silently\n", "    except (ServerRejected, RedirectRefused) as e:  # server reachable but refused/redirected the call: ask, never allow silently\n        open_server_down(OSError())\n")], PYT),
    ("hook-py: the window is ignored (a local allow still calls the server)", [(PYH, '    data = _state_read("server-down")\n', "    data = None\n")], PYT),
    ("hook-py: the window never expires", [(PYH, "return code if 0 <= time.time() - t < SERVER_DOWN_WINDOW else None", "return code if 0 <= time.time() - t else None")], PYT),
    ("hook-py: a window with a timestamp in the future is believed", [(PYH, "return code if 0 <= time.time() - t < SERVER_DOWN_WINDOW else None", "return code if time.time() - t < SERVER_DOWN_WINDOW else None")], PYT),
    ("hook-py: a window with a code outside the closed list is believed", [(PYH, "code not in DOWN_CODES:\n        return None\n    return code if", "False:\n        return None\n    return code if")], PYT),
    ("hook-py: a successful Worker call does not clear the window", [(PYH, "    clear_server_down()  # the server answered: a window opened by an earlier failure is over\n", "")], PYT),
    ("hook-py: an unclear command is skipped by the window", [(PYH, "    out = server_outcome(args, local, unclear, verifying=trust is not None)\n", '    if unclear and server_down():\n        return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason="client_network", enforced=True))\n    out = server_outcome(args, local, unclear, verifying=trust is not None)\n')], PYT),
    ("hook-py: a failing unclear command opens the window", [(PYH, "verifying=trust is not None)", "verifying=True)")], PYT),
    ("hook-py: a failing verification call does not open the window", [(PYH, "        if verifying:\n            open_server_down(e)", "        if False:\n            open_server_down(e)")], PYT),
    ("hook-py: a failing fingerprint fetch does not open the window", [(PYH, "    except Exception as e:\n        open_server_down(e)\n        return None\n", "    except Exception:\n        return None\n")], PYT),
    ("hook-py: the fingerprint is fetched while the server is called down", [(PYH, "    if server_down():\n        return None\n    fp = fetch_server_fp()", "    fp = fetch_server_fp()")], PYT),
    ("hook-py: the standing allow is recorded as a trusted local decision", [(PYH, 'row=dict(decision="allow", decided_by="fail_open", fail_reason=server_down() or "client_network", enforced=True),\n                           notice=trust_notice("down"))', 'row=dict(decision="allow", decided_by="prefilter", enforced=True),\n                           notice=trust_notice("down"))')], PYT),
    ("hook-py: no notice for a standing allow", [(PYH, 'notice=trust_notice("down"))', "notice=None)")], PYT),
    ("hook-omp: the down window is never opened", [(TS, "function openServerDown(code: DownCode): void { serverDown = { key: mcpUrl(), code, at: Date.now() }; }", "function openServerDown(code: DownCode): void { void code; }")], OMPT),
    ("hook-omp: a 401, a 5xx with a body or a JSON-RPC error opens the window", [(TS, 'if ((trust === "mismatch" || trust === "unverified") && answered.kind === "unavailable" && (answered.code === "client_timeout" || answered.code === "client_network")) openServerDown(answered.code);', 'if ((trust === "mismatch" || trust === "unverified") && answered.kind !== "reply") openServerDown("client_network");')], OMPT),
    ("hook-omp: a refused redirect counts as a network failure", [(TS, '  if (msg.includes("redirect")) return null;\n  const code = failCodeFor(e);', "  const code = failCodeFor(e);")], OMPT),
    ("hook-omp: the window is ignored (a local allow still calls the server)", [(TS, "return serverDown && serverDown.key === mcpUrl() && age >= 0 && age < SERVER_DOWN_MS ? serverDown.code : null;", "return null;")], OMPT),
    ("hook-omp: the window never expires", [(TS, "serverDown.key === mcpUrl() && age >= 0 && age < SERVER_DOWN_MS ?", "serverDown.key === mcpUrl() && age >= 0 ?")], OMPT),
    ("hook-omp: the window is shared between servers", [(TS, "return serverDown && serverDown.key === mcpUrl() && age", "return serverDown && age")], OMPT),
    ("hook-omp: a successful Worker call does not clear the window", [(TS, "      clearServerDown(); // the server answered: a window opened by an earlier failure is over\n", "")], OMPT),
    ("hook-omp: an unclear command is skipped by the window", [(TS, ': trust === "down" ? Promise.resolve<McpResult<GuardReply>>', ': (trust === "down" || (local?.unclear && serverDownCode())) ? Promise.resolve<McpResult<GuardReply>>')], OMPT),
    ("hook-omp: a failing unclear command opens the window", [(TS, 'if ((trust === "mismatch" || trust === "unverified") && answered.kind === "unavailable" && (', 'if (answered.kind === "unavailable" && (')], OMPT),
    ("hook-omp: a failing fingerprint fetch does not open the window", [(TS, "    if (code) openServerDown(code);\n", "    void code;\n")], OMPT),
    ("hook-omp: the fingerprint is fetched while the server is called down", [(TS, "  if (serverDownCode()) return null; // the server is called down: no fetch\n", "")], OMPT),
    ("hook-omp: no notice for a standing allow", [(TS, '(trust === "mismatch" || trust === "unverified" || trust === "down") && !trustNoticed.has(trust)', '(trust === "mismatch" || trust === "unverified") && !trustNoticed.has(trust)')], OMPT),
    # ── install.sh doctor: the guard state is what the HOOKS see, and the fingerprint check ──
    ("doctor: a server that exists only in the env file is treated as no server", [(INST, 'if [ "$url_file_only" = "$tok_file_only" ] && [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then hooks_see_server=1; fi', 'if [ "$url_file_only" = 0 ] && [ "$tok_file_only" = 0 ] && [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then hooks_see_server=1; fi')], SCRIPTS),
    ("doctor: a URL that is not https counts as a server the hooks see", [(INST, 'if [ "$url_file_only" = "$tok_file_only" ] && [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then hooks_see_server=1; fi', 'if [ "$url_file_only" = "$tok_file_only" ] && [ -n "${JEV_MCP_URL:-}" ] && [ -n "${JEV_MCP_TOKEN:-}" ]; then hooks_see_server=1; fi')], SCRIPTS),
    ("doctor: one process value and one file value are combined", [(INST, 'if [ -z "${JEV_MCP_URL:-}" ] && [ -z "${JEV_MCP_TOKEN:-}" ]; then', 'if [ -z "${JEV_MCP_URL:-}" ] || [ -z "${JEV_MCP_TOKEN:-}" ]; then')], SCRIPTS),
    ("doctor: a URL that is not https is reported as set", [(INST, 'elif [ "$url_https" = 0 ]; then bad "JEV_MCP_URL is not an https:// URL', 'elif false; then bad "JEV_MCP_URL is not an https:// URL')], SCRIPTS),
    ("doctor: a URL that is not https is contacted", [(INST, '[ -n "${JEV_MCP_TOKEN:-}" ] && [ "$url_https" = 1 ]; then\n    base=', '[ -n "${JEV_MCP_TOKEN:-}" ]; then\n    base=')], SCRIPTS),
    ("doctor: a rules fingerprint mismatch is not a failure", [(INST, '      else bad "guard rules differ from the server', '      else ok "guard rules differ from the server')], SCRIPTS),
    ("doctor: a server without a fingerprint is a failure", [(INST, 'elif [ -z "$sfp" ]; then echo "note the server did not report', 'elif [ -z "$sfp" ]; then bad "the server did not report')], SCRIPTS),
    ("doctor: the fingerprints are never compared", [(INST, 'elif [ "$sfp" = "$lfp" ]; then ok', 'elif true; then ok')], SCRIPTS),
    ("doctor: the fingerprint request puts the token in argv", [(INST, '--config - "$base/health" <<<"header = \\"authorization: Bearer $tokcfg\\"" 2>/dev/null \\', '-H "authorization: Bearer $JEV_MCP_TOKEN" "$base/health" 2>/dev/null \\')], SCRIPTS),
]


def fresh_copy(work):
    """The whole tree (never .git or node_modules) in a scratch directory; the stub Worker finds zod through a symlink."""
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "node_modules", "rules-fingerprint.mjs"))
    os.symlink(os.path.join(ROOT, "server", "node_modules"), os.path.join(work, "server", "node_modules"))


def main():
    verbose = "-v" in sys.argv
    pats = [a for a in sys.argv[1:] if a != "-v"]
    todo = [m for m in MUTATIONS if not pats or any(p in m[0] for p in pats)]
    tmp = tempfile.mkdtemp(prefix="jev-mut-localfirst-", dir=os.path.expanduser("~"))
    killed, survived, bad_mutations = 0, [], []
    try:
        # Control: every suite must PASS on the unmutated copy, or a "killed" mutation proves nothing (a suite that cannot run fails everything).
        for cmd in sorted({tuple(m[2]) for m in todo}):
            fresh_copy(os.path.join(tmp, "w"))
            p = subprocess.run(list(cmd), cwd=os.path.join(tmp, "w"), capture_output=True, text=True, timeout=600)
            print("CONTROL  %-4s %s" % ("ok" if p.returncode == 0 else "FAIL", " ".join(cmd[-2:])))
            if p.returncode != 0:
                print((p.stdout + p.stderr)[-1500:])
                return 2
        for name, edits, cmd in todo:
            work = os.path.join(tmp, "w")
            fresh_copy(work)
            bad = False
            for rel, old, new in edits:
                path = os.path.join(work, rel)
                with open(path) as f:
                    text = f.read()
                if text.count(old) != 1:
                    print("BAD MUTATION (pattern count %d): %s :: %s" % (text.count(old), name, old[:60]))
                    bad = True
                    break
                with open(path, "w") as f:
                    f.write(text.replace(old, new))
            if bad:
                bad_mutations.append(name)
                continue
            p = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=600)
            if p.returncode != 0:
                killed += 1
                print("KILLED   %s" % name)
                if verbose:
                    out = (p.stdout + p.stderr).splitlines()
                    hits = [l for l in out if l.startswith(("FAIL:", "ERROR:", "(fail)", "not ok", "✖", "FAIL "))]
                    for l in hits[:3] or out[-3:]:
                        print("           | %s" % l[:170])
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d mutations, %d killed, %d survived, %d BAD MUTATION" % (len(todo), killed, len(survived), len(bad_mutations)))
    return 1 if survived or bad_mutations else 0


if __name__ == "__main__":
    sys.exit(main())
